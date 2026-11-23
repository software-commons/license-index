"""Compare recorded SCES source receipts with explicitly supplied private Codex logs."""

import argparse
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

from .audit_claims import audit_claims
from .capture_source import fingerprints
from .qualification import _exact_file
from .records import DataError, decode, encode, require, unique_fields


class ObjectPairs(list):
    """JSON object entries before duplicate field checks."""


def strict_objects(value):
    if isinstance(value, ObjectPairs):
        return {name: strict_objects(item) for name, item in unique_fields(value).items()}
    if isinstance(value, list):
        return [strict_objects(item) for item in value]
    return value


def cli_event(line):
    pairs = json.loads(line, object_pairs_hook=ObjectPairs)
    require(isinstance(pairs, ObjectPairs), "Codex CLI event is not an object")
    event = unique_fields(pairs)
    item = event.get("item")
    if event.get("type") in {"item.started", "item.completed"} and isinstance(item, ObjectPairs):
        types = [value for name, value in item if name == "type"]
        ids = [value for name, value in item if name == "id"]
        # Codex CLI serializes a display ID before the extension's capture ID
        # for this web event shape. The capture ID still has to match the session.
        if types == ["web_search"] and len(ids) == 2 and all(isinstance(value, str) for value in ids):
            require(re.fullmatch(r"item_[0-9]+", ids[0]) and ids[1].startswith("exec-") and len(ids[1]) > 5,
                    "Codex CLI web event has ambiguous IDs")
            item.remove(("id", ids[0]))
    return {name: strict_objects(value) for name, value in event.items()}


def jsonl(path, parse=decode):
    try:
        raw = _exact_file(Path(os.path.abspath(path)))
        rows = [parse(line) for line in raw.removeprefix(b"\xef\xbb\xbf").splitlines()]
    except (DataError, OSError, ValueError, RecursionError) as error:
        raise DataError("a supplied Codex log is unreadable or contains invalid JSONL") from error
    require(rows and all(isinstance(row, dict) for row in rows), "a supplied Codex log has invalid events")
    return rows, sha256(raw).hexdigest()


def one(items, description):
    matches = list(items)
    require(len(matches) == 1, f"expected one {description}")
    return matches[0]


def instant(value):
    parsed = datetime.fromisoformat(value)
    require(parsed.utcoffset() is not None, "a Codex event timestamp lacks an offset")
    return parsed.astimezone(timezone.utc)


def seconds(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def execution(events_path, session_path):
    events, events_digest = jsonl(events_path, cli_event)
    session, session_digest = jsonl(session_path)
    kinds = [event["type"] for event in events]
    require(kinds[:2] == ["thread.started", "turn.started"] and kinds[-1] == "turn.completed"
            and all(kinds.count(kind) == 1 for kind in ("thread.started", "turn.started", "turn.completed"))
            and not {"error", "turn.failed"} & set(kinds), "Codex event stream is not one successful execution")
    thread = events[0]["thread_id"]
    event_items = [row["item"] for row in events if row["type"] == "item.completed"]
    message = next(item["text"] for item in reversed(event_items) if item["type"] == "agent_message")
    try:
        parsed = decode(message.encode("utf-8"))
    except (DataError, ValueError, RecursionError) as error:
        raise DataError("Codex final assessment contains invalid JSON") from error
    require(isinstance(parsed, dict), "Codex final assessment is not a JSON object")
    assessments = parsed.get("claims", [parsed])
    conclusions = {row["claim_sha256"]: row["conclusion"] for row in assessments}
    require(conclusions and len(conclusions) == len(assessments), "Codex claim assessments are ambiguous")

    meta = one((row["payload"] for row in session if row["type"] == "session_meta"), "Codex session header")
    context = one((row["payload"] for row in session if row["type"] == "turn_context"), "Codex turn context")
    require(meta["id"] == thread and meta["source"] == "exec" and not meta.get("forked_from_id"),
            "Codex logs identify different or unsupported executions")
    timing = {}
    for marker in ("task_started", "task_complete"):
        row = one((entry for entry in session if entry["type"] == "event_msg"
                   and entry["payload"].get("type") == marker), f"Codex {marker} event")
        require(row["payload"]["turn_id"] == context["turn_id"], "Codex task belongs to another turn")
        timing[marker] = instant(row["timestamp"])
    require(row["payload"]["last_agent_message"].strip() == message.strip(),
            "Codex event stream and session disagree on the final assessment")
    require(timing["task_started"] <= timing["task_complete"], "Codex task timestamps are out of order")
    return {
        "execution": thread,
        "harness": f"codex-cli {meta['cli_version']}",
        "model": context["model"],
        "turn": context["turn_id"],
        "started": timing["task_started"],
        "completed": timing["task_complete"],
        "final_message": message,
        "conclusions": conclusions,
        "event_items": event_items,
        "session": session,
        "events_sha256": events_digest,
        "session_sha256": session_digest,
    }


def check_web_acquisition(run, recorded):
    require("sha256" not in recorded, "rendered Codex web results cannot corroborate a source byte digest")
    capture, locator = recorded["capture"], recorded["locator"]
    native = one((item for item in run["event_items"] if item.get("id") == capture), "receipt event completion")
    require(native["type"] == "web_search" and native["action"] == {"type": "open_page", "url": locator},
            "recorded receipt differs from the Codex web-open event")
    session = run["session"]
    index, row = one(
        ((index, row) for index, row in enumerate(session)
         if row["type"] == "event_msg" and row["payload"].get("type") == "item_completed"
         and row["payload"].get("item", {}).get("id") == capture),
        "receipt session completion",
    )
    item = row["payload"]["item"]
    when = instant(row["timestamp"])
    require(row["payload"]["turn_id"] == run["turn"] and item["type"] == "Extension"
            and item["action"] == {"type": "openPage", "url": locator},
            "session receipt differs from the exact web-open action or turn")
    require(run["started"] <= when <= run["completed"] and seconds(when) == recorded["retrieved_at"],
            "recorded receipt differs from the Codex acquisition time")
    refs = {result["ref_id"] for result in item["results"]
            if result["type"] == "text_result" and result["url"] == locator
            and re.fullmatch(r"turn[0-9]+(?:view|fetch|search)[0-9]+", result["ref_id"])}
    require(refs, "Codex session lacks a result for the recorded locator")
    call = next((previous["payload"] for previous in reversed(session[:index])
                 if previous["type"] == "response_item"
                 and previous["payload"].get("type") == "custom_tool_call"), {})
    require(call.get("name") == "exec", "receipt lacks the associated Codex tool invocation")
    output = one((later["payload"]["output"] for later in session[index + 1:]
                  if later["type"] == "response_item" and later["payload"].get("type") == "custom_tool_call_output"
                  and later["payload"]["call_id"] == call["call_id"]), "associated Codex tool output")
    require(any(f"\ue200cite\ue202{reference}\ue201" in part["text"] for reference in refs for part in output
                if part.get("type") in {"input_text", "text"}), "Codex tool output lacks the recorded result reference")


def check_byte_delivery(run, index, text):
    session = run["session"]
    call = next((row["payload"] for row in reversed(session[:index])
                 if row["type"] == "response_item"
                 and row["payload"].get("type") == "custom_tool_call"), {})
    require(call.get("name") == "exec", "source-byte receipt lacks its Codex tool invocation")
    output_index, output = one(
        ((i, row["payload"]["output"]) for i, row in enumerate(session)
         if row["type"] == "response_item" and row["payload"].get("type") == "custom_tool_call_output"
         and row["payload"]["call_id"] == call["call_id"]),
        "source-byte tool output delivered to Codex",
    )
    final_index = one(
        (i for i, row in enumerate(session) if row["type"] == "response_item"
         and row["payload"].get("type") == "message" and row["payload"].get("role") == "assistant"
         and any(part.get("text", "").strip() == run["final_message"].strip()
                 for part in row["payload"]["content"])),
        "final Codex session assessment",
    )
    representations = (text, *(json.dumps(text, ensure_ascii=ascii_only)[1:-1] for ascii_only in (True, False)))
    require(index < output_index < final_index
            and any(value in part["text"] for part in output if part.get("type") in {"input_text", "text"}
                    for value in representations),
            "source-byte tool result was not delivered before the assessment")


def check_byte_acquisition(run, index, row, recorded):
    event = row["payload"]
    item = event["item"]
    arguments = item["arguments"]
    result = item["result"]
    require(event["thread_id"] == run["execution"] and event["turn_id"] == run["turn"]
            and item["server"] == "fixed_public_source" and item["tool"] == "open_original_source"
            and item["readOnlyHint"] is True and item["status"] == "completed"
            and result.get("isError") is False and arguments.keys() == {"source"},
            "byte receipt differs from a completed fixed-source call")
    content = result["content"]
    native = one((entry for entry in run["event_items"]
                  if entry["type"] == "mcp_tool_call" and entry["server"] == item["server"]
                  and entry["tool"] == item["tool"] and entry["arguments"] == arguments
                  and entry.get("result") and entry["result"]["content"] == content),
                 "matching Codex CLI source-byte tool completion")
    final_item = next(entry for entry in reversed(run["event_items"]) if entry["type"] == "agent_message")
    require(run["event_items"].index(native) < run["event_items"].index(final_item)
            and native["status"] == "completed" and len(content) == 1 and content[0]["type"] == "text",
            "source-byte tool completion is invalid")
    check_byte_delivery(run, index, content[0]["text"])
    try:
        observation = decode(content[0]["text"].encode("utf-8"))
    except (DataError, ValueError, RecursionError) as error:
        raise DataError("source-byte tool returned invalid observation JSON") from error
    require(observation["source"] == arguments["source"] and observation["url"] == recorded["locator"]
            and type(observation["http_status"]) is int and observation["http_status"] == 200
            and observation["retrieved_at"] == recorded["retrieved_at"]
            and re.fullmatch(r"[0-9a-f]{32}", observation["acquisition_id"]),
            "byte receipt differs from the observed acquisition")
    retrieved = instant(observation["retrieved_at"])
    when = instant(row["timestamp"])
    start_ms, end_ms = event["started_at_ms"], event["completed_at_ms"]
    require(type(start_ms) is int and type(end_ms) is int and start_ms <= end_ms,
            "source-byte tool call has invalid timestamps")
    started, completed = (datetime.fromtimestamp(value // 1000, timezone.utc) for value in (start_ms, end_ms))
    require(run["started"] <= when <= run["completed"]
            and instant(seconds(run["started"])) <= started <= retrieved <= completed <= instant(seconds(when)),
            "byte receipt is outside the recorded tool call")
    try:
        raw = b64decode(observation["body_base64"], validate=True)
    except (Base64Error, ValueError) as error:
        raise DataError("source-byte tool returned invalid base64") from error
    require(raw and b64encode(raw).decode("ascii") == observation["body_base64"]
            and observation["source_text"].encode("utf-8") == raw,
            "retained source bytes differ from the displayed source text")
    ranges = observation["ranges"]
    require(isinstance(ranges, list), "source-byte tool returned invalid citation ranges")
    observed = fingerprints(raw, [(area["start"], area["end"]) for area in ranges])
    require(type(observation["bytes"]) is int and {field: observation[field] for field in observed} == observed
            and recorded.get("sha256") == observed["sha256"],
            "recorded source byte or range digest differs from the retained bytes")
    return native["id"], observation["acquisition_id"]


def check_acquisition(run, recorded, byte_bindings=None):
    mcp_items = [(index, row) for index, row in enumerate(run["session"]) if row["type"] == "event_msg"
                 and row["payload"].get("type") == "item_completed"
                 and row["payload"].get("item", {}).get("type") == "McpToolCall"
                 and row["payload"]["item"]["id"] == recorded["capture"]]
    if mcp_items:
        index, row = one(mcp_items, "native source-byte tool event")
        native_id, acquisition_id = check_byte_acquisition(run, index, row, recorded)
        if byte_bindings is not None:
            owner = (run["execution"], recorded["capture"])
            for key in (("cli", run["execution"], native_id), ("acquisition", acquisition_id)):
                require(byte_bindings.setdefault(key, owner) == owner,
                        "source-byte tool completion or acquisition was reused across captures")
        return "source-bytes"
    check_web_acquisition(run, recorded)
    return "web-open"


def audit_receipts(registry, executions):
    runs = {}
    for events, session in executions:
        run = execution(events, session)
        thread = run["execution"]
        require(thread not in runs, "a Codex execution was supplied more than once")
        runs[thread] = run
    used = set()
    captures = set()
    claims = []
    acquisitions = 0
    methods = set()
    byte_bindings = {}
    for row in registry["claims"]:
        reviews = row.get("recorded_reviews", ())
        expected = {review["run"]["execution"] for review in reviews}
        if not expected or not expected <= runs.keys():
            continue
        require(len(expected) == 2, "a matched claim must have two separate recorded executions")
        require({review["phase"] for review in reviews} == {"research", "independent-review"},
                "recorded execution pair lacks distinct research and review phases")
        for review in reviews:
            recorded = review["run"]
            run = runs[recorded["execution"]]
            require(recorded["harness"] == run["harness"] and recorded["model"] == run["model"]
                    and recorded["started"] == seconds(run["started"])
                    and recorded["completed"] == seconds(run["completed"]),
                    "recorded execution metadata differs from the Codex session")
            require(run["conclusions"].get(review["claim_sha256"]) == review["conclusion"],
                    "Codex final assessment differs from the recorded claim or conclusion")
            require(review["acquisitions"], "the recorded execution has no source acquisitions to compare")
            for acquisition in review["acquisitions"]:
                methods.add(check_acquisition(run, acquisition, byte_bindings))
                acquisitions += 1
                captures.add((run["execution"], acquisition["capture"]))
            used.add(run["execution"])
        claims.append(row["claim"])
    require(claims and used == runs.keys(), "supplied executions must form complete recorded eligible claim pairs")
    return {
        "status": ("recorded-source-receipts-match-supplied-codex-logs" if "source-bytes" in methods
                   else "recorded-web-receipts-match-supplied-codex-logs"),
        "claims": claims,
        "acquisition_bindings": acquisitions,
        "unique_acquisitions": len(captures),
        "executions": [{field: run[field] for field in ("execution", "events_sha256", "session_sha256")}
                       for _, run in sorted(runs.items())],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path, help="private evidence checkout")
    parser.add_argument("--policy", required=True, type=Path, help="pinned SCES checkout")
    parser.add_argument("--base", help="full SHA of the trusted history base")
    parser.add_argument("--execution", action="append", nargs=2, type=Path, required=True,
                        metavar=("EVENTS", "SESSION"), help="one original Codex CLI event stream and session log")
    args = parser.parse_args(argv)
    try:
        registry = audit_claims(args.repo, args.policy, args.base, include_receipts=True)
    except (DataError, KeyError, OSError, ValueError):
        parser.exit(1, "receipt audit: pinned SCES eligibility check failed. Run the claim audit privately.\n")
    try:
        result = audit_receipts(registry, args.execution)
    except DataError as error:
        parser.exit(1, f"receipt audit: {error}\n")
    except (KeyError, ValueError, TypeError, AttributeError, StopIteration, IndexError, OverflowError, RecursionError):
        parser.exit(1, "receipt audit: unsupported or incomplete Codex log structure.\n")
    sys.stdout.buffer.write(encode(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
