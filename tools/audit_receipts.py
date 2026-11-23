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
from .records import HEX_256, DataError, decode, encode, require, unique_fields


CHECKS = {"authenticity", "integrity", "relevance", "interpretation", "applicability", "contradiction"}
CHALLENGE_FIELDS = {"challenge_method", "challenge_result"}
# Historical execution ID: original CLI log digest, original session digest, sorted claim digests.
# These pins permit replay of the archived format. They do not qualify the underlying records.
LEGACY_ARCHIVES = {
    "01a207ff-6549-7aa2-a766-a57007b0035b": (
        "5e3230e5348842d2d19097d5b0c7e7bcb18ed09f65c3010e2794ceaf25693893",
        "97af4f9dcd4bbcb2ace739e0547412533b6a0339867be9bdff822367d3435aa9",
        ("d4fbc15c2ad949cbc78006ae474293cc69c16ceb8981ed44ed30d4a469a2e6ba",),
    ),
    "01a207ff-db7e-77d0-b9d7-c2890da86dd5": (
        "fb9ee6e30e224f3935457458daba28c00acd5960d24b9ed89888e3fdaee6e205",
        "a73daf215ea8eb754ca158b677b79e66246ab6d997aa8fffe30d709cdb7f6dc7",
        ("d4fbc15c2ad949cbc78006ae474293cc69c16ceb8981ed44ed30d4a469a2e6ba",),
    ),
    "01a20808-5af2-7780-ab27-6a17452c78ec": (
        "de3618b1c15af7b03af969173025ae160f61797a54473791b9fa370a77e7b40c",
        "6dded626a1be347ca24b55f628f48b3b0b102afae88cd986ae96ceaf44675600",
        ("f5227f39dbf57c3ea8c6aa642193c98358278ac009ab9f75424a12dcdcffabd4",),
    ),
    "01a20808-d88d-7ea2-a5ca-80ee3714efc8": (
        "4f27b054509ee0d8b0105d28ca49eb7474e644ceb81ced9b5ff76b4a819faad6",
        "02e6e91bf426c069732c8d4be06076165134e40e8cea1e83bd4f1784b35f30e7",
        ("f5227f39dbf57c3ea8c6aa642193c98358278ac009ab9f75424a12dcdcffabd4",),
    ),
    "01a20818-6f53-7922-954f-b7f1eb382a0a": (
        "ac5e14204eac77141250edcc69dc8c2d3ef443f30446aade88bd6b4c6e70270e",
        "a291a36d90e61dd55eb59a63d441e474ff62bf839d1d2da1586081c21c7854d5",
        ("156a44ba1a6a52d26a9cc4010368457df9262d9c9f5d53f511d898ae488668d8",
         "f38cd63ad2f23a9837d93880c22ffed2e2f8405b238d81e842554384883d3e84"),
    ),
    "01a20819-289c-76c0-85b7-c388529e9786": (
        "0953bf1c3224fd99e11e4e87f5adf6e0c7c5ed8415add7ff66854c9ca4bedd19",
        "c08acb420e56a3982c3b7cd277c283cc8ae37c73987d34d509e32f2157fcf695",
        ("156a44ba1a6a52d26a9cc4010368457df9262d9c9f5d53f511d898ae488668d8",
         "f38cd63ad2f23a9837d93880c22ffed2e2f8405b238d81e842554384883d3e84"),
    ),
    "01a20836-6952-74d3-9bac-2eb72a5e346f": (
        "45541fdb472e978fd1e94e7792311860ed6bcdcfb479c9f7ee59f10c44330303",
        "d9e417ce7b52b1e0191c7c11f6f8dcbb84204111cb6fef94ccf868cfbfef6cc5",
        ("71ae4b65f92df592fb57fbb7a898935c7135fa339b028fcb51340b9ecb71c722",
         "993ae4bdf9acb739a35d74d6a0db9903dac1aea3cbd4dd4e3b24dcdb2afad848"),
    ),
    "01a20838-229a-7b33-b003-28636bcea490": (
        "470ebfa825a6100f8333709a97960ece1d8254f5b11c5adaa30c23c9ee601111",
        "bd21b47289ea21e8750692199d25cd0ed8ada5b47b04ce3693095abebe02eafa",
        ("71ae4b65f92df592fb57fbb7a898935c7135fa339b028fcb51340b9ecb71c722",
         "993ae4bdf9acb739a35d74d6a0db9903dac1aea3cbd4dd4e3b24dcdb2afad848"),
    ),
}


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


def legacy_assessment(row, batched):
    checks = row.get("checks")
    if isinstance(checks, dict) and checks.keys() == CHECKS and CHALLENGE_FIELDS <= row.keys():
        return True
    assessments = row.get("assessments")
    return (not batched and isinstance(assessments, list) and bool(assessments)
            and all(isinstance(item, dict) and item.keys() == {"dependency_id", "outcome", "reasoning", "checks"}
                    and isinstance(item["checks"], dict) and item["checks"].keys() == CHECKS
                    for item in assessments))


def execution(events_path, session_path):
    events, events_digest = jsonl(events_path, cli_event)
    session, session_digest = jsonl(session_path)
    kinds = [event["type"] for event in events]
    require(kinds[:2] == ["thread.started", "turn.started"] and kinds[-1] == "turn.completed"
            and all(kinds.count(kind) == 1 for kind in ("thread.started", "turn.started", "turn.completed"))
            and not {"error", "turn.failed"} & set(kinds), "Codex event stream is not one successful execution")
    thread = events[0]["thread_id"]
    event_items = [row["item"] for row in events if row["type"] == "item.completed"]
    final_event_index = next(index for index in range(len(event_items) - 1, -1, -1)
                             if event_items[index]["type"] == "agent_message")
    message = event_items[final_event_index]["text"]
    try:
        parsed = decode(message.encode("utf-8"))
    except (DataError, ValueError, RecursionError) as error:
        raise DataError("Codex final assessment contains invalid JSON") from error
    require(isinstance(parsed, dict), "Codex final assessment is not a JSON object")
    rows = parsed.get("claims", [parsed])
    require(isinstance(rows, list) and rows and all(isinstance(row, dict) for row in rows),
            "Codex claim assessments are incomplete")
    assessments = {}
    for row in rows:
        digest = row.get("claim_sha256")
        require(isinstance(digest, str) and HEX_256.fullmatch(digest)
                and isinstance(row.get("conclusion"), str) and digest not in assessments,
                "Codex claim assessments are incomplete or ambiguous")
        assessments[digest] = row
    structured = any("dependencies" in row for row in rows)
    if structured:
        require(all("dependencies" in row for row in rows), "structured Codex claim assessments are incomplete")
    else:
        require(all(legacy_assessment(row, batched="claims" in parsed) for row in rows),
                "structured Codex claim assessments are incomplete")
        require(LEGACY_ARCHIVES.get(thread) == (events_digest, session_digest, tuple(sorted(assessments))),
                "legacy assessment requires a pinned historical execution, exact claim set and both original logs")

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
        "final_event_index": final_event_index,
        "assessments": assessments,
        "structured": structured,
        "event_items": event_items,
        "session": session,
        "events_sha256": events_digest,
        "session_sha256": session_digest,
    }


def final_session_assessment_index(run):
    return one(
        (index for index, row in enumerate(run["session"]) if row["type"] == "response_item"
         and row["payload"].get("type") == "message" and row["payload"].get("role") == "assistant"
         and any(part.get("text", "").strip() == run["final_message"].strip()
                 for part in row["payload"]["content"])),
        "final Codex session assessment",
    )


def check_web_acquisition(run, recorded):
    require("sha256" not in recorded, "rendered Codex web results cannot corroborate a source byte digest")
    capture, locator = recorded["capture"], recorded["locator"]
    native_index, native = one(((index, item) for index, item in enumerate(run["event_items"])
                                if item.get("id") == capture), "receipt event completion")
    require(native["type"] == "web_search" and native["action"] == {"type": "open_page", "url": locator},
            "recorded receipt differs from the Codex web-open event")
    require(native_index < run["final_event_index"], "Codex web-open completion follows the final assessment")
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
    output_index, output = one(
        ((i, entry["payload"]["output"]) for i, entry in enumerate(session)
         if entry["type"] == "response_item" and entry["payload"].get("type") == "custom_tool_call_output"
         and entry["payload"]["call_id"] == call["call_id"]),
        "associated Codex tool output",
    )
    require(index < output_index < final_session_assessment_index(run),
            "Codex web tool result was not delivered before the assessment")
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
    final_index = final_session_assessment_index(run)
    representations = (text, *(json.dumps(text, ensure_ascii=ascii_only)[1:-1] for ascii_only in (True, False)))
    require(index < output_index < final_index
            and any(value in part["text"] for part in output if part.get("type") in {"input_text", "text"}
                    for value in representations),
            "source-byte tool result was not delivered before the assessment")


def retained_source_bytes(observation):
    if "body_encoding" in observation:
        require(observation.keys() == {"source", "url", "http_status", "retrieved_at", "acquisition_id",
                                       "bytes", "sha256", "ranges", "body_encoding", "source_text"}
                and observation["body_encoding"] == "utf-8" and isinstance(observation["source_text"], str),
                "source-byte tool returned an invalid UTF-8 observation")
        try:
            raw = observation["source_text"].encode("utf-8")
        except UnicodeEncodeError as error:
            raise DataError("source-byte tool returned an invalid UTF-8 body") from error
        require(raw, "source-byte tool returned an empty UTF-8 body")
        return raw

    try:
        raw = b64decode(observation["body_base64"], validate=True)
    except (Base64Error, ValueError) as error:
        raise DataError("source-byte tool returned invalid base64") from error
    require(raw and b64encode(raw).decode("ascii") == observation["body_base64"]
            and observation["source_text"].encode("utf-8") == raw,
            "retained source bytes differ from the displayed source text")
    return raw


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
    require(isinstance(observation, dict), "source-byte tool returned invalid observation JSON")
    raw = retained_source_bytes(observation)
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


def check_assessment(run, review):
    assessment = run["assessments"].get(review["claim_sha256"])
    require(assessment is not None and assessment["conclusion"] == review["conclusion"],
            "Codex final assessment differs from the recorded claim or conclusion")
    structured = run["structured"]
    require(all(field in review and assessment.get(field) == review[field]
                for field in ("reasoning", "limitations") if structured or field in assessment),
            "Codex claim reasoning or limitations differ from the recorded assessment")

    rows = review["assessments"]
    recorded = {row["dependency"]["id"]: row for row in rows}
    require(len(recorded) == len(rows), "recorded dependency assessments have ambiguous IDs")
    if structured or "assessments" in assessment:
        dependencies = assessment["dependencies" if structured else "assessments"]
        identifier_field = "id" if structured else "dependency_id"
        require(isinstance(dependencies, list) and dependencies, "Codex dependency assessments are incomplete")
        native = {}
        for dependency in dependencies:
            identifier = dependency.get(identifier_field) if isinstance(dependency, dict) else None
            require(isinstance(identifier, str) and identifier and identifier not in native,
                    "Codex dependency assessments are incomplete or ambiguous")
            native[identifier] = dependency
        require(native.keys() == recorded.keys(), "Codex dependency assessments differ from the recorded dependencies")
        for identifier, dependency in recorded.items():
            findings = native[identifier]
            checks = findings.get("checks")
            require(isinstance(checks, dict) and checks.keys() == CHECKS and checks == dependency["checks"]
                    and findings.get("outcome") == dependency["outcome"]
                    and findings.get("reasoning") == dependency["reasoning"],
                    "Codex dependency outcome, reasoning or checks differ from the recorded assessment")
    if "checks" in assessment:
        checks = assessment["checks"]
        require(isinstance(checks, dict) and checks.keys() == CHECKS and recorded
                and all(row["checks"] == checks for row in recorded.values()),
                "Codex claim-level checks differ from the recorded dependency checks")

    # Research output without a recorded SCES challenge has no corresponding challenge to match.
    if review["phase"] == "independent-review" or "challenge" in review:
        challenge = review.get("challenge")
        require(all(challenge is not None and recorded_field in challenge
                    and assessment.get(native_field) == challenge[recorded_field]
                    for native_field, recorded_field in (("challenge_method", "method"), ("challenge_result", "results"))
                    if structured or native_field in assessment),
                "Codex challenge method or results differ from the recorded assessment")


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
        require(len(reviews) == len(expected) == 2, "a matched claim must have two separate recorded executions")
        require({review["phase"] for review in reviews} == {"research", "independent-review"},
                "recorded execution pair lacks distinct research and review phases")
        for review in reviews:
            recorded = review["run"]
            run = runs[recorded["execution"]]
            require(recorded["harness"] == run["harness"] and recorded["model"] == run["model"]
                    and recorded["started"] == seconds(run["started"])
                    and recorded["completed"] == seconds(run["completed"]),
                    "recorded execution metadata differs from the Codex session")
            check_assessment(run, review)
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
