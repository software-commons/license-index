"""Audit complete original job bytes despite the native tool-event summary's display cap."""
from argparse import ArgumentParser
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import re
import sys

repo = Path.cwd()
sys.path.insert(0, str(repo))
from tools.audit_receipts import check_byte_delivery, execution, final_session_assessment_index, instant, retained_source_bytes, seconds

name = "spdx_release_job"
locator = "https://api.github.com/repos/spdx/license-list-XML/actions/jobs/104892289184/logs"
expected_count = 81691
expected_digest = "1e9137b29385a9ce0deaa48c20ab9927916426819a69f0cfc6281d239340c282"
marker = re.compile(r"\u2026[0-9]+ chars truncated\u2026")


def full_job_receipt(run, original_body):
    entries = [
        (index, row) for index, row in enumerate(run["session"])
        if row["type"] == "event_msg" and row["payload"].get("type") == "item_completed"
        and row["payload"].get("item", {}).get("type") == "McpToolCall"
        and row["payload"]["item"].get("server") == "fixed_public_source"
        and row["payload"]["item"].get("tool") == "open_original_source"
        and row["payload"]["item"].get("arguments") == {"source": name}
    ]
    (position, row), = entries
    event = row["payload"]
    item = event["item"]
    assert event["thread_id"] == run["execution"] and event["turn_id"] == run["turn"]
    assert item["status"] == "completed" and item["readOnlyHint"] is True
    assert item["result"]["isError"] is False
    content, = item["result"]["content"]
    original, = [
        row for row in run["event_items"] if row.get("type") == "mcp_tool_call"
        and row.get("server") == item["server"] and row.get("tool") == item["tool"]
        and row.get("arguments") == item["arguments"] and row["status"] == "completed"
    ]
    cli, = original["result"]["content"]
    assert cli["type"] == "text" and not original["result"].get("isError")
    complete = cli["text"]
    if content["text"] != complete:
        truncated = json.loads(content["text"])
        assert truncated["isError"] is False
        displayed, = truncated["content"]
        assert displayed["type"] == "text"
        separator, = list(marker.finditer(displayed["text"]))
        prefix = displayed["text"][:separator.start()]
        suffix = displayed["text"][separator.end():]
        assert len(prefix) > 20000 and len(suffix) > 20000
        assert complete.startswith(prefix) and complete.endswith(suffix)
        assert len(prefix) + len(suffix) < len(complete)

    check_byte_delivery(run, position, complete)
    assert position < final_session_assessment_index(run)
    last = next(row for row in reversed(run["event_items"]) if row["type"] == "agent_message")
    assert run["event_items"].index(original) < run["event_items"].index(last)
    result = json.loads(complete)
    body = retained_source_bytes(result)
    assert result["source"] == name and result["url"] == locator and result["http_status"] == 200
    assert result["bytes"] == len(body) == expected_count
    assert result["sha256"] == sha256(body).hexdigest() == expected_digest
    assert body == original_body
    assert re.fullmatch(r"[a-f0-9]{32}", result["acquisition_id"])
    started, completed = (datetime.fromtimestamp(event[field] // 1000, timezone.utc)
                          for field in ("started_at_ms", "completed_at_ms"))
    retrieved = instant(result["retrieved_at"])
    recorded = instant(row["timestamp"])
    assert run["started"] <= recorded <= run["completed"]
    assert instant(seconds(run["started"])) <= started <= retrieved <= completed <= instant(seconds(recorded))
    return item, result, body


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("cli_events", type=Path)
    parser.add_argument("native_session", type=Path)
    args = parser.parse_args()
    run = execution(args.cli_events, args.native_session)
    event, result, _ = full_job_receipt(run, args.original.read_bytes())
    print(json.dumps({"execution":run["execution"], "capture":event["id"],
                      "bytes":result["bytes"], "sha256":result["sha256"],
                      "events_sha256":run["events_sha256"],
                      "session_sha256":run["session_sha256"],
                      "matched_complete_model_delivery":True}, sort_keys=True))


if __name__ == "__main__":
    main()
