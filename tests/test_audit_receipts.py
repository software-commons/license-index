"""Synthetic event streams for testing mechanical receipt matching."""

from contextlib import redirect_stderr
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.audit_receipts import audit_receipts, cli_event, main
from tools.records import DataError


CLAIM = {"kind": "claim", "id": "fixture", "revision": 1}
CLAIM_DIGEST = "a" * 64
LOCATOR = "https://example.invalid/fixture"
STARTED = "2026-01-01T12:00:00Z"
RETRIEVED = "2026-01-01T12:00:01Z"
COMPLETED = "2026-01-01T12:00:02Z"


class ReceiptAuditTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.first, research = self.fixture("research")
        self.second, review = self.fixture("independent-review")
        self.registry = {"claims": [{"claim": CLAIM, "recorded_reviews": [research, review]}]}

    def fixture(self, phase):
        thread = f"fixture-{phase}"
        turn = f"fixture-turn-{phase}"
        capture = f"exec-{phase}"
        result = "turn1view0" if phase == "research" else "turn2view0"
        message = json.dumps({"claim_sha256": CLAIM_DIGEST, "conclusion": "supported"})
        events = [
            {"type": "thread.started", "thread_id": thread},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "web_search", "id": capture,
                                                "action": {"type": "open_page", "url": LOCATOR}}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": message}},
            {"type": "turn.completed"},
        ]
        session = [
            {"type": "session_meta", "payload": {"id": thread, "source": "exec", "cli_version": "fixture"}},
            {"type": "event_msg", "timestamp": STARTED, "payload": {"type": "task_started", "turn_id": turn}},
            {"type": "turn_context", "payload": {"model": "fixture", "turn_id": turn}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "fixture"}},
            {"type": "event_msg", "timestamp": RETRIEVED,
             "payload": {"type": "item_completed", "turn_id": turn,
                         "item": {"type": "Extension", "id": capture, "action": {"type": "openPage", "url": LOCATOR},
                                  "results": [{"url": LOCATOR, "ref_id": result, "type": "text_result"}]}}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "fixture",
                                                 "output": [{"type": "input_text",
                                                             "text": f"\ue200cite\ue202{result}\ue201"}]}},
            {"type": "event_msg", "timestamp": COMPLETED, "payload": {"type": "task_complete", "turn_id": turn,
                                                                   "last_agent_message": message}},
        ]
        paths = self.root / f"{phase}-events.jsonl", self.root / f"{phase}-session.jsonl"
        for path, rows in zip(paths, (events, session)):
            path.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))
        verification = {
            "phase": phase, "conclusion": "supported", "claim_sha256": CLAIM_DIGEST,
            "run": {"execution": thread, "model": "fixture", "harness": "codex-cli fixture",
                    "started": STARTED, "completed": COMPLETED},
            "acquisitions": [{"capture": capture, "locator": LOCATOR, "retrieved_at": RETRIEVED}],
        }
        return paths, verification

    def test_matches_both_original_streams_and_counts_checked_acquisitions(self):
        checked = audit_receipts(self.registry, [self.first, self.second])
        self.assertEqual(checked["claims"], [CLAIM])
        self.assertEqual(checked["acquisition_bindings"], 2)
        self.assertEqual(checked["unique_acquisitions"], 2)
        self.assertEqual(len(checked["executions"]), 2)

    def test_rejects_incomplete_or_mixed_execution_pairs(self):
        with self.assertRaisesRegex(DataError, "complete recorded eligible claim pairs"):
            audit_receipts(self.registry, [self.first])
        with self.assertRaisesRegex(DataError, "supplied more than once"):
            audit_receipts(self.registry, [self.first, self.first])
        with self.assertRaisesRegex(DataError, "different or unsupported executions"):
            audit_receipts(self.registry, [(self.first[0], self.second[1]), self.second])
        self.second[0].write_bytes(b"\n".join(self.second[0].read_bytes().splitlines()[:-1]) + b"\n")
        with self.assertRaisesRegex(DataError, "not one successful execution"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_allows_a_complete_pair_when_one_execution_serves_other_claims(self):
        research, review = self.registry["claims"][0]["recorded_reviews"]
        other_review = {**review, "run": {**review["run"], "execution": "other-review"}}
        self.registry["claims"].append({"claim": {**CLAIM, "id": "other"},
                                        "recorded_reviews": [research, other_review]})
        self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])

    def test_rejects_changed_claim_digest_locator_and_non_web_digests(self):
        review = self.registry["claims"][0]["recorded_reviews"][1]
        with patch.dict(review, {"claim_sha256": "b" * 64}):
            with self.assertRaisesRegex(DataError, "differs from the recorded claim"):
                audit_receipts(self.registry, [self.first, self.second])
        acquisition = review["acquisitions"][0]
        with patch.dict(acquisition, {"locator": LOCATOR + "/other"}):
            with self.assertRaisesRegex(DataError, "differs from the Codex web-open"):
                audit_receipts(self.registry, [self.first, self.second])
        with patch.dict(acquisition, {"sha256": "c" * 64}):
            with self.assertRaisesRegex(DataError, "cannot corroborate a source byte digest"):
                audit_receipts(self.registry, [self.first, self.second])

    def test_requires_actual_tool_output_even_when_agent_message_is_present(self):
        self.first[1].write_bytes(self.first[1].read_bytes().replace(
            rb"\ue202turn1view0\ue201", rb"\ue202turn1view01\ue201"
        ))
        with self.assertRaisesRegex(DataError, "tool output lacks"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_cli_accepts_only_the_documented_duplicate_web_item_shape(self):
        event = b'{"type":"item.completed","item":{"id":"item_1","type":"web_search","id":"exec-fixture"}}'
        self.assertEqual(cli_event(event)["item"]["id"], "exec-fixture")
        with self.assertRaisesRegex(DataError, "ambiguous IDs"):
            cli_event(event.replace(b'"item_1"', b'"arbitrary"'))
        with self.assertRaisesRegex(DataError, "duplicate JSON field"):
            cli_event(event.replace(b'"web_search"', b'"agent_message"'))

    def test_cli_error_does_not_echo_private_log_content_or_path(self):
        self.first[1].write_bytes(b'{"private-sentinel":0,"private-sentinel":1}\n')
        self.assert_private_error("invalid JSONL")

    def test_cli_error_does_not_echo_malformed_final_assessment(self):
        rows = [json.loads(line) for line in self.first[0].read_bytes().splitlines()]
        rows[-2]["item"]["text"] = '{"private-sentinel":0,"private-sentinel":1}'
        self.first[0].write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))
        self.assert_private_error("final assessment contains invalid JSON")

    def assert_private_error(self, expected):
        output = StringIO()
        with patch("tools.audit_receipts.audit_claims", return_value=self.registry), redirect_stderr(output):
            with self.assertRaises(SystemExit) as error:
                main(["--repo", str(self.root), "--policy", str(self.root), "--execution",
                      *map(str, self.first), "--execution", *map(str, self.second)])
        self.assertEqual(error.exception.code, 1)
        self.assertIn(expected, output.getvalue())
        self.assertNotIn("private-sentinel", output.getvalue())
        self.assertNotIn(str(self.first[1]), output.getvalue())
