"""Synthetic event streams for testing mechanical receipt matching."""

from base64 import b64encode
from contextlib import redirect_stderr
from copy import deepcopy
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.audit_receipts import audit_receipts, cli_event, instant, main
from tools.records import DataError


CLAIM = {"kind": "claim", "id": "fixture", "revision": 1}
CLAIM_DIGEST = "a" * 64
LOCATOR = "https://example.invalid/fixture"
STARTED = "2026-01-01T12:00:00Z"
RETRIEVED = "2026-01-01T12:00:01Z"
COMPLETED = "2026-01-01T12:00:02Z"
CHECK_NAMES = ("authenticity", "integrity", "relevance", "interpretation", "applicability", "contradiction")


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
        message = json.dumps({"claim_sha256": CLAIM_DIGEST, "conclusion": "supported",
                              "dependencies": [{"id": "fixture", "outcome": "supports", "reasoning": "Clause applies.",
                                                "checks": dict.fromkeys(CHECK_NAMES, "pass")}],
                              "reasoning": "Claim reasoning.",
                              "limitations": ["Exact edition only."], "challenge_method": "Compare editions.",
                              "challenge_result": "Claim holds for this edition."})
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
            {"type": "response_item", "payload": {"type": "message", "role": "assistant",
                                                 "content": [{"type": "output_text", "text": message}]}},
            {"type": "event_msg", "timestamp": COMPLETED, "payload": {"type": "task_complete", "turn_id": turn,
                                                                   "last_agent_message": message}},
        ]
        paths = self.root / f"{phase}-events.jsonl", self.root / f"{phase}-session.jsonl"
        for path, rows in zip(paths, (events, session)):
            path.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))
        verification = {
            "phase": phase, "conclusion": "supported", "claim_sha256": CLAIM_DIGEST,
            "reasoning": "Claim reasoning.", "limitations": ["Exact edition only."],
            "assessments": [{"dependency": {"kind": "dependency", "id": "fixture", "revision": 1},
                             "outcome": "supports", "reasoning": "Clause applies.",
                             "checks": dict.fromkeys(CHECK_NAMES, "pass")}],
            "challenge": {"method": "Compare editions.", "results": "Claim holds for this edition.", "targeted": True},
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

    def write_final_assessment(self, paths, assessment):
        message = json.dumps(assessment)
        events, session = [[json.loads(line) for line in path.read_bytes().splitlines()] for path in paths]
        events[-2]["item"]["text"] = message
        session[-2]["payload"]["content"][0]["text"] = message
        session[-1]["payload"]["last_agent_message"] = message
        for path, rows in zip(paths, (events, session)):
            path.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))

    def pin_legacy(self, *logs, claims=(CLAIM_DIGEST,)):
        pins = {}
        for events, session in logs:
            raw_events = events.read_bytes()
            thread = json.loads(raw_events.splitlines()[0])["thread_id"]
            pins[thread] = sha256(raw_events).hexdigest(), sha256(session.read_bytes()).hexdigest(), claims
        return patch.dict("tools.audit_receipts.LEGACY_ARCHIVES", pins)

    def use_structured_assessments(self):
        messages = []
        for paths, recorded in zip((self.first, self.second), self.registry["claims"][0]["recorded_reviews"]):
            dependencies = [
                {"id": identity, "outcome": "supports", "reasoning": f"Rationale for {identity}",
                 "checks": dict.fromkeys(CHECK_NAMES, "pass")}
                for identity in ("fixture-first", "fixture-second")
            ]
            claim = {"claim_sha256": CLAIM_DIGEST, "conclusion": "supported",
                     "reasoning": f"Rationale for {recorded['phase']}", "limitations": ["This exact edition only."],
                     "dependencies": dependencies}
            recorded.update(reasoning=claim["reasoning"], limitations=claim["limitations"].copy(), assessments=[
                {**{field: row[field] for field in ("outcome", "reasoning")},
                 "checks": row["checks"].copy(), "dependency": {"id": row["id"], "kind": "dependency", "revision": 1}}
                for row in reversed(dependencies)
            ])
            if recorded["phase"] == "independent-review":
                claim.update(challenge_method="Check another edition.", challenge_result="Another edition differs.")
                recorded["challenge"] = {"method": claim["challenge_method"], "results": claim["challenge_result"],
                                         "targeted": True}
            else:
                recorded.pop("challenge", None)
            message = {"claims": [claim]}
            self.write_final_assessment(paths, message)
            messages.append(message)
        return messages

    def test_matches_structured_findings_in_both_phases_by_dependency_id(self):
        self.use_structured_assessments()
        report = audit_receipts(self.registry, [self.first, self.second])
        self.assertEqual(report["claims"], [CLAIM])
        self.assertEqual(report["acquisition_bindings"], 2)
        self.assertNotIn("Rationale", json.dumps(report))

    def test_preserves_archived_batched_assessments_with_claim_level_checks(self):
        legacy = {"claim_sha256": CLAIM_DIGEST, "conclusion": "supported", "reasoning": "Claim reasoning.",
                  "limitations": ["Exact edition only."], "challenge_method": "Compare editions.",
                  "challenge_result": "Claim holds for this edition.", "checks": dict.fromkeys(CHECK_NAMES, "pass")}
        self.write_final_assessment(self.first, {"claims": [legacy]})
        self.write_final_assessment(self.second, {"claims": [legacy]})
        with self.pin_legacy(self.first, self.second):
            self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])
        review = self.registry["claims"][0]["recorded_reviews"][1]
        for changed, expected in (
            ({"reasoning": "A different rationale."}, "claim reasoning or limitations"),
            ({"limitations": ["A different limitation."]}, "claim reasoning or limitations"),
            ({"assessments": [{**review["assessments"][0], "checks": dict.fromkeys(CHECK_NAMES, "fail")}]},
             "claim-level checks"),
            ({"challenge": {**review["challenge"], "results": "A different result."}}, "challenge method or results"),
        ):
            with self.subTest(fields=tuple(changed)), patch.dict(review, changed), self.pin_legacy(self.first, self.second):
                with self.assertRaisesRegex(DataError, expected):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_preserves_archived_flat_assessments_with_dependency_checks(self):
        legacy = {"claim_sha256": CLAIM_DIGEST, "conclusion": "supported", "reasoning": "Claim reasoning.",
                  "limitations": ["Exact edition only."], "assessments": [
                      {"dependency_id": "fixture", "outcome": "supports", "reasoning": "Clause applies.",
                       "checks": dict.fromkeys(CHECK_NAMES, "pass")}
                  ]}
        self.write_final_assessment(self.first, legacy)
        research = self.registry["claims"][0]["recorded_reviews"][0]
        research.pop("challenge")
        with self.pin_legacy(self.first):
            self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])
        recorded = research["assessments"][0]
        for changed, expected in (
            ({"dependency": {**recorded["dependency"], "id": "other"}}, "differ from the recorded dependencies"),
            ({"outcome": "opposes"}, "dependency outcome, reasoning or checks"),
            ({"reasoning": "Another conclusion."}, "dependency outcome, reasoning or checks"),
            ({"checks": dict.fromkeys(CHECK_NAMES, "fail")}, "dependency outcome, reasoning or checks"),
        ):
            with self.subTest(fields=tuple(changed)), patch.dict(recorded, changed), self.pin_legacy(self.first):
                with self.assertRaisesRegex(DataError, expected):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_legacy_shape_requires_pinned_execution_claims_and_both_exact_archives(self):
        message = {"claim_sha256": CLAIM_DIGEST, "conclusion": "supported", "reasoning": "Claim reasoning.",
                   "limitations": ["Exact edition only."], "challenge_method": "Compare editions.",
                   "challenge_result": "Claim holds for this edition.", "checks": dict.fromkeys(CHECK_NAMES, "pass")}
        self.write_final_assessment(self.first, {"claims": [message]})
        with self.assertRaisesRegex(DataError, "legacy assessment requires a pinned historical execution"):
            audit_receipts(self.registry, [self.first, self.second])
        with self.pin_legacy(self.first, claims=("b" * 64,)):
            with self.assertRaisesRegex(DataError, "exact claim set"):
                audit_receipts(self.registry, [self.first, self.second])
        with self.pin_legacy(self.first):
            self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])
            for original_log in self.first:
                with self.subTest(log=original_log.name):
                    original = original_log.read_bytes()
                    original_log.write_bytes(b"\xef\xbb\xbf" + original)
                    with self.assertRaisesRegex(DataError, "both original logs"):
                        audit_receipts(self.registry, [self.first, self.second])
                    original_log.write_bytes(original)

    def test_rejects_web_tool_output_delivered_after_the_assessment_before_task_completion(self):
        path = self.first[1]
        session = [json.loads(line) for line in path.read_bytes().splitlines()]
        session.insert(-1, session.pop(5))
        path.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in session))
        with self.assertRaisesRegex(DataError, "web tool result was not delivered before the assessment"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_web_completion_after_the_cli_assessment(self):
        path = self.first[0]
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        events[2:4] = reversed(events[2:4])
        path.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in events))
        with self.assertRaisesRegex(DataError, "web-open completion follows the final assessment"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_compares_structured_claim_reasoning_limitations_and_independent_challenge(self):
        _, original = self.use_structured_assessments()
        for field, error in (
            ("reasoning", "claim reasoning or limitations"),
            ("limitations", "claim reasoning or limitations"),
            ("challenge_method", "challenge method or results"),
            ("challenge_result", "challenge method or results"),
        ):
            with self.subTest(field=field):
                modified = deepcopy(original)
                modified["claims"][0][field] = ["Changed scope."] if field == "limitations" else "Changed finding."
                self.write_final_assessment(self.second, modified)
                with self.assertRaisesRegex(DataError, error):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_dependency_assessment_coverage_changes(self):
        original, _ = self.use_structured_assessments()
        dependencies = original["claims"][0]["dependencies"]
        for rows, error in (
            ([], "dependency assessments are incomplete"),
            (dependencies[:1], "differ from the recorded dependencies"),
            ([*dependencies, dependencies[0]], "dependency assessments are incomplete or ambiguous"),
            ([{**dependencies[0], "id": "unexpected-dependency"}, dependencies[1]],
             "differ from the recorded dependencies"),
        ):
            with self.subTest(rows=rows):
                self.write_final_assessment(self.first, {"claims": [{**original["claims"][0], "dependencies": rows}]})
                with self.assertRaisesRegex(DataError, error):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_changed_dependency_outcome_reasoning_and_each_check(self):
        original, _ = self.use_structured_assessments()
        for field in ("outcome", "reasoning", *CHECK_NAMES):
            with self.subTest(field=field):
                modified = deepcopy(original)
                dependency = modified["claims"][0]["dependencies"][0]
                if field in CHECK_NAMES:
                    dependency["checks"][field] = "fail"
                else:
                    dependency[field] = "changed"
                self.write_final_assessment(self.first, modified)
                with self.assertRaisesRegex(DataError, "dependency outcome, reasoning or checks"):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_duplicate_claims_and_partly_structured_claims(self):
        original, _ = self.use_structured_assessments()
        claim = original["claims"][0]
        for other, error in (
            (claim, "claim assessments are incomplete or ambiguous"),
            ({"claim_sha256": "b" * 64, "conclusion": "supported"}, "structured Codex claim assessments are incomplete"),
        ):
            with self.subTest(other=other):
                self.write_final_assessment(self.first, {"claims": [claim, other]})
                with self.assertRaisesRegex(DataError, error):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_missing_dependencies_in_single_structured_claim(self):
        originals = self.use_structured_assessments()
        for paths, original in zip((self.first, self.second), originals):
            with self.subTest(paths=paths):
                modified = deepcopy(original)
                del modified["claims"][0]["dependencies"]
                self.write_final_assessment(paths, modified)
                with self.assertRaisesRegex(DataError, "structured Codex claim assessments are incomplete"):
                    audit_receipts(self.registry, [self.first, self.second])
                self.write_final_assessment(paths, original)

    def test_retains_checks_for_unwrapped_structured_assessment(self):
        _, original = self.use_structured_assessments()
        claim = original["claims"][0]
        self.write_final_assessment(self.second, claim)
        self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])
        claim["dependencies"][0]["outcome"] = "insufficient"
        self.write_final_assessment(self.second, claim)
        with self.assertRaisesRegex(DataError, "dependency outcome, reasoning or checks"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_cli_does_not_echo_structured_assessment_content(self):
        _, original = self.use_structured_assessments()
        original["claims"][0]["challenge_result"] = "private-sentinel"
        self.write_final_assessment(self.second, original)
        self.assert_private_error("challenge method or results")

    def test_requires_actual_tool_output_even_when_agent_message_is_present(self):
        self.first[1].write_bytes(self.first[1].read_bytes().replace(
            rb"\ue202turn1view0\ue201", rb"\ue202turn1view01\ue201"
        ))
        with self.assertRaisesRegex(DataError, "tool output lacks"):
            audit_receipts(self.registry, [self.first, self.second])

    def use_byte_receipt(self, phase="research", *, retrieved=RETRIEVED, observation_text=None,
                         mode="full", observation_changes=None):
        raw = b'\xef\xbb\xbfPublisher "quoted" e\xcc\x81 \x00\r\n' if mode == "full-utf8" else b"Publisher text\n"
        digest = sha256(raw).hexdigest()
        citation = {"start": 0, "end": 9, "sha256": sha256(raw[:9]).hexdigest()}
        observation = {
            "source": "publisher", "url": LOCATOR, "http_status": 200,
            "retrieved_at": retrieved, "acquisition_id": "1" * 32,
            "body_base64": b64encode(raw).decode("ascii"), "source_text": raw.decode("utf-8"),
            "sha256": digest, "bytes": len(raw),
            "ranges": [citation],
        }
        if mode == "full-utf8":
            observation["body_encoding"] = "utf-8"
            del observation["body_base64"]
        observation.update(observation_changes or {})
        content = [{"type": "text", "text": observation_text or json.dumps(observation)}]
        call = {"server": "fixed_public_source", "tool": "open_original_source",
                "arguments": {"source": "publisher"}, "status": "completed"}
        paths = self.first if phase == "research" else self.second
        events, session = [[json.loads(line) for line in path.read_bytes().splitlines()] for path in paths]
        events[2]["item"] = {**call, "id": "item_1", "type": "mcp_tool_call",
                             "result": {"content": content, "structured_content": None}}
        timestamp = int(instant(retrieved).timestamp() * 1000)
        session[4]["payload"].update(thread_id=f"fixture-{phase}", started_at_ms=timestamp,
                                     completed_at_ms=timestamp)
        session[4]["payload"]["item"] = {**call, "id": f"exec-{phase}", "type": "McpToolCall",
                                         "readOnlyHint": True, "result": {"content": content, "isError": False}}
        session[5]["payload"]["output"] = content
        for path, rows in zip(paths, (events, session)):
            path.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))
        claim = self.registry["claims"][0]
        review = next(row for row in claim["recorded_reviews"] if row["phase"] == phase)
        receipt = review["acquisitions"][0]
        reference = {"kind": "dependency", "id": "publisher-citation", "revision": 1}
        source = {"kind": "source", "id": "publisher", "revision": 1}
        receipt.update(sha256=digest, retrieved_at=retrieved, dependency=reference, source=source)
        claim["recorded_dependencies"] = [{**reference, "basis": source, "citation": dict(citation)}]
        return receipt

    def test_checks_fixed_source_bytes_and_keeps_web_receipts_separate(self):
        receipt = self.use_byte_receipt()
        checked = audit_receipts(self.registry, [self.first, self.second])
        self.assertEqual(checked["status"], "recorded-source-receipts-match-supplied-codex-logs")
        self.assertEqual(checked["unique_acquisitions"], 2)
        with patch.dict(receipt, {"sha256": "c" * 64}):
            with self.assertRaisesRegex(DataError, "digest differs from the retained bytes"):
                audit_receipts(self.registry, [self.first, self.second])
        self.first[1].write_bytes(self.first[1].read_bytes().replace(b"Publisher text", b"Different text"))
        with self.assertRaisesRegex(DataError, "matching Codex CLI source-byte tool completion"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_checks_lossless_utf8_delivery_in_both_executions(self):
        self.use_byte_receipt(mode="full-utf8")
        self.use_byte_receipt("independent-review", mode="full-utf8", observation_changes={"acquisition_id": "2" * 32})
        checked = audit_receipts(self.registry, [self.first, self.second])
        self.assertEqual(checked["status"], "recorded-source-receipts-match-supplied-codex-logs")
        self.assertEqual(checked["unique_acquisitions"], 2)

    def test_rejects_self_consistent_tool_results_without_the_exact_cited_span(self):
        different_range = {"start": 0, "end": 8, "sha256": sha256(b"Publishe").hexdigest()}
        for ranges in ([], [different_range]):
            with self.subTest(ranges=ranges):
                self.use_byte_receipt(observation_changes={"ranges": ranges})
                with self.assertRaisesRegex(DataError, "lacks the exact SCES dependency citation range"):
                    audit_receipts(self.registry, [self.first, self.second])

        receipt = self.use_byte_receipt()
        with patch.dict(receipt, {"dependency": {**receipt["dependency"], "revision": 2}}):
            with self.assertRaisesRegex(DataError, "expected one exact SCES dependency"):
                audit_receipts(self.registry, [self.first, self.second])
        with patch.dict(receipt, {"source": {**receipt["source"], "revision": 2}}):
            with self.assertRaisesRegex(DataError, "differs from the exact SCES dependency source"):
                audit_receipts(self.registry, [self.first, self.second])
        self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])

        self.use_byte_receipt(observation_changes={"ranges": []})
        dependency = self.registry["claims"][0]["recorded_dependencies"][0]
        dependency["citation"] = {"locator": "publisher record without a preserved byte-range dependency"}
        self.assertEqual(audit_receipts(self.registry, [self.first, self.second])["claims"], [CLAIM])

    def test_rejects_invalid_or_changed_utf8_byte_receipts(self):
        for changes, expected in (
            ({"body_encoding": "latin-1"}, "invalid UTF-8 observation"),
            ({"source_text": 3}, "invalid UTF-8 observation"),
            ({"body_base64": "YQ=="}, "invalid UTF-8 observation"),
            ({"source_text": "\ud800"}, "invalid UTF-8 body"),
            ({"source_text": ""}, "empty UTF-8 body"),
            ({"source_text": "Changed publisher text\r\n"}, "digest differs from the retained bytes"),
            ({"ranges": [{"start": 0, "end": 9, "sha256": "a" * 64}]}, "digest differs from the retained bytes"),
        ):
            with self.subTest(changes=changes):
                self.use_byte_receipt(mode="full-utf8", observation_changes=changes)
                with self.assertRaisesRegex(DataError, expected):
                    audit_receipts(self.registry, [self.first, self.second])

    def test_requires_the_complete_utf8_observation_in_actual_tool_output(self):
        self.use_byte_receipt(mode="full-utf8")
        rows = [json.loads(line) for line in self.first[1].read_bytes().splitlines()]
        delivered = rows[5]["payload"]["output"][0]
        delivered["text"] = delivered["text"][:-1]
        self.first[1].write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))
        with self.assertRaisesRegex(DataError, "source-byte tool result was not delivered"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_replayed_byte_acquisition_across_executions(self):
        self.use_byte_receipt()
        self.use_byte_receipt("independent-review")
        with self.assertRaisesRegex(DataError, "reused across captures"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_rejects_byte_acquisition_before_the_run(self):
        self.use_byte_receipt(retrieved="2026-01-01T11:00:00Z")
        with self.assertRaisesRegex(DataError, "outside the recorded tool call"):
            audit_receipts(self.registry, [self.first, self.second])

    def test_cli_does_not_echo_malformed_byte_observation(self):
        self.use_byte_receipt(observation_text='{"private-sentinel":0,"private-sentinel":1}')
        self.assert_private_error("invalid observation JSON")

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
