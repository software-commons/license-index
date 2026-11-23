"""Synthetic technical-gate fixtures. They never supply production review evidence."""

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools.records import DataError
from tools.review_gate import CHECK_NAME, load_issuer, review_result, run, verify_issued_check
from tools.review_snapshot import PullSnapshot

EXECUTION = "90c3284d-c009-4e34-bc00-beb41319adad"
SNAPSHOT = PullSnapshot(repository_id=1468281504, number=1, base="a" * 40, head="b" * 40, merge="c" * 40)
PATCH = b"diff --git a/tools/index.py b/tools/index.py\n+fixture change\n"
BINDING = {"merge": SNAPSHOT.merge, "diff_sha256": sha256(PATCH).hexdigest()}


def make_trace(token="abc", *, verdict=None, inspect=True, terminal="turn.completed", proof=True):
    output = {"decision": "approve", "inspection_token": token, "merge_sha": BINDING["merge"],
              "diff_sha256": BINDING["diff_sha256"], "findings": [], "rationale": "Synthetic fixture outcome"}
    output.update(verdict or {})
    events = [{"type": "thread.started", "thread_id": EXECUTION}, {"type": "turn.started"}]
    if inspect:
        events.append({"type": "item.completed", "item": {
            "type": "command_execution", "status": "completed", "exit_code": 0,
            "command": "inspect review.diff",
            "aggregated_output": (sha256(token.encode() + PATCH).hexdigest() + "\n" + PATCH.decode()
                                  if proof else BINDING["diff_sha256"] + "\n" + PATCH.decode().splitlines()[0]),
        }})
    events.extend([{"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(output)}},
                   {"type": terminal}])
    return ("\n".join(json.dumps(event) for event in events) + "\n").encode()


def api_check(payload, app=123):
    return {**payload, "app": {"id": app}, "id": 42}


class ReviewGateTests(unittest.TestCase):
    def test_only_a_complete_bound_approval_is_accepted(self):
        execution, verdict = review_result(make_trace(), BINDING, "abc", PATCH)
        self.assertEqual(execution, EXECUTION)
        self.assertEqual(verdict["decision"], "approve")
        for trace in (b"", make_trace(terminal="turn.failed"), make_trace(inspect=False), make_trace(proof=False),
                      make_trace(token="forged"), make_trace(verdict={"merge_sha": "d" * 40}),
                      make_trace(verdict={"decision": "changes-required"}),
                      make_trace(verdict={"findings": ["Material defect"]})):
            with self.subTest(trace=trace), self.assertRaises(DataError):
                review_result(trace, BINDING, "abc", PATCH)

    def test_issuer_publishes_only_to_the_current_merge_result(self):
        with TemporaryDirectory() as directory:
            args = SimpleNamespace(state_dir=Path(directory), mode="review", pull=1,
                                   model="fixture", codex=Path("fixture"), app_id=123)
            github = Mock()
            def respond(_, payload, *, check_id=None):
                return api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.merge,
                                  "external_id": publisher.call_args_list[-2].args[1]["external_id"],
                                  **payload} if check_id is not None else payload)

            publisher = Mock(side_effect=respond)
            github.get_pull.return_value = SNAPSHOT

            def fake_launch(_codex, _model, input_dir, _schema, _audit):
                return make_trace(json.loads((input_dir / "review-input.json").read_bytes())["inspection_token"])

            with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.launch_review", side_effect=fake_launch)):
                result = run(args, github, token_input=lambda: "ghs_fixture", publisher=publisher)
                self.assertEqual(result["status"], "check-issued")
                first, last = publisher.call_args_list
                self.assertEqual(first.args[1]["head_sha"], SNAPSHOT.merge)
                self.assertNotEqual(first.args[1]["head_sha"], SNAPSHOT.head)
                self.assertEqual(first.args[1]["status"], "in_progress")
                self.assertEqual(last.kwargs["check_id"], 42)
                self.assertTrue((Path(result["audit"]) / "decision.json").is_file())
                for stale in (replace(SNAPSHOT, head="f" * 40), replace(SNAPSHOT, base="f" * 40),
                              replace(SNAPSHOT, merge="f" * 40)):
                    with self.subTest(stale=stale):
                        publisher.reset_mock()
                        github.get_pull.side_effect = [SNAPSHOT, SNAPSHOT, stale]
                        with self.assertRaisesRegex(DataError, "changed after review"):
                            run(args, github, token_input=lambda: "ghs_fixture", publisher=publisher)
                        publisher.assert_not_called()
                github.get_pull.side_effect = None
                publisher.reset_mock(side_effect=True)
                publisher.side_effect = lambda _, payload: api_check(payload, 999)
                with self.assertRaisesRegex(DataError, "wrong-source"):
                    run(args, github, token_input=lambda: "ghs_fixture", publisher=publisher)
                self.assertEqual(publisher.call_count, 1)
                self.assertEqual(publisher.call_args.args[1]["status"], "in_progress")
                github.get_pull.side_effect = [SNAPSHOT, SNAPSHOT, SNAPSHOT, replace(SNAPSHOT, base="f" * 40)]
                publisher.reset_mock(side_effect=True)
                publisher.side_effect = respond
                with self.assertRaisesRegex(DataError, "changed after review"):
                    run(args, github, token_input=lambda: "ghs_fixture", publisher=publisher)
                self.assertEqual(publisher.call_count, 1)
                self.assertEqual(publisher.call_args.args[1]["status"], "in_progress")

    def test_wrong_source_and_stale_returned_checks_are_rejected(self):
        payload = {"name": CHECK_NAME, "head_sha": SNAPSHOT.merge,
                   "status": "completed", "conclusion": "success", "external_id": "expected"}
        verify_issued_check(api_check(payload), SNAPSHOT.merge, 123, "expected", "completed", "success")
        for check in (api_check(payload, 999), api_check({**payload, "head_sha": SNAPSHOT.head}),
                      api_check({**payload, "external_id": "unrelated"}), api_check({**payload, "conclusion": "failure"})):
            with self.subTest(check=check), self.assertRaisesRegex(DataError, "wrong-source"):
                verify_issued_check(check, SNAPSHOT.merge, 123, "expected", "completed", "success")

    def test_incomplete_review_does_not_read_credential_or_issue(self):
        with TemporaryDirectory() as directory:
            args = SimpleNamespace(state_dir=Path(directory), mode="review", pull=1,
                                   model="fixture", codex=Path("fixture"), app_id=123)
            github = Mock()
            github.get_pull.return_value = SNAPSHOT
            credential = Mock()
            publisher = Mock()
            with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.launch_review", return_value=b"")):
                with self.assertRaises(DataError):
                    run(args, github, token_input=credential, publisher=publisher)
            credential.assert_not_called()
            publisher.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "issuer deployment requires POSIX permissions")
    def test_protected_issuer_config_rejects_unpinned_runner_and_shared_permissions(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            codex = root / "codex"
            codex.write_bytes(b"synthetic executable")
            config = root / "review.json"
            config.write_text(json.dumps({
                "app_id": 123, "audit_dir": str(root), "codex": str(codex), "model": "fixture",
                "codex_sha256": sha256(codex.read_bytes()).hexdigest(),
            }), encoding="utf-8")
            config.chmod(0o600)
            self.assertEqual(load_issuer(config), (root, codex, "fixture", 123))
            config.chmod(0o640)
            with self.assertRaisesRegex(DataError, "must be private"):
                load_issuer(config)
            config.chmod(0o600)
            codex.write_bytes(b"another executable")
            with self.assertRaisesRegex(DataError, "differs from"):
                load_issuer(config)
