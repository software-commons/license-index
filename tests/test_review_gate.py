"""Synthetic technical-gate fixtures. They never supply production review evidence."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools.records import DataError
from tools.review_gate import (
    ACTIONS_APP_ID, APP_TOKEN, CHECK_NAME, CI_CONTEXTS, Reviewer, create_check, launch_review, load_issuer, main,
    load_reviewer, protected_path, require_queue_rules, review_result, run, verify_issued_check,
)
from tools.review_snapshot import PullSnapshot, REPOSITORY, SnapshotError

EXECUTION = "90c3284d-c009-4e34-bc00-beb41319adad"
SNAPSHOT = PullSnapshot(repository_id=1468281504, number=1, base="a" * 40, head="b" * 40, merge="c" * 40)
QUEUE = {"merge": "d" * 40, "queue_ref": "refs/heads/gh-readonly-queue/main/pr-1-" + "c" * 40}
PATCH = b"diff --git a/tools/index.py b/tools/index.py\n+fixture change\n"
BINDING = {"merge": SNAPSHOT.merge, "diff_sha256": sha256(PATCH).hexdigest()}
LEGACY_TOKEN = "ghs_" + "a" * 36
STATELESS_TOKEN = "ghs_12345_" + "A" * 120 + "." + "_-" * 100 + "." + "B" * 180
TOKEN_REPOSITORY = {"id": SNAPSHOT.repository_id, "full_name": REPOSITORY}
SCOPE_PATH = "/installation/repositories?per_page=100"


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


def active_queue_rules():
    checks = [{"context": name, "integration_id": ACTIONS_APP_ID} for name in CI_CONTEXTS]
    return [{"type": kind} for kind in ("pull_request", "deletion", "non_fast_forward")] + [
        {"type": "merge_queue", "parameters": {
            "merge_method": "MERGE", "grouping_strategy": "ALLGREEN",
            "max_entries_to_build": 1, "min_entries_to_merge": 1, "max_entries_to_merge": 1,
        }},
        {"type": "required_status_checks", "parameters": {
            "required_status_checks": [*checks, {"context": CHECK_NAME, "integration_id": 123}],
            "strict_required_status_checks_policy": True,
            "do_not_enforce_on_create": False,
        }},
    ]


class ReviewGateTests(unittest.TestCase):
    def test_accepts_only_complete_bound_verdicts(self):
        execution, verdict = review_result(make_trace(), BINDING, "abc", PATCH)
        self.assertEqual(execution, EXECUTION)
        self.assertEqual(verdict["decision"], "approve")
        for trace in (b"", make_trace(terminal="turn.failed"), make_trace(inspect=False), make_trace(proof=False),
                      make_trace(token="forged"), make_trace(verdict={"merge_sha": "d" * 40}),
                      make_trace(verdict={"findings": ["Material defect"]})):
            with self.subTest(trace=trace), self.assertRaises(DataError):
                review_result(trace, BINDING, "abc", PATCH)
        _, verdict = review_result(make_trace(verdict={"decision": "inconclusive"}, inspect=False), BINDING, "abc", PATCH)
        self.assertEqual(verdict["decision"], "inconclusive")

    def test_installation_token_accepts_supported_formats_without_header_delimiters(self):
        for token in (LEGACY_TOKEN, STATELESS_TOKEN):
            self.assertIsNotNone(APP_TOKEN.fullmatch(token))
        for token in ("ghp_" + "a" * 36, "ghs_short", LEGACY_TOKEN + "\r\nAuthorization: fixture"):
            self.assertIsNone(APP_TOKEN.fullmatch(token))

    def test_issuer_refuses_unverified_repository_scope_before_writing(self):
        scope = Mock()
        publisher = Mock()
        fresh = Mock()
        other = {"id": SNAPSHOT.repository_id + 1, "full_name": "software-commons/other-index"}
        wrong_rows = ([], [TOKEN_REPOSITORY, TOKEN_REPOSITORY], [TOKEN_REPOSITORY, other], [None],
                      [{**TOKEN_REPOSITORY, "id": SNAPSHOT.repository_id + 1}],
                      [{**TOKEN_REPOSITORY, "id": float(SNAPSHOT.repository_id)}],
                      [{**TOKEN_REPOSITORY, "full_name": "software-commons/other-index"}])
        responses = [{"total_count": len(rows), "repositories": rows} for rows in wrong_rows]
        responses.extend(({"total_count": 2, "repositories": [TOKEN_REPOSITORY]},
                          {"total_count": True, "repositories": [TOKEN_REPOSITORY]},
                          {"total_count": 1, "repositories": {}}, None))
        with patch("tools.review_gate.GitHub", return_value=scope) as client:
            for response in responses:
                scope._get_json.return_value = response
                with self.subTest(response=response), self.assertRaisesRegex(
                    (DataError, SnapshotError), "installation token|repositories",
                ):
                    create_check(SNAPSHOT, 123, LEGACY_TOKEN, {}, publisher, fresh)
            scope._get_json.side_effect = SnapshotError("GitHub could not supply the review target")
            with self.assertRaises(SnapshotError):
                create_check(SNAPSHOT, 123, LEGACY_TOKEN, {}, publisher, fresh)
        self.assertEqual(client.call_count, len(responses) + 1)
        scope._get_json.assert_called_with(SCOPE_PATH)
        publisher.assert_not_called()
        fresh.assert_not_called()

    def test_issuer_publishes_final_review_only_to_the_current_queue_result(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"), queue_run=321)
            github = Mock()
            github._get_json.return_value = active_queue_rules()
            def respond(_, payload, *, check_id=None):
                return api_check({"name": CHECK_NAME, "head_sha": QUEUE["merge"],
                                  "external_id": publisher.call_args_list[-2].args[1]["external_id"],
                                  **payload} if check_id is not None else payload)

            publisher = Mock(side_effect=respond)
            scope = Mock()
            scope._get_json.return_value = {"total_count": 1, "repositories": [TOKEN_REPOSITORY]}
            github.get_pull.return_value = SNAPSHOT

            def fake_launch(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                bound = json.loads((input_dir / "review-input.json").read_bytes())
                return make_trace(bound["inspection_token"], verdict={"merge_sha": bound["merge"]})

            with (patch("tools.review_gate.GitHub", return_value=scope) as client,
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.capture_queue_observation", return_value=QUEUE) as observed,
                  patch("tools.review_gate.protected_staging", return_value=state),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.launch_review", side_effect=fake_launch)):
                result = run(args, github, token_input=lambda: STATELESS_TOKEN, publisher=publisher)
                self.assertEqual(result["status"], "check-issued")
                client.assert_called_once_with(STATELESS_TOKEN)
                scope._get_json.assert_called_once_with(SCOPE_PATH)
                first, last = publisher.call_args_list
                self.assertEqual(first.args[0], STATELESS_TOKEN)
                self.assertEqual(first.args[1]["head_sha"], QUEUE["merge"])
                self.assertIn("Final merge-queue review", last.args[1]["output"]["title"])
                self.assertEqual(result["binding"]["queue_ci"], QUEUE)
                self.assertEqual(result["binding"]["test_merge"], SNAPSHOT.merge)
                self.assertEqual(first.args[1]["status"], "in_progress")
                self.assertEqual(last.kwargs["check_id"], 42)
                self.assertTrue((Path(result["audit"]) / "decision.json").is_file())
                self.assertEqual(first.args[1]["external_id"], result["decision_sha256"])
                for stale in (replace(SNAPSHOT, head="f" * 40), replace(SNAPSHOT, base="f" * 40),
                              replace(SNAPSHOT, merge="f" * 40)):
                    with self.subTest(stale=stale):
                        publisher.reset_mock()
                        github.get_pull.side_effect = [SNAPSHOT, SNAPSHOT, stale]
                        with self.assertRaisesRegex(DataError, "changed after review"):
                            run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                        publisher.assert_not_called()
                github.get_pull.side_effect = None
                publisher.reset_mock(side_effect=True)
                publisher.side_effect = lambda _, payload: api_check(payload, 999)
                with self.assertRaisesRegex(DataError, "wrong-source"):
                    run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                self.assertEqual(publisher.call_count, 1)
                self.assertEqual(publisher.call_args.args[1]["status"], "in_progress")
                github.get_pull.side_effect = [SNAPSHOT, SNAPSHOT, SNAPSHOT, replace(SNAPSHOT, base="f" * 40)]
                publisher.reset_mock(side_effect=True)
                publisher.side_effect = respond
                with self.assertRaisesRegex(DataError, "changed after review"):
                    run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                self.assertEqual(publisher.call_count, 1)
                self.assertEqual(publisher.call_args.args[1]["status"], "in_progress")
                github.get_pull.side_effect = None
                observed.side_effect = [QUEUE, {**QUEUE, "merge": "f" * 40}]
                credential = Mock()
                publisher.reset_mock(side_effect=True)
                with self.assertRaisesRegex(DataError, "candidate or CI evidence changed"):
                    run(args, github, token_input=credential, publisher=publisher)
                credential.assert_not_called()
                publisher.assert_not_called()

    def test_queue_admission_targets_only_the_head_and_records_its_purpose(self):
        checks = []
        def publish(_token, payload, *, check_id=None):
            checks.append(payload)
            if check_id is None:
                return api_check(payload)
            return api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head,
                              "external_id": checks[0]["external_id"], **payload})

        fresh = Mock()
        scope = Mock()
        scope._get_json.return_value = {"total_count": 1, "repositories": [TOKEN_REPOSITORY]}
        with patch("tools.review_gate.GitHub", return_value=scope) as client:
            create_check(SNAPSHOT, 123, STATELESS_TOKEN, {"execution": EXECUTION}, publish, fresh, admission=True)
        client.assert_called_once_with(STATELESS_TOKEN)
        scope._get_json.assert_called_once_with(SCOPE_PATH)
        self.assertEqual(checks[0]["head_sha"], SNAPSHOT.head)
        self.assertIn("Queue admission", checks[1]["output"]["title"])
        self.assertEqual(fresh.call_count, 2)

    def test_queue_rules_require_replay_protection_and_source_pins(self):
        github = Mock()
        github._get_json.return_value = active_queue_rules()
        require_queue_rules(github, 123)
        with self.assertRaisesRegex(DataError, "exact integration"):
            require_queue_rules(github, 321)
        for key, value in (("merge_method", "SQUASH"), ("grouping_strategy", "HEADGREEN"),
                           ("max_entries_to_merge", 2), ("max_entries_to_build", True)):
            rules = active_queue_rules()
            rules[3]["parameters"][key] = value
            github._get_json.return_value = rules
            with self.subTest(key=key), self.assertRaisesRegex(DataError, "single-entry"):
                require_queue_rules(github, 123)
        for key, value in (("strict_required_status_checks_policy", False),
                           ("strict_required_status_checks_policy", 1), ("do_not_enforce_on_create", True),
                           ("do_not_enforce_on_create", None)):
            rules = active_queue_rules()
            rules[-1]["parameters"][key] = value
            github._get_json.return_value = rules
            with self.subTest(key=key, value=value), self.assertRaisesRegex(DataError, "enforce strict checks"):
                require_queue_rules(github, 123)
        github._get_json.return_value = [row for row in active_queue_rules() if row["type"] != "merge_queue"]
        with self.assertRaisesRegex(DataError, "mandatory merge queue"):
            require_queue_rules(github, 123)

    def test_wrong_source_and_stale_returned_checks_are_rejected(self):
        payload = {"name": CHECK_NAME, "head_sha": SNAPSHOT.merge,
                   "status": "completed", "conclusion": "success", "external_id": "expected"}
        verify_issued_check(api_check(payload), SNAPSHOT.merge, 123, "expected", "completed", "success")
        for check in (api_check(payload, 999), api_check({**payload, "head_sha": SNAPSHOT.head}),
                      api_check({**payload, "external_id": "unrelated"}), api_check({**payload, "conclusion": "failure"})):
            with self.subTest(check=check), self.assertRaisesRegex(DataError, "wrong-source"):
                verify_issued_check(check, SNAPSHOT.merge, 123, "expected", "completed", "success")

    def test_issuer_without_reviewer_fails_before_capture_or_credential_read(self):
        with TemporaryDirectory() as directory:
            args = SimpleNamespace(state_dir=Path(directory), mode="review", pull=1,
                                   model="fixture", codex=Path("fixture"), app_id=123)
            github = Mock()
            credential = Mock()
            publisher = Mock()
            with self.assertRaisesRegex(DataError, "requires the isolated reviewer identity"):
                run(args, github, token_input=credential, publisher=publisher)
            github.get_pull.assert_not_called()
            credential.assert_not_called()
            publisher.assert_not_called()

    def test_incomplete_review_does_not_read_credential_or_issue(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"),
                                   queue_admission=True)
            github = Mock()
            github._get_json.return_value = active_queue_rules()
            github.get_pull.return_value = SNAPSHOT
            credential = Mock()
            publisher = Mock()
            with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.protected_staging", return_value=state),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.launch_review", return_value=b"")):
                with self.assertRaises(DataError):
                    run(args, github, token_input=credential, publisher=publisher)
            credential.assert_not_called()
            publisher.assert_not_called()

    def test_bound_negative_reviews_save_decisions_without_reading_credential(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"),
                                   queue_admission=True)
            github = Mock()
            github._get_json.return_value = active_queue_rules()
            github.get_pull.return_value = SNAPSHOT
            credential = Mock()
            publisher = Mock()
            for disposition in ("changes-required", "inconclusive"):
                with self.subTest(disposition=disposition):
                    def fake_launch(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                        token = json.loads((input_dir / "review-input.json").read_bytes())["inspection_token"]
                        return make_trace(token, verdict={"decision": disposition, "findings": ["Fixture finding"]},
                                          inspect=disposition != "inconclusive")

                    with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                          patch("tools.review_gate.protected_staging", return_value=state),
                          patch("tools.review_gate.share_reviewer_inputs"),
                          patch("tools.review_gate.launch_review", side_effect=fake_launch)):
                        result = run(args, github, token_input=credential, publisher=publisher)
                    self.assertEqual(result["status"], disposition)
                    data = (Path(result["audit"]) / "decision.json").read_bytes()
                    record = json.loads(data)
                    self.assertEqual(record["decision"], disposition)
                    self.assertEqual(record["findings"], ["Fixture finding"])
                    self.assertEqual(record["binding"]["merge"], SNAPSHOT.merge)
                    self.assertEqual(result["decision_sha256"], sha256(data).hexdigest())
            credential.assert_not_called()
            publisher.assert_not_called()

    def test_protected_launcher_uses_separate_identity_and_scoped_filesystem(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            reviewer = Reviewer(4001, 4002, root / "reviewer-home")
            original = {"HOME": "issuer-home", "CODEX_HOME": "issuer-codex-home", "GH_TOKEN": "fixture"}

            def fake_run(*_args, **kwargs):
                kwargs["stdout"].write(b"fixture trace")
                return SimpleNamespace(returncode=0)

            with (patch.dict(os.environ, original, clear=True),
                  patch("tools.review_gate.subprocess.run", side_effect=fake_run) as process):
                trace = launch_review(root / "codex", "fixture", root / "inputs", root / "schema.json", root,
                                      reviewer=reviewer)
            self.assertEqual(trace, b"fixture trace")
            invocation = process.call_args
            self.assertEqual(invocation.kwargs["user"], reviewer.uid)
            self.assertEqual(invocation.kwargs["group"], reviewer.gid)
            self.assertEqual(invocation.kwargs["extra_groups"], ())
            self.assertTrue(invocation.kwargs["start_new_session"])
            self.assertEqual(invocation.kwargs["env"]["CODEX_HOME"], str(reviewer.home / ".codex"))
            self.assertNotIn("GH_TOKEN", invocation.kwargs["env"])
            self.assertNotIn("--sandbox", invocation.args[0])
            self.assertIn('default_permissions="review-inputs"', invocation.args[0])
            profile, = [arg for arg in invocation.args[0] if arg.startswith("permissions.review-inputs=")]
            permissions = tomllib.loads(profile)["permissions"]["review-inputs"]
            self.assertEqual(permissions, {
                "network": {"enabled": False},
                "filesystem": {":minimal": "read", str(root / "inputs"): "read", str(root / "codex"): "read"},
            })

    def test_protected_rehearsal_records_a_review_without_reading_a_token_or_writing_a_check(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            reviewer = Reviewer(4001, 4002, root / "reviewer-home")
            config = root / "rehearsal.json"
            github = Mock()
            github.get_pull.return_value = SNAPSHOT
            stdout = BytesIO()
            stdin = Mock()

            def fake_launch(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                self.assertEqual(reviewer.uid, 4001)
                self.assertEqual((input_dir / "review.diff").read_bytes(), PATCH)
                token = json.loads((input_dir / "review-input.json").read_bytes())["inspection_token"]
                return make_trace(token)

            with (patch("tools.review_gate.load_issuer", return_value=(root, root / "codex", "fixture", None, reviewer)) as load,
                  patch("tools.review_gate.GitHub", return_value=github),
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)) as capture,
                  patch("tools.review_gate.protected_staging", return_value=root),
                  patch("tools.review_gate.share_reviewer_inputs") as share,
                  patch("tools.review_gate.launch_review", side_effect=fake_launch) as launch,
                  patch("tools.review_gate.create_check") as issuer,
                  patch("tools.review_gate.sys.stdout", SimpleNamespace(buffer=stdout)),
                  patch("tools.review_gate.sys.stdin", stdin)):
                self.assertEqual(main(["review", "1", "--rehearsal-config", str(config), "--queue-admission"]), 0)

            load.assert_called_once_with(config, rehearsal=True)
            self.assertTrue(capture.call_args.kwargs["linear_head"])
            self.assertEqual(share.call_args.args[1], reviewer.gid)
            self.assertEqual(launch.call_args.kwargs["reviewer"], reviewer)
            self.assertEqual(len(github.method_calls), 2)
            self.assertTrue(all(method[0] == "get_pull" for method in github.method_calls))
            stdin.readline.assert_not_called()
            issuer.assert_not_called()
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "protected-rehearsal")
            decision = (Path(result["audit"]) / "decision.json").read_bytes()
            self.assertTrue(json.loads(decision)["rehearsal"])
            self.assertEqual(result["decision_sha256"], sha256(decision).hexdigest())
            self.assertFalse((Path(result["audit"]) / "issued-check.json").exists())

    @unittest.skipUnless(os.name == "posix", "issuer deployment requires POSIX permissions")
    def test_protected_issuer_config_rejects_unpinned_runner_and_shared_permissions(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            codex = root / "codex"
            codex.write_bytes(b"synthetic executable")
            config = root / "review.json"
            settings = {
                "app_id": 123, "audit_dir": str(root), "codex": str(codex), "model": "fixture",
                "codex_sha256": sha256(codex.read_bytes()).hexdigest(),
                "reviewer_uid": 4001, "reviewer_gid": 4002, "reviewer_home": str(root / "reviewer-home"),
            }
            config.write_text(json.dumps(settings), encoding="utf-8")
            config.chmod(0o600)
            reviewer = Reviewer(4001, 4002, root / "reviewer-home")
            with patch("tools.review_gate.load_reviewer", return_value=reviewer):
                self.assertEqual(load_issuer(config), (root, codex, "fixture", 123, reviewer))
                with self.assertRaisesRegex(DataError, "invalid protected issuer configuration"):
                    load_issuer(config, rehearsal=True)
                config.chmod(0o640)
                with self.assertRaisesRegex(DataError, "must be private"):
                    load_issuer(config)
                config.chmod(0o600)
                codex.chmod(0o666)
                with self.assertRaisesRegex(DataError, "shared write bits"):
                    load_issuer(config)
                codex.chmod(0o644)
                codex.write_bytes(b"another executable")
                with self.assertRaisesRegex(DataError, "differs from"):
                    load_issuer(config)
                codex.write_bytes(b"synthetic executable")
                del settings["app_id"]
                config.write_text(json.dumps(settings), encoding="utf-8")
                self.assertEqual(load_issuer(config, rehearsal=True), (root, codex, "fixture", None, reviewer))
                with self.assertRaisesRegex(DataError, "invalid protected issuer configuration"):
                    load_issuer(config)

    @unittest.skipUnless(os.name == "posix", "issuer deployment requires POSIX permissions")
    def test_protected_storage_rejects_shared_write_on_an_ancestor(self):
        with TemporaryDirectory() as directory:
            shared = Path(directory).resolve() / "parent"
            shared.mkdir(mode=0o700)
            private = shared / "issuer-audit"
            private.mkdir(mode=0o700)
            protected_path(private, directory=True)
            shared.chmod(0o777)
            with self.assertRaisesRegex(DataError, "trusted ancestor directories"):
                protected_path(private, directory=True)

    @unittest.skipUnless(os.name == "posix", "issuer deployment requires POSIX permissions")
    def test_protected_reviewer_cannot_reuse_the_issuer_identity(self):
        with self.assertRaisesRegex(DataError, "UID and GID separate from the issuer"):
            load_reviewer({"reviewer_uid": os.geteuid(), "reviewer_gid": os.getegid(), "reviewer_home": "/fixture"})
