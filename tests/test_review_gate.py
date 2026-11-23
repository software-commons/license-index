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
from urllib.parse import parse_qs, urlsplit

from tools.records import DataError
from tools.review_gate import (
    ACTIONS_APP_ID, APP_TOKEN, CHECK_NAME, CI_CONTEXTS, AuthorizationPaths, Reviewer, create_check, launch_review,
    load_issuer, load_reviewer, main, protected_path, require_queue_rules, review_result, run, successful_checks,
    verify_issued_check,
)
from tools.review_protection import commissioning_policy
from tools.review_snapshot import PullSnapshot, REPOSITORY, SnapshotError

EXECUTION = "90c3284d-c009-4e34-bc00-beb41319adad"
SNAPSHOT = PullSnapshot(repository_id=1468281504, number=1, base="a" * 40, head="b" * 40, merge="c" * 40)
QUEUE = {"merge": "d" * 40, "queue_ref": "refs/heads/gh-readonly-queue/main/pr-1-" + "c" * 40}
PATCH = b"diff --git a/tools/index.py b/tools/index.py\n@@ -1,0 +2 @@\n+fixture change\n"
BINDING = {"merge": SNAPSHOT.merge, "diff_sha256": sha256(PATCH).hexdigest()}
LEGACY_TOKEN = "ghs_" + "a" * 36
STATELESS_TOKEN = "ghs_12345_" + "A" * 120 + "." + "_-" * 100 + "." + "B" * 180
TOKEN_REPOSITORY = {"id": SNAPSHOT.repository_id, "full_name": REPOSITORY}
SCOPE_PATH = "/installation/repositories?per_page=100"
RULESET = 27875276
ADDITIVE = commissioning_policy(REPOSITORY, "main", "additive")
OWNER_BINDING = {"grant_commit": "e" * 40, "grant_sha256": "e" * 64,
                 "record_sha256": "f" * 64, "state_sha256": "1" * 64}


def make_trace(token="abc", *, verdict=None, inspect=True, terminal="turn.completed", proof=True, evidence=None,
               diff=PATCH, displayed=None):
    diff_digest = sha256(diff).hexdigest()
    output = {"decision": "approve", "inspection_token": token, "merge_sha": BINDING["merge"],
              "diff_sha256": diff_digest, "findings": [], "rationale": "Synthetic fixture outcome"}
    output.update(verdict or {})
    events = [{"type": "thread.started", "thread_id": EXECUTION}, {"type": "turn.started"}]
    if inspect:
        if displayed is None:
            displayed = diff.decode() if proof else diff.decode().splitlines()[0]
        digest = sha256(token.encode() + diff).hexdigest() if proof else diff_digest
        events.append({"type": "item.completed", "item": {
            "type": "command_execution", "status": "completed", "exit_code": 0,
            "command": "inspect review.diff",
            "aggregated_output": digest + "\n" + displayed,
        }})
    if evidence:
        names = sorted(evidence)
        batches = []
        for number, start in enumerate(range(0, len(names), 128)):
            content = "".join(f"{name} {sha256(token.encode() + evidence[name]).hexdigest()}\n"
                              for name in names[start:start + 128])
            batches.append(f"sces-proof {number} {sha256(content.encode()).hexdigest()}")
        events.append({"type": "item.completed", "item": {
            "type": "command_execution", "status": "completed", "exit_code": 0,
            "command": "inspect evidence listed in review-input.json",
            "aggregated_output": "\n".join(batches),
        }})
    events.extend([{"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(output)}},
                   {"type": terminal}])
    return ("\n".join(json.dumps(event) for event in events) + "\n").encode()


def api_check(payload, app=123):
    return {**payload, "app": {"id": app}, "id": 42}


def active_queue_rules(policy=ADDITIVE, *, ruleset=None):
    checks = [{"context": name, "integration_id": ACTIONS_APP_ID} for name in CI_CONTEXTS]
    approval = policy.approval
    rules = [
        {"type": "pull_request", "parameters": {
            "require_code_owner_review": approval.code_owner_review,
            "required_approving_review_count": approval.approving_review_count,
        }},
        *[{"type": kind} for kind in ("deletion", "non_fast_forward")],
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
    source = ruleset or approval.ruleset_id or 27933278
    return [{**rule, "ruleset_id": source} for rule in rules]


def use_queue_rules(github, rules=None, *, bypass=None, on_read=None):
    rules = active_queue_rules() if rules is None else rules

    def read(path):
        if "/rules/branches/" in path:
            return on_read() if on_read is not None else rules
        ruleset = int(path.rsplit("/", 1)[1])
        return {"id": ruleset, "target": "branch", "enforcement": "active",
                "bypass_actors": [] if bypass is None else bypass}

    github._get_json.side_effect = read


class ReviewGateTests(unittest.TestCase):
    def setUp(self):
        capture = patch("tools.review_gate.capture_selected_evidence", return_value={})
        self.capture_evidence = capture.start()
        self.addCleanup(capture.stop)
        checks = patch("tools.review_gate.successful_checks", return_value=[])
        self.successful_checks = checks.start()
        self.addCleanup(checks.stop)
        controls = patch("tools.review_gate.capture_control_paths", return_value=[])
        controls.start()
        self.addCleanup(controls.stop)

    def test_license_control_authorization_matches_each_exact_candidate(self):
        for admission, merge in ((True, SNAPSHOT.merge), (False, QUEUE["merge"])):
            for authorized, has_record in ((None, False), (SNAPSHOT.head, True), (merge, False), (merge, True)):
                valid = authorized == merge and has_record
                with (self.subTest(admission=admission, authorized=authorized, has_record=has_record),
                      TemporaryDirectory() as directory):
                    root = Path(directory)
                    github = Mock(get_pull=Mock(return_value=SNAPSHOT))
                    paths = AuthorizationPaths(root / "auth.json", root / "grant.json") if has_record else None
                    args = SimpleNamespace(state_dir=root, mode="review", pull=1, app_id=123, model="fixture",
                                           codex=Path("fixture"), reviewer=Reviewer(4001, 4002, root),
                                           queue_admission=admission, queue_run=None if admission else 321,
                                           commissioning_policy=ADDITIVE, authorized_control_merge=authorized,
                                           authorization_paths=paths)
                    credential = Mock()
                    with (patch("tools.review_gate.require_queue_rules", return_value=ADDITIVE.approval),
                          patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                          patch("tools.review_gate.capture_control_paths", return_value=["sces/publication.json"]) as capture,
                          patch("tools.review_gate.capture_queue_observation", return_value=QUEUE),
                          patch("tools.review_gate.protected_staging", return_value=root),
                          patch("tools.review_gate.share_reviewer_inputs"),
                          patch("tools.review_gate.validate_control_authorization", return_value=OWNER_BINDING) as authorizes,
                          patch("tools.review_gate.launch_review", side_effect=DataError("fixture launch")) as launch):
                        diagnostic = ("fixture launch" if valid else "authenticated owner authorization"
                                      if authorized == merge else "separate authorization")
                        with self.assertRaisesRegex(DataError, diagnostic):
                            run(args, github, token_input=credential)
                    self.assertEqual(capture.call_args.args[1].merge, merge)
                    self.assertEqual(launch.call_count, int(valid))
                    self.assertEqual(authorizes.call_count, int(valid))
                    credential.assert_not_called()
                    binding, = root.glob("*/binding.json")
                    data = json.loads(binding.read_bytes())
                    self.assertEqual(data["protected_paths"], ["sces/publication.json"])
                    self.assertEqual(data["protected_control_authorization"], {
                        "required": True, "authorized_merge": authorized,
                        **(OWNER_BINDING if valid else {}),
                    })

    def test_changed_owner_grant_blocks_token_access_after_review(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            github = Mock(get_pull=Mock(return_value=SNAPSHOT))
            args = SimpleNamespace(state_dir=root, mode="review", pull=1, app_id=123, model="fixture",
                                   codex=Path("fixture"), reviewer=Reviewer(4001, 4002, root),
                                   queue_admission=True, commissioning_policy=ADDITIVE,
                                   authorized_control_merge=SNAPSHOT.merge,
                                   authorization_paths=AuthorizationPaths(root / "auth.json", root / "grant.json"))
            token_input = Mock()
            publisher = Mock()

            def fake_launch(_codex, _model, inputs, _schema, _audit, *, reviewer):
                staged = json.loads((inputs / "review-input.json").read_bytes())
                self.assertEqual(staged["protected_control_authorization"]["grant_commit"], OWNER_BINDING["grant_commit"])
                return make_trace(staged["inspection_token"])

            with (patch("tools.review_gate.require_queue_rules", return_value=ADDITIVE.approval),
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.capture_control_paths", return_value=["sces/publication.json"]),
                  patch("tools.review_gate.protected_staging", return_value=root),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.validate_control_authorization",
                        side_effect=[OWNER_BINDING, {**OWNER_BINDING, "state_sha256": "0" * 64}]),
                  patch("tools.review_gate.launch_review", side_effect=fake_launch)):
                with self.assertRaisesRegex(DataError, "owner authorization changed after review"):
                    run(args, github, token_input=token_input, publisher=publisher)
            token_input.assert_not_called()
            publisher.assert_not_called()

    def test_license_trial_records_protected_paths_without_a_production_pin(self):
        trial_branch = "codex-gate-trial"
        policy = commissioning_policy(REPOSITORY, trial_branch, "trial")
        with patch("tools.review_gate.BASE_REF", trial_branch), TemporaryDirectory() as directory:
            root = Path(directory)
            github = Mock(get_pull=Mock(return_value=SNAPSHOT))
            args = SimpleNamespace(state_dir=root, mode="review", pull=1, app_id=123, model="fixture",
                                   codex=Path("fixture"), reviewer=Reviewer(4001, 4002, root),
                                   queue_admission=True, commissioning_policy=policy)
            credential = Mock()
            with (patch("tools.review_gate.require_queue_rules", return_value=policy.approval),
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.capture_control_paths", return_value=[".github/workflows/domain.yml"]),
                  patch("tools.review_gate.protected_staging", return_value=root),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.launch_review", side_effect=DataError("fixture launch"))):
                with self.assertRaisesRegex(DataError, "fixture launch"):
                    run(args, github, token_input=credential)
            credential.assert_not_called()
            binding, = root.glob("*/binding.json")
            data = json.loads(binding.read_bytes())
            self.assertEqual(data["protected_paths"], [".github/workflows/domain.yml"])
            self.assertEqual(data["protected_control_authorization"], {"required": False, "authorized_merge": None})

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

    def test_approval_requires_evidence_binding_and_each_successful_byte_proof(self):
        binding = {**BINDING, "sces_evidence_sha256": "e" * 64}
        evidence = {"sces-00001.data": b"claim", "sces-00002.data": b"unchanged verification"}
        verdict = {"sces_evidence_sha256": binding["sces_evidence_sha256"]}
        for trace, message in (
            (make_trace(evidence=evidence), "does not bind"),
            (make_trace(verdict={**verdict, "sces_evidence_sha256": "f" * 64}, evidence=evidence), "does not bind"),
            (make_trace(verdict=verdict, evidence={"sces-00001.data": b"claim"}), "lacks exact selected SCES"),
            (make_trace(verdict=verdict, evidence={**evidence, "sces-00002.data": b"other"}), "lacks exact selected SCES"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(DataError, message):
                review_result(trace, binding, "abc", PATCH, evidence)
        _, decision = review_result(make_trace(verdict=verdict, evidence=evidence), binding, "abc", PATCH, evidence)
        self.assertEqual(decision["decision"], "approve")

    def test_truncated_multiple_batch_proof_cannot_authorize_approval(self):
        binding = {**BINDING, "sces_evidence_sha256": "e" * 64}
        evidence = {f"sces-{index:05}.data": f"fixture {index}".encode() for index in range(129)}
        verdict = {"sces_evidence_sha256": binding["sces_evidence_sha256"]}
        trace = make_trace(verdict=verdict, evidence=evidence)
        review_result(trace, binding, "abc", PATCH, evidence)
        first_batch = {name: evidence[name] for name in sorted(evidence)[:128]}
        with self.assertRaisesRegex(DataError, "lacks exact selected SCES"):
            review_result(make_trace(verdict=verdict, evidence=first_batch), binding, "abc", PATCH, evidence)

    def test_stages_exact_selected_bytes_and_requires_them_in_review(self):
        evidence = {"sces/releases/r/claims.json": b"published bytes",
                    "sces/records/verification/example--1.json": b"unchanged verification"}
        self.capture_evidence.return_value = evidence
        github = Mock(get_pull=Mock(return_value=SNAPSHOT))
        with TemporaryDirectory() as directory:
            args = SimpleNamespace(state_dir=Path(directory), mode="review", pull=1, model="fixture",
                                   codex=Path("fixture"), app_id=None)

            def inspect(_, __, input_dir, schema, ___, *, reviewer):
                review_input = json.loads((input_dir / "review-input.json").read_bytes())
                opened = {name: (input_dir / name).read_bytes() for name in review_input["sces_review_files"]}
                self.assertEqual({path: opened[name] for name, path in review_input["sces_review_files"].items()},
                                 evidence)
                self.assertIn("sces_evidence_sha256", json.loads(schema.read_bytes())["required"])
                return make_trace(review_input["inspection_token"], evidence=opened, verdict={
                    "sces_evidence_sha256": review_input["sces_evidence_sha256"],
                })

            with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)) as capture,
                  patch("tools.review_gate.launch_review", side_effect=inspect)):
                result = run(args, github)
            self.capture_evidence.assert_called_once_with(capture.call_args.args[1], SNAPSHOT.merge, REPOSITORY,
                                                          base=SNAPSHOT.base)
            self.assertEqual(result["status"], "reviewed-locally")
            self.assertEqual(result["binding"]["sces_evidence"],
                             {path: sha256(raw).hexdigest() for path, raw in evidence.items()})

    def test_short_patch_lines_qualify_but_text_headers_do_not(self):
        diff = (b"diff --git a/mode b/mode\nold mode 100644\nnew mode 100755\n"
                b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n"
                b"@@ -0,0 +1,2 @@\n+x\n+++ y\n")
        binding = {**BINDING, "diff_sha256": sha256(diff).hexdigest()}
        for displayed in ("new file mode 100644", "new mode 100755", "+++ b/file", "@@ -0,0 +1,2 @@"):
            with self.subTest(displayed=displayed), self.assertRaisesRegex(DataError, "patch body inspection"):
                review_result(make_trace(diff=diff, displayed=displayed), binding, "abc", diff)
        for displayed in ("+x", "+++ y"):
            with self.subTest(displayed=displayed):
                execution, verdict = review_result(make_trace(diff=diff, displayed=displayed), binding, "abc", diff)
                self.assertEqual((execution, verdict["decision"]), (EXECUTION, "approve"))

    def test_mode_only_and_binary_patches_require_their_own_content(self):
        cases = (
            (b"diff --git a/file b/file\nold mode 100644\nnew mode 100755\n",
             "diff --git a/file b/file", "new mode 100755"),
            (b"diff --git a/file b/file\nnew file mode 100644\nGIT binary patch\nliteral 3\nKc${Nk^?r|oO9I;v\n",
             "GIT binary patch\nnew file mode 100644\nliteral 3", "Kc${Nk^?r|oO9I;v"),
        )
        for diff, header, body in cases:
            binding = {**BINDING, "diff_sha256": sha256(diff).hexdigest()}
            with self.subTest(diff=diff):
                with self.assertRaisesRegex(DataError, "patch body inspection"):
                    review_result(make_trace(diff=diff, displayed=header), binding, "abc", diff)
                execution, verdict = review_result(make_trace(diff=diff, displayed=body), binding, "abc", diff)
                self.assertEqual((execution, verdict["decision"]), (EXECUTION, "approve"))

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
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"), queue_run=321,
                                   commissioning_policy=ADDITIVE)
            github = Mock()
            use_queue_rules(github)
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
                self.assertEqual(result["binding"]["commissioning"], {"phase": "additive", "approval": {
                    "ruleset_id": RULESET, "code_owner_review": True, "approving_review_count": 1,
                }})
                wrong_approvals = active_queue_rules()
                wrong_approvals[0]["parameters"]["required_approving_review_count"] = 0
                live_reads = iter((active_queue_rules(), wrong_approvals))
                use_queue_rules(github, on_read=lambda: next(live_reads))
                publisher.reset_mock()
                credential = Mock()
                with self.assertRaisesRegex(DataError, "ordinary approval"):
                    run(args, github, token_input=credential, publisher=publisher)
                credential.assert_not_called()
                publisher.assert_not_called()
                use_queue_rules(github)
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
        use_queue_rules(github)
        require_queue_rules(github, 123, policy=ADDITIVE)
        github._get_json.assert_any_call(f"/repos/{REPOSITORY}/rulesets/{RULESET}")
        with self.assertRaisesRegex(DataError, "exact integration"):
            require_queue_rules(github, 321, policy=ADDITIVE)
        for key, value in (("merge_method", "SQUASH"), ("grouping_strategy", "HEADGREEN"),
                           ("max_entries_to_merge", 2), ("max_entries_to_build", True)):
            rules = active_queue_rules()
            rules[3]["parameters"][key] = value
            use_queue_rules(github, rules)
            with self.subTest(key=key), self.assertRaisesRegex(DataError, "single-entry"):
                require_queue_rules(github, 123, policy=ADDITIVE)
        for key, value in (("strict_required_status_checks_policy", False),
                           ("strict_required_status_checks_policy", 1), ("do_not_enforce_on_create", True),
                           ("do_not_enforce_on_create", None)):
            rules = active_queue_rules()
            rules[-1]["parameters"][key] = value
            use_queue_rules(github, rules)
            with self.subTest(key=key, value=value), self.assertRaisesRegex(DataError, "enforce strict checks"):
                require_queue_rules(github, 123, policy=ADDITIVE)
        use_queue_rules(github, [row for row in active_queue_rules() if row["type"] != "merge_queue"])
        with self.assertRaisesRegex(DataError, "mandatory merge queue"):
            require_queue_rules(github, 123, policy=ADDITIVE)
        use_queue_rules(github, bypass=[{"actor_id": 123}])
        with self.assertRaisesRegex(DataError, "no-bypass"):
            require_queue_rules(github, 123, policy=ADDITIVE)

    def test_exact_approval_rule_for_every_commissioning_phase(self):
        github = Mock()
        for phase, base, owner, count, authorized in (
            ("trial", "codex-gate-trial", False, 0, None),
            ("additive", "main", True, 1, None),
            ("final", "main", False, 0, RULESET),
        ):
            with self.subTest(phase=phase), patch("tools.review_gate.BASE_REF", base):
                policy = commissioning_policy(REPOSITORY, base, phase, authorized)
                rules = active_queue_rules(policy)
                use_queue_rules(github, rules)
                observed = require_queue_rules(github, 123, policy=policy)
                self.assertIs(observed.code_owner_review, owner)
                self.assertEqual(observed.approving_review_count, count)
                use_queue_rules(github, [*rules, rules[0]])
                with self.assertRaisesRegex(DataError, "ordinary approval"):
                    require_queue_rules(github, 123, policy=policy)
                if phase != "trial":
                    use_queue_rules(github, active_queue_rules(policy, ruleset=14))
                    with self.assertRaisesRegex(DataError, "ordinary approval"):
                        require_queue_rules(github, 123, policy=policy)
        for wrong in (True, None, 14, str(RULESET)):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(DataError, "exact production ruleset"):
                commissioning_policy(REPOSITORY, "main", "final", wrong)
        with self.assertRaisesRegex(DataError, "pinned trial branch"):
            commissioning_policy(REPOSITORY, "main", "trial")

    def test_protected_issuance_uses_owner_transport_and_local_inspection_uses_public_transport(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            settings = (root, root / "codex", "fixture", 123, Reviewer(4001, 4002, root), ADDITIVE, SNAPSHOT.merge, None)
            with (patch("tools.review_gate.load_issuer", return_value=settings),
                  patch("tools.review_commission.OwnerGitHub") as owner,
                  patch("tools.review_gate.GitHub") as public,
                  patch("tools.review_gate.run_serialized", return_value={"status": "check-issued"}) as issuer,
                  patch("tools.review_gate.run", return_value={"status": "inspection-only"}) as execute,
                  patch("tools.review_gate.sys.stdout", SimpleNamespace(buffer=BytesIO()))):
                self.assertEqual(main(["review", "1", "--issuer-config", str(root / "config"), "--queue-admission"]), 0)
                self.assertIs(issuer.call_args.args[1], owner.return_value)
                self.assertEqual(issuer.call_args.args[0].authorized_control_merge, SNAPSHOT.merge)
                self.assertTrue(callable(issuer.call_args.args[2]))
                execute.assert_not_called()
                public.assert_not_called()
                owner.reset_mock()
                self.assertEqual(main(["inspect", "1", "--state-dir", str(root)]), 0)
                self.assertIs(execute.call_args.args[1], public.return_value)
                owner.assert_not_called()

    def test_wrong_source_and_stale_returned_checks_are_rejected(self):
        payload = {"name": CHECK_NAME, "head_sha": SNAPSHOT.merge,
                   "status": "completed", "conclusion": "success", "external_id": "expected"}
        verify_issued_check(api_check(payload), SNAPSHOT.merge, 123, "expected", "completed", "success")
        for check in (api_check(payload, 999), api_check({**payload, "head_sha": SNAPSHOT.head}),
                      api_check({**payload, "external_id": "unrelated"}), api_check({**payload, "conclusion": "failure"})):
            with self.subTest(check=check), self.assertRaisesRegex(DataError, "wrong-source"):
                verify_issued_check(check, SNAPSHOT.merge, 123, "expected", "completed", "success")

    def test_listing_selects_only_exact_app_context_and_ref_and_rejects_an_incomplete_history(self):
        prior = api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head, "external_id": "a" * 64,
                           "status": "completed", "conclusion": "success"})
        rows = [prior, {**prior, "app": {"id": 124}}, {**prior, "name": "unrelated"},
                {**prior, "id": 43, "conclusion": "failure"}]
        github = Mock()
        github._get_json.return_value = {"total_count": len(rows), "check_runs": rows}
        self.assertEqual(successful_checks(github, SNAPSHOT.head, 123), [prior])
        endpoint = urlsplit(github._get_json.call_args.args[0])
        self.assertEqual(endpoint.path, f"/repos/{REPOSITORY}/commits/{SNAPSHOT.head}/check-runs")
        self.assertEqual(parse_qs(endpoint.query), {
            "check_name": [CHECK_NAME], "app_id": ["123"], "filter": ["all"], "per_page": ["100"],
        })
        github._get_json.return_value["total_count"] += 1
        with self.assertRaisesRegex(DataError, "complete history"):
            successful_checks(github, SNAPSHOT.head, 123)

        github._get_json.return_value = {"total_count": 1, "check_runs": [{**prior, "head_sha": SNAPSHOT.merge}]}
        with self.assertRaisesRegex(DataError, "invalid exact review checks"):
            successful_checks(github, SNAPSHOT.head, 123)

    def test_same_head_adverse_review_revokes_old_success_before_launch(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"),
                                   queue_admission=True, commissioning_policy=ADDITIVE)
            github = Mock()
            use_queue_rules(github)
            github.get_pull.return_value = SNAPSHOT
            prior = api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head, "external_id": "a" * 64,
                               "status": "completed", "conclusion": "success"})
            self.successful_checks.side_effect = [[prior], [prior], []]
            publisher = Mock(return_value={**prior, "conclusion": "failure"})

            def negative(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                publisher.assert_called_once()
                self.assertEqual(publisher.call_args.kwargs["check_id"], prior["id"])
                self.assertEqual(publisher.call_args.args[1]["conclusion"], "failure")
                staged = (input_dir / "review-input.json").read_bytes()
                self.assertNotIn(LEGACY_TOKEN.encode(), staged)
                token = json.loads(staged)["inspection_token"]
                return make_trace(token, verdict={"decision": "changes-required", "findings": ["Fixture finding"]})

            with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.protected_staging", return_value=state),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.token_is_target_only", return_value=True),
                  patch("tools.review_gate.launch_review", side_effect=negative)):
                result = run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
            self.assertEqual(result["status"], "changes-required")
            self.assertEqual(json.loads((Path(result["audit"]) / "superseded-checks.json").read_bytes()), [prior])
            self.assertFalse((Path(result["audit"]) / "issued-check.json").exists())

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
                                   queue_admission=True, commissioning_policy=ADDITIVE)
            github = Mock()
            use_queue_rules(github)
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
                                   queue_admission=True, commissioning_policy=ADDITIVE)
            github = Mock()
            use_queue_rules(github)
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

            with (patch("tools.review_gate.load_issuer",
                        return_value=(root, root / "codex", "fixture", None, reviewer, None, None, None)) as load,
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
                "commissioning_phase": "additive",
            }
            config.write_text(json.dumps(settings), encoding="utf-8")
            config.chmod(0o600)
            reviewer = Reviewer(4001, 4002, root / "reviewer-home")
            with patch("tools.review_gate.load_reviewer", return_value=reviewer):
                self.assertEqual(load_issuer(config), (root, codex, "fixture", 123, reviewer, ADDITIVE, None, None))
                with self.assertRaisesRegex(DataError, "exact production ruleset"):
                    config.write_text(json.dumps({**settings, "commissioning_phase": "final"}), encoding="utf-8")
                    load_issuer(config)
                config.write_text(json.dumps({**settings, "commissioning_phase": "final",
                                              "authorized_cutover_ruleset": RULESET}), encoding="utf-8")
                self.assertEqual(load_issuer(config)[-3], commissioning_policy(REPOSITORY, "main", "final", RULESET))
                config.write_text(json.dumps({**settings, "authorized_control_merge": SNAPSHOT.merge}), encoding="utf-8")
                self.assertEqual(load_issuer(config)[-2], SNAPSHOT.merge)
                record = root / "private-record.json"
                grant = root / "private-grant.json"
                for path in (record, grant):
                    path.touch(mode=0o600)
                config.write_text(json.dumps({**settings, "authorized_control_merge": SNAPSHOT.merge,
                                              "authorized_control_record": str(record), "owner_grant_state": str(grant)}),
                                  encoding="utf-8")
                self.assertEqual(load_issuer(config)[-1], AuthorizationPaths(record, grant))
                config.write_text(json.dumps({**settings, "authorized_control_merge": SNAPSHOT.merge,
                                              "authorized_control_record": str(record)}), encoding="utf-8")
                with self.assertRaisesRegex(DataError, "owner authorization configuration"):
                    load_issuer(config)
                config.write_text(json.dumps({**settings, "authorized_control_merge": "short"}), encoding="utf-8")
                with self.assertRaisesRegex(DataError, "protected control authorization"):
                    load_issuer(config)
                config.write_text(json.dumps(settings), encoding="utf-8")
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
                del settings["commissioning_phase"]
                config.write_text(json.dumps(settings), encoding="utf-8")
                self.assertEqual(load_issuer(config, rehearsal=True),
                                 (root, codex, "fixture", None, reviewer, None, None, None))
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
