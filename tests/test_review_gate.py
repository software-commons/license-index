"""Synthetic technical-gate fixtures. They never supply production review evidence."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from tools.records import DataError
from tools.review_gate import (
    ACTIONS_APP_ID, APP_TOKEN, CHECK_NAME, CI_CONTEXTS, AuthorizationPaths, Reviewer, capture_reviewer_streams, create_check, launch_review,
    load_issuer, load_reviewer, main, protected_path, require_queue_rules, review_result, run, passing_checks, supersede_checks,
    verify_issued_check,
)
from tools.review_protection import commissioning_policy
from tools.review_snapshot import AdmissionHead, PullSnapshot, QueuePull, REPOSITORY, SnapshotError

EXECUTION = "90c3284d-c009-4e34-bc00-beb41319adad"
SNAPSHOT = PullSnapshot(repository_id=1468281504, number=1, base="a" * 40, head="b" * 40, merge="c" * 40)
ADMISSION = AdmissionHead(SNAPSHOT.repository_id, SNAPSHOT.number, SNAPSHOT.head)
QUEUE_PULL = QueuePull(SNAPSHOT.repository_id, SNAPSHOT.number, SNAPSHOT.base, SNAPSHOT.head)
DOMAIN = ".github/workflows/domain.yml"
QUEUE = {"merge": "d" * 40, "queue_ref": "refs/heads/gh-readonly-queue/main/pr-1-" + "c" * 40,
         "workflows": {DOMAIN: {"workflow_id": 123, "id": 321}}}
QUEUE_TARGET = {"merge": QUEUE["merge"], "queue_ref": QUEUE["queue_ref"], "workflow": DOMAIN,
                "workflow_id": 123, "observed_run_id": 321}
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


class CheckHistoryTests(unittest.TestCase):
    def suite(self, suite_id):
        return {"id": suite_id, "head_sha": SNAPSHOT.head, "app": {"id": 123}, "repository": TOKEN_REPOSITORY}

    def check(self, check_id, suite_id, conclusion="failure"):
        return {"id": check_id, "head_sha": SNAPSHOT.head, "name": CHECK_NAME, "app": {"id": 123},
                "check_suite": {"id": suite_id}, "status": "completed", "conclusion": conclusion, "external_id": "a" * 64}

    def github(self, suites, runs):
        def respond(url):
            path = urlsplit(url)
            query = parse_qs(path.query)
            self.assertEqual(query.pop("per_page"), ["100"])
            page, = query.pop("page")
            index = (int(page) - 1) * 100
            repo = f"/repos/{REPOSITORY}"
            if path.path == f"{repo}/commits/{SNAPSHOT.head}/check-suites":
                self.assertEqual(query, {"app_id": ["123"]})
                key, rows = "check_suites", suites
            else:
                match = path.path.removeprefix(f"{repo}/check-suites/").removesuffix("/check-runs")
                self.assertEqual(path.path, f"{repo}/check-suites/{match}/check-runs")
                self.assertEqual(query, {"check_name": [CHECK_NAME], "filter": ["all"]})
                key, rows = "check_runs", runs[int(match)]
            return {"total_count": len(rows), key: rows[index:index + 100]}

        return Mock(_get_json=Mock(side_effect=respond))

    def test_revokes_success_on_second_run_page_of_second_suite_page(self):
        suites = [self.suite(suite_id) for suite_id in range(1, 102)]
        runs = {suite["id"]: [] for suite in suites}
        runs[101] = [self.check(check_id, 101) for check_id in range(1, 102)]
        prior = {**runs[101][-1], "conclusion": "success"}
        runs[101][-1] = prior
        github = self.github(suites, runs)
        self.assertEqual(passing_checks(github, SNAPSHOT, SNAPSHOT.head, 123), [prior])

        def publish(token, payload, *, check_id):
            self.assertEqual((token, payload["conclusion"], check_id), (LEGACY_TOKEN, "failure", prior["id"]))
            replacement = {**prior, "conclusion": "failure"}
            runs[101][-1] = replacement
            return replacement

        freshness = Mock()
        with patch("tools.review_gate.token_is_target_only", return_value=True):
            supersede_checks(github, SNAPSHOT, SNAPSHOT.head, 123, LEGACY_TOKEN, [prior], publish, freshness)
        freshness.assert_called_once()
        self.assertEqual(passing_checks(github, SNAPSHOT, SNAPSHOT.head, 123), [])

    def test_does_not_apply_a_per_suite_limit_globally(self):
        suites = [self.suite(1), self.suite(2)]
        runs = {1: [self.check(check_id, 1) for check_id in range(1, 1001)],
                2: [self.check(1001, 2, "success")]}
        self.assertEqual(passing_checks(self.github(suites, runs), SNAPSHOT, SNAPSHOT.head, 123), runs[2])

    def test_denial_revokes_an_authenticated_success_without_an_approval_digest(self):
        for digest in (None, "legacy-unstructured-identifier"):
            with self.subTest(digest=digest):
                prior = self.check(42, 1, "success")
                prior["external_id"] = digest
                runs = {1: [prior]}
                github = self.github([self.suite(1)], runs)

                def publish(token, payload, *, check_id):
                    self.assertEqual((token, payload["conclusion"], check_id), (LEGACY_TOKEN, "failure", prior["id"]))
                    replacement = {**prior, "conclusion": "failure"}
                    runs[1][0] = replacement
                    return replacement

                with patch("tools.review_gate.token_is_target_only", return_value=True):
                    supersede_checks(github, SNAPSHOT, SNAPSHOT.head, 123, LEGACY_TOKEN, [prior], publish, Mock())
                self.assertEqual(passing_checks(github, SNAPSHOT, SNAPSHOT.head, 123), [])
                with self.assertRaisesRegex(DataError, "wrong-source review check"):
                    verify_issued_check(prior, SNAPSHOT.head, 123, "a" * 64, "completed", "success")

    def test_admission_revocation_retires_neutral_and_skipped_checks(self):
        for retained in (None, "neutral", "skipped"):
            with self.subTest(retained=retained), TemporaryDirectory() as directory:
                state = Path(directory)
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, app_id=123,
                                       reviewer=Reviewer(4001, 4002, state), queue_admission=True,
                                       revoke_only=True, expected_head=SNAPSHOT.head)
                rows = [self.check(1, 1, "neutral"), self.check(2, 1, "skipped"), self.check(3, 1, "cancelled")]
                github = self.github([self.suite(1)], {1: rows})
                github.get_admission_head.return_value = ADMISSION

                def publish(token, payload, *, check_id):
                    self.assertEqual((token, payload["status"], payload["conclusion"]),
                                     (LEGACY_TOKEN, "completed", "failure"))
                    prior = rows[check_id - 1]
                    replacement = {**prior, "conclusion": "failure"}
                    if prior["conclusion"] != retained:
                        rows[check_id - 1] = replacement
                    return replacement

                for prior in rows[:2]:
                    with self.assertRaisesRegex(DataError, "wrong-source review check"):
                        verify_issued_check(prior, SNAPSHOT.head, 123, "a" * 64, "completed", "success")
                publisher = Mock(side_effect=publish)
                with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40),
                      patch("tools.review_gate.token_is_target_only", return_value=True),
                      patch("tools.review_gate.launch_review") as reviewer):
                    if retained is None:
                        result = run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                        self.assertEqual(result["revoked_check_ids"], [1, 2])
                        self.assertEqual(passing_checks(github, SNAPSHOT, SNAPSHOT.head, 123), [])
                    else:
                        with self.assertRaisesRegex(DataError, "superseded passing check remains visible"):
                            run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                self.assertEqual([call.kwargs["check_id"] for call in publisher.call_args_list], [1, 2])
                self.assertEqual(rows[2]["conclusion"], "cancelled")
                github.get_pull.assert_not_called()
                reviewer.assert_not_called()

    def test_unstable_partial_duplicate_or_wrong_scope_history_is_rejected(self):
        runs = [self.check(check_id, 12) for check_id in range(1, 102)]
        for page in ({"total_count": 102, "check_runs": runs[-1:]},
                     {"total_count": 101, "check_runs": []},
                     {"total_count": 101, "check_runs": runs[:1]},
                     {"total_count": 101, "check_runs": [{**runs[-1], "check_suite": {"id": 13}}]},
                     {"total_count": 101, "check_runs": [{**runs[-1], "app": {"id": 13}}]}):
            with self.subTest(page=page):
                github = Mock(_get_json=Mock(side_effect=[{"total_count": 1, "check_suites": [self.suite(12)]},
                                                          {"total_count": 101, "check_runs": runs[:100]}, page]))
                with self.assertRaises(DataError):
                    passing_checks(github, SNAPSHOT, SNAPSHOT.head, 123)

        for suites, runs in (([{**self.suite(12), "repository": {"id": 1468265981, "full_name": "software-commons/language-index"}}], {12: []}),
                             ([self.suite(12), self.suite(13)], {12: [self.check(1, 12)], 13: [self.check(1, 13)]})):
            with self.subTest(suites=suites):
                with self.assertRaises(DataError):
                    passing_checks(self.github(suites, runs), SNAPSHOT, SNAPSHOT.head, 123)


class ReviewGateTests(unittest.TestCase):
    def setUp(self):
        capture = patch("tools.review_gate.capture_selected_evidence", return_value={})
        self.capture_evidence = capture.start()
        self.addCleanup(capture.stop)
        checks = patch("tools.review_gate.passing_checks", return_value=[])
        self.passing_checks = checks.start()
        self.addCleanup(checks.stop)
        targets = patch("tools.review_gate.capture_queue_target", return_value=QUEUE_TARGET)
        self.capture_queue_target = targets.start()
        self.addCleanup(targets.stop)
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
                    github = Mock(get_pull=Mock(return_value=SNAPSHOT), get_admission_head=Mock(return_value=ADMISSION),
                                  get_queue_pull=Mock(return_value=QUEUE_PULL))
                    paths = AuthorizationPaths(root / "auth.json", root / "grant.json") if has_record else None
                    args = SimpleNamespace(state_dir=root, mode="review", pull=1, app_id=123, model="fixture",
                                           codex=Path("fixture"), reviewer=Reviewer(4001, 4002, root),
                                           queue_admission=admission, queue_run=None if admission else 321,
                                           commissioning_policy=ADDITIVE, authorized_control_merge=authorized,
                                           authorization_paths=paths)
                    credential = Mock()
                    with (patch("tools.review_gate.require_queue_rules", return_value=ADDITIVE.approval),
                          patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                          patch("tools.review_gate.capture_admission_head", return_value="f" * 40),
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
            github = Mock(get_pull=Mock(return_value=SNAPSHOT), get_admission_head=Mock(return_value=ADMISSION))
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
                  patch("tools.review_gate.capture_admission_head", return_value="f" * 40),
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
            github = Mock(get_pull=Mock(return_value=SNAPSHOT), get_admission_head=Mock(return_value=ADMISSION))
            args = SimpleNamespace(state_dir=root, mode="review", pull=1, app_id=123, model="fixture",
                                   codex=Path("fixture"), reviewer=Reviewer(4001, 4002, root),
                                   queue_admission=True, commissioning_policy=policy)
            credential = Mock()
            with (patch("tools.review_gate.require_queue_rules", return_value=policy.approval),
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.capture_admission_head", return_value="f" * 40),
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

    def test_review_rejects_nonlocal_tool_events_even_with_a_bound_verdict(self):
        for stage in ("started", "completed"):
            for tool in ("mcp_tool_call", "web_search", "dynamic_tool_call", "file_change"):
                with self.subTest(stage=stage, tool=tool):
                    events = make_trace().splitlines()
                    events.insert(2, json.dumps({
                        "type": f"item.{stage}", "item": {"type": tool},
                    }).encode())
                    with self.assertRaisesRegex(DataError, "outside the isolated reviewer profile"):
                        review_result(b"\n".join(events), BINDING, "abc", PATCH)

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

    def test_approval_requires_bound_policies_and_a_complete_nonce_proof(self):
        token = "abc"
        binding = {**BINDING, "review_policy_sha256": "1" * 64}
        policies = {"policy-00001.data": b"fixture evidence standard",
                    "policy-00002.data": b"fixture registry standard"}
        verdict = {"review_policy_sha256": binding["review_policy_sha256"]}

        def trace(echo, inspected=None):
            events = make_trace(token, verdict=echo).splitlines()
            if inspected is not None:
                statement = "".join(f"{name} {sha256(token.encode() + data).hexdigest()}\n"
                                    for name, data in sorted(inspected.items()))
                proof = f"policy-proof 0 {sha256(statement.encode()).hexdigest()}"
                events.insert(-2, json.dumps({"type": "item.completed", "item": {
                    "type": "command_execution", "status": "completed", "exit_code": 0,
                    "command": "inspect policies listed in review-input.json",
                    "aggregated_output": proof,
                }}).encode())
            return b"\n".join(events) + b"\n"

        execution, approved = review_result(trace(verdict, policies), binding, token, PATCH, policy_files=policies)
        self.assertEqual((execution, approved["decision"]), (EXECUTION, "approve"))
        for label, candidate, error in (
            ("missing digest", trace({}, policies), "does not bind"),
            ("wrong digest", trace({"review_policy_sha256": "2" * 64}, policies), "does not bind"),
            ("missing proof", trace(verdict), "lacks.*polic"),
            ("partial proof", trace(verdict, {"policy-00001.data": policies["policy-00001.data"]}), "lacks.*polic"),
            ("wrong bytes", trace(verdict, {**policies, "policy-00002.data": b"changed standard"}), "lacks.*polic"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(DataError, error):
                review_result(candidate, binding, token, PATCH, policy_files=policies)

    def test_approval_requires_a_separate_review_history_digest_and_proof(self):
        token = "abc"
        history_name = "review-history.zip"
        history = b"synthetic review history archive"
        history_files = {history_name: history}
        evidence = {"sces-00001.data": b"synthetic selected evidence"}
        policies = {"policy-00001.data": b"synthetic policy"}
        other_digests = {"sces_evidence_sha256": "1" * 64, "review_policy_sha256": "2" * 64}
        history_digest = {"review_history_sha256": sha256(history).hexdigest()}
        binding = {**BINDING, **other_digests, **history_digest}

        def proof(label, files):
            entries = "".join(f"{name} {sha256(token.encode() + raw).hexdigest()}\n"
                              for name, raw in sorted(files.items()))
            return f"{label} 0 {sha256(entries.encode()).hexdigest()}"

        def result(echo, inspected, label="history-proof"):
            events = make_trace(token, verdict={**other_digests, **echo}, evidence=evidence).splitlines()
            outputs = [proof("policy-proof", policies)]
            if inspected is not None:
                outputs.append(proof(label, {history_name: inspected}))
            events.insert(-2, json.dumps({"type": "item.completed", "item": {
                "type": "command_execution", "status": "completed", "exit_code": 0,
                "command": "inspect policy and history listed in review-input.json",
                "aggregated_output": "\n".join(outputs),
            }}).encode())
            return review_result(b"\n".join(events), binding, token, PATCH, evidence,
                                 policy_files=policies, history_files=history_files)

        execution, approved = result(history_digest, history)
        self.assertEqual((execution, approved["decision"]), (EXECUTION, "approve"))
        for echo in ({}, {"review_history_sha256": "3" * 64}):
            with self.subTest(echo=echo), self.assertRaisesRegex(DataError, "does not bind"):
                result(echo, history)
        for inspected, label in ((None, "history-proof"), (b"other archive", "history-proof"),
                                 (history, "policy-proof")):
            with self.subTest(inspected=inspected, label=label), self.assertRaisesRegex(DataError, "lacks.*histor"):
                result(history_digest, inspected, label)

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
        github = Mock(get_pull=Mock(return_value=SNAPSHOT), get_admission_head=Mock(return_value=ADMISSION))
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

    def test_only_lf_delimits_patch_and_displayed_records(self):
        header = b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1,2 +1,2 @@\n"
        for separator in ("\r", "\f", "\u2028"):
            context = f" unchanged{separator}+context material\n".encode()
            changed = f"+real{separator}value"
            diff = header + context + b"-old value\n" + changed.encode() + b"\n"
            binding = {**BINDING, "diff_sha256": sha256(diff).hexdigest()}
            for displayed in ("+context material", "+real", f"other output{separator}-old value"):
                with self.subTest(separator=separator, displayed=displayed):
                    with self.assertRaisesRegex(DataError, "patch body inspection"):
                        review_result(make_trace(diff=diff, displayed=displayed), binding, "abc", diff)
            execution, verdict = review_result(make_trace(diff=diff, displayed=changed), binding, "abc", diff)
            self.assertEqual((execution, verdict["decision"]), (EXECUTION, "approve"))

    def test_patch_record_proof_preserves_trailing_carriage_return(self):
        diff = b"diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\r\n+new\r\n"
        binding = {**BINDING, "diff_sha256": sha256(diff).hexdigest()}
        with self.assertRaisesRegex(DataError, "patch body inspection"):
            review_result(make_trace(diff=diff, displayed="+new\n"), binding, "abc", diff)
        execution, verdict = review_result(make_trace(diff=diff, displayed="+new\r\n"), binding, "abc", diff)
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
            github.get_admission_head.return_value = ADMISSION
            github.get_queue_pull.return_value = QUEUE_PULL

            def fake_launch(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                bound = json.loads((input_dir / "review-input.json").read_bytes())
                return make_trace(bound["inspection_token"], verdict={"merge_sha": bound["merge"]})

            with (patch("tools.review_gate.GitHub", return_value=scope) as client,
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.capture_candidate_tree", return_value="e" * 40) as fresh_tree,
                  patch("tools.review_gate.capture_queue_observation", return_value=QUEUE) as observed,
                  patch("tools.review_gate.protected_staging", return_value=state),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.launch_review", side_effect=fake_launch)):
                result = run(args, github, token_input=lambda: STATELESS_TOKEN, publisher=publisher)
                self.assertEqual(result["status"], "check-issued")
                self.assertEqual(fresh_tree.call_count, 3)
                for capture in fresh_tree.call_args_list:
                    self.assertEqual(capture.args[0], replace(SNAPSHOT, merge=QUEUE["merge"]))
                    self.assertEqual(capture.kwargs, {"queue_ref": QUEUE["queue_ref"]})
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

    def test_issuance_rechecks_live_git_refs_when_rest_still_reports_the_reviewed_candidate(self):
        scenarios = (("admission", "merge", False), ("admission", "head", True),
                     ("queue", "merge", True), ("admission", None, False))
        for phase, stale_ref, after_pending in scenarios:
            with self.subTest(phase=phase, stale_ref=stale_ref), TemporaryDirectory() as directory:
                state = Path(directory)
                admission = phase == "admission"
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                       app_id=123, reviewer=Reviewer(4001, 4002, state), queue_admission=admission,
                                       queue_run=None if admission else 321, commissioning_policy=ADDITIVE)
                github = Mock(get_pull=Mock(return_value=SNAPSHOT), get_admission_head=Mock(return_value=ADMISSION),
                              get_queue_pull=Mock(return_value=QUEUE_PULL))
                candidate = SNAPSHOT if admission else replace(SNAPSHOT, merge=QUEUE["merge"])
                git_moved = False
                checked_sha = candidate.head if admission else candidate.merge

                def fresh_merge(snapshot, _directory, **options):
                    self.assertEqual(snapshot, candidate)
                    self.assertEqual(options, {"linear_head": True} if admission else {"queue_ref": QUEUE["queue_ref"]})
                    if git_moved and stale_ref == "merge":
                        raise SnapshotError("Fixture Git ref moved")
                    return "e" * 40

                def fresh_head(identity, _directory):
                    self.assertEqual(identity, ADMISSION)
                    if git_moved and stale_ref == "head":
                        raise SnapshotError("Fixture Git ref moved")
                    return "f" * 40

                def inspect(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                    nonlocal git_moved
                    git_moved = not after_pending
                    bound = json.loads((input_dir / "review-input.json").read_bytes())
                    return make_trace(bound["inspection_token"], verdict={"merge_sha": candidate.merge})

                def publish(_token, payload, *, check_id=None):
                    nonlocal git_moved
                    if check_id is None:
                        git_moved = True
                        return api_check(payload)
                    return api_check({"name": CHECK_NAME, "head_sha": checked_sha,
                                      "external_id": publisher.call_args_list[0].args[1]["external_id"], **payload})

                publisher = Mock(side_effect=publish)
                with (patch("tools.review_gate.require_queue_rules", return_value=ADDITIVE.approval),
                      patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                      patch("tools.review_gate.capture_queue_observation", return_value=QUEUE),
                      patch("tools.review_gate.capture_candidate_tree", side_effect=fresh_merge),
                      patch("tools.review_gate.capture_admission_head", side_effect=fresh_head),
                      patch("tools.review_gate.token_is_target_only", return_value=True),
                      patch("tools.review_gate.protected_staging", return_value=state),
                      patch("tools.review_gate.share_reviewer_inputs"),
                      patch("tools.review_gate.launch_review", side_effect=inspect)):
                    if stale_ref is None:
                        self.assertEqual(run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                                         ["status"], "check-issued")
                    else:
                        with self.assertRaisesRegex(SnapshotError, "Fixture Git ref moved"):
                            run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)

                expected = (["in_progress", "completed"] if stale_ref is None else
                            ["in_progress"] if after_pending else [])
                self.assertEqual([call.args[1]["status"] for call in publisher.call_args_list], expected)

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

    def test_same_head_adverse_review_revokes_old_success_before_launch(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"),
                                   queue_admission=True, commissioning_policy=ADDITIVE)
            github = Mock()
            use_queue_rules(github)
            github.get_pull.return_value = SNAPSHOT
            github.get_admission_head.return_value = ADMISSION
            prior = api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head, "external_id": "a" * 64,
                               "status": "completed", "conclusion": "success"})
            self.passing_checks.side_effect = [[prior], [prior], []]
            publisher = Mock(return_value={**prior, "conclusion": "failure"})

            def negative(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                publisher.assert_called_once()
                self.assertEqual(publisher.call_args.kwargs["check_id"], prior["id"])
                self.assertEqual(publisher.call_args.args[1]["conclusion"], "failure")
                staged = (input_dir / "review-input.json").read_bytes()
                self.assertNotIn(LEGACY_TOKEN.encode(), staged)
                token = json.loads(staged)["inspection_token"]
                return make_trace(token, verdict={"decision": "changes-required", "findings": ["Fixture finding"]})

            with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40) as capture,
                  patch("tools.review_gate.capture_candidate_tree", return_value="f" * 40),
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.protected_staging", return_value=state),
                  patch("tools.review_gate.share_reviewer_inputs"),
                  patch("tools.review_gate.token_is_target_only", return_value=True),
                  patch("tools.review_gate.launch_review", side_effect=negative)):
                result = run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
            self.assertEqual(capture.call_args.args[0], ADMISSION)
            self.assertEqual(result["status"], "changes-required")
            self.assertEqual(json.loads((Path(result["audit"]) / "superseded-checks.json").read_bytes()), [prior])
            self.assertFalse((Path(result["audit"]) / "issued-check.json").exists())

    def test_rechecks_role_and_revokes_before_a_failed_domain_or_grant_precondition(self):
        for failure in ("evidence", "authorization", "CI", "rules"):
            with self.subTest(failure=failure), TemporaryDirectory() as directory:
                state = Path(directory)
                queue = failure == "CI"
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                       app_id=123, reviewer=Reviewer(4001, 4002, state),
                                       queue_admission=not queue, queue_run=321 if queue else None,
                                       expected_merge=QUEUE["merge"] if queue else SNAPSHOT.merge,
                                       commissioning_policy=ADDITIVE, authorized_control_merge=SNAPSHOT.merge,
                                       authorization_paths=AuthorizationPaths(state / "record", state / "grant"))
                github = Mock()
                use_queue_rules(github)
                if failure == "rules":
                    drifted = active_queue_rules()
                    drifted[-1]["parameters"]["strict_required_status_checks_policy"] = False
                    use_queue_rules(github, drifted)
                github.get_pull.return_value = SNAPSHOT
                github.get_admission_head.return_value = ADMISSION
                github.get_queue_pull.return_value = QUEUE_PULL
                check_target = QUEUE["merge"] if queue else SNAPSHOT.head
                prior = api_check({"name": CHECK_NAME, "head_sha": check_target, "external_id": "a" * 64,
                                   "status": "completed", "conclusion": "success"})
                self.passing_checks.side_effect = [[prior], [prior], []]
                publisher = Mock(return_value={**prior, "conclusion": "failure"})

                def reject(*_args, **_kwargs):
                    self.assertEqual(publisher.call_args.kwargs["check_id"], prior["id"])
                    raise DataError("Rejected " + failure)

                with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40) as head,
                      patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                      patch("tools.review_gate.capture_candidate_tree", return_value="e" * 40) as tree,
                      patch("tools.review_gate.capture_candidate_patch", return_value=PATCH),
                      patch("tools.review_gate.capture_control_paths", return_value=["tools/review_gate.py"]),
                      patch("tools.review_gate.capture_selected_evidence", side_effect=reject if failure == "evidence" else None),
                      patch("tools.review_gate.validate_control_authorization", side_effect=reject),
                      patch("tools.review_gate.capture_queue_observation", side_effect=reject),
                      patch("tools.review_gate.token_is_target_only", return_value=True),
                      patch("tools.review_gate.launch_review") as reviewer):
                    message = "enforce strict checks" if failure == "rules" else "Rejected " + failure
                    with self.assertRaisesRegex(DataError, message):
                        run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                if queue:
                    self.assertEqual(tree.call_args.kwargs, {"queue_ref": QUEUE["queue_ref"]})
                    head.assert_not_called()
                else:
                    self.assertEqual(head.call_args.args[0], ADMISSION)
                    self.assertEqual(tree.call_count, 2)
                    self.assertTrue(all(call.args[0] == SNAPSHOT and call.kwargs == {"linear_head": True}
                                        for call in tree.call_args_list))
                reviewer.assert_not_called()
                publisher.assert_called_once()

    def test_protected_revoke_only_checks_exact_merge_and_skips_new_approval_gates(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, app_id=123,
                                   reviewer=Reviewer(4001, 4002, state), queue_admission=True,
                                   commissioning_policy=ADDITIVE, revoke_only=True, expected_merge="e" * 40)
            github = Mock()
            use_queue_rules(github)
            github.get_pull.return_value = SNAPSHOT
            github.get_admission_head.return_value = ADMISSION
            github.get_queue_pull.return_value = QUEUE_PULL
            credential = Mock(return_value=LEGACY_TOKEN)
            publisher = Mock()
            with patch("tools.review_gate.capture_candidate_tree",
                       side_effect=SnapshotError("GitHub merge candidate changed during capture")) as wrong_pin:
                with self.assertRaisesRegex(SnapshotError, "merge candidate changed during capture"):
                    run(args, github, token_input=credential, publisher=publisher)
            wrong_pin.assert_called_once()
            self.assertEqual(wrong_pin.call_args.args[0], replace(SNAPSHOT, merge=args.expected_merge))
            self.assertEqual(wrong_pin.call_args.kwargs, {"linear_head": True})
            credential.assert_not_called()
            publisher.assert_not_called()

            prior = api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head, "external_id": "a" * 64,
                               "status": "completed", "conclusion": "success"})
            args.expected_merge = SNAPSHOT.merge
            with patch("tools.review_gate.capture_candidate_tree", return_value="f" * 40) as merge_tree:
                result = run(args, github, token_input=credential, publisher=publisher)
            self.assertEqual(result["revoked_check_ids"], [])
            merge_tree.assert_called_once()
            credential.assert_not_called()
            publisher.assert_not_called()

            self.passing_checks.side_effect = [[prior]]
            with patch("tools.review_gate.capture_admission_head", side_effect=SnapshotError("single-parent")):
                with self.assertRaisesRegex(SnapshotError, "single-parent"):
                    run(args, github, token_input=credential, publisher=publisher)
            credential.assert_not_called()
            publisher.assert_not_called()

            self.passing_checks.side_effect = [[prior], [prior], []]
            publisher.return_value = {**prior, "conclusion": "failure"}
            github._get_json.side_effect = AssertionError("denial-only must not read issuance protection policy")
            with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40),
                  patch("tools.review_gate.capture_candidate_tree", return_value="f" * 40) as merge_tree,
                  patch("tools.review_gate.capture_candidate_patch") as diff,
                  patch("tools.review_gate.token_is_target_only", return_value=True),
                  patch("tools.review_gate.validate_control_authorization") as grant,
                  patch("tools.review_gate.launch_review") as reviewer):
                result = run(args, github, token_input=credential, publisher=publisher)
            self.assertEqual(result["revoked_check_ids"], [prior["id"]])
            self.assertEqual(result["checked_sha"], SNAPSHOT.head)
            self.assertEqual(merge_tree.call_count, 2)
            target = json.loads((Path(result["audit"]) / "revocation-target.json").read_bytes())
            self.assertEqual((target["base"], target["test_merge"], target["test_merge_tree"]),
                             (SNAPSHOT.base, SNAPSHOT.merge, "f" * 40))
            diff.assert_not_called()
            grant.assert_not_called()
            reviewer.assert_not_called()
            github.get_pull.assert_not_called()

    def test_admission_merges_must_bind_fresh_git_ref_and_ordered_parents_before_revocation(self):
        for captures, expected_token_reads in (
            ([SnapshotError("Test merge commit does not have the exact ordered base and head parents")], 0),
            (["f" * 40, SnapshotError("GitHub merge candidate changed during capture")], 1),
        ):
            with self.subTest(captures=captures), TemporaryDirectory() as directory:
                state = Path(directory)
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, app_id=123, queue_admission=True,
                                       reviewer=Reviewer(4001, 4002, state), expected_head=SNAPSHOT.head,
                                       expected_merge=SNAPSHOT.merge, commissioning_policy=ADDITIVE)
                github = Mock(get_pull=Mock(return_value=SNAPSHOT),
                              get_admission_head=Mock(return_value=ADMISSION),
                              get_queue_pull=Mock(return_value=QUEUE_PULL))
                prior = api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head,
                                   "status": "completed", "conclusion": "success"})
                self.passing_checks.side_effect = [[prior], [prior]]
                publisher = Mock()
                credential = Mock(return_value=LEGACY_TOKEN)
                with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40),
                      patch("tools.review_gate.capture_candidate_tree", side_effect=captures) as merge_tree,
                      patch("tools.review_gate.token_is_target_only", return_value=True),
                      patch("tools.review_gate.launch_review") as launch):
                    with self.assertRaisesRegex(SnapshotError, str(captures[-1])):
                        run(args, github, token_input=credential, publisher=publisher)
                self.assertEqual(merge_tree.call_count, len(captures))
                self.assertEqual(credential.call_count, expected_token_reads)
                publisher.assert_not_called()
                launch.assert_not_called()
                github.get_pull.assert_not_called()

    def test_protected_admission_can_deny_an_exact_head_without_a_mergeable_test_commit(self):
        for reason in ("Review requires a non-draft pull request", "GitHub has not established a mergeable test commit"):
            with self.subTest(reason=reason), TemporaryDirectory() as directory:
                state = Path(directory)
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, app_id=123,
                                       reviewer=Reviewer(4001, 4002, state), queue_admission=True,
                                       commissioning_policy=ADDITIVE, revoke_only=True, expected_head="e" * 40)
                github = Mock(get_admission_head=Mock(return_value=ADMISSION), get_pull=Mock(side_effect=SnapshotError(reason)))
                prior = api_check({"name": CHECK_NAME, "head_sha": SNAPSHOT.head,
                                   "status": "completed", "conclusion": "success"})
                credential = Mock(return_value=LEGACY_TOKEN)
                publisher = Mock(return_value={**prior, "conclusion": "failure"})
                with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40),
                      patch("tools.review_gate.capture_candidate_tree", return_value="f" * 40) as merge_tree,
                      patch("tools.review_gate.capture_diff") as diff,
                      patch("tools.review_gate.token_is_target_only", return_value=True),
                      patch("tools.review_gate.launch_review") as reviewer):
                    with self.assertRaisesRegex(DataError, "differs from the expected review head"):
                        run(args, github, token_input=credential, publisher=publisher)
                    credential.assert_not_called()
                    publisher.assert_not_called()

                    args.expected_head = SNAPSHOT.head
                    github.get_admission_head.side_effect = [ADMISSION, replace(ADMISSION, head="f" * 40)]
                    self.passing_checks.side_effect = [[prior], [prior]]
                    with self.assertRaisesRegex(DataError, "live admission head changed before revocation"):
                        run(args, github, token_input=credential, publisher=publisher)
                    publisher.assert_not_called()
                    github.get_admission_head.side_effect = None
                    self.passing_checks.side_effect = [[prior], [prior], []]
                    result = run(args, github, token_input=credential, publisher=publisher)
                    self.assertEqual(result["checked_sha"], ADMISSION.head)
                    self.assertEqual(result["revoked_check_ids"], [prior["id"]])
                    github.get_pull.assert_not_called()
                    merge_tree.assert_not_called()

                    publisher.reset_mock()
                    args.revoke_only = False
                    args.expected_merge = SNAPSHOT.merge
                    self.passing_checks.side_effect = None
                    with self.assertRaisesRegex(SnapshotError, reason):
                        run(args, github, token_input=credential, publisher=publisher)
                    publisher.assert_not_called()
                    github.get_pull.side_effect = None
                    github.get_pull.return_value = replace(SNAPSHOT, merge="f" * 40)
                    with self.assertRaisesRegex(DataError, "live review target differs from the expected review merge"):
                        run(args, github, token_input=credential, publisher=publisher)
                    publisher.assert_not_called()

                    github.get_pull.reset_mock()
                    github.get_queue_pull.side_effect = [QUEUE_PULL, replace(QUEUE_PULL, base="f" * 40)]
                    self.passing_checks.side_effect = [[prior], [prior]]
                    with self.assertRaisesRegex(DataError, "live test merge changed before revocation"):
                        run(args, github, token_input=credential, publisher=publisher)
                    publisher.assert_not_called()
                    github.get_pull.assert_not_called()
                    diff.assert_not_called()
                    reviewer.assert_not_called()

    def test_rerun_retires_prior_check_before_pending_pull_eligibility(self):
        for admission in (True, False):
            with self.subTest(admission=admission), TemporaryDirectory() as directory:
                state = Path(directory)
                merge = SNAPSHOT.merge if admission else QUEUE["merge"]
                target = SNAPSHOT.head if admission else merge
                prior = api_check({"name": CHECK_NAME, "head_sha": target,
                                   "status": "completed", "conclusion": "neutral"})
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, app_id=123,
                                       reviewer=Reviewer(4001, 4002, state), queue_admission=admission,
                                       queue_run=None if admission else 321, commissioning_policy=ADDITIVE,
                                       expected_head=SNAPSHOT.head if admission else None, expected_merge=merge)
                self.passing_checks.side_effect = [[prior], [prior], []]
                publisher = Mock(return_value={**prior, "conclusion": "failure"})

                def eligible(_number):
                    publisher.assert_called_once()
                    self.assertEqual(publisher.call_args.kwargs["check_id"], prior["id"])
                    self.assertEqual(publisher.call_args.args[1]["conclusion"], "failure")
                    raise SnapshotError("GitHub has not established a mergeable test commit")

                github = Mock(get_admission_head=Mock(return_value=ADMISSION),
                              get_queue_pull=Mock(return_value=QUEUE_PULL), get_pull=Mock(side_effect=eligible))
                with (patch("tools.review_gate.capture_admission_head", return_value="e" * 40),
                      patch("tools.review_gate.capture_candidate_tree", return_value="f" * 40) as tree,
                      patch("tools.review_gate.token_is_target_only", return_value=True),
                      patch("tools.review_gate.require_queue_rules") as rules,
                      patch("tools.review_gate.capture_queue_observation") as ci,
                      patch("tools.review_gate.launch_review") as launch):
                    with self.assertRaisesRegex(SnapshotError, "has not established a mergeable test commit"):
                        run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                self.assertEqual(tree.call_count, 2 if admission else 1)
                options = {"linear_head": True} if admission else {"queue_ref": QUEUE["queue_ref"]}
                self.assertTrue(all(call.args[0] == QUEUE_PULL.bind_merge(merge) and call.kwargs == options
                                    for call in tree.call_args_list))
                github.get_pull.assert_called_once_with(1)
                result, = state.glob("*/revocation-result.json")
                self.assertEqual(json.loads(result.read_bytes())["revoked_check_ids"], [prior["id"]])
                self.assertEqual(list(state.glob("*/issued-check.json")), [])
                rules.assert_not_called()
                ci.assert_not_called()
                launch.assert_not_called()

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

    def test_queue_revocation_uses_exact_live_group_without_the_test_merge(self):
        identity = QueuePull(SNAPSHOT.repository_id, SNAPSHOT.number, SNAPSHOT.base, SNAPSHOT.head)
        prior = api_check({"name": CHECK_NAME, "head_sha": QUEUE["merge"],
                           "status": "completed", "conclusion": "success"})
        for drift in (False, True):
            with self.subTest(drift=drift), TemporaryDirectory() as directory:
                state = Path(directory)
                args = SimpleNamespace(state_dir=state, mode="review", pull=1, app_id=123,
                                       reviewer=Reviewer(4001, 4002, state), queue_run=321,
                                       revoke_only=True, expected_merge=QUEUE["merge"])
                github = Mock(get_queue_pull=Mock(side_effect=[identity, replace(identity, base="f" * 40) if drift else identity]),
                              get_pull=Mock(side_effect=SnapshotError("GitHub has not established a mergeable test commit")))
                self.passing_checks.side_effect = [[prior], [prior], []]
                publisher = Mock(return_value={**prior, "conclusion": "failure"})
                with (patch("tools.review_gate.capture_queue_target", return_value=QUEUE_TARGET) as queue,
                      patch("tools.review_gate.capture_candidate_tree", return_value="e" * 40) as tree,
                      patch("tools.review_gate.capture_queue_observation") as approval_ci,
                      patch("tools.review_gate.token_is_target_only", return_value=True)):
                    if drift:
                        with self.assertRaisesRegex(DataError, "pull request changed after review target capture"):
                            run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                        publisher.assert_not_called()
                    else:
                        result = run(args, github, token_input=lambda: LEGACY_TOKEN, publisher=publisher)
                        self.assertEqual(result["revoked_check_ids"], [prior["id"]])
                        publisher.assert_called_once()
                self.assertEqual(github.get_queue_pull.call_count, 2)
                github.get_pull.assert_not_called()
                self.assertEqual(queue.call_count, 1 if drift else 2)
                self.assertEqual(tree.call_args.args[0], replace(SNAPSHOT, merge=QUEUE["merge"]))
                self.assertEqual(tree.call_args.kwargs, {"queue_ref": QUEUE["queue_ref"]})
                approval_ci.assert_not_called()

    def test_incomplete_review_does_not_read_credential_or_issue(self):
        with TemporaryDirectory() as directory:
            state = Path(directory)
            args = SimpleNamespace(state_dir=state, mode="review", pull=1, model="fixture", codex=Path("fixture"),
                                   app_id=123, reviewer=Reviewer(4001, 4002, state / "reviewer-home"),
                                   queue_admission=True, commissioning_policy=ADDITIVE)
            github = Mock()
            use_queue_rules(github)
            github.get_pull.return_value = SNAPSHOT
            github.get_admission_head.return_value = ADMISSION
            credential = Mock()
            publisher = Mock()
            with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                  patch("tools.review_gate.capture_admission_head", return_value="f" * 40),
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
            github.get_admission_head.return_value = ADMISSION
            credential = Mock()
            publisher = Mock()
            for disposition in ("changes-required", "inconclusive"):
                with self.subTest(disposition=disposition):
                    def fake_launch(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                        token = json.loads((input_dir / "review-input.json").read_bytes())["inspection_token"]
                        return make_trace(token, verdict={"decision": disposition, "findings": ["Fixture finding"]},
                                          inspect=disposition != "inconclusive")

                    with (patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)),
                          patch("tools.review_gate.capture_admission_head", return_value="f" * 40),
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
            catalog = root / "model-catalog.json"
            catalog.write_bytes(b'{"models":[{"slug":"fixture"}]}')
            catalog_digest = sha256(catalog.read_bytes()).hexdigest()

            def fake_run(*_args, **kwargs):
                _args[2].write(b"fixture trace")
                return 0

            with (patch.dict(os.environ, original, clear=True),
                  patch("tools.review_gate.PROTECTED_MODEL_CATALOG", catalog),
                  patch("tools.review_gate.PROTECTED_CATALOG_SHA256", catalog_digest),
                  patch("tools.review_gate.trusted_executable"),
                  patch("tools.review_gate.capture_reviewer_streams", side_effect=fake_run) as process):
                with patch("tools.review_gate.PROTECTED_CATALOG_SHA256", "0" * 64):
                    with self.assertRaisesRegex(DataError, "catalog differs from the protected issuer pin"):
                        launch_review(root / "codex", "fixture", root / "inputs", root / "schema.json", root,
                                      reviewer=reviewer)
                with self.assertRaisesRegex(DataError, "reviewer model differs from the pinned catalog"):
                    launch_review(root / "codex", "other-model", root / "inputs", root / "schema.json", root,
                                  reviewer=reviewer)
                process.assert_not_called()
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
            for feature in {"apps", "plugins", "remote_plugin", "computer_use", "browser_use",
                            "browser_use_external", "in_app_browser", "image_generation", "view_image",
                            "multi_agent", "multi_agent_v2", "goals"}:
                self.assertIn(("--disable", feature), zip(invocation.args[0], invocation.args[0][1:]))
            self.assertIn("tools.experimental_request_user_input.enabled=false", invocation.args[0])
            self.assertIn(f"model_catalog_json={json.dumps(str(catalog))}", invocation.args[0])
            self.assertIn('default_permissions="review-inputs"', invocation.args[0])
            profile, = [arg for arg in invocation.args[0] if arg.startswith("permissions.review-inputs=")]
            permissions = tomllib.loads(profile)["permissions"]["review-inputs"]
            self.assertEqual(permissions, {
                "network": {"enabled": False},
                "filesystem": {":minimal": "read", str(root / "inputs"): "read", str(root / "codex"): "read"},
            })

    def test_reviewer_output_caps_both_streams_while_the_process_is_running(self):
        command = lambda stream: [sys.executable, "-c", "import sys,time; "
                                  f"sys.{stream}.buffer.write(b'x' * 65536); sys.{stream}.flush(); time.sleep(30)"]
        with (TemporaryDirectory() as directory, patch("tools.review_gate.MAX_TRACE_BYTES", 2048),
              patch("tools.review_gate.MAX_REVIEW_STDERR_BYTES", 1024), patch("tools.review_gate.REVIEW_TIMEOUT", 5)):
            for stream, message, maximum in (("stdout", "trace", 2048), ("stderr", "stderr", 1024)):
                output, errors = BytesIO(), BytesIO()
                with self.subTest(stream=stream), self.assertRaisesRegex(DataError, f"{message} exceeds .* capture limit"):
                    capture_reviewer_streams(command(stream), b"prompt", output, errors, cwd=directory, env=os.environ)
                limited, other = (output, errors) if stream == "stdout" else (errors, output)
                self.assertEqual(len(limited.getvalue()), maximum)
                other_limit = 1024 if stream == "stdout" else 2048
                self.assertLessEqual(len(other.getvalue()), other_limit)

    def test_reviewer_output_keeps_complete_streams_and_preserves_timeout(self):
        with TemporaryDirectory() as directory:
            command = [sys.executable, "-c", "import sys; "
                       "sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.buffer.write(b'notice')"]
            output, errors = BytesIO(), BytesIO()
            self.assertEqual(capture_reviewer_streams(command, b"exact prompt", output, errors,
                                                      cwd=directory, env=os.environ), 0)
            self.assertEqual(output.getvalue(), b"exact prompt")
            self.assertEqual(errors.getvalue(), b"notice")
            with patch("tools.review_gate.REVIEW_TIMEOUT", 0.2), self.assertRaises(subprocess.TimeoutExpired):
                capture_reviewer_streams([sys.executable, "-c", "import time; time.sleep(30)"], b"", BytesIO(),
                                         BytesIO(), cwd=directory, env=os.environ)

    def test_protected_rehearsal_records_a_review_without_reading_a_token_or_writing_a_check(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            reviewer = Reviewer(4001, 4002, root / "reviewer-home")
            config = root / "rehearsal.json"
            github = Mock()
            github.get_pull.return_value = SNAPSHOT
            github.get_admission_head.return_value = ADMISSION
            stdout = BytesIO()
            stdin = Mock()
            policy_files = {"policy-00001.data": b"fixture protected policy"}
            policy_sources = {"policy-00001.data": {"path": "policy.md"}}
            policy_manifest = json.dumps({"files": policy_sources}).encode()
            policy_digest = sha256(policy_manifest).hexdigest()

            def fake_launch(_codex, _model, input_dir, _schema, _audit, *, reviewer):
                self.assertEqual(reviewer.uid, 4001)
                self.assertEqual((input_dir / "review.diff").read_bytes(), PATCH)
                review_input = json.loads((input_dir / "review-input.json").read_bytes())
                token = review_input["inspection_token"]
                self.assertEqual(review_input["review_policy"], policy_sources)
                self.assertEqual(review_input["review_policy_sha256"], policy_digest)
                raw = (input_dir / "policy-00001.data").read_bytes()
                self.assertEqual(raw, policy_files["policy-00001.data"])
                line = f"policy-00001.data {sha256(token.encode() + raw).hexdigest()}\n"
                proof = f"policy-proof 0 {sha256(line.encode()).hexdigest()}"
                events = make_trace(token, verdict={"review_policy_sha256": policy_digest}).splitlines()
                events.insert(-2, json.dumps({"type": "item.completed", "item": {
                    "type": "command_execution", "status": "completed", "exit_code": 0,
                    "command": "read policy listed in review-input.json", "aggregated_output": proof,
                }}).encode())
                return b"\n".join(events) + b"\n"

            with (patch("tools.review_gate.load_issuer",
                        return_value=(root, root / "codex", "fixture", None, reviewer, None, None, None)) as load,
                  patch("tools.review_gate.GitHub", return_value=github),
                  patch("tools.review_gate.capture_diff", return_value=("e" * 40, PATCH)) as capture,
                  patch("tools.review_gate.load_review_policy",
                        return_value=(policy_manifest, policy_sources, policy_files)),
                  patch("tools.review_gate.protected_staging", return_value=root),
                  patch("tools.review_gate.share_reviewer_inputs") as share,
                  patch("tools.review_gate.launch_review", side_effect=fake_launch) as launch,
                  patch("tools.review_gate.create_check") as issuer,
                  patch("tools.review_gate.sys.stdout", SimpleNamespace(buffer=stdout)),
                  patch("tools.review_gate.sys.stdin", stdin)):
                self.assertEqual(main(["review", "1", "--rehearsal-config", str(config), "--queue-admission"]), 0)

            load.assert_called_once_with(config, rehearsal=True, revocation=False)
            self.assertTrue(capture.call_args.kwargs["linear_head"])
            self.assertEqual(share.call_args.args[1], reviewer.gid)
            self.assertEqual(launch.call_args.kwargs["reviewer"], reviewer)
            self.assertEqual(len(github.method_calls), 2)
            self.assertTrue(all(method[0] == "get_pull" for method in github.method_calls))
            stdin.readline.assert_not_called()
            issuer.assert_not_called()
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "protected-rehearsal")
            self.assertEqual(result["binding"]["review_policy_sha256"], policy_digest)
            self.assertEqual((Path(result["audit"]) / "review-policy-manifest.json").read_bytes(), policy_manifest)
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
                self.assertEqual(load_issuer(config, revocation=True),
                                 (root, codex, "fixture", 123, reviewer, None, None, None))
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
