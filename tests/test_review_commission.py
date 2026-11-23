"""Synthetic observations for the read-only commissioning check."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from tools.review_commission import (
    ACTIONS_APP_ID, APP_PERMISSIONS, CHECK_NAME, CI_CONTEXTS, LATEST_CHECKS,
    OwnerGitHub, observe_check, preflight,
)
from tools.review_snapshot import BASE_REF, REPOSITORY, REPOSITORY_ID, PullSnapshot, SnapshotError

APP_ID = 8421
RULESET = 14
NOW = datetime(2026, 11, 23, tzinfo=timezone.utc)
DECISION = "0" * 64
SNAPSHOT = PullSnapshot(REPOSITORY_ID, 1, "a" * 40, "b" * 40, "c" * 40)
REPO_PATH = f"/repos/{REPOSITORY}"
BRANCH_RULES = f"{REPO_PATH}/rules/branches/{BASE_REF}?per_page=100"
RULESET_PATH = f"{REPO_PATH}/rulesets/{RULESET}"
INSTALLATIONS = "/orgs/software-commons/installations?per_page=100"
TOKEN_SCOPE = "/installation/repositories?per_page=100"
CHECKS_HEAD = f"{REPO_PATH}/commits/{SNAPSHOT.head}{LATEST_CHECKS}"
CHECKS_MERGE = f"{REPO_PATH}/commits/{SNAPSHOT.merge}{LATEST_CHECKS}"
STATUS_HEAD = f"{REPO_PATH}/commits/{SNAPSHOT.head}/status?per_page=100"
STATUS_MERGE = f"{REPO_PATH}/commits/{SNAPSHOT.merge}/status?per_page=100"


def rows(key, items):
    return {key: items, "total_count": len(items)}


def rule(rule_type, parameters=None):
    return {"type": rule_type, "ruleset_id": RULESET, "parameters": parameters}


def run(name, app, commit, **changes):
    return {
        "name": name, "app": {"id": app}, "head_sha": commit, "id": 432,
        "completed_at": (NOW - timedelta(minutes=5)).isoformat(),
        "status": "completed", "conclusion": "success", "external_id": DECISION,
        **changes,
    }


def responses():
    return {
        BRANCH_RULES: [
            rule("deletion"), rule("non_fast_forward"),
            rule("pull_request", {"required_approving_review_count": 1, "require_code_owner_review": True}),
            rule("required_status_checks", {
                "strict_required_status_checks_policy": True, "do_not_enforce_on_create": False,
                "required_status_checks": [
                    *[{"context": name, "integration_id": ACTIONS_APP_ID} for name in CI_CONTEXTS],
                    {"context": CHECK_NAME, "integration_id": APP_ID},
                ],
            }),
        ],
        RULESET_PATH: {"id": RULESET, "target": "branch", "bypass_actors": [], "enforcement": "active"},
        INSTALLATIONS: rows("installations", [{
            "id": 781, "app_id": APP_ID, "app_slug": "codex-review-check",
            "target_type": "Organization", "account": {"login": "software-commons"},
            "repository_selection": "selected", "permissions": APP_PERMISSIONS.copy(), "suspended_at": None,
        }]),
        "/apps/codex-review-check": {"id": APP_ID, "owner": {"login": "software-commons"}, "public": False},
        CHECKS_HEAD: rows("check_runs", [run(name, ACTIONS_APP_ID, SNAPSHOT.head) for name in CI_CONTEXTS]),
        CHECKS_MERGE: rows("check_runs", [run(CHECK_NAME, APP_ID, SNAPSHOT.merge),
                                        *[run(name, ACTIONS_APP_ID, SNAPSHOT.merge) for name in CI_CONTEXTS]]),
        STATUS_HEAD: rows("statuses", []),
        STATUS_MERGE: rows("statuses", []),
        TOKEN_SCOPE: rows("repositories", [{"id": REPOSITORY_ID, "full_name": REPOSITORY}]),
    }


class FixtureGitHub:
    def __init__(self, values, after=SNAPSHOT):
        self.values = values
        self.snapshots = iter((SNAPSHOT, after))

    def _get_json(self, path):
        return deepcopy(self.values[path])

    def get_pull(self, number):
        if number != 1:
            raise AssertionError("Fixture expected PR #1")
        return next(self.snapshots)


class CommissionTests(unittest.TestCase):
    def inspect(self, values=None, *, after=SNAPSHOT, **options):
        github = FixtureGitHub(values if values is not None else responses(), after)
        options = {"app_id": APP_ID, "decision": DECISION, "owner_session": True,
                   "scope_github": github, "now": NOW, **options}
        return preflight(github, pull=1, **options)

    def test_match_reports_observations_only_and_distinguishes_head_and_merge(self):
        result = self.inspect()
        self.assertEqual(result["status"], "matching-observations")
        self.assertFalse(result["live_branch_enforcement_proven"])
        self.assertFalse(result["approval_cutover_authorized"])
        self.assertFalse(result["app_installation"]["full_installation_repository_selection_proven"])
        self.assertEqual(result["app_installation"]["token_scope"], "target-only")
        self.assertEqual(result["checks"]["head"]["contexts"][CHECK_NAME]["classification"], "missing")
        self.assertEqual(result["checks"]["test_merge"]["contexts"][CHECK_NAME]["classification"], "matching-success")
        self.assertEqual(result["checks"]["head"]["contexts"][CI_CONTEXTS[0]]["classification"], "matching-success")

    def test_no_unprovisioned_or_misconfigured_installation_counts_as_verified(self):
        empty = responses()
        empty[INSTALLATIONS] = rows("installations", [])
        result = self.inspect(empty)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["app_installation"]["organization_installation_count"], 0)
        self.assertIsNone(result["app_installation"]["installation_id"])
        for update in ({"repository_selection": "all"}, {"suspended_at": NOW.isoformat()},
                       {"permissions": {**APP_PERMISSIONS, "administration": "write"}},
                       {"account": {"login": "another-org"}}):
            with self.subTest(update=update):
                values = responses()
                values[INSTALLATIONS]["installations"][0].update(update)
                self.assertFalse(self.inspect(values)["app_installation"]["configuration_matches"])
        result = self.inspect(owner_session=False)
        self.assertIsNone(result["app_installation"]["organization_installation_count"])
        self.assertEqual(self.inspect(scope_github=None)["status"], "blocked")

    def test_app_ownership_visibility_and_token_scope(self):
        values = responses()
        values["/apps/codex-review-check"]["owner"]["login"] = "another-org"
        self.assertEqual(self.inspect(values)["status"], "blocked")
        values = responses()
        values["/apps/codex-review-check"]["public"] = True
        self.assertEqual(self.inspect(values)["status"], "blocked")
        del values["/apps/codex-review-check"]["public"]
        self.assertEqual(self.inspect(values)["app_installation"]["app_visibility"], "unreported")
        values[TOKEN_SCOPE] = rows("repositories", [{"id": 77, "full_name": "software-commons/other"}])
        result = self.inspect(values)
        self.assertEqual(result["app_installation"]["token_scope"], "mismatch")
        self.assertEqual(result["status"], "blocked")

    def test_active_human_and_protection_rules_must_remain(self):
        for details in ({}, {"bypass_actors": [{"actor_id": APP_ID}]}, {"enforcement": "evaluate"}):
            with self.subTest(details=details):
                values = responses()
                if details:
                    values[RULESET_PATH].update(details)
                else:
                    del values[RULESET_PATH]["bypass_actors"]
                result = self.inspect(values)
                self.assertFalse(result["protection"]["active_rulesets_explicitly_without_bypass"])
                self.assertTrue(result["protection"]["human_approval_configured"])
                self.assertEqual(result["status"], "blocked")
        values = responses()
        values[BRANCH_RULES][2]["parameters"].update(required_approving_review_count=0, require_code_owner_review=False)
        missing = self.inspect(values)["protection"]
        self.assertFalse(missing["human_approval_configured"])
        self.assertFalse(missing["code_owner_review_configured"])

    def test_ruleset_context_requires_exact_app_and_strict_enforcement(self):
        for update in ({"integration_id": ACTIONS_APP_ID}, {"integration_id": None}):
            with self.subTest(update=update):
                values = responses()
                values[BRANCH_RULES][-1]["parameters"]["required_status_checks"][-1].update(update)
                self.assertFalse(self.inspect(values)["protection"]["contexts"][CHECK_NAME]["strict_source_bound"])
        values = responses()
        values[BRANCH_RULES][-1]["parameters"].update(strict_required_status_checks_policy=False)
        self.assertFalse(self.inspect(values)["protection"]["contexts"][CHECK_NAME]["strict_source_bound"])
        with self.assertRaisesRegex(SnapshotError, "separate from GitHub Actions"):
            self.inspect(app_id=ACTIONS_APP_ID)

    def test_review_checks_report_wrong_source_stale_digest_or_head_fallback(self):
        for status, replacements in (
            ("wrong-source-or-commit", {"app": {"id": ACTIONS_APP_ID}}),
            ("wrong-source-or-commit", {"head_sha": SNAPSHOT.head}),
            ("stale-or-invalid-time", {"completed_at": (NOW - timedelta(days=8)).isoformat()}),
            ("stale-or-invalid-time", {"completed_at": "undefined"}),
            ("not-successful", {"conclusion": "failure"}),
            ("pending", {"status": "in_progress"}),
            ("wrong-decision", {"external_id": "6" * 64}),
        ):
            with self.subTest(status=status, replacements=replacements):
                values = responses()
                values[CHECKS_MERGE]["check_runs"][0].update(replacements)
                self.assertEqual(self.inspect(values)["checks"]["test_merge"]["contexts"][CHECK_NAME]["classification"],
                                 status)
        unchecked = self.inspect(decision=None)
        self.assertEqual(unchecked["checks"]["test_merge"]["contexts"][CHECK_NAME]["classification"],
                         "decision-digest-unchecked")
        values = responses()
        values[STATUS_HEAD] = rows("statuses", [{"context": CHECK_NAME.lower()}])
        self.assertEqual(self.inspect(values)["status"], "blocked")
        values = responses()
        values[CHECKS_HEAD]["check_runs"].append(run(CHECK_NAME, APP_ID, SNAPSHOT.head))
        values[CHECKS_HEAD]["total_count"] += 1
        values[CHECKS_MERGE] = rows("check_runs", [])
        result = self.inspect(values)
        self.assertEqual(result["checks"]["test_merge"]["contexts"][CHECK_NAME]["classification"], "missing")
        self.assertEqual(result["status"], "blocked")

    def test_ambiguous_results_and_classic_status_remain_visible(self):
        checks = [run(CHECK_NAME, APP_ID, SNAPSHOT.merge), run(CHECK_NAME, APP_ID, SNAPSHOT.merge, id=781)]
        self.assertEqual(observe_check(checks, [], SNAPSHOT.merge, CHECK_NAME, APP_ID, NOW)["classification"],
                         "ambiguous")
        self.assertEqual(
            observe_check(checks[:1], [{"context": CHECK_NAME}], SNAPSHOT.merge, CHECK_NAME, APP_ID, NOW)["classification"],
            "matching-check-with-classic-status",
        )

    def test_head_success_does_not_mask_a_failing_test_merge_ci_run(self):
        values = responses()
        values[CHECKS_MERGE]["check_runs"][1]["conclusion"] = "failure"
        result = self.inspect(values)
        self.assertEqual(result["checks"]["head"]["contexts"][CI_CONTEXTS[0]]["classification"], "matching-success")
        self.assertEqual(result["status"], "blocked")
        self.assertIn(f"Expected CI result unconfirmed on test merge: {CI_CONTEXTS[0]} "
                      "(not-successful; head: matching-success)", result["findings"])

    def test_split_commit_checks_do_not_pass_commissioning(self):
        values = responses()
        values[CHECKS_MERGE] = rows("check_runs", [run(CHECK_NAME, APP_ID, SNAPSHOT.merge)])
        result = self.inspect(values)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["checks"]["test_merge"]["contexts"][CHECK_NAME]["classification"], "matching-success")
        self.assertIn(f"Expected CI result unconfirmed on test merge: {CI_CONTEXTS[0]} "
                      "(missing; head: matching-success)", result["findings"])

    def test_partial_data_and_snapshot_changes_fail(self):
        values = responses()
        values[CHECKS_MERGE]["total_count"] = 1000
        with self.assertRaisesRegex(SnapshotError, "only part of the check_runs"):
            self.inspect(values)
        changed = PullSnapshot(REPOSITORY_ID, 1, "d" * 40, SNAPSHOT.head, "e" * 40)
        with self.assertRaisesRegex(SnapshotError, "changed during commissioning"):
            self.inspect(after=changed)

    def test_owner_cli_selects_read_only_requests_without_interactive_input(self):
        with patch("tools.review_commission.subprocess.run") as process:
            process.return_value.returncode = 0
            process.return_value.stdout = b"{}"
            self.assertEqual(OwnerGitHub()._get_json(BRANCH_RULES), {})
            command, = process.call_args.args
            self.assertEqual(command[command.index("--method") + 1], "GET")
            self.assertEqual(command[command.index("--hostname") + 1], "github.com")
            self.assertEqual(process.call_args.kwargs["env"]["GH_PROMPT_DISABLED"], "1")


if __name__ == "__main__":
    unittest.main()
