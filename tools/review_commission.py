"""Read-only comparison of GitHub review-gate commissioning observations."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import os
import re
import subprocess
import sys

from .records import encode
from .review_gate import APP_TOKEN, CHECK_NAME
from .review_snapshot import BASE_REF, REPOSITORY, REPOSITORY_ID, GitHub, SnapshotError

ORGANIZATION = REPOSITORY.split("/", 1)[0]
ACTIONS_APP_ID = 15368
CI_CONTEXTS = ("Evidence / SCES validation", "Registry validation")
APP_PERMISSIONS = {"checks": "write", "statuses": "write", "metadata": "read"}
LATEST_CHECKS = "/check-runs?filter=latest&per_page=100"
MAX_AGE = timedelta(days=7)
DECISION_SHA = re.compile(r"[0-9a-f]{64}")
APP_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class OwnerGitHub(GitHub):
    """Use the host's existing GitHub CLI identity for GET requests only."""

    def _get_json(self, path):
        command = [
            "gh", "api", "--hostname", "github.com", "--method", "GET",
            "-H", "Cache-Control: no-cache", path.lstrip("/"),
        ]
        try:
            response = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={**os.environ, "GH_PROMPT_DISABLED": "1"}, timeout=30, check=False,
            )
            if response.returncode == 0:
                return json.loads(response.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        raise SnapshotError(f"GitHub CLI could not supply owner-readable commissioning data for {path}")


def complete_rows(response, key):
    """An incomplete listing cannot establish a negative finding."""
    if not isinstance(response, dict):
        raise SnapshotError(f"GitHub returned malformed {key}")
    rows = response.get(key)
    if not isinstance(rows, list) or type(response.get("total_count")) is not int:
        raise SnapshotError(f"GitHub returned malformed {key}")
    if len(rows) != response["total_count"]:
        raise SnapshotError(f"GitHub returned only part of the {key} listing")
    return rows


def read_protection(github, sources):
    repo_path = f"/repos/{REPOSITORY}"
    rules = github._get_json(f"{repo_path}/rules/branches/{BASE_REF}?per_page=100")
    if not isinstance(rules, list) or len(rules) >= 100:
        raise SnapshotError("The applied branch rules could not be read completely")
    identifiers = {rule.get("ruleset_id") for rule in rules}
    if any(type(value) is not int or value <= 0 for value in identifiers):
        raise SnapshotError("An applied branch rule lacks a ruleset ID")
    sets = {value: github._get_json(f"{repo_path}/rulesets/{value}") for value in sorted(identifiers)}

    seal = all(
        isinstance(item, dict) and item.get("id") == key and item.get("enforcement") == "active"
        and item.get("target") == "branch" and item.get("bypass_actors") == []
        for key, item in sets.items()
    ) and bool(sets)
    types = {rule.get("type") for rule in rules}
    approvals = [
        rule.get("parameters") or {} for rule in rules if rule.get("type") == "pull_request"
    ]
    count_required = any(
        type(policy.get("required_approving_review_count")) is int and policy["required_approving_review_count"] >= 1
        for policy in approvals
    )
    configured_sources = {}
    for name, integration in sources.items():
        matches = [
            (check.get("integration_id"), policy.get("strict_required_status_checks_policy"),
             policy.get("do_not_enforce_on_create"))
            for rule in rules
            if rule.get("type") == "required_status_checks"
            for policy in [rule.get("parameters") or {}]
            for check in (policy.get("required_status_checks") or [])
            if check.get("context") == name
        ]
        configured_sources[name] = {
            "expected_app_id": integration,
            "observed_app_ids": [match[0] for match in matches],
            "strict_source_bound": bool(matches) and integration is not None and all(
                app == integration and strict is True and waive is False for app, strict, waive in matches
            ),
        }
    return {
        "ruleset_ids": sorted(identifiers),
        "active_rulesets_explicitly_without_bypass": seal,
        "pull_request_required": "pull_request" in types,
        "deletion_blocked": "deletion" in types,
        "force_push_blocked": "non_fast_forward" in types,
        "human_approval_configured": count_required,
        "code_owner_review_configured": any(policy.get("require_code_owner_review") is True for policy in approvals),
        "contexts": configured_sources,
    }


def read_installation(github, scope_github, app_id, owner_session):
    permissions = APP_PERMISSIONS.copy()
    result = {
        "requested_app_id": app_id,
        "expected_repository_permissions": permissions,
        "organization_installation_count": None,
        "installation_id": None,
        "configuration_matches": False,
        "app_visibility": "not-observed",
        "token_scope": "not-observed",
        "token_scope_proves_app_identity": False,
        "full_installation_repository_selection_proven": False,
        "problems": [],
    }
    problems = result["problems"]
    if not owner_session:
        problems.append("Owner-readable organization installation data is required")
        return result
    installations = complete_rows(github._get_json(f"/orgs/{ORGANIZATION}/installations?per_page=100"), "installations")
    result["organization_installation_count"] = len(installations)
    if app_id is None:
        problems.append("The expected Codex review App ID has not been configured")
        return result
    candidates = [install for install in installations if install.get("app_id") == app_id]
    if len(candidates) != 1:
        problems.append("Exactly one installation of the expected App must exist in the organization")
        return result
    install, = candidates
    result["installation_id"] = install.get("id")
    if ((install.get("account") or {}).get("login") != ORGANIZATION or install.get("target_type") != "Organization"
            or type(install.get("id")) is not int or install["id"] < 1):
        problems.append("The installation target is not the Software Commons organization")
    if install.get("repository_selection") != "selected":
        problems.append("The App installation must use selected repositories")
    if "suspended_at" not in install or install["suspended_at"] is not None:
        problems.append("The App installation is suspended or its active state is unavailable")
    if install.get("permissions") != permissions:
        problems.append("The installation permissions differ from the approved minimal permissions")
    slug = install.get("app_slug")
    if not isinstance(slug, str) or not APP_SLUG.fullmatch(slug):
        problems.append("GitHub supplied no verifiable App slug")
    else:
        app = github._get_json(f"/apps/{slug}")
        if (not isinstance(app, dict) or app.get("id") != app_id
                or (app.get("owner") or {}).get("login") != ORGANIZATION):
            problems.append("GitHub did not confirm ownership of the App by Software Commons")
        else:
            visibility = app.get("public")
            result["app_visibility"] = {True: "public", False: "private"}.get(visibility, "unreported")
            if visibility is True:
                problems.append("The expected App is configured as public")
    result["configuration_matches"] = not problems
    if scope_github is None:
        problems.append("The installation token's repository scope has not been observed")
    else:
        repositories = complete_rows(scope_github._get_json("/installation/repositories?per_page=100"), "repositories")
        observed = [(repo.get("id"), repo.get("full_name")) for repo in repositories]
        if observed == [(REPOSITORY_ID, REPOSITORY)]:
            result["token_scope"] = "target-only"
        else:
            result["token_scope"] = "mismatch"
            problems.append("The installation token did not list only License Index")
    return result


def completed_at(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def observe_check(rows, classic, commit, name, app_id, now, *, decision=None, decision_required=False):
    checks = [check for check in rows if check.get("name") == name]
    matching = [check for check in checks if check.get("head_sha") == commit
                and app_id is not None and (check.get("app") or {}).get("id") == app_id]
    observation = {
        "classification": "missing",
        "check_run_ids": [check.get("id") for check in checks],
        "other_source_runs_present": bool(len(checks) > len(matching)),
        "classic_status_present": any(str(item.get("context", "")).casefold() == name.casefold() for item in classic),
    }
    if not matching:
        if checks:
            observation["classification"] = "wrong-source-or-commit"
        return observation
    if len(matching) != 1:
        observation["classification"] = "ambiguous"
        return observation
    check, = matching
    stamp = completed_at(check.get("completed_at"))
    if check.get("status") != "completed":
        classification = "pending"
    elif check.get("conclusion") != "success":
        classification = "not-successful"
    elif stamp is None or stamp > now or now - stamp > MAX_AGE:
        classification = "stale-or-invalid-time"
    elif decision_required and decision is None:
        classification = "decision-digest-unchecked"
    elif decision is not None and check.get("external_id") != decision:
        classification = "wrong-decision"
    elif observation["classic_status_present"]:
        classification = "matching-check-with-classic-status"
    else:
        classification = "matching-success"
    observation.update(classification=classification, completed_at=check.get("completed_at"), id=check.get("id"))
    return observation


def read_checks(github, snapshot, sources, now, decision):
    results = {}
    for name, commit in (("head", snapshot.head), ("test_merge", snapshot.merge)):
        path = f"/repos/{REPOSITORY}/commits/{commit}"
        runs = complete_rows(github._get_json(path + LATEST_CHECKS), "check_runs")
        statuses = complete_rows(github._get_json(path + "/status?per_page=100"), "statuses")
        results[name] = {
            "commit": commit,
            "contexts": {
                context: observe_check(
                    runs, statuses, commit, context, app, now,
                    decision=decision if context == CHECK_NAME else None, decision_required=context == CHECK_NAME,
                )
                for context, app in sources.items()
            },
        }
    return results


def preflight(github, *, pull, app_id=None, decision=None, owner_session=False, scope_github=None, now=None):
    if app_id is not None and (type(app_id) is not int or app_id <= 0 or app_id == ACTIONS_APP_ID):
        raise SnapshotError("Supply the numeric ID of a dedicated App, separate from GitHub Actions")
    if decision is not None and not DECISION_SHA.fullmatch(decision):
        raise SnapshotError("Supply the lowercase SHA-256 of the protected review decision")
    now = now or datetime.now(timezone.utc)
    snapshot = github.get_pull(pull)
    sources = {**dict.fromkeys(CI_CONTEXTS, ACTIONS_APP_ID), CHECK_NAME: app_id}
    controls = read_protection(github, sources)
    install = read_installation(github, scope_github, app_id, owner_session)
    checks = read_checks(github, snapshot, sources, now, decision)
    if github.get_pull(pull) != snapshot:
        raise SnapshotError("The GitHub review target changed during commissioning")

    findings = [
        *[f"Branch control unconfirmed: {name}" for name, confirmed in controls.items()
          if type(confirmed) is bool and not confirmed],
        *[f"Exact strict ruleset binding unconfirmed: {name}" for name, context in controls["contexts"].items()
          if not context["strict_source_bound"]],
        *install["problems"],
    ]
    for context in CI_CONTEXTS:
        merged = checks["test_merge"]["contexts"][context]
        observed = merged if merged["check_run_ids"] or merged["classic_status_present"] else checks["head"]["contexts"][context]
        if observed["classification"] != "matching-success":
            findings.append(f"Expected CI result unconfirmed: {context} ({observed['classification']})")
    review = checks["test_merge"]["contexts"][CHECK_NAME]["classification"]
    if review != "matching-success":
        findings.append(f"Exact review check on test merge: {review}")
    head_review = checks["head"]["contexts"][CHECK_NAME]
    if head_review["check_run_ids"] or head_review["classic_status_present"]:
        findings.append("A review check or same-name status exists on the raw PR head")
    return {
        "repository": REPOSITORY,
        "base_ref": BASE_REF,
        "observed_at": now.isoformat(),
        "snapshot": asdict(snapshot),
        "status": "blocked" if findings else "matching-observations",
        "live_branch_enforcement_proven": False,
        "approval_cutover_authorized": False,
        "owner_verifications_remaining": [
            "Confirm private App visibility in GitHub settings if the API did not report it",
            "Confirm the full installation repository selection in GitHub settings",
            "Verify live branch enforcement on positive and negative cases before replacing any protection",
        ],
        "protection": controls,
        "app_installation": install,
        "checks": checks,
        "findings": findings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull", type=int, default=1)
    parser.add_argument("--app-id", type=int, help="Expected dedicated GitHub App ID")
    parser.add_argument("--decision-sha256", help="SHA-256 of the protected review decision")
    parser.add_argument("--gh-owner", action="store_true", help="Use the existing organization owner GitHub CLI session")
    parser.add_argument("--installation-token-stdin", action="store_true",
                        help="Read a short-lived installation token over standard input for repository-scope inspection")
    args = parser.parse_args(argv)
    try:
        scope = None
        if args.installation_token_stdin:
            if args.app_id is None or not args.gh_owner:
                parser.error("installation token inspection also requires --app-id and --gh-owner")
            token = sys.stdin.readline(4096).strip()
            if not APP_TOKEN.fullmatch(token):
                raise SnapshotError("Expected a GitHub App installation token")
            scope = GitHub(bearer=token)
        result = preflight(OwnerGitHub() if args.gh_owner else GitHub(), pull=args.pull, app_id=args.app_id,
                           decision=args.decision_sha256, owner_session=args.gh_owner, scope_github=scope)
        sys.stdout.buffer.write(encode(result))
        return 0 if result["status"] == "matching-observations" else 1
    except (OSError, SnapshotError, TypeError, ValueError, KeyError, AttributeError) as error:
        parser.exit(1, f"review commissioning: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
