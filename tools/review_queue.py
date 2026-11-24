"""Read and correlate GitHub Actions evidence for an exact live merge-group commit."""

from __future__ import annotations

import re
from urllib.parse import urlencode

from .review_snapshot import BASE_REF, REPOSITORY, PullSnapshot, QueuePull, SnapshotError


_REPO_PATH = f"/repos/{REPOSITORY}"
_QUEUE_BRANCH = re.compile(rf"gh-readonly-queue/{re.escape(BASE_REF)}/pr-([1-9][0-9]*)-[0-9a-f]{{40}}")
_CHECK_RUN_URL = re.compile(rf"https://api\.github\.com{re.escape(_REPO_PATH)}/check-runs/([1-9][0-9]*)")
_WORKFLOWS = {
    ".github/workflows/domain.yml": (
        "Domain", ("Registry validation", "Tests on macos-15", "Tests on ubuntu-24.04", "Tests on windows-2025"),
    ),
    ".github/workflows/sces-ci.yml": ("SCES", ("Evidence / SCES validation",)),
}


def _require(ok, message):
    if not ok:
        raise SnapshotError(message)


def _positive_id(value):
    return type(value) is int and value > 0


def _successful(row):
    return row.get("status") == "completed" and row.get("conclusion") == "success"


def _rows(response, key):
    _require(isinstance(response, dict), f"GitHub returned malformed {key}")
    rows = response.get(key)
    total = response.get("total_count")
    _require(isinstance(rows, list) and type(total) is int and total == len(rows) <= 100,
             f"GitHub returned an incomplete or malformed {key} listing")
    _require(all(isinstance(row, dict) and _positive_id(row.get("id")) for row in rows),
             f"GitHub returned malformed {key} identifiers")
    _require(len({row["id"] for row in rows}) == len(rows), f"GitHub returned duplicate {key} identifiers")
    return rows


def _required_workflow(row):
    path = row.get("path")
    _require(isinstance(path, str), "GitHub returned an invalid workflow path")
    return path.split("@", 1)[0]


def _verify_run(row, path, snapshot, branch, merge):
    name, _ = _WORKFLOWS[path]
    _require(row.get("path") in (path, f"{path}@{branch}", f"{path}@refs/heads/{branch}")
             and row.get("name") == name and row.get("event") == "merge_group"
             and row.get("head_branch") == branch and row.get("head_sha") == merge,
             "GitHub workflow does not bind the exact merge-group event, ref, commit and path")
    for key in ("repository", "head_repository"):
        repository = row.get(key)
        _require(isinstance(repository, dict) and repository.get("id") == snapshot.repository_id
                 and repository.get("full_name") == REPOSITORY,
                 "GitHub workflow does not originate from the configured queue repository")
    evidence = {key: row.get(key) for key in ("id", "workflow_id", "run_number", "run_attempt", "check_suite_id")}
    _require(all(_positive_id(value) for value in evidence.values()), "GitHub returned invalid workflow evidence IDs")
    return evidence


def _selected_runs(github, listing_path, snapshot, branch, merge):
    candidates = {path: {} for path in _WORKFLOWS}
    for row in _rows(github._get_json(listing_path), "workflow_runs"):
        path = _required_workflow(row)
        if path in candidates:
            binding = _verify_run(row, path, snapshot, branch, merge)
            number = binding["run_number"]
            _require(number not in candidates[path], f"GitHub returned ambiguous {path} runs")
            candidates[path][number] = (binding, _successful(row))

    selected = {}
    for path, runs in candidates.items():
        _require(bool(runs), f"GitHub has no {path} run for the exact merge group")
        _require(len({binding["workflow_id"] for binding, _ in runs.values()}) == 1,
                 f"GitHub returned ambiguous workflow IDs at {path}")
        binding, success = runs[max(runs)]
        _require(success, f"The latest GitHub {path} run did not complete successfully")
        selected[path] = binding
    _require(len({binding["check_suite_id"] for binding in selected.values()}) == len(selected),
             "GitHub returned ambiguous check suites for the merge-group workflows")
    return selected


def _verify_ref(github, branch, merge):
    item = github._get_json(f"{_REPO_PATH}/git/ref/heads/{branch}")
    _require(isinstance(item, dict) and item.get("ref") == f"refs/heads/{branch}",
             "GitHub did not return the exact live merge-queue ref")
    target = item.get("object")
    _require(isinstance(target, dict) and target.get("type") == "commit" and target.get("sha") == merge,
             "GitHub merge-queue ref no longer names the observed commit")


def _jobs(github, path, run, branch, merge, selected_checks, actions_app_id):
    name, expected = _WORKFLOWS[path]
    run_id, attempt = run["id"], run["run_attempt"]
    listing = f"{_REPO_PATH}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
    jobs = _rows(github._get_json(listing), "jobs")
    _require(len(jobs) == len(expected) and all(job.get("name") in expected for job in jobs)
             and len({job["name"] for job in jobs}) == len(expected),
             f"GitHub {path} has missing, unexpected or duplicate jobs for the exact attempt")

    evidence = {}
    for job in jobs:
        _require(job.get("run_id") == run_id and job.get("run_attempt") == attempt
                 and job.get("workflow_name") == name and job.get("head_sha") == merge
                 and job.get("head_branch") == branch and _successful(job),
                 f"GitHub {path} job did not succeed on the exact workflow attempt and merge group")
        check_url = job.get("check_run_url")
        link = _CHECK_RUN_URL.fullmatch(check_url) if isinstance(check_url, str) else None
        _require(link is not None, f"GitHub {path} job has no exact repository check-run link")
        check_id = int(link[1])
        _require(check_id not in selected_checks, "GitHub linked the same check run to multiple required jobs")
        # Fetch only the check ID from the validated repository-qualified Actions job link.
        check = github._get_json(f"{_REPO_PATH}/check-runs/{check_id}")
        _require(isinstance(check, dict) and _positive_id(check.get("id")) and check["id"] == check_id,
                 f"GitHub {path} returned a different check run than the exact job link")
        app, suite = check.get("app"), check.get("check_suite")
        _require(check.get("name") == job["name"] and check.get("head_sha") == merge and _successful(check)
                 and isinstance(app, dict) and _positive_id(app.get("id")) and app["id"] == actions_app_id
                 and isinstance(suite, dict) and _positive_id(suite.get("id")) and suite["id"] == run["check_suite_id"],
                 f"GitHub {path} job has no matching successful GitHub Actions check on the exact merge group")
        selected_checks.add(check_id)
        evidence[job["name"]] = {"job_id": job["id"], "check_run_id": check_id}
    return evidence


def _queue_anchor(github, pull_snapshot, run_id):
    _require(isinstance(pull_snapshot, (PullSnapshot, QueuePull)), "Expected a validated pull-request identity")
    _require(_positive_id(run_id), "Expected a positive Actions run ID")
    anchor = github._get_json(f"{_REPO_PATH}/actions/runs/{run_id}")
    _require(isinstance(anchor, dict) and anchor.get("id") == run_id, "GitHub returned the wrong workflow run")
    path = _required_workflow(anchor)
    _require(path in _WORKFLOWS, "Expected a Domain or SCES run for the merge group")
    branch = anchor.get("head_branch")
    marker = _QUEUE_BRANCH.fullmatch(branch) if isinstance(branch, str) else None
    _require(marker is not None and marker[1] == str(pull_snapshot.number),
             "GitHub workflow is not on the merge-queue ref for the selected pull request")
    merge = anchor.get("head_sha")
    _require(isinstance(merge, str) and re.fullmatch(r"[0-9a-f]{40}", merge)
             and merge not in (pull_snapshot.base, pull_snapshot.head),
             "GitHub workflow does not name a distinct merge-group commit")
    verified_anchor = _verify_run(anchor, path, pull_snapshot, branch, merge)
    _verify_ref(github, branch, merge)
    return anchor, path, branch, merge, verified_anchor


def capture_queue_target(github, pull_snapshot, run_id):
    """Bind the exact live queue identity without relying on CI completion or success."""
    _, path, branch, merge, anchor = _queue_anchor(github, pull_snapshot, run_id)
    return {"merge": merge, "queue_ref": f"refs/heads/{branch}", "workflow": path,
            "workflow_id": anchor["workflow_id"], "observed_run_id": run_id}


def capture_queue_observation(github, pull_snapshot, run_id, *, actions_app_id):
    """Observe current CI provenance. The caller must still verify the commit's Git parents."""
    _require(isinstance(pull_snapshot, PullSnapshot), "Expected a validated pull-request snapshot")
    _require(_positive_id(actions_app_id), "Expected a positive Actions App ID")
    anchor, path, branch, merge, verified_anchor = _queue_anchor(github, pull_snapshot, run_id)
    _require(_successful(anchor), "The selected GitHub merge-group run did not complete successfully")
    query = urlencode({"event": "merge_group", "branch": branch, "head_sha": merge, "per_page": 100})
    listing = f"{_REPO_PATH}/actions/runs?{query}"
    runs = _selected_runs(github, listing, pull_snapshot, branch, merge)
    _require(runs[path] == verified_anchor, "The selected GitHub workflow run is no longer the latest exact run")
    selected_checks = set()
    workflows = {path: {**run, "jobs": _jobs(github, path, run, branch, merge, selected_checks, actions_app_id)}
                 for path, run in runs.items()}

    _require(_selected_runs(github, listing, pull_snapshot, branch, merge) == runs,
             "GitHub merge-group workflow runs changed during evidence collection")
    _verify_ref(github, branch, merge)
    return {"repository_id": pull_snapshot.repository_id, "pull_number": pull_snapshot.number, "merge": merge,
            "queue_ref": f"refs/heads/{branch}", "observed_run_id": run_id, "workflows": workflows}
