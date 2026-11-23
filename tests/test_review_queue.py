"""Queue evidence fixtures using the GitHub Actions and Git refs REST shapes."""

from copy import deepcopy
from json import dumps
import unittest
from urllib.parse import quote

from tools.review_queue import capture_queue_observation, capture_queue_target
from tools.review_snapshot import REPOSITORY, REPOSITORY_ID, PullSnapshot, SnapshotError


PULL = PullSnapshot(REPOSITORY_ID, 17, "a" * 40, "b" * 40, "c" * 40)
QUEUE_SHA = "d" * 40
BRANCH = f"gh-readonly-queue/main/pr-17-{'e' * 40}"
REF = f"refs/heads/{BRANCH}"
APP = 15368
REPOSITORY_DATA = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
ROOT = f"/repos/{REPOSITORY}"
DOMAIN_PATH = ".github/workflows/domain.yml"
SCES_PATH = ".github/workflows/sces-ci.yml"
DOMAIN_RUN = f"{ROOT}/actions/runs/11"
SCES_RUN = f"{ROOT}/actions/runs/12"
REF_API = f"{ROOT}/git/ref/heads/{BRANCH}"
RUN_LIST = f"{ROOT}/actions/runs?event=merge_group&branch={quote(BRANCH, safe='')}&head_sha={QUEUE_SHA}&per_page=100"
DOMAIN_JOBS = f"{DOMAIN_RUN}/attempts/2/jobs?per_page=100"
SCES_JOBS = f"{SCES_RUN}/attempts/1/jobs?per_page=100"
CHECKS = f"{ROOT}/commits/{QUEUE_SHA}/check-runs?filter=all&per_page=100"


def _rows(key, values):
    return {key: values, "total_count": len(values)}


def _run(run_id, name, path, attempt, suite):
    return {"id": run_id, "name": name, "path": path, "run_attempt": attempt, "run_number": 7,
            "workflow_id": run_id + 100, "check_suite_id": suite, "event": "merge_group", "head_branch": BRANCH,
            "head_sha": QUEUE_SHA, "repository": dict(REPOSITORY_DATA), "head_repository": dict(REPOSITORY_DATA),
            "status": "completed", "conclusion": "success"}


def _job(name, job_id, run):
    return {"name": name, "id": job_id, "run_id": run["id"], "run_attempt": run["run_attempt"],
            "workflow_name": run["name"], "head_sha": QUEUE_SHA, "head_branch": BRANCH,
            "check_run_url": f"https://api.github.com{ROOT}/check-runs/{job_id}",
            "status": "completed", "conclusion": "success"}


def _check(job, suite):
    return {"name": job["name"], "id": job["id"], "head_sha": QUEUE_SHA, "app": {"id": APP},
            "check_suite": {"id": suite}, "status": "completed", "conclusion": "success"}


def _responses():
    domain = _run(11, "Domain", DOMAIN_PATH, 2, 1001)
    sces = _run(12, "SCES", SCES_PATH, 1, 1002)
    domain_jobs = [
        _job("Registry validation", 201, domain), _job("Tests on ubuntu-24.04", 202, domain),
        _job("Tests on windows-2025", 203, domain), _job("Tests on macos-15", 204, domain),
    ]
    sces_job = _job("Evidence / SCES validation", 301, sces)
    checks = [*(_check(job, 1001) for job in domain_jobs), _check(sces_job, 1002)]
    # A check of the same name from another suite or App cannot replace the linked job check.
    checks.append({**checks[0], "id": 991, "check_suite": {"id": 993}, "app": {"id": 992}})
    return {DOMAIN_RUN: deepcopy(domain), SCES_RUN: deepcopy(sces),
            REF_API: {"ref": REF, "object": {"type": "commit", "sha": QUEUE_SHA}},
            RUN_LIST: _rows("workflow_runs", [domain, sces]), DOMAIN_JOBS: _rows("jobs", domain_jobs),
            SCES_JOBS: _rows("jobs", [sces_job]), CHECKS: _rows("check_runs", checks)}


class FixtureGitHub:
    def __init__(self, responses=None, *, later_ref=None, later_listing=None):
        self.responses = responses if responses is not None else _responses()
        self.calls = []
        self.later = {REF_API: later_ref, RUN_LIST: later_listing}

    def _get_json(self, path):
        result = self.responses[path]
        if path in self.calls and self.later.get(path) is not None:
            result = self.later[path]
        self.calls.append(path)
        return deepcopy(result)


class QueueObservationTests(unittest.TestCase):
    def capture(self, responses=None, *, run_id=11, **later):
        return capture_queue_observation(FixtureGitHub(responses, **later), PULL, run_id, actions_app_id=APP)

    def test_retains_exact_ref_commit_runs_attempts_and_job_check_ids(self):
        github = FixtureGitHub()
        result = capture_queue_observation(github, PULL, 12, actions_app_id=APP)
        self.assertEqual((result["merge"], result["queue_ref"], result["observed_run_id"]), (QUEUE_SHA, REF, 12))
        self.assertEqual(result["repository_id"], REPOSITORY_ID)
        self.assertEqual(result["pull_number"], 17)
        domain = result["workflows"][DOMAIN_PATH]
        self.assertEqual((domain["id"], domain["run_attempt"], domain["check_suite_id"]), (11, 2, 1001))
        self.assertEqual(domain["jobs"]["Tests on windows-2025"], {"job_id": 203, "check_run_id": 203})
        self.assertEqual(result["workflows"][SCES_PATH]["jobs"], {
            "Evidence / SCES validation": {"job_id": 301, "check_run_id": 301},
        })
        self.assertEqual(github.calls, [SCES_RUN, REF_API, RUN_LIST, CHECKS, DOMAIN_JOBS, SCES_JOBS, RUN_LIST, REF_API])
        self.assertIsInstance(dumps(result), str)

    def test_target_authentication_does_not_require_successful_ci(self):
        responses = _responses()
        responses[DOMAIN_RUN].update(status="completed", conclusion="failure")
        github = FixtureGitHub(responses)
        target = capture_queue_target(github, PULL, 11)
        self.assertEqual(target, {"merge": QUEUE_SHA, "queue_ref": REF, "workflow": DOMAIN_PATH,
                                  "workflow_id": 111, "observed_run_id": 11})
        self.assertEqual(github.calls, [DOMAIN_RUN, REF_API])
        with self.assertRaisesRegex(SnapshotError, "did not complete successfully"):
            self.capture(responses)

    def test_rejects_bad_anchor(self):
        for changes in ({"id": 19}, {"event": "push"}, {"path": ".github/workflows/other.yml"},
                        {"path": DOMAIN_PATH + "@main"}, {"head_branch": BRANCH.replace("pr-17-", "pr-18-")},
                        {"head_branch": BRANCH.replace("/main/", "/branch/")}, {"head_branch": REF},
                        {"head_branch": BRANCH[:-1]}, {"head_sha": PULL.base}, {"head_sha": PULL.head},
                        {"head_sha": "f" * 39}, {"head_repository": {**REPOSITORY_DATA, "id": 13}},
                        {"repository": {**REPOSITORY_DATA, "full_name": "someone/license-index"}}):
            with self.subTest(changes=changes):
                responses = _responses()
                responses[DOMAIN_RUN].update(changes)
                with self.assertRaises(SnapshotError):
                    self.capture(responses)

    def test_rejects_missing_or_wrong_live_ref_and_end_of_collection_drift(self):
        responses = _responses()
        for ref in ({"ref": REF + "-different", "object": {"type": "commit", "sha": QUEUE_SHA}},
                    {"ref": REF, "object": {"type": "tag", "sha": QUEUE_SHA}},
                    {"ref": REF, "object": {"type": "commit", "sha": PULL.merge}}, {}):
            with self.subTest(ref=ref), self.assertRaises(SnapshotError):
                self.capture(later_ref=ref)
        responses[REF_API] = []
        with self.assertRaises(SnapshotError):
            self.capture(responses)

    def test_rejects_missing_incomplete_wrong_and_ambiguous_corresponding_runs(self):
        for changes in ({"head_sha": PULL.merge}, {"event": "pull_request"}, {"head_branch": "main"},
                        {"head_repository": None}, {"conclusion": "skipped"}, {"conclusion": "failure"},
                        {"status": "in_progress"}, {"path": SCES_PATH + "@main"}):
            with self.subTest(changes=changes), self.assertRaises(SnapshotError):
                responses = _responses()
                responses[RUN_LIST]["workflow_runs"][1].update(changes)
                self.capture(responses)
        responses = _responses()
        domain, sces = responses[RUN_LIST]["workflow_runs"]
        for listing in (_rows("workflow_runs", [domain]), {"workflow_runs": [domain, sces], "total_count": 102},
                        _rows("workflow_runs", [domain, sces, deepcopy(sces)]),
                        _rows("workflow_runs", [domain, sces, {**sces, "id": 912}])):
            with self.subTest(listing=listing), self.assertRaises(SnapshotError):
                responses[RUN_LIST] = listing
                self.capture(responses)

    def test_checks_newest_run_and_attempt_instead_of_older_success(self):
        responses = _responses()
        domain, sces = responses[RUN_LIST]["workflow_runs"]
        older = {**domain, "id": 13, "run_number": 6, "conclusion": "failure"}
        unrelated = {**domain, "id": 14, "path": ".github/workflows/other.yml"}
        responses[RUN_LIST] = _rows("workflow_runs", [unrelated, older, sces, domain])
        self.assertEqual(self.capture(responses)["workflows"][DOMAIN_PATH]["id"], 11)
        for conclusion in ("success", "failure", None):
            with self.subTest(conclusion=conclusion), self.assertRaises(SnapshotError):
                newer = {**older, "run_number": 8, "conclusion": conclusion}
                self.capture(responses, later_listing=_rows("workflow_runs", [domain, newer, sces]))
        responses[RUN_LIST] = _rows("workflow_runs", [domain, {**sces, "id": 15, "run_number": 8,
                                                              "conclusion": "failure"}, sces])
        with self.assertRaises(SnapshotError):
            self.capture(responses)

    def test_rejects_missing_failed_skipped_duplicate_and_wrong_attempt_jobs(self):
        for changes in ({"name": "Tests on macos-15"}, {"name": "Unexpected"}, {"id": 204},
                        {"conclusion": "skipped"}, {"conclusion": "failure"}, {"run_attempt": 1},
                        {"run_id": 12}, {"head_sha": PULL.merge}, {"head_branch": "main"}, {"workflow_name": "SCES"},
                        {"check_run_url": f"https://api.github.com/repos/other/repo/check-runs/201"}):
            with self.subTest(changes=changes), self.assertRaises(SnapshotError):
                responses = _responses()
                responses[DOMAIN_JOBS]["jobs"][0].update(changes)
                self.capture(responses)
        responses = _responses()
        responses[DOMAIN_JOBS] = _rows("jobs", responses[DOMAIN_JOBS]["jobs"][:-1])
        with self.assertRaises(SnapshotError):
            self.capture(responses)

    def test_rejects_wrong_or_failed_linked_check_despite_other_contexts(self):
        for changes in ({"id": 801}, {"head_sha": PULL.merge}, {"app": {"id": 18}}, {"app": None},
                        {"check_suite": {"id": 1002}}, {"conclusion": "skipped"}, {"conclusion": "failure"},
                        {"status": "in_progress"}, {"name": "Tests on ubuntu-24.04"}):
            with self.subTest(changes=changes), self.assertRaises(SnapshotError):
                responses = _responses()
                responses[CHECKS]["check_runs"][0].update(changes)
                self.capture(responses)
