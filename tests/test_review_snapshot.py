"""Read-only review candidate fixtures. No GitHub mutations or trusted check writes."""

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.review_authorization import GRANT_PATH
from tools.review_snapshot import (
    REPOSITORY, REPOSITORY_ID, AdmissionHead, GitHub, PullSnapshot, SnapshotError, capture_admission_head,
    capture_control_paths, capture_diff,
)


def pull_response():
    return {
        "number": 1,
        "state": "open",
        "draft": False,
        "mergeable": True,
        "merge_commit_sha": "c" * 40,
        "base": {"ref": "main", "sha": "a" * 40, "repo": {"id": REPOSITORY_ID, "full_name": REPOSITORY}},
        "head": {"sha": "b" * 40},
    }


class PullTests(unittest.TestCase):
    def read(self, response, number=1):
        github = GitHub()
        with patch.object(github, "_get_json", return_value=response):
            return github.get_pull(number)

    def test_accepts_exact_mergeable_pull_request(self):
        self.assertEqual(
            self.read(pull_response()),
            PullSnapshot(REPOSITORY_ID, 1, "a" * 40, "b" * 40, "c" * 40),
        )

    def test_open_admission_head_does_not_require_positive_review_availability(self):
        github = GitHub()
        for draft, mergeable in ((True, True), (False, False), (False, None)):
            response = {**pull_response(), "draft": draft, "mergeable": mergeable, "merge_commit_sha": None}
            with self.subTest(draft=draft, mergeable=mergeable), patch.object(github, "_get_json", return_value=response):
                self.assertEqual(github.get_admission_head(1), AdmissionHead(REPOSITORY_ID, 1, "b" * 40))
                with self.assertRaises(SnapshotError):
                    github.get_pull(1)
                response["base"]["ref"] = "unknown-branch"
                with self.assertRaisesRegex(SnapshotError, "configured base branch"):
                    github.get_admission_head(1)

    def test_rejects_wrong_repository_and_retargeting(self):
        response = pull_response()
        response["base"]["ref"] = "feature"
        with self.assertRaisesRegex(SnapshotError, "configured base branch"):
            self.read(response)
        response["base"]["ref"] = "main"
        response["base"]["repo"]["full_name"] = "another/license-index"
        with self.assertRaisesRegex(SnapshotError, "configured repository"):
            self.read(response)
        response["base"]["repo"]["full_name"] = REPOSITORY
        response["base"]["repo"]["id"] += 1
        with self.assertRaisesRegex(SnapshotError, "unexpected repository identifier"):
            self.read(response)

    def test_rejects_draft_closed_pr_wrong_number_and_unready_merge(self):
        for key, value, diagnostic in (
            ("draft", True, "non-draft"),
            ("state", "closed", "open"),
            ("number", 2, "different pull request"),
            ("mergeable", None, "has not established"),
            ("mergeable", False, "has not established"),
            ("merge_commit_sha", "b" * 40, "distinct full"),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(SnapshotError, diagnostic):
                    self.read({**pull_response(), key: value})


class CaptureTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.source = self.root / "origin"
        self.source.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        example = self.source / "review.txt"
        example.write_bytes(b"before\n")
        self.git("add", "review.txt")
        self.git("commit", "--quiet", "-m", "Base fixture")
        self.base = self.git("rev-parse", "HEAD")
        example.write_bytes(b"after\n")
        self.git("commit", "--quiet", "-am", "Proposed change")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.merge = self.git("commit-tree", self.tree, "-p", self.base, "-p", self.head, "-m", "Test merge")
        self.git("update-ref", "refs/pull/1/merge", self.merge)

    def git(self, *arguments):
        result = subprocess.run(["git", "-C", str(self.source), *arguments], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def capture(self, *, head=None, merge=None, **options):
        snapshot = PullSnapshot(REPOSITORY_ID, 1, self.base, head or self.head, merge or self.merge)
        with patch("tools.review_snapshot._REMOTE_URL", self.source.as_uri()):
            return capture_diff(snapshot, self.root / "snapshot", **options)

    def test_captures_exact_complete_diff_without_checking_out(self):
        inherited = {**os.environ, "GIT_DIR": "cannot-use-this", "GIT_EXTERNAL_DIFF": "cannot-run-this"}
        with patch("tools.review_snapshot.os.environ", inherited):
            tree, diff = self.capture()
        self.assertEqual(tree, self.tree)
        self.assertIn(b"diff --git a/review.txt b/review.txt\n", diff)
        self.assertIn(b"-before\n+after\n", diff)
        self.assertFalse((self.root / "snapshot" / "review.txt").exists())

    def test_rejects_changed_merge_ref(self):
        with self.assertRaisesRegex(SnapshotError, "changed during capture"):
            self.capture(merge="c" * 40)

    def test_admission_denial_checks_the_exact_live_head_and_its_single_parent(self):
        identity = AdmissionHead(REPOSITORY_ID, 1, self.head)
        self.git("update-ref", "refs/pull/1/head", self.head)
        with patch("tools.review_snapshot._REMOTE_URL", self.source.as_uri()):
            self.assertEqual(capture_admission_head(identity, self.root / "head"), self.tree)
            self.git("update-ref", "refs/pull/1/head", self.merge)
            with self.assertRaisesRegex(SnapshotError, "admission head changed during capture"):
                capture_admission_head(identity, self.root / "stale")
            with self.assertRaisesRegex(SnapshotError, "single-parent pull-request head"):
                capture_admission_head(AdmissionHead(REPOSITORY_ID, 1, self.merge), self.root / "two-parent")

    def test_grant_only_change_is_a_protected_control(self):
        grant = self.source / GRANT_PATH
        grant.parent.mkdir()
        grant.write_bytes(b'{"fixture":"synthetic grant"}\n')
        self.git("add", "--", GRANT_PATH)
        self.git("commit", "--quiet", "-m", "Change only the signed grant path")
        head = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        merge = self.git("commit-tree", tree, "-p", self.head, "-p", head, "-m", "Grant-only merge")
        self.assertEqual(self.git("diff", "--name-only", self.head, merge), GRANT_PATH)
        snapshot = PullSnapshot(REPOSITORY_ID, 1, self.head, head, merge)
        self.assertEqual(capture_control_paths(self.source, snapshot), [GRANT_PATH])

    def test_root_license_is_a_protected_control(self):
        (self.source / "LICENSE").write_bytes(b"synthetic root license\n")
        (self.source / "examples").mkdir()
        (self.source / "examples/LICENSE").write_bytes(b"synthetic example license\n")
        self.git("add", "--", "LICENSE", "examples/LICENSE")
        self.git("commit", "--quiet", "-m", "Change repository and example licenses")
        head = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        merge = self.git("commit-tree", tree, "-p", self.head, "-p", head, "-m", "License merge")
        snapshot = PullSnapshot(REPOSITORY_ID, 1, self.head, head, merge)
        self.assertEqual(capture_control_paths(self.source, snapshot), ["LICENSE"])

    def test_rejects_ordered_parent_mismatch(self):
        with self.assertRaisesRegex(SnapshotError, "ordered base and head parents"):
            self.capture(head="d" * 40)

    def test_rejects_oversize_diff(self):
        with patch("tools.review_snapshot.MAX_DIFF_BYTES", 32):
            with self.assertRaisesRegex(SnapshotError, "capture limit"):
                self.capture()

    def test_captures_single_pr_queue_commit_from_its_exact_branch(self):
        ref = f"refs/heads/gh-readonly-queue/main/pr-1-{self.base}"
        queue_merge = self.git("commit-tree", self.tree, "-p", self.base, "-p", self.head, "-m", "Queue merge")
        self.git("update-ref", ref, queue_merge)
        tree, diff = self.capture(merge=queue_merge, queue_ref=ref)
        self.assertEqual(tree, self.tree)
        self.assertIn(b"-before\n+after\n", diff)

    def test_rejects_other_queue_ref_before_fetch(self):
        with self.assertRaisesRegex(SnapshotError, "merge-queue branch"):
            self.capture(queue_ref=f"refs/heads/gh-readonly-queue/main/pr-2-{self.base}")

    def test_admission_refuses_a_merge_candidate_reused_as_the_head(self):
        replay = self.git("commit-tree", self.tree, "-p", self.base, "-p", self.merge, "-m", "Replayed test merge")
        self.git("update-ref", "refs/pull/1/merge", replay)
        with self.assertRaisesRegex(SnapshotError, "single-parent"):
            self.capture(head=self.merge, merge=replay, linear_head=True)


if __name__ == "__main__":
    unittest.main()
