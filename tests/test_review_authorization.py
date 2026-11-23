"""Synthetic checks for protected exact-candidate authorization."""

from base64 import b64encode
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha1, sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from tools.records import DataError, encode
from tools.review_authorization import (
    GRANT_KIND, GRANT_PATH, GRANT_REPOSITORY, GRANT_SCOPE, REPOSITORY_RULESETS,
    GRANT_ACTIONS, candidate_identity, validate_control_authorization,
)


GRANT_COMMIT = "a" * 40
OWNER = {"id": 123, "login": "fixture-owner", "type": "User"}
WEB_FLOW = {"id": 456, "login": "web-flow", "type": "User"}
MEMBERSHIP = {"role": "admin", "state": "active", "organization": {"login": "software-commons"}}
COMMIT_PATH = f"/repos/{GRANT_REPOSITORY}/commits/{GRANT_COMMIT}"
BLOB_PATH = f"/repos/{GRANT_REPOSITORY}/contents/{GRANT_PATH}?ref={GRANT_COMMIT}"


class OwnerAuthorizationTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.record_path = self.directory / "exact-candidate.json"
        self.state_path = self.directory / "active-owner-grant.json"
        self.protected = Mock()
        self.binding = {
            "repository": "software-commons/license-index", "repository_id": 1468281504, "number": 1, "base_ref": "main",
            "phase": "queue-admission", "head": "b" * 40, "base": "c" * 40, "merge": "d" * 40,
            "diff_sha256": "e" * 64, "sces_evidence_sha256": "f" * 64,
            "protected_paths": ["tools/index.py", ".github/workflows/domain.yml"],
        }
        self.grant = {
            "kind": GRANT_KIND, "scope": GRANT_SCOPE, "repositories": list(REPOSITORY_RULESETS),
            "rulesets": list(REPOSITORY_RULESETS.values()), "expiry": "completion-or-owner-revocation",
            "actions": GRANT_ACTIONS, "publication_authorization": "required-separately",
            "integration_prs": {"software-commons/language-index": list(range(3, 24)),
                                "software-commons/license-index": [1]},
            "issued_on": datetime.now(timezone.utc).date().isoformat(),
        }
        self.commit = {
            "sha": GRANT_COMMIT, "author": OWNER, "committer": WEB_FLOW,
            "commit": {"verification": {"verified": True, "reason": "valid", "verified_at": "2026-11-23T00:00:00Z",
                                        "payload": "signed fixture payload", "signature": "fixture signature"}},
        }
        self.responses = {
            "/user": OWNER, "/user/memberships/orgs/software-commons": MEMBERSHIP, COMMIT_PATH: self.commit,
        }
        self.github = Mock()
        self.github._get_json.side_effect = lambda path: deepcopy(self.responses[path])
        self.set_grant(self.grant)

    def set_grant(self, grant):
        raw = encode(grant)
        self.responses[BLOB_PATH] = {
            "type": "file", "path": GRANT_PATH, "encoding": "base64", "size": len(raw),
            "sha": sha1(f"blob {len(raw)}\0".encode("ascii") + raw, usedforsecurity=False).hexdigest(),
            "content": b64encode(raw).decode("ascii"),
        }
        digest = sha256(raw).hexdigest()
        self.state = {"version": 1, "status": "active", "repository": GRANT_REPOSITORY, "commit": GRANT_COMMIT,
                      "path": GRANT_PATH, "sha256": digest, "owner_id": OWNER["id"], "owner_login": OWNER["login"],
                      "signer_id": WEB_FLOW["id"], "signer_login": WEB_FLOW["login"]}
        self.record = {"version": 1, "candidate": candidate_identity(self.binding),
                       "grant_commit": GRANT_COMMIT, "grant_sha256": digest}
        self.state_path.write_bytes(encode(self.state))
        self.record_path.write_bytes(encode(self.record))

    def verify(self, binding=None):
        return validate_control_authorization(
            self.github, binding or self.binding, self.record_path, self.state_path, self.protected,
        )

    def test_accepts_exact_phase_and_logs_only_safe_hashes(self):
        result = self.verify()
        self.assertEqual(result, {
            "grant_commit": GRANT_COMMIT, "grant_sha256": self.state["sha256"],
            "record_sha256": sha256(self.record_path.read_bytes()).hexdigest(),
            "state_sha256": sha256(self.state_path.read_bytes()).hexdigest(),
        })
        for path in (self.record_path, self.state_path):
            self.protected.assert_any_call(path, directory=False)
        self.assertEqual(self.github._get_json.call_count, 4)
        self.binding.update(repository=GRANT_REPOSITORY, number=23, phase="queue-merge", sces_evidence_sha256=None)
        self.set_grant(self.grant)
        self.assertEqual(self.verify()["grant_commit"], GRANT_COMMIT)

    def test_refuses_each_changed_exact_candidate_field_before_github_reads(self):
        changes = {
            "repository": GRANT_REPOSITORY, "repository_id": 456, "number": 9,
            "base_ref": "codex-gate-trial", "phase": "queue-merge", "head": "1" * 40, "base": "2" * 40,
            "merge": "3" * 40, "diff_sha256": "4" * 64, "sces_evidence_sha256": "5" * 64,
            "protected_paths": ["tools/index.py"],
        }
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaisesRegex(DataError, "exact review candidate"):
                self.verify({**self.binding, field: value})
        self.github._get_json.assert_not_called()

    def test_active_record_is_revoked_or_completed_in_protected_state(self):
        for status in ("revoked", "completed", "inactive"):
            self.state_path.write_bytes(encode({**self.state, "status": status}))
            with self.subTest(status=status), self.assertRaisesRegex(DataError, "inactive"):
                self.verify()
        self.github._get_json.assert_not_called()

    def test_exact_record_cannot_authorize_a_pull_outside_the_signed_scope(self):
        for repository, number in (("software-commons/license-index", 2), (GRANT_REPOSITORY, 24)):
            self.binding.update(repository=repository, number=number)
            self.set_grant(self.grant)
            self.assertEqual(self.record["candidate"], candidate_identity(self.binding))
            with self.subTest(repository=repository, number=number):
                with self.assertRaisesRegex(DataError, "outside the signed"):
                    self.verify()

    def test_missing_or_malformed_signed_request_scope_fails_closed(self):
        no_scope = {key: value for key, value in self.grant.items() if key != "integration_prs"}
        self.set_grant(no_scope)
        with self.assertRaisesRegex(DataError, "does not cover"):
            self.verify()
        repository = "software-commons/license-index"
        for invalid in ([1, 1], [True], ["1"], [2, 1], []):
            integration = {**self.grant["integration_prs"], repository: invalid}
            self.set_grant({**self.grant, "integration_prs": integration})
            with self.subTest(integration=invalid), self.assertRaisesRegex(DataError, "outside the signed"):
                self.verify()

    def test_active_owner_and_web_flow_verified_signature_are_both_required(self):
        for path, change in (
            ("/user", {**OWNER, "id": 999}),
            ("/user/memberships/orgs/software-commons", {**MEMBERSHIP, "role": "member"}),
            (COMMIT_PATH, {**self.commit, "author": WEB_FLOW}),
            (COMMIT_PATH, {**self.commit, "committer": OWNER}),
            (COMMIT_PATH, {**self.commit, "commit": {"verification": {"verified": False}}}),
        ):
            original = self.responses[path]
            self.responses[path] = change
            with self.subTest(path=path), self.assertRaises(DataError):
                self.verify()
            self.responses[path] = original

    def test_blob_identity_and_separate_publication_authority_are_checked(self):
        blob = self.responses[BLOB_PATH]
        self.responses[BLOB_PATH] = {**blob, "sha": "1" * 40}
        with self.assertRaisesRegex(DataError, "protected Git and SHA-256 pins"):
            self.verify()
        self.set_grant({**self.grant, "publication_authorization": "included"})
        with self.assertRaisesRegex(DataError, "protected integration scope"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
