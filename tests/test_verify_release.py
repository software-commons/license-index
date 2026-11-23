"""Synthetic archive fixtures for byte verification, without publication authority."""

from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import warnings
from zipfile import ZipFile

from tools.distribution import archive_entry
from tools.qualification import DATASET, POLICY_COMMIT, POLICY_DIGEST, REPOSITORY, SCHEMA_VERSION
from tools.records import DataError, decode, encode
from tools.stage_release import CHECKSUMS, REQUEST_STATUS, checksum_listing
from tools.verify_release import GATES, verify


def describe(content):
    return {"bytes": len(content), "sha256": sha256(content).hexdigest()}


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.zip_path = Path(temporary.name) / "fixture.zip"
        self.request = {
            "repository": REPOSITORY, "dataset": DATASET, "schema_version": SCHEMA_VERSION,
            "release": "fixture", "dataset_version": "1.0.0", "source_commit": "a" * 40,
            "policy_sha256": POLICY_DIGEST, "selection_sha256": "f" * 64,
            "publication_candidate_commit": "b" * 40, "history_base_commit": "c" * 40,
            "policy_commit": POLICY_COMMIT, "status": REQUEST_STATUS,
        }
        claim = {"kind": "claim", "id": "fixture", "revision": 1}
        payload = encode([{"claim": claim, "dependencies": []}])
        self.report = {
            **{name: self.request[name] for name in ("repository", "release", "dataset", "dataset_version",
                                                     "schema_version", "source_commit",
                                                     "policy_sha256", "selection_sha256")},
            "policy": "SCES-1.0", "synthetic": False, "gates": GATES.copy(), "claims": [claim],
            "review_kind": "separate-codex-executions", "outcome": "structure-and-recorded-review-qualified",
            "coverage": {"selected": 1},
            "artifacts": [{"path": "sces/releases/fixture/claims.json", "sha256": describe(payload)["sha256"]}],
        }
        self.assets = {"claims.json": payload, "sces-contracts.schema.json": b'{"fixture": true}\n'}

    def pack(self, *, extra=None, checksum_override=None):
        assets = {**self.assets, "qualification.json": encode(self.report)}
        assets[CHECKSUMS] = checksum_listing(assets) if checksum_override is None else checksum_override
        buffer = BytesIO()
        with ZipFile(buffer, "w") as archive:
            for name, content in sorted(assets.items()):
                archive_entry(archive, name, content)
            if extra:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive_entry(archive, *extra)
        content = buffer.getvalue()
        self.zip_path.write_bytes(content)
        return encode({
            **self.request,
            "archive": {"name": self.zip_path.name, **describe(content)},
            "assets": [{"path": name, **describe(value)} for name, value in sorted(assets.items())],
        })

    def check_local(self, raw):
        return verify(raw, describe(raw)["sha256"], archive_path=self.zip_path)

    def test_verifies_exact_local_archive_without_approval(self):
        raw = self.pack()
        report = self.check_local(raw)
        self.assertEqual(report["status"], "local-archive-integrity-verified")
        self.assertEqual(report["selected_claims"], 1)
        self.assertEqual(report["publication_commit"], self.request["publication_candidate_commit"])
        self.assertEqual(report["archive"]["sha256"], describe(self.zip_path.read_bytes())["sha256"])
        self.assertNotIn("public_release", report)

    def test_rejects_request_and_zip_edits(self):
        raw = self.pack()
        with self.assertRaisesRegex(DataError, "independently recorded SHA-256"):
            verify(raw + b"\n", describe(raw)["sha256"], archive_path=self.zip_path)
        self.zip_path.write_bytes(self.zip_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(DataError, "release size or SHA-256 mismatch"):
            self.check_local(raw)

    def test_rejects_an_extra_or_duplicate_zip_entry(self):
        for name in ("discovery.json", "claims.json"):
            with self.subTest(name=name), self.assertRaisesRegex(DataError, "ZIP members"):
                self.check_local(self.pack(extra=(name, b"unapproved")))

    def test_rejects_an_out_of_range_archive_size_before_io(self):
        raw = decode(self.pack())
        raw["archive"]["bytes"] = 10 ** 100
        with self.assertRaisesRegex(DataError, "attachment size limit"):
            self.check_local(encode(raw))

    def test_recomputes_manifest_checksums(self):
        with self.assertRaisesRegex(DataError, "SHA256SUMS differs"):
            self.check_local(self.pack(checksum_override=b"1  claims.json\n"))

    def test_rejects_report_drift_even_with_self_consistent_archive_hashes(self):
        self.report["coverage"]["selected"] = 2
        with self.assertRaisesRegex(DataError, "coverage does not match"):
            self.check_local(self.pack())
        self.report["coverage"]["selected"] = 1
        self.report["gates"]["C"] = "fail"
        with self.assertRaisesRegex(DataError, "policy result"):
            self.check_local(self.pack())

    def test_public_verification_requires_notes_and_the_staged_commit(self):
        raw = self.pack()
        digest = describe(raw)["sha256"]
        with self.assertRaisesRegex(DataError, "title and body SHA-256"):
            verify(raw, digest, tag="v1.0.0")
        notes = "d" * 64
        result = {"release_url": "https://github.com/software-commons/license-index/releases/tag/v1.0.0"}
        with patch("tools.verify_release.fetch_public_archive",
                   return_value=(self.zip_path.read_bytes(), result)) as fetch:
            output = verify(raw, digest, tag="v1.0.0", notes_digest=notes)
        self.assertEqual(output["status"], "public-release-integrity-verified")
        self.assertEqual(output["public_release"], result)
        args = fetch.call_args
        self.assertEqual(args.args[1:3], ("v1.0.0", self.request["publication_candidate_commit"]))
        self.assertEqual(args.kwargs["notes_sha256"], notes)
