from hashlib import sha256
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import reconcile


DATA = "a" * 40
XML = "b" * 40
NEXT = "c" * 40
TEXT = b"Fixture for deterministic fingerprinting.\r\n"


def add_file(tar, path, raw):
    member = tarfile.TarInfo(path)
    member.size = len(raw)
    tar.addfile(member, io.BytesIO(raw))


def fixture(archive_path, *, release="3.29.0", data=DATA, licenses=("Example",),
            deprecated=False, text=TEXT, mismatch=False):
    with tarfile.open(archive_path, "w:gz") as tar:
        prefix = f"license-list-data-{data}/"
        for kind, (label, id_field, detail_folder) in reconcile.KINDS.items():
            ids = licenses if kind == "license" else ("Example-exception",)
            manifest = []
            for identifier in ids:
                row = {id_field: identifier, "name": identifier, "isDeprecatedLicenseId": deprecated}
                manifest.append(row)
                detail = dict(row)
                if mismatch and kind == "license":
                    detail[id_field] = "Another"
                add_file(tar, f"{prefix}json/{detail_folder}/{identifier}.json",
                         reconcile.json_bytes(detail))
                add_file(tar, f"{prefix}text/{identifier}.txt", text)
                stem = f"deprecated_{identifier}" if deprecated else identifier
                add_file(tar, f"{prefix}template/{stem}.template.txt", b"fixture\n")
            add_file(tar, f"{prefix}json/{label}.json", reconcile.json_bytes({
                "licenseListVersion": release, label: manifest, "releaseDate": "2026-09-16T00:00:00Z",
            }))
        if deprecated:
            identifier = "Example-exception"
            raw_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<SPDXLicenseCollection xmlns="http://www.spdx.org/license">
  <exception licenseId="{identifier}"><obsoletedBys>
    <obsoletedBy expression="Example WITH Example-exception">Target</obsoletedBy>
  </obsoletedBys></exception>
</SPDXLicenseCollection>""".encode()
            add_file(tar, f"{prefix}license-list-XML/exceptions/{identifier}.xml", raw_xml)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "archive.tar.gz"
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def read(self, release="3.29.0", data=DATA, expected_sha=None):
        return reconcile.load_release(self.archive, release, data, XML, expected_sha)

    def test_fingerprints_and_deprecated_text_fallback(self):
        fixture(self.archive, deprecated=True)
        origins, provenance = self.read(expected_sha=sha256(self.archive.read_bytes()).hexdigest())
        row = origins["Example-exception"]
        self.assertTrue(row["deprecated"])
        self.assertEqual(row["artifacts"]["text"]["path"], "text/Example-exception.txt")
        self.assertEqual(row["artifacts"]["text"]["sha256"], sha256(TEXT).hexdigest())
        self.assertEqual(row["artifacts"]["text"]["line_endings"], "CRLF")
        self.assertEqual(row["artifacts"]["template"]["path"],
                         "template/deprecated_Example-exception.template.txt")
        self.assertEqual(row["upstream_replacements"], [{
            "target": "Target",
            "for_expression": "Example WITH Example-exception",
        }])
        self.assertEqual(provenance["population"], {
            "licenses": 1, "exceptions": 1, "deprecated_licenses": 1, "deprecated_exceptions": 1,
            "missing_template": 0, "missing_text": 0,
        })

    def test_bad_archive_digest_release_identity_and_duplicate_ids(self):
        fixture(self.archive)
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.read(expected_sha="0" * 64)
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            self.read(release="3.30.0")
        fixture(self.archive, mismatch=True)
        with self.assertRaisesRegex(ValueError, "summary/detail identity mismatch"):
            self.read()
        fixture(self.archive, licenses=("Example", "EXAMPLE"))
        with self.assertRaisesRegex(ValueError, "Duplicate SPDX identifier"):
            self.read()

    def test_changed_added_removed_and_independent_output(self):
        fixture(self.archive, licenses=("Example", "Removed", "Unchanged"))
        first, provenance = self.read()
        reconcile.prepare(self.repo, self.repo, first, provenance, initial=True)
        original = reconcile.read_candidates(self.repo)
        original_files = {path: path.read_bytes() for path in self.repo.rglob("*.json")}

        fixture(self.archive, release="3.30.0", data=NEXT, licenses=("EXAMPLE", "Unchanged", "Added"))
        second, manifest = self.read(release="3.30.0", data=NEXT)
        second["EXAMPLE"]["deprecated"] = True
        second["EXAMPLE"]["artifacts"]["text"]["sha256"] = "9" * 64
        report = reconcile.prepare(self.repo, self.root / "pending", second, manifest)
        prepared = reconcile.read_candidates(self.root / "pending")

        self.assertEqual(report["events"], {
            "added": ["Added"], "changed": ["EXAMPLE"], "removed": ["Removed"],
            "deprecated": ["EXAMPLE"], "restored": [],
        })
        self.assertEqual(report["unchanged"], 2)
        self.assertEqual(prepared["EXAMPLE"]["id"], original["Example"]["id"])
        self.assertEqual(prepared["EXAMPLE"]["history"], [{"origin": first["Example"]}])
        self.assertEqual(prepared["Removed"]["id"], original["Removed"]["id"])
        self.assertEqual(prepared["Removed"]["membership"]["status"], "removed")
        self.assertEqual(original_files, {path: path.read_bytes() for path in self.repo.rglob("*.json")})

    def test_restore_history_and_repeated_initial(self):
        fixture(self.archive, licenses=("Example", "WillReturn"))
        first, manifest = self.read()
        reconcile.prepare(self.repo, self.repo, first, manifest, initial=True)
        saved = reconcile.read_candidates(self.repo)
        repeat = reconcile.prepare(self.repo, self.repo, first, manifest, initial=True)
        self.assertEqual(repeat["candidate_changes"], 0)
        self.assertEqual(saved, reconcile.read_candidates(self.repo))

        absent = {identifier: origin for identifier, origin in first.items()
                  if identifier != "WillReturn"}
        updates, _ = reconcile.reconcile(saved, absent, manifest)
        restored, events = reconcile.reconcile({**saved, **updates}, first, manifest)
        self.assertEqual(events["restored"], ["WillReturn"])
        self.assertEqual(restored["WillReturn"]["id"], saved["WillReturn"]["id"])
        self.assertEqual([event["membership"]["status"] for event in restored["WillReturn"]["history"]],
                         ["removed", "restored"])

    def test_prepare_requires_separate_empty_output(self):
        fixture(self.archive)
        origins, provenance = self.read()
        for out in (self.repo, self.repo / "new", self.root):
            with self.assertRaisesRegex(ValueError, "separate empty output"):
                reconcile.prepare(self.repo, out, origins, provenance)
        staging = self.root / "staging"
        reconcile.prepare(self.repo, staging, origins, provenance)
        with self.assertRaisesRegex(ValueError, "separate empty output"):
            reconcile.prepare(self.repo, staging, origins, provenance)

    def test_data_revision_with_same_list_version_preserves_source_manifest(self):
        fixture(self.archive)
        first, manifest = self.read()
        reconcile.prepare(self.repo, self.repo, first, manifest, initial=True)
        prior_manifest = self.repo / "research/sources/spdx-3.29.0.json"
        before = prior_manifest.read_bytes()

        fixture(self.archive, data=NEXT, text=TEXT + b"New bytes.\n")
        second, new_manifest = self.read(data=NEXT)
        staging = self.root / "staging"
        reconcile.prepare(self.repo, staging, second, new_manifest)
        revision_manifest = staging / f"research/sources/spdx-3.29.0-{NEXT}.json"
        self.assertEqual(reconcile.read_json(revision_manifest.read_bytes())["data_commit"], NEXT)
        self.assertEqual(prior_manifest.read_bytes(), before)

    def test_dependency_review_includes_claims_for_matching_entities(self):
        for path, record in (
            (self.repo / "registry/entities/ab/entity.json", {
                "id": "entity", "crosswalk": {"spdx": "Example"}
            }),
            (self.repo / "sces/records/claim.json", {"id": "claim", "subject": "entity"}),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(reconcile.json_bytes(record))
        self.assertEqual(reconcile.find_dependencies(self.repo, ["Example"], []), [
            {"path": "registry/entities/ab/entity.json", "direct_matches": ["Example"]},
            {"path": "sces/records/claim.json", "direct_matches": ["entity"]},
        ])

    def test_discover_resolves_annotated_tag_to_commit(self):
        payloads = {
            "repos/spdx/license-list-XML/releases/latest": {"tag_name": "v3.29.0"},
            "repos/spdx/license-list-data/releases/tags/v3.29.0": {"tag_name": "v3.29.0"},
            "repos/spdx/license-list-XML/git/ref/tags/v3.29.0": {
                "object": {"type": "commit", "sha": XML},
            },
            "repos/spdx/license-list-data/git/ref/tags/v3.29.0": {
                "object": {"type": "tag", "sha": NEXT},
            },
            f"repos/spdx/license-list-data/git/tags/{NEXT}": {
                "object": {"type": "commit", "sha": DATA},
            },
        }
        with patch.object(reconcile, "github_json", side_effect=payloads.__getitem__):
            self.assertEqual(reconcile.discover()["data_commit"], DATA)


if __name__ == "__main__":
    unittest.main()
