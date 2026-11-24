from copy import deepcopy
from hashlib import sha256
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

from tools import reconcile, spdx_replay
from tools.distribution import COVERAGE, validate, validate_discovery
from tools.records import Catalog, DataError, encode


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
                if kind == "license":
                    detail["standardLicenseHeaderHtml"] = "\n      "
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

    def replay_catalog(self, candidates):
        return SimpleNamespace(root=self.repo, spdx={key.casefold(): row for key, row in candidates.items()})

    def test_archive_replay_checks_exact_membership_and_origin(self):
        fixture(self.archive)
        origins, source = self.read()
        reconcile.prepare(self.repo, self.repo, origins, source, initial=True)
        rows = reconcile.read_candidates(self.repo)
        spdx_replay.replay(self.replay_catalog(rows), source, self.archive, None)

        changed = deepcopy(rows)
        changed["Substitute"] = changed.pop("Example")
        changed["Substitute"]["origin"]["identifier"] = "Substitute"
        with self.assertRaisesRegex(DataError, "inventory mismatch .*missing: example; unexpected: substitute"):
            spdx_replay.replay(self.replay_catalog(changed), source, self.archive, None)

        for change in ("digest", "reference number", "forged history", "invented older pin", "invented membership"):
            with self.subTest(change=change):
                changed = deepcopy(rows)
                row = changed["Example"]
                if change == "digest":
                    row["origin"]["artifacts"]["text"]["sha256"] = "0" * 64
                elif change == "reference number":
                    row["origin"]["metadata"]["referenceNumber"] = 12
                elif change == "forged history":
                    row["history"] = [{"origin": row["origin"]}]
                elif change == "invented older pin":
                    row["origin"]["source"] = NEXT
                else:
                    row["membership"] = {"status": "restored", "source": DATA, "release": source["release"]}
                with self.assertRaises(DataError):
                    spdx_replay.replay(self.replay_catalog(changed), source, self.archive, None)

        rows["Example"]["origin"]["metadata"]["referenceNumber"] = 12
        catalog = self.replay_catalog(rows)
        with patch.object(spdx_replay, "trusted_candidates", return_value=catalog.spdx):
            with self.assertRaisesRegex(DataError, "current origin differs from the archive: Example"):
                spdx_replay.replay(catalog, source, self.archive, DATA)

    def test_archive_replay_retains_trusted_origins_and_ids_at_release_change(self):
        fixture(self.archive, licenses=("Example", "Removed"))
        first, source = self.read()
        reconcile.prepare(self.repo, self.repo, first, source, initial=True)
        previous = self.replay_catalog(reconcile.read_candidates(self.repo))
        fixture(self.archive, release="3.30.0", data=NEXT, licenses=("Example", "Added"))
        second, source = self.read(release="3.30.0", data=NEXT)
        delta, _ = reconcile.reconcile(previous.spdx, second, source)
        catalog = self.replay_catalog({**previous.spdx, **{key.casefold(): row for key, row in delta.items()}})
        with patch.object(spdx_replay, "trusted_candidates", return_value=previous.spdx):
            spdx_replay.replay(catalog, source, self.archive, DATA)
            changed = deepcopy(catalog)
            changed.spdx["example"]["origin"] = second["Example"]
            with self.assertRaisesRegex(DataError, "origin mismatch: Example"):
                spdx_replay.replay(changed, source, self.archive, DATA)
            changed = deepcopy(catalog)
            del changed.spdx["removed"]["membership"]
            with self.assertRaisesRegex(DataError, "membership mismatch: Removed"):
                spdx_replay.replay(changed, source, self.archive, DATA)
            changed = deepcopy(catalog)
            changed.spdx["example"]["id"] = "0" * 32
            with self.assertRaisesRegex(DataError, "candidate ID mismatch: Example"):
                spdx_replay.replay(changed, source, self.archive, DATA)

    def test_two_releases_validate_current_membership_and_retained_origins(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                                  capture_output=True, text=True).stdout.strip()

        def snapshot(release):
            archive = f"registry/coverage/snapshots/{release}.json"
            saved = {"source_manifest": f"research/sources/spdx-{release}.json",
                     "snapshot": archive, "assessment": Catalog(self.repo).coverage()}
            (self.repo / archive).parent.mkdir(parents=True, exist_ok=True)
            for name in (archive, COVERAGE):
                (self.repo / name).write_bytes(encode(saved))
            git("add", "-A")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", release)

        git("init", "--quiet")
        git("config", "core.autocrlf", "false")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Protected baseline")
        protected = git("rev-parse", "HEAD")
        fixture(self.archive, licenses=("Example", "Removed"))
        first, source = self.read()
        first_archive = self.root / "first.tar.gz"
        first_archive.write_bytes(self.archive.read_bytes())
        reconcile.prepare(self.repo, self.repo, first, source, initial=True)
        snapshot("3.29.0")
        base = git("rev-parse", "HEAD")
        self.assertEqual(validate(Catalog(self.repo), spdx_archive=self.archive), (None, []))

        fixture(self.archive, release="3.30.0", data=NEXT, licenses=("Example", "Added"))
        second, source = self.read(release="3.30.0", data=NEXT)
        staging = self.root / "pending"
        reconcile.prepare(self.repo, staging, second, source)
        for path in staging.rglob("*.json"):
            if path.name != "reconciliation-report.json":
                installed = self.repo / path.relative_to(staging)
                installed.parent.mkdir(parents=True, exist_ok=True)
                installed.write_bytes(path.read_bytes())
        snapshot("3.30.0")
        current = Catalog(self.repo)
        self.assertEqual(current.spdx["added"]["origin"]["source"], NEXT)
        self.assertEqual(current.spdx["example"]["origin"]["source"], DATA)
        self.assertEqual(validate(current, base=base, spdx_archive=self.archive), (None, []))

        def download(pin, destination):
            original = first_archive if pin["data_commit"] == DATA else self.archive
            destination.write_bytes(original.read_bytes())

        with (patch.object(spdx_replay, "resolve_upstream_ref", side_effect=lambda repo, commit, *_: commit),
              patch.object(spdx_replay, "resolve_release_tag", side_effect=(XML, NEXT)),
              patch.object(spdx_replay, "fetch_archive", side_effect=download)):
            self.assertEqual(validate(current, base=protected, fetch_spdx_archive=True), (None, []))
        # The first exact archive is unavailable to a one-archive offline invocation.
        with self.assertRaisesRegex(DataError, "3.30.0.json: SPDX replay inventory mismatch"):
            validate(current, base=protected, spdx_archive=self.archive)

        prior = self.repo / "research/sources/spdx-3.29.0.json"
        prior.unlink()
        with self.assertRaisesRegex(DataError, "unregistered retained SPDX source pin"):
            validate_discovery(current)

    def test_local_archive_replay_preserves_identity_from_an_incoming_predecessor(self):
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                                  capture_output=True, text=True).stdout.strip()

        def commit(label):
            git("add", "-A")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", label)

        def snapshot(label):
            archive = f"registry/coverage/snapshots/{label}.json"
            saved = {"source_manifest": "research/sources/spdx-3.29.0.json",
                     "snapshot": archive, "assessment": Catalog(self.repo).coverage()}
            (self.repo / archive).parent.mkdir(parents=True, exist_ok=True)
            for name in (archive, COVERAGE):
                (self.repo / name).write_bytes(encode(saved))
            commit(label)

        git("init", "--quiet")
        git("config", "core.autocrlf", "false")
        commit("Protected baseline")
        base = git("rev-parse", "HEAD")
        fixture(self.archive)
        origins, source = self.read()
        reconcile.prepare(self.repo, self.repo, origins, source, initial=True)
        snapshot("first")
        snapshot("second")
        self.assertEqual(validate(Catalog(self.repo), base=base, spdx_archive=self.archive), (None, []))

        original = Catalog(self.repo).spdx["example"]
        candidate_path = self.repo / "registry/candidates" / original["id"][:2] / f"{original['id']}.json"
        candidate_path.unlink()
        different = "123456789abc4def8123456789abcdef"
        path = self.repo / "registry/candidates" / different[:2] / f"{different}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(encode({**original, "id": different}))
        snapshot("untrusted")
        with self.assertRaisesRegex(DataError, "untrusted.json: SPDX replay candidate ID mismatch"):
            validate(Catalog(self.repo), base=base, spdx_archive=self.archive)

    def test_archive_replay_requires_exact_committed_acquisition(self):
        fixture(self.archive)
        _, source = self.read()
        with patch.object(spdx_replay, "build_opener") as opener:
            changed = deepcopy(source)
            changed["archive"]["url"] = "https://example.org/archive.tar.gz"
            with self.assertRaisesRegex(DataError, "archive location or size"):
                spdx_replay.fetch_archive(changed, self.root / "download.tar.gz")
            opener.assert_not_called()
        changed = deepcopy(source)
        changed["archive"]["bytes"] += 1
        with self.assertRaisesRegex(DataError, "archive size differs"):
            spdx_replay.replay(None, changed, self.archive, None)
        changed = deepcopy(source)
        changed["archive"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(DataError, "SHA-256 mismatch"):
            spdx_replay.replay(None, changed, self.archive, None)

    def test_online_replay_resolves_the_separate_xml_release_pin(self):
        fixture(self.archive)
        _, source = self.read()
        source["xml_commit"] = NEXT
        with (patch.object(spdx_replay, "resolve_release_tag", return_value=XML) as resolve,
              patch.object(spdx_replay, "fetch_archive") as fetch):
            with self.assertRaisesRegex(DataError, "XML release tag differs from the committed XML pin"):
                spdx_replay.replay_download(None, source, None)
            resolve.assert_called_once()
            repository, release, directory = resolve.call_args.args
            self.assertEqual(repository, reconcile.SOURCE_REPOSITORY)
            self.assertEqual(release, "3.29.0")
            self.assertFalse(directory.exists())
            fetch.assert_not_called()

    def test_online_replay_rejects_matching_archive_from_an_untagged_data_commit(self):
        fixture(self.archive, data=NEXT)
        origins, source = self.read(data=NEXT)
        reconcile.prepare(self.repo, self.repo, origins, source, initial=True)
        catalog = self.replay_catalog(reconcile.read_candidates(self.repo))
        spdx_replay.replay(catalog, source, self.archive, None)

        with (patch.object(spdx_replay, "resolve_release_tag", side_effect=(XML, DATA)) as resolve,
              patch.object(spdx_replay, "fetch_archive") as fetch):
            with self.assertRaisesRegex(DataError, "data release tag differs from the committed data pin"):
                spdx_replay.replay_download(catalog, source, None)
            directory = resolve.call_args.args[2]
            self.assertEqual(resolve.call_args_list, [
                call(reconcile.SOURCE_REPOSITORY, "3.29.0", directory),
                call(reconcile.DATA_REPOSITORY, "3.29.0", directory),
            ])
            fetch.assert_not_called()

    def test_online_replay_accepts_matching_xml_and_data_release_tags(self):
        fixture(self.archive)
        origins, source = self.read()
        reconcile.prepare(self.repo, self.repo, origins, source, initial=True)
        catalog = self.replay_catalog(reconcile.read_candidates(self.repo))

        def download(pin, destination):
            self.assertEqual(pin, source)
            destination.write_bytes(self.archive.read_bytes())

        with (patch.object(spdx_replay, "resolve_release_tag", side_effect=(XML, DATA)) as resolve,
              patch.object(spdx_replay, "fetch_archive", side_effect=download) as fetch):
            spdx_replay.replay_download(catalog, source, None)
            self.assertEqual([args.args[0] for args in resolve.call_args_list],
                             [reconcile.SOURCE_REPOSITORY, reconcile.DATA_REPOSITORY])
            fetch.assert_called_once()

    def test_historical_replay_uses_exact_upstream_revisions_and_caches_full_pins(self):
        fixture(self.archive)
        _, first = self.read()
        second_archive = self.root / "second.tar.gz"
        fixture(second_archive, data=NEXT)
        _, second = reconcile.load_release(second_archive, "3.29.0", NEXT, XML)
        archives = {}

        def download(pin, destination):
            original = self.archive if pin == first else second_archive
            destination.write_bytes(original.read_bytes())

        with (patch.object(spdx_replay, "resolve_upstream_ref", side_effect=lambda repo, revision, *_: revision) as resolve,
              patch.object(spdx_replay, "resolve_release_tag", side_effect=(XML, NEXT)) as tag,
              patch.object(spdx_replay, "fetch_archive", side_effect=download) as fetch,
              patch.object(spdx_replay, "compare_registry") as compare):
            spdx_replay.replay_download(None, first, None, archives=archives, historical=True)
            spdx_replay.replay_download(None, first, None, archives=archives, historical=True)
            spdx_replay.replay_download(None, second, None, archives=archives, historical=True)
            tag.assert_not_called()
            spdx_replay.replay_download(None, second, None, archives=archives)
            self.assertEqual([call.args[:2] for call in resolve.call_args_list], [
                (reconcile.SOURCE_REPOSITORY, XML), (reconcile.DATA_REPOSITORY, DATA),
                (reconcile.SOURCE_REPOSITORY, XML), (reconcile.DATA_REPOSITORY, NEXT),
            ])
            self.assertEqual([call.args[0] for call in fetch.call_args_list], [first, second])
            self.assertEqual([call.args[2] for call in compare.call_args_list], [first, first, second, second])
            self.assertEqual(tag.call_count, 2)

        with (patch.object(spdx_replay, "resolve_upstream_ref", return_value=NEXT),
              patch.object(spdx_replay, "fetch_archive") as fetch):
            with self.assertRaisesRegex(DataError, "historical XML commit differs from the committed pin"):
                spdx_replay.replay_download(None, first, None, historical=True)
            fetch.assert_not_called()

    def test_fingerprints_and_deprecated_text_fallback(self):
        fixture(self.archive, deprecated=True)
        origins, provenance = self.read(expected_sha=sha256(self.archive.read_bytes()).hexdigest())
        row = origins["Example-exception"]
        self.assertNotIn("headers", origins["Example"])
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
        identity = "123456789abc4def8123456789abcdef"
        subject = f"e-{identity}"
        entity_path = f"registry/entities/{identity[:2]}/{identity}.json"
        claim = "example-identity"
        verification = "example-review"
        for path, record in (
            (entity_path, {"id": identity, "crosswalks": [{"origin": "spdx", "key": "Example"}]}),
            (f"sces/records/claim/{claim}--1.json", {"kind": "claim", "id": claim, "revision": 1,
                                                   "subject": subject, "predicate": "instrument-identity"}),
            ("sces/records/verification/example-review--1.json", {
                "kind": "verification", "id": verification, "revision": 1,
                "claim": {"kind": "claim", "id": claim, "revision": 1},
            }),
            ("sces/records/disposition/example-disposition--1.json", {
                "kind": "disposition", "id": "example-disposition", "revision": 1,
                "review": {"kind": "verification", "id": verification, "revision": 1},
            }),
        ):
            path = self.repo / path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(reconcile.json_bytes(record))
        self.assertEqual(reconcile.find_dependencies(self.repo, ["Example"], []), [
            {"path": entity_path, "direct_matches": ["Example"]},
            {"path": f"sces/records/claim/{claim}--1.json", "direct_matches": [subject]},
            {"path": "sces/records/verification/example-review--1.json", "direct_matches": [claim]},
            {"path": "sces/records/disposition/example-disposition--1.json", "direct_matches": [verification]},
        ])

    def test_dependency_review_matches_exact_encoded_spdx_membership_keys(self):
        path = self.repo / "sces/records/claim/example-crosswalk--1.json"
        path.parent.mkdir(parents=True)
        record = {"kind": "claim", "id": "example-crosswalk", "revision": 1,
                  "subject": "e-123456789abc4def8123456789abcdef",
                  "predicate": "spdx-membership",
                  "value": f'{{"key":"Example","origin":"spdx","revision":"{DATA}"}}'}
        path.write_bytes(reconcile.json_bytes(record))
        self.assertEqual(reconcile.find_dependencies(self.repo, ["Example"], []),
                         [{"path": path.relative_to(self.repo).as_posix(), "direct_matches": ["Example"]}])
        self.assertEqual(reconcile.find_dependencies(self.repo, ["Exam"], []), [])
        record["predicate"] = "instrument-identity"
        path.write_bytes(reconcile.json_bytes(record))
        self.assertEqual(reconcile.find_dependencies(self.repo, ["Example"], []), [])

    def test_dependency_review_follows_changed_mit_artifacts_to_exact_claim_revisions(self):
        def record(kind, identity, revision=1, **fields):
            ref = {"kind": kind, "id": identity, "revision": revision}
            path = self.repo / f"sces/records/{kind}/{identity}--{revision}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(reconcile.json_bytes({**ref, **fields}))
            return ref

        fixture(self.archive, licenses=("MIT", "Other"))
        first, source = self.read()
        reconcile.prepare(self.repo, self.repo, first, source, initial=True)
        fixture(self.archive, data=NEXT, licenses=("MIT", "Other"))
        second, source = self.read(data=NEXT)
        raw = "https://raw.githubusercontent.com/spdx/license-list-data"
        blob = "https://github.com/spdx/license-list-data/blob"
        plain = record("source", "mit-plain", locator=f"{raw}/{DATA}/text/MIT.txt")
        detail = record("source", "mit-detail", locator=f"{raw}/{DATA}/json/details/MIT.json")
        template = record("source", "mit-template", locator=f"{raw}/{DATA}/template/MIT.template.txt")
        incoming = record("source", "mit-incoming", locator=f"{blob}/{NEXT}/text/MIT.txt")
        wrong_pin = record("source", "mit-plain", 2, locator=f"{raw}/{XML}/text/MIT.txt")
        wrong_path = record("source", "similar", locator=f"{raw}/{DATA}/text/MIT-other.txt")
        foreign = record("source", "foreign", locator=f"https://example.invalid/{DATA}/text/MIT.txt")
        equality = "mit-spdx-3290-plaintext-detail-byte-equality"
        boundary = "mit-spdx-3290-template-detail-byte-boundary"
        older = record("claim", equality)
        newer = record("claim", equality, 2)
        matcher = record("claim", boundary)
        unrelated = record("claim", "other-claim")
        for name, claim, basis in (("plain", older, plain), ("detail", older, detail),
                                   ("matcher-plain", matcher, plain), ("matcher-detail", matcher, detail),
                                   ("matcher-template", matcher, template), ("new-source", newer, wrong_pin),
                                   ("similar-name", unrelated, wrong_path), ("different-origin", unrelated, foreign)):
            record("dependency", name, claim=claim, basis=basis)
        record("verification", "prior-review", claim=older)
        record("verification", "later-review", claim=newer)
        # A new pinned locator can already have its own exact evidence.
        record("dependency", "incoming-review", claim=matcher, basis=incoming)

        for artifact, wanted in (("text", {equality, boundary}), ("detail", {equality, boundary}),
                                 ("template", {boundary})):
            with self.subTest(artifact=artifact):
                changed = deepcopy(second)
                previous = changed["MIT"]["artifacts"][artifact]
                changed["MIT"]["artifacts"][artifact] = reconcile.describe_text(previous["path"], b"New bytes.\n")
                report = reconcile.prepare(self.repo, self.root / artifact, changed, source)
                self.assertEqual(report["events"]["changed"], ["MIT"])
                paths = {row["path"]: row["direct_matches"] for row in report["dependency_review"]}
                self.assertEqual({path for path in paths if path.startswith("sces/records/claim/")},
                                 {f"sces/records/claim/{name}--1.json" for name in wanted})
                self.assertNotIn("sces/records/source/mit-plain--2.json", paths)
                self.assertNotIn("sces/records/source/similar--1.json", paths)
                self.assertNotIn("sces/records/source/foreign--1.json", paths)
                self.assertNotIn("sces/records/verification/later-review--1.json", paths)
                if artifact == "text":
                    self.assertEqual(paths["sces/records/source/mit-plain--1.json"], [f"{raw}/{DATA}/text/MIT.txt"])
                    self.assertEqual(paths["sces/records/source/mit-incoming--1.json"], [f"{blob}/{NEXT}/text/MIT.txt"])
                    self.assertIn("sces/records/verification/prior-review--1.json", paths)

        second["MIT"]["name"] = "MIT (display name change)"
        report = reconcile.prepare(self.repo, self.root / "metadata", second, source)
        self.assertEqual(report["events"]["changed"], ["MIT"])
        self.assertEqual(report["dependency_review"], [])

    def test_case_only_spdx_change_reviews_both_exact_spellings(self):
        fixture(self.archive)
        first, source = self.read()
        reconcile.prepare(self.repo, self.repo, first, source, initial=True)
        baseline = reconcile.read_candidates(self.repo)["Example"]["id"]
        claim_folder = self.repo / "sces/records/claim"
        claim_folder.mkdir(parents=True)
        for claim_id, key, revision in (("old-key", "Example", DATA), ("new-key", "EXAMPLE", NEXT),
                                        ("substring-key", "Example-other", DATA)):
            record = {"kind": "claim", "id": claim_id, "revision": 1,
                      "subject": "e-123456789abc4def8123456789abcdef", "predicate": "spdx-membership",
                      "value": f'{{"key":"{key}","origin":"spdx","revision":"{revision}"}}'}
            (claim_folder / f"{claim_id}--1.json").write_bytes(reconcile.json_bytes(record))

        fixture(self.archive, release="3.30.0", data=NEXT, licenses=("EXAMPLE",))
        second, source = self.read(release="3.30.0", data=NEXT)
        pending = self.root / "pending"
        report = reconcile.prepare(self.repo, pending, second, source)
        self.assertEqual(report["events"]["changed"], ["EXAMPLE"])
        self.assertEqual(reconcile.read_candidates(pending)["EXAMPLE"]["id"], baseline)
        self.assertEqual(report["dependency_review"], [
            {"path": "sces/records/claim/new-key--1.json", "direct_matches": ["EXAMPLE"]},
            {"path": "sces/records/claim/old-key--1.json", "direct_matches": ["Example"]},
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
