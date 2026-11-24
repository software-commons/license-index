"""Test exact publisher rights bytes without acquiring or distributing real statements."""

from hashlib import sha256
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch
from zipfile import ZipFile

from tools.distribution import (
    CC_LEGAL_TEXTS, CC_RIGHTS, CC_RIGHTS_SHA256, COVERAGE, POLYFORM_RIGHTS, RIGHTS_DOCUMENTS, RIGHTS_MAX_BYTES,
    bundle, read_rights_document, validate_discovery, validate_incoming_snapshots, validate_texts,
)
from tools.records import COVERAGE_VERSION, Catalog, DataError, NoRedirects, decode, encode


class DistributionTests(unittest.TestCase):
    def test_bundle_rejects_nested_registry_inputs_before_validation_or_writes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            catalog = Catalog(root)
            with (patch("tools.distribution.validate_discovery",
                        side_effect=AssertionError("discovery validation should not start")) as validate,
                  patch("tools.distribution.write_license") as write):
                for section in ("registry", "sces", "research", "legal-texts"):
                    with self.subTest(section=section):
                        output = root / section / "nested" / "discovery.zip"
                        output.parent.mkdir(parents=True)
                        with self.assertRaisesRegex(DataError, "outside.*input"):
                            bundle(catalog, output)
                        self.assertFalse(output.exists())
                validate.assert_not_called()
                write.assert_not_called()

    def test_bundle_retains_removed_and_historical_spdx_origin_manifests(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()

            def write(name, data):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(encode(data))
                return path

            identity = "123456789abc4def8123456789abcdef"
            source_pin = "a" * 40
            history_pin = "b" * 40
            current_pin = "c" * 40
            origin = {
                "kind": "spdx", "identifier": "Removed-Fixture", "name": "Retained fixture",
                "source": source_pin, "release": "3.28.0", "list_kind": "license", "deprecated": False,
                "metadata": {"licenseId": "Removed-Fixture", "name": "Retained fixture", "isDeprecatedLicenseId": False},
                "artifacts": {"detail": {"path": "json/details/Removed-Fixture.json", "sha256": "d" * 64, "bytes": 1}},
            }
            candidate = {
                "id": identity, "disposition": "historical", "reason": "Synthetic removal fixture",
                "origin": origin,
                "history": [{"origin": {**origin, "release": "3.27.0", "source": history_pin}}],
                "membership": {"status": "removed", "release": "3.29.0", "source": current_pin},
            }
            candidate_path = f"registry/candidates/{identity[:2]}/{identity}.json"
            write(candidate_path, candidate)
            current_source = "research/sources/spdx-3.29.0.json"
            write(current_source, {
                "release": "3.29.0", "data_commit": current_pin, "xml_commit": current_pin,
                "manifests": {}, "population": dict.fromkeys((
                    "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                    "missing_text", "missing_template",
                ), 0),
            })
            catalog = Catalog(root)
            counts = catalog.coverage()["catalog"]
            self.assertEqual(counts["spdx_licenses"], 0)
            self.assertEqual(counts["spdx_historical_only"], 1)
            self.assertEqual(counts["candidate_dispositions"], {"historical": 1})
            snapshot = "registry/coverage/snapshots/3.29.0.json"
            coverage = {
                "schema_version": COVERAGE_VERSION, "cutoff": "2026-11-23", "method": "Synthetic removal fixture",
                "source_manifest": current_source, "snapshot": snapshot,
                "assessment": catalog.coverage(),
            }
            write(COVERAGE, coverage)
            write(snapshot, coverage)
            older_sources = {
                "research/sources/spdx-3.28.0.json": {"release": "3.28.0", "data_commit": source_pin},
                "research/sources/spdx-3.27.0.json": {"release": "3.27.0", "data_commit": history_pin},
            }
            output = root / "discovery.zip"
            with patch("tools.distribution.BUNDLE_SUPPORT", {COVERAGE}):
                with self.assertRaisesRegex(DataError, "unregistered retained SPDX source pin"):
                    bundle(catalog, output)
                self.assertFalse(output.exists())
                for name, source in older_sources.items():
                    write(name, source)
                bundle(catalog, output)
                repeat = root / "repeat.zip"
                bundle(catalog, repeat)
            self.assertEqual(output.read_bytes(), repeat.read_bytes())
            with ZipFile(output) as archive:
                for name, source in older_sources.items():
                    self.assertEqual(archive.read(name), encode(source))
                self.assertEqual(archive.read(candidate_path), encode(candidate))
                exported = decode(archive.read("catalog.json"))
                self.assertEqual(exported["candidates"][0]["record"], candidate)
                self.assertEqual(exported["coverage"], coverage)


    def test_snapshot_restoration_replays_the_original_archival_inputs(self):
        for original_matches in (False, True):
            with self.subTest(original_matches=original_matches), TemporaryDirectory() as directory:
                root = Path(directory).resolve()

                def git(*arguments):
                    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                                          capture_output=True, text=True).stdout.strip()

                def commit(message):
                    git("add", "-A")
                    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)
                    return git("rev-parse", "HEAD")

                def write(name, value):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(encode(value))

                identity = "123456789abc4def8123456789abcdef"
                candidate_path = f"registry/candidates/{identity[:2]}/{identity}.json"
                source_path = "research/sources/spdx-3.29.0.json"
                candidate = {
                    "id": identity, "reason": "Synthetic restoration fixture", "history": [],
                    "origin": {"kind": "publisher", "identifier": "Fixture", "name": "Fixture",
                               "source": "https://example.invalid/fixture"},
                }

                def set_disposition(disposition):
                    write(candidate_path, {**candidate, "disposition": disposition})

                def snapshot(name, *, assessment=None):
                    row = {"schema_version": COVERAGE_VERSION, "cutoff": "2026-11-23", "method": "Synthetic coverage fixture",
                           "source_manifest": source_path, "snapshot": f"registry/coverage/snapshots/{name}.json",
                           "assessment": Catalog(root).coverage() if assessment is None else assessment}
                    write(row["snapshot"], row)
                    write(COVERAGE, row)
                    return row

                git("init", "--quiet")
                git("config", "core.autocrlf", "false")
                write(source_path, {"release": "3.29.0", "data_commit": "a" * 40, "xml_commit": "b" * 40,
                                    "manifests": {}, "population": dict.fromkeys((
                                        "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                        "missing_text", "missing_template",
                                    ), 0)})
                set_disposition("excluded")
                restored_assessment = Catalog(root).coverage()
                set_disposition("unresolved")
                base = commit("Set a synthetic discovery baseline")

                if original_matches:
                    set_disposition("excluded")
                archived = snapshot("original", assessment=restored_assessment)
                original = commit("Archive the first assessment")

                set_disposition("unresolved")
                snapshot("intervening")
                commit("Select a second assessment")

                set_disposition("excluded")
                write(COVERAGE, archived)
                commit("Restore the first assessment after the registry changes")
                validate_discovery(Catalog(root))

                if original_matches:
                    replays = []

                    def replay(catalog, _source, predecessor):
                        replays.append((catalog.candidates[identity]["disposition"], predecessor))

                    validate_incoming_snapshots(root, base, replay_spdx=replay)
                    self.assertEqual(replays, [("excluded", base), ("unresolved", original)])
                else:
                    with self.assertRaisesRegex(DataError, f"original.json: coverage differs.*{original}"):
                        validate_incoming_snapshots(root, base)


class RightsTests(unittest.TestCase):
    def test_approved_cc_installers_require_exact_current_publisher_pins(self):
        for identifier in CC_LEGAL_TEXTS:
            with self.subTest(identifier=identifier):
                catalog = Catalog()
                original = catalog.packaged[identifier]
                self.assertEqual((original["rights"], original["rights_sha256"]), (CC_RIGHTS, CC_RIGHTS_SHA256))
                catalog.packaged = {identifier: original}
                validate_texts(catalog)

                missing = {key: value for key, value in original.items() if key != "rights_sha256"}
                catalog.packaged[identifier] = missing
                with self.assertRaisesRegex(DataError, f"invalid rights digest for {identifier}"):
                    validate_texts(catalog)

                catalog.packaged[identifier] = {**original, "rights_sha256": "0" * 64}
                with self.assertRaisesRegex(DataError, f"invalid rights digest for {identifier}"):
                    validate_texts(catalog)
                catalog.packaged[identifier] = missing
                with self.assertRaisesRegex(DataError, f"(?:unverified archival publisher reference|invalid rights digest) for {identifier}"):
                    validate_texts(catalog, archived=True)

                catalog.packaged[identifier] = original
                with self.assertRaisesRegex(DataError, f"publisher rights SHA-256 mismatch for {identifier}"):
                    validate_texts(catalog, rights_reader=lambda _: b"Tampered publisher archive")

    def test_one_cc_edition_cannot_supply_another_edition(self):
        catalog = Catalog()
        wanted = "CC-BY-NC-SA-4.0"
        original = catalog.packaged[wanted]
        other = catalog.packaged["CC-BY-SA-4.0"]
        alternate = (catalog.root / other["path"]).read_bytes()
        catalog.packaged = {wanted: {**original, "bytes": len(alternate), "sha256": sha256(alternate).hexdigest(),
                                    "source": other["source"]}}
        with self.assertRaisesRegex(DataError, f"unexpected admitted publisher text digest for {wanted}"):
            validate_texts(catalog, lambda _: alternate)
        wrong_locator = {**original, "source": other["source"]}
        wrong_revision = {**original, "revision": "0" * 40}
        for attempted in (wrong_locator, wrong_revision):
            with self.subTest(attempted=attempted):
                catalog.packaged[wanted] = attempted
                with self.assertRaisesRegex(DataError, f"unapproved publisher text locator for {wanted}"):
                    validate_texts(catalog)

    def test_polyform_installation_cannot_exchange_publisher_editions(self):
        catalog = Catalog()
        noncommercial = "PolyForm-Noncommercial-1.0.0"
        small_business = "PolyForm-Small-Business-1.0.0"
        originals = {name: catalog.packaged[name] for name in (noncommercial, small_business)}
        catalog.packaged = originals
        self.assertNotEqual(originals[noncommercial]["sha256"], originals[small_business]["sha256"])
        self.assertEqual({row["rights"] for row in originals.values()}, {POLYFORM_RIGHTS})
        self.assertEqual(len({row["rights_sha256"] for row in originals.values()}), 1)
        validate_texts(catalog)
        validate_texts(catalog, archived=True)

        for identifier, other in ((noncommercial, small_business), (small_business, noncommercial)):
            with self.subTest(identifier=identifier):
                catalog.packaged = {identifier: originals[other], other: originals[identifier]}
                with self.assertRaisesRegex(DataError, f"unexpected admitted publisher text digest for {identifier}"):
                    validate_texts(catalog)

    def test_legacy_cc_bindings_are_only_for_exact_archived_publisher_editions(self):
        for identifier in ("CC-BY-4.0", "CC0-1.0"):
            with self.subTest(identifier=identifier):
                catalog = Catalog()
                row = dict(catalog.packaged[identifier])
                del row["rights_sha256"]
                row["rights"] = "https://creativecommons.org/policies/"
                row["source"] = f"https://creativecommons.org/{CC_LEGAL_TEXTS[identifier][0]}"
                catalog.packaged = {identifier: row}
                validate_texts(catalog, archived=True)
                with self.assertRaisesRegex(DataError, f"unapproved publisher text locator for {identifier}"):
                    validate_texts(catalog)
                with self.assertRaisesRegex(DataError, f"publisher rights SHA-256 mismatch for {identifier}"):
                    validate_texts(catalog, archived=True, rights_reader=lambda _: b"Tampered publisher archive")

                changed = (catalog.root / row["path"]).read_bytes() + b"\nChanged example\n"
                catalog.packaged[identifier] = {**row, "bytes": len(changed), "sha256": sha256(changed).hexdigest()}
                with self.assertRaisesRegex(DataError, f"unexpected admitted publisher text digest for {identifier}"):
                    validate_texts(catalog, lambda _: changed, archived=True)

    def test_custody_reader_rejects_wrong_bytes_locator_and_missing_digest(self):
        catalog = Catalog()
        identifier = "CC-BY-SA-4.0"
        fixture = b"Synthetic rights statement.\n"
        row = {**catalog.packaged[identifier], "rights_sha256": sha256(fixture).hexdigest()}
        catalog.packaged = {identifier: row}
        with TemporaryDirectory() as directory, patch("tools.distribution.CC_RIGHTS_SHA256", row["rights_sha256"]):
            root = Path(directory).resolve()
            path = root / RIGHTS_DOCUMENTS[CC_RIGHTS]
            path.write_bytes(fixture)

            def read(url):
                return read_rights_document(url, root=root)

            validate_texts(catalog, rights_reader=read)
            path.write_bytes(fixture.lower())
            with self.assertRaisesRegex(DataError, "publisher rights SHA-256 mismatch"):
                validate_texts(catalog, rights_reader=read)
            row["rights"] = POLYFORM_RIGHTS
            with self.assertRaisesRegex(DataError, "unapproved publisher rights locator"):
                validate_texts(catalog, rights_reader=read)
            row["rights"] = CC_RIGHTS
            del row["rights_sha256"]
            with self.assertRaisesRegex(DataError, "invalid rights digest"):
                validate_texts(catalog, rights_reader=read)

    def test_network_reader_is_allowlisted_bounded_and_redirect_free(self):
        body = MagicMock(status=200)
        body.__enter__.return_value = body
        body.geturl.return_value = CC_RIGHTS
        body.read.return_value = b"Synthetic document"
        with patch("tools.distribution.build_opener") as opener:
            opener.return_value.open.return_value = body
            with self.assertRaisesRegex(DataError, "unapproved publisher rights locator"):
                read_rights_document("https://example.invalid/backup")
            opener.assert_not_called()
            self.assertEqual(read_rights_document(CC_RIGHTS), b"Synthetic document")
            request, = opener.return_value.open.call_args.args
            handler, = opener.call_args.args
            self.assertEqual(request.full_url, CC_RIGHTS)
            self.assertEqual(request.get_method(), "GET")
            self.assertIsInstance(handler, NoRedirects)
            self.assertIsNone(handler.redirect_request(request, None, 302, None, None, POLYFORM_RIGHTS))
            body.read.assert_called_once_with(RIGHTS_MAX_BYTES + 1)
            body.read.return_value = bytes(RIGHTS_MAX_BYTES + 1)
            with self.assertRaisesRegex(DataError, "invalid size"):
                read_rights_document(CC_RIGHTS)


if __name__ == "__main__":
    unittest.main()
