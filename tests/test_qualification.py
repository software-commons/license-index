"""Synthetic domain fixtures. They do not supply SCES research or verification."""

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.audit_claims import audit_claims
from tools.distribution import COVERAGE, validate, validate_discovery
from tools.index import execute, parser
from tools.qualification import (
    POLICY_COMMIT, POLICY_DIGEST, _bind_payload, _claim_value, _run, _validate_policy, check_history, qualified,
)
from tools.records import ROOT, Catalog, DataError, encode


MIT = "123456789abc4def8123456789abcdef"
OTHER = "23456789abcd4ef09123456789abcdef"
CANDIDATE = "3456789abcde4f01a123456789abcdef"
SOURCE = "a" * 40


def reference(name):
    return {"kind": "claim", "id": name, "revision": 1}


def entity(identifier=MIT, kind="license", name="Fixture License"):
    return {
        "id": identifier, "kind": kind, "name": name, "state": "active",
        "identity_claim": reference("identity-" + identifier),
        "aliases": [], "crosswalks": [], "relations": [],
    }


def claim(ref, identifier, predicate, value, scope=None):
    return {
        "claim": {**ref, "subject": f"e-{identifier}", "predicate": predicate, "value": value, "scope": scope or {},
                  "polarity": "affirmative", "modality": "descriptive", "conditions": []},
        "dependencies": [],
    }


def identity_claim(row):
    value = _claim_value({key: row[key] for key in ("kind", "name", "state")})
    return claim(row["identity_claim"], row["id"], "instrument-identity", value, row.get("identity_scope"))

class BindingsTests(unittest.TestCase):
    def test_bind_exact_identity_alias_spdx_crosswalk_and_external_edge(self):
        row = entity()
        identity_scope = {"authority": "fixture-publisher", "revision": "2024-01"}
        row["identity_scope"] = identity_scope
        alias = {"name": "Fixture Alternate", "claim": reference("alias"), "scope": identity_scope}
        crosswalk = {"origin": "spdx", "revision": SOURCE, "key": "MIT"}
        crosswalk_scope = {"upstream-release": "3.2.0"}
        external = {"index": "software-commons/specification-index", "id": OTHER, "revision": "1.2.0"}
        relationship_scope = {"owning-revision": SOURCE}
        row["aliases"].append(alias)
        row["crosswalks"].append({**crosswalk, "claim": reference("crosswalk"), "scope": crosswalk_scope})
        row["relations"].append({"type": "related-to", "target": external, "claim": reference("external"),
                                 "scope": relationship_scope})
        evidence = [
            identity_claim(row),
            claim(alias["claim"], MIT, "instrument-identity", alias["name"], identity_scope),
            claim(reference("external"), MIT, "cross-index-relationship",
                  "related-to:" + _claim_value(external), {**relationship_scope, "target-revision": "1.2.0"}),
            claim(reference("crosswalk"), MIT, "spdx-membership", _claim_value(crosswalk),
                  {**crosswalk_scope, "data-revision": SOURCE}),
        ]
        bound = _bind_payload({MIT: row}, evidence)
        self.assertEqual(
            [item["claim"]["id"] for item in bound], sorted(item["claim"]["id"] for item in evidence)
        )

        for entry, field, invalid_value in (
            (evidence[0], "value", "invented"),
            (evidence[1], "revision", 2),
            (evidence[2], "scope", {**relationship_scope, "target-revision": "2.0.0"}),
            (evidence[3], "scope", {**crosswalk_scope, "data-revision": "b" * 40}),
            (evidence[3], "predicate", "instrument-identity"),
            (evidence[0], "polarity", "documented-absence"),
        ):
            with self.subTest(field=field, value=invalid_value), patch.dict(entry["claim"], {field: invalid_value}):
                with self.assertRaisesRegex(DataError, "does not bind"):
                    _bind_payload({MIT: row}, evidence)
        row["crosswalks"][0]["scope"]["data-revision"] = "b" * 40
        with self.assertRaisesRegex(DataError, "conflicts with pinned data-revision"):
            _bind_payload({MIT: row}, evidence)

    def test_rejects_unbound_claim_subject(self):
        row = entity()
        wrong = claim(reference("unsupported"), OTHER, "permission", "unsupported")
        with self.assertRaisesRegex(DataError, "noncanonical claim subject"):
            _bind_payload({MIT: row}, [identity_claim(row), wrong])

    def test_relations_cannot_flatten_conditions_or_modality(self):
        base, exception = entity(), entity(OTHER, kind="exception")
        entities = {MIT: base, OTHER: exception}
        for row in entities.values():
            row["identity_scope"] = {"authority": "fixture-publisher", "revision": "2024-01"}
        reference_key = reference("exception-for-fixture")
        target = {"id": MIT}
        edge = {"type": "exception-for", "target": target, "claim": reference_key}
        exception["relations"].append(edge)
        scope = {"edition": "2024", "base-license": "fixture-license", "revision": "2024-01",
                 "material": "covered-file", "environment": "fixture-runtime"}
        evidence = [identity_claim(base), identity_claim(exception),
                    claim(reference_key, OTHER, "exception-relationship", "exception-for:" + _claim_value(target), scope)]
        with self.assertRaisesRegex(DataError, "does not bind the canonical field"):
            _bind_payload(entities, evidence)

        edge["scope"] = {key: scope[key] for key in ("edition", "base-license", "revision")}
        with self.assertRaisesRegex(DataError, "does not bind the canonical field"):
            _bind_payload(entities, evidence)

        edge["scope"] = dict(scope)
        _bind_payload(entities, evidence)

        for applicability in ({"conditions": ["Exact file notice required."]}, {"modality": "conditional"}):
            with self.subTest(applicability=applicability), patch.dict(evidence[-1]["claim"], applicability):
                with self.assertRaisesRegex(DataError, "does not bind the canonical field"):
                    _bind_payload(entities, evidence)

        scoped = claim(reference("scoped-applicability"), OTHER, "exception-relationship",
                       "exception-for:" + _claim_value(target), {"material": "covered-file"})
        scoped["claim"].update(modality="conditional", conditions=["Exact file notice required."])
        self.assertIn(scoped, _bind_payload(entities, [*evidence, scoped]))

        args = parser().parse_args(["export", "--qualified", "--policy", "fixture-policy"])
        with patch("tools.distribution.validate", return_value=({"release": "fixture"}, evidence)):
            exported, _ = execute(SimpleNamespace(entities=entities), args)
        self.assertEqual(exported["entities"][1]["relations"][0]["scope"], scope)
        self.assertEqual(exported["claims"][-1]["claim"]["scope"], scope)

    def test_crosswalk_revision_matches_immutable_origin_type(self):
        record = entity()
        record["identity_scope"] = {"authority": "fixture-publisher", "revision": "2024-01"}
        binding = reference("external-origin")
        digest = "sha256:" + "b" * 64
        for origin, revision in (("software-commons/specification-index", SOURCE),
                                 ("git+https://example.org/fixtures/instruments.git", SOURCE),
                                 ("fixture-publisher", digest)):
            with self.subTest(origin=origin, revision=revision):
                scope = {"authority": "fixture-publisher"}
                value = {"origin": origin, "revision": revision, "key": "exact-key"}
                record["crosswalks"] = [{**value, "claim": binding, "scope": scope}]
                match = claim(binding, MIT, "instrument-identity", _claim_value(value), {**scope, "revision": revision})
                self.assertIn(match, _bind_payload({MIT: record}, [identity_claim(record), match]))

        for origin, revision in (("software-commons/specification-index", "refs/heads/release"),
                                 ("git+https://example.org/fixtures/instruments.git", "1.2.0"),
                                 ("fixture-publisher", "2024-01"), ("fixture-publisher", SOURCE), ("spdx", digest)):
            with self.subTest(origin=origin, revision=revision):
                record["crosswalks"] = [{"origin": origin, "revision": revision, "key": "exact-key", "claim": binding}]
                with self.assertRaisesRegex(DataError, "immutable revision appropriate to its origin"):
                    _bind_payload({MIT: record}, [])

    def test_rejects_ambiguous_crosswalk_across_entities(self):
        first = entity()
        second = entity(OTHER)
        first["crosswalks"] = [{"origin": "spdx", "revision": SOURCE, "key": "MIT", "claim": reference("first")}]
        second["crosswalks"] = [{"origin": "spdx", "revision": SOURCE, "key": "mit", "claim": reference("second")}]
        with self.assertRaisesRegex(DataError, "duplicates"):
            _bind_payload({MIT: first, OTHER: second}, [])

    def test_rejects_circular_lineage_and_unpinned_external_target(self):
        first = entity()
        second = entity(OTHER)
        first["relations"] = [{"type": "derived-from", "target": {"id": OTHER}, "claim": reference("first")}]
        second["relations"] = [{"type": "derived-from", "target": {"id": MIT}, "claim": reference("second")}]
        with self.assertRaisesRegex(DataError, "cyclic"):
            _bind_payload({MIT: first, OTHER: second}, [])
        second["relations"] = [{
            "type": "related-to",
            "target": {"index": "software-commons/specification-index", "id": OTHER, "revision": "main"},
            "claim": reference("second"),
        }]
        with self.assertRaisesRegex(DataError, "immutable revision"):
            _bind_payload({MIT: first, OTHER: second}, [])

    def test_rejects_unresolved_and_mistyped_exception_relationship(self):
        base = entity()
        child = entity(OTHER, "exception")
        child["relations"] = [{"type": "exception-for", "target": {"id": MIT}, "claim": reference("applies")}]
        with self.assertRaisesRegex(DataError, "unresolved"):
            _bind_payload({OTHER: child}, [])
        base["kind"] = "related-instrument"
        with self.assertRaisesRegex(DataError, "base license"):
            _bind_payload({MIT: base, OTHER: child}, [])


class GitHistoryTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.row = entity()
        self.path = self.write(f"registry/entities/{MIT[:2]}/{MIT}.json", self.row)
        self.write(f"registry/candidates/{CANDIDATE[:2]}/{CANDIDATE}.json", {"id": CANDIDATE})
        self.source = self.write("research/sources/first.json", {"source": "first"})
        self.snapshot = self.write("registry/coverage/snapshots/first.json", {
            "snapshot": "first", "source_manifest": "research/sources/first.json",
        })
        self.commit("Synthetic domain snapshot")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.catalog = SimpleNamespace(root=self.root, entities={MIT: self.row}, candidates={CANDIDATE: {}})

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.root), *arguments], check=True,
                              capture_output=True, text=True).stdout

    def commit(self, message):
        self.git("add", "-A")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(encode(value))
        return path

    def test_candidate_and_canonical_paths_are_never_reused_or_dropped(self):
        check_history(self.catalog, self.base)
        self.catalog.candidates.clear()
        with self.assertRaisesRegex(DataError, "candidates"):
            check_history(self.catalog, self.base)
        self.catalog.entities.clear()
        with self.assertRaisesRegex(DataError, "entities"):
            check_history(self.catalog, self.base)

    def test_history_preserves_snapshots_byte_for_byte(self):
        self.snapshot.write_bytes(self.snapshot.read_bytes() + b"\n")
        with self.assertRaisesRegex(DataError, "snapshot was modified"):
            check_history(self.catalog, self.base)

    def test_history_preserves_prior_snapshot_source_after_current_moves(self):
        self.write("research/sources/next.json", {"source": "next"})
        self.write(COVERAGE, {"source_manifest": "research/sources/next.json"})
        check_history(self.catalog, self.base)
        self.source.write_bytes(self.source.read_bytes() + b"\n")
        with self.assertRaisesRegex(DataError, "prior coverage source manifest was modified"):
            check_history(self.catalog, self.base)
        self.source.unlink()
        with self.assertRaisesRegex(DataError, "missing or linked file: .*first.json"):
            check_history(self.catalog, self.base)

    def test_current_coverage_requires_a_distinct_tracked_json_archive(self):
        self.path.unlink()
        candidate_path = f"registry/candidates/{CANDIDATE[:2]}/{CANDIDATE}.json"
        self.write(candidate_path, {"id": CANDIDATE, "disposition": "unresolved", "origin": {"kind": "publisher"}})
        source = "research/sources/fixture.json"
        self.write(source, {"data_commit": SOURCE, "xml_commit": SOURCE, "manifests": {},
                            "population": dict.fromkeys((
                                "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                "missing_text", "missing_template",
                            ), 0)})
        self.commit("Set discovery baseline")
        base = self.git("rev-parse", "HEAD").strip()
        catalog = Catalog(self.root)
        ledger = {"source_manifest": source, "snapshot": COVERAGE, "assessment": catalog.coverage()}
        self.write(COVERAGE, ledger)
        with self.assertRaisesRegex(DataError, "must name a JSON archive"):
            validate_discovery(catalog)

        archive = "registry/coverage/snapshots/selected.json"
        ledger["snapshot"] = archive
        self.write(COVERAGE, ledger)
        self.write(archive, ledger)
        validate_discovery(catalog)
        self.commit("Retain the exact selected archive")
        validate(catalog, base=base)

        edited = {**ledger, "method": "Uncommitted fixture metadata"}
        self.write(COVERAGE, edited)
        self.write(archive, edited)
        validate_discovery(catalog)
        with self.assertRaisesRegex(DataError, "current coverage differs from the committed ledger"):
            validate(catalog, base=base)

    def test_incoming_archives_replay_the_original_ledger(self):
        (self.root / f"registry/entities/{MIT[:2]}/{MIT}.json").unlink()
        source = "research/sources/fixture.json"
        self.write(source, {"data_commit": SOURCE, "xml_commit": SOURCE, "manifests": {},
                            "population": dict.fromkeys((
                                "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                "missing_text", "missing_template",
                            ), 0)})
        candidate_path = f"registry/candidates/{CANDIDATE[:2]}/{CANDIDATE}.json"
        row = {"id": CANDIDATE, "disposition": "unresolved", "origin": {"kind": "publisher"}}
        self.write(candidate_path, row)
        self.commit("Set the pre-admission baseline without qualified entities")
        base = self.git("rev-parse", "HEAD").strip()
        archive = "registry/coverage/snapshots/archived.json"
        assessment = Catalog(self.root).coverage()
        snapshot = {"source_manifest": source, "snapshot": archive, "assessment": assessment}
        self.write(archive, snapshot)
        self.write(COVERAGE, snapshot)
        self.commit("Introduce a truthful archive")
        archived_commit = self.git("rev-parse", "HEAD").strip()

        def select_current():
            self.write(candidate_path, {**row, "disposition": "out-of-scope"})
            current = {"source_manifest": source, "snapshot": "registry/coverage/snapshots/current.json",
                       "assessment": Catalog(self.root).coverage()}
            self.write(current["snapshot"], current)
            self.write(COVERAGE, current)
            self.commit("Publish a different truthful current assessment")

        select_current()
        validate(Catalog(self.root), base=base)

        self.git("reset", "--hard", archived_commit)
        assessment["catalog"]["beyond_spdx_leads"] = 99
        self.write(archive, snapshot)
        self.write(COVERAGE, snapshot)
        self.commit("Introduce a false historical archive")
        select_current()
        validate_discovery(Catalog(self.root))
        with self.assertRaisesRegex(DataError, "archived.json: coverage differs from historical"):
            validate(Catalog(self.root), base=base)

    def test_strict_validation_replays_each_incoming_snapshot_at_its_own_source_pins(self):
        (self.root / f"registry/entities/{MIT[:2]}/{MIT}.json").unlink()
        candidate_path = f"registry/candidates/{CANDIDATE[:2]}/{CANDIDATE}.json"
        self.write(candidate_path, {"id": CANDIDATE, "disposition": "unresolved", "origin": {"kind": "publisher"}})
        self.commit("Set the protected baseline")
        base = self.git("rev-parse", "HEAD").strip()
        checkpoints = []
        for release, pin in (("3.28.0", SOURCE), ("3.29.0", "b" * 40)):
            source_path = f"research/sources/spdx-{release}.json"
            source = {"release": release, "data_commit": pin, "xml_commit": pin, "manifests": {},
                      "population": dict.fromkeys(("licenses", "exceptions", "deprecated_licenses",
                                                  "deprecated_exceptions", "missing_text", "missing_template"), 0)}
            self.write(source_path, source)
            path = f"registry/coverage/snapshots/{release}.json"
            snapshot = {"source_manifest": source_path, "snapshot": path, "assessment": Catalog(self.root).coverage()}
            self.write(COVERAGE, snapshot)
            self.write(path, snapshot)
            self.commit(f"Retain {release} coverage")
            checkpoints.append((source, self.git("rev-parse", "HEAD").strip()))
        (first_pin, first), (second_pin, second) = checkpoints

        with patch("tools.spdx_replay.replay_download") as replay:
            validate(Catalog(self.root), base=base)
            replay.assert_not_called()
            validate(Catalog(self.root), base=base, fetch_spdx_archive=True)
            calls = replay.call_args_list
            self.assertEqual([call.args[1:] for call in calls],
                             [(first_pin, base), (second_pin, first), (second_pin, first)])
            self.assertEqual([call.kwargs.get("historical", False) for call in calls], [True, True, False])
            archive_cache = calls[0].kwargs["archives"]
            self.assertTrue(all(call.kwargs["archives"] is archive_cache for call in calls))

        with patch("tools.spdx_replay.replay_download", side_effect=DataError("SPDX replay origin mismatch")) as replay:
            with self.assertRaisesRegex(DataError, "3.28.0.json: SPDX replay origin mismatch"):
                validate(Catalog(self.root), base=base, fetch_spdx_archive=True)
            replay.assert_called_once()

        self.write("fixture.json", {"change": "after the verified archive"})
        self.commit("Keep the current archive beside unrelated work")
        with patch("tools.spdx_replay.replay_download") as replay:
            validate(Catalog(self.root), base=base, fetch_spdx_archive=True)
            self.assertEqual(replay.call_args.args[1:], (second_pin, second))
            replay.reset_mock()
            validate(Catalog(self.root), fetch_spdx_archive=True)
            self.assertEqual(replay.call_args.args[1:], (second_pin, None))
            replay.assert_called_once()

    @unittest.skipUnless(os.name == "nt", "requires Git for Windows")
    def test_validator_reads_committed_evidence_with_a_long_git_path(self):
        self.git("config", "core.longpaths", "false")
        parent = "sces/records/dependency"
        suffix = "--1.json"
        name_length = 245 - len(str(self.root / parent)) - len(suffix) - 1
        path = f"{parent}/{'d' * name_length}{suffix}"
        evidence = self.write(path, {"fixture": "synthetic evidence reference"})
        self.git("add", "--", path)
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Synthetic evidence snapshot")
        revision = self.git("rev-parse", "HEAD").strip()
        # Invoke Git through a child interpreter as the isolated SCES validator does.
        code = "import subprocess, sys; sys.stdout.buffer.write(subprocess.check_output(sys.argv[1:]))"
        inherited = {"GIT_DIR": str(self.root / "wrong"), "GIT_CONFIG_COUNT": "1",
                     "GIT_CONFIG_KEY_0": "core.longpaths", "GIT_CONFIG_VALUE_0": "false"}
        with patch.dict(os.environ, inherited):
            output = _run([sys.executable, "-I", "-B", "-c", code, "git", "-C", str(self.root),
                           "show", f"{revision}:{path}"])
        self.assertEqual(output, evidence.read_bytes())

    def test_no_active_qualification_rejects_registered_entities(self):
        with self.assertRaisesRegex(DataError, "require an active"):
            qualified(self.catalog, None)
        self.catalog.entities.clear()
        self.assertEqual(qualified(self.catalog, None), (None, []))

    def test_checked_withdrawal_preserves_entities_without_qualified_output(self):
        report = {
            "repository": "software-commons/license-index", "dataset": "license-index",
            "schema_version": "1.0.0", "synthetic": False, "source_commit": self.base,
        }
        self.write("sces/releases/withdrawn-fixture/qualification.json", report)
        with patch("tools.qualification._validate_policy") as validate_policy:
            with self.assertRaisesRegex(DataError, "checked withdrawal"):
                qualified(self.catalog, self.root, base=self.base)
            self.write("sces/advisories/withdrawn-fixture.json", {"fixture": True})
            self.assertEqual(qualified(self.catalog, self.root, base=self.base), (None, []))
            validate_policy.assert_called_with(self.root, self.root, self.base)
            validate_policy.side_effect = DataError("pinned SCES policy rejected the advisory")
            with self.assertRaisesRegex(DataError, "policy rejected"):
                qualified(self.catalog, self.root, base=self.base)
            validate_policy.side_effect = None
            self.path.write_bytes(self.path.read_bytes() + b"\n")
            with self.assertRaisesRegex(DataError, "exact trusted baseline bytes"):
                qualified(self.catalog, self.root, base=self.base)

    def test_mocked_policy_boundary_accepts_only_frozen_exact_registry_bytes(self):
        self.write("sces/publication.json", {"release": "synthetic-fixture"})
        report = {
            "repository": "software-commons/license-index", "dataset": "license-index",
            "schema_version": "1.0.0", "synthetic": False, "source_commit": self.base,
        }
        self.write("sces/releases/synthetic-fixture/qualification.json", report)
        self.write("sces/releases/synthetic-fixture/claims.json", [identity_claim(self.row)])
        with self.assertRaisesRegex(DataError, "requires --policy"):
            qualified(self.catalog, None)
        with patch("tools.qualification._validate_policy") as validate:
            result = qualified(self.catalog, self.root, base=self.base)
            self.assertEqual(result, (report, [identity_claim(self.row)]))
            validate.assert_called_once_with(self.root, self.root, self.base)
            self.path.write_bytes(self.path.read_bytes() + b"\n")
            with self.assertRaisesRegex(DataError, "bytes differ"):
                qualified(self.catalog, self.root)
            self.write("sces/releases/synthetic-fixture/qualification.json", {**report, "synthetic": True})
            with self.assertRaisesRegex(DataError, "synthetic"):
                qualified(self.catalog, self.root)

    def test_discovery_and_checked_release_views_report_separate_counts(self):
        self.write(f"registry/candidates/{CANDIDATE[:2]}/{CANDIDATE}.json", {
            "id": CANDIDATE, "disposition": "unresolved", "reason": "Synthetic test lead",
            "origin": {"kind": "publisher", "identifier": "fixture", "name": "Fixture", "source": "https://example.invalid"},
            "history": [],
        })
        catalog = Catalog(self.root)
        source = "research/sources/fixture.json"
        snapshot = "registry/coverage/snapshots/discovery.json"
        self.write(source, {"data_commit": SOURCE, "xml_commit": SOURCE, "manifests": {},
                            "population": dict.fromkeys((
                                "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                "missing_text", "missing_template",
                            ), 0)})
        saved = {"source_manifest": source, "snapshot": snapshot, "assessment": catalog.coverage()}
        self.write(snapshot, saved)
        self.write("registry/coverage/current.json", saved)
        self.write("sces/publication.json", {"release": "synthetic-fixture"})
        report = {"repository": "software-commons/license-index", "dataset": "license-index",
                  "schema_version": "1.0.0", "synthetic": False, "source_commit": self.base}
        self.write("sces/releases/synthetic-fixture/qualification.json", report)
        self.write("sces/releases/synthetic-fixture/claims.json", [identity_claim(self.row)])

        def invoke(*arguments):
            return execute(catalog, parser().parse_args(arguments))[0]

        policy_flag = ("--policy", str(self.root))
        with patch("tools.qualification._validate_policy") as check:
            self.assertEqual(invoke("coverage")["catalog"]["accepted_entities"], 0)
            self.assertEqual(invoke("export")["status"], "development-discovery")
            check.assert_not_called()
            validated = invoke("validate", *policy_flag)
            self.assertEqual(validated["coverage"]["catalog"]["accepted_entities"], 1)
            self.assertEqual(validated["coverage"]["qualification"]["independently_verified_claims"], 1)
            self.assertEqual(invoke("coverage", *policy_flag), validated["coverage"])
            self.assertEqual(invoke("export", "--qualified", *policy_flag)["entities"], [self.row])
            check.side_effect = DataError("fixture policy rejected")
            with self.assertRaisesRegex(DataError, "fixture policy rejected"):
                invoke("export", *policy_flag)

    def test_untrusted_policy_bytes_are_not_executed(self):
        self.write("evidence/v1/policy.json", {"policy": "SCES-1.0", "files": {}})
        with (
            patch("tools.qualification._git", return_value=f"{POLICY_COMMIT}\n".encode()),
            patch("tools.qualification._run") as run,
        ):
            with self.assertRaisesRegex(DataError, "manifest does not match"):
                _validate_policy(self.root, self.root, None)
            run.assert_not_called()

    def test_claim_audit_reports_exact_eligibility_without_writing_selection(self):
        adoption = self.root / "sces/adoption.json"
        adoption.parent.mkdir(parents=True, exist_ok=True)
        adoption.write_bytes((ROOT / "sces/adoption.json").read_bytes())
        validator = self.root / "fixture-validator.py"
        # Synthetic validator API for testing the audit bridge, not an evidence record.
        validator.write_text(f'''
import json

def policy_bundle():
    return {POLICY_DIGEST!r}

def canonical(data):
    return json.dumps(data).encode("utf-8")

class Invalid(ValueError):
    pass

class Registry:
    def __init__(self, root, digest, now, *, repository):
        assert repository == "software-commons/license-index"
        assert digest == policy_bundle()
        self.passed = ("claim", "fixture-reviewed", 2)
        self.pending = ("claim", "fixture-pending", 1)
        self.records = {{self.passed: {{}}, self.pending: {{}}}}
        self.dispositions = {{self.passed: {{"evidence": "supported", "verification": "independently-reviewed"}}}}
        self.verifications = {{(self.passed, "research"): [True], (self.passed, "independent-review"): [True]}}

    def validate_publication(self, *, write=False, base=None):
        assert write is False
        assert base == {self.base!r}

    def check_eligibility(self, identity, now):
        if identity == self.pending:
            raise Invalid("unqualified-claim: diagnostic detail")

    def record_digest(self, identity):
        return ("e" if identity == self.passed else "f") * 64
''', encoding="utf-8")
        with patch("tools.audit_claims._pinned_validator", return_value=validator):
            report = audit_claims(self.root, self.root, self.base)
        self.assertEqual((report["eligible"], report["ineligible"]), (1, 1))
        pending, reviewed = report["claims"]
        self.assertEqual(pending["first_blocking_check"], "unqualified-claim")
        self.assertEqual(pending["recorded_phases"], [])
        self.assertEqual(reviewed["claim"]["revision"], 2)
        self.assertEqual(reviewed["record_sha256"], "e" * 64)
        self.assertEqual(reviewed["recorded_phases"], ["research", "independent-review"])
        self.assertFalse((self.root / "sces/publication.json").exists())

        tree = self.git("rev-parse", "HEAD^{tree}").strip()
        unrelated = self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                             "commit-tree", tree, "-m", "Synthetic unrelated history").strip()
        with patch("tools.audit_claims._pinned_validator") as load:
            with self.assertRaisesRegex(DataError, "history base must be an ancestor"):
                audit_claims(self.root, self.root, unrelated)
            load.assert_not_called()

        adoption.write_bytes(adoption.read_bytes() + b"\n")
        with patch("tools.audit_claims._pinned_validator") as load:
            with self.assertRaisesRegex(DataError, "draft adoption file differs"):
                audit_claims(self.root, self.root, self.base)
            load.assert_not_called()
