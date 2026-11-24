"""Synthetic domain fixtures. They do not supply SCES research or verification."""

from hashlib import sha256
import json
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
        "candidate_ids": [CANDIDATE],
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
    def test_canonical_provenance_requires_distinct_opaque_candidate_ids(self):
        row = entity()
        for candidate_ids in (None, [], [CANDIDATE, CANDIDATE], ["MIT"]):
            with self.subTest(candidate_ids=candidate_ids):
                candidate = {**row, "candidate_ids": candidate_ids}
                if candidate_ids is None:
                    del candidate["candidate_ids"]
                with self.assertRaises(DataError):
                    _bind_payload({MIT: candidate}, [identity_claim(candidate)])

    def test_bind_exact_identity_alias_spdx_crosswalk_and_external_edge(self):
        row = entity()
        identity_scope = {"authority": "fixture-publisher", "revision": "2024-01"}
        row["identity_scope"] = identity_scope
        alias = {"name": "Fixture Alternate", "claim": reference("alias"), "scope": identity_scope}
        crosswalk = {"origin": "spdx", "revision": SOURCE, "key": "MIT"}
        crosswalk_scope = {"upstream-release": "3.2.0"}
        target_revision = "b" * 40
        external = {"index": "software-commons/specification-index", "id": OTHER, "revision": target_revision}
        relationship_scope = {"owning-revision": SOURCE}
        row["aliases"].append(alias)
        row["crosswalks"].append({**crosswalk, "claim": reference("crosswalk"), "scope": crosswalk_scope})
        row["relations"].append({"type": "related-to", "target": external, "claim": reference("external"),
                                 "scope": relationship_scope})
        evidence = [
            identity_claim(row),
            claim(alias["claim"], MIT, "instrument-identity", alias["name"], identity_scope),
            claim(reference("external"), MIT, "cross-index-relationship",
                  "related-to:" + _claim_value(external), {**relationship_scope, "target-revision": target_revision}),
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
            (evidence[2], "scope", {**relationship_scope, "target-revision": "c" * 40}),
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

    def test_qualified_lookup_derives_only_incoming_local_edges(self):
        target = entity(name="Fixture Base")
        owner = entity(OTHER, kind="exception", name="Fixture Exception")
        target["aliases"] = [{"name": "Straße License", "claim": reference("alias")}]
        relation = {
            "type": "exception-for", "target": {"id": MIT}, "claim": reference("local"),
            "scope": {"edition": "2024"},
        }
        external = {
            "type": "related-to", "target": {"id": MIT, "index": "software-commons/specification-index",
                                            "revision": SOURCE}, "claim": reference("external"),
        }
        owner["relations"] = [relation, external]
        catalog = SimpleNamespace(entities={MIT: target, OTHER: owner})

        def lookup(identifier):
            args = parser().parse_args(["show", "--qualified", "--policy", "fixture-policy", identifier])
            return execute(catalog, args)[0]

        with patch("tools.distribution.validate", return_value=({"release": "fixture"}, [])):
            expected = {"entity": target, "incoming_relations": [{"source": OTHER, **relation}]}
            self.assertEqual(lookup(MIT), expected)
            self.assertEqual(lookup("STRASSE LICENSE"), expected)
            self.assertEqual(lookup("fixture base"), expected)
            self.assertEqual(lookup(OTHER), {"entity": owner, "incoming_relations": []})
            with self.assertRaisesRegex(DataError, "unknown qualified entity"):
                lookup("unknown")

            owner["aliases"] = [{"name": MIT, "claim": reference("id-as-alias")},
                                {"name": "STRASSE LICENSE", "claim": reference("ambiguous")}]
            self.assertEqual(lookup(MIT), expected)
            with self.assertRaisesRegex(DataError, "ambiguous qualified entity"):
                lookup("Straße License")

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

    def test_rejects_circular_lineage(self):
        first = entity()
        second = entity(OTHER)
        first["relations"] = [{"type": "derived-from", "target": {"id": OTHER}, "claim": reference("first")}]
        second["relations"] = [{"type": "derived-from", "target": {"id": MIT}, "claim": reference("second")}]
        with self.assertRaisesRegex(DataError, "cyclic"):
            _bind_payload({MIT: first, OTHER: second}, [])

    def test_external_relationship_requires_immutable_target_and_exact_claim(self):
        record = entity()
        digest = "sha256:" + "b" * 64
        target = {"index": "software-commons/specification-index", "id": OTHER, "revision": digest}
        reference_key = reference("external-edge")
        scope = {"owning-revision": SOURCE}
        record["relations"] = [{
            "type": "related-to", "target": target, "claim": reference_key, "scope": scope,
        }]
        exact = claim(reference_key, MIT, "cross-index-relationship", "related-to:" + _claim_value(target),
                      {**scope, "target-revision": digest})
        self.assertIn(exact, _bind_payload({MIT: record}, [identity_claim(record), exact]))

        for revision in ("main", "v1.2", "1.2.0", "v1.2.3-rc1", "b" * 64, digest[:-1]):
            with self.subTest(revision=revision):
                changed = {**target, "revision": revision}
                record["relations"][0]["target"] = changed
                matching = claim(reference_key, MIT, "cross-index-relationship", "related-to:" + _claim_value(changed),
                                 {**scope, "target-revision": revision})
                with self.assertRaisesRegex(DataError, "immutable revision"):
                    _bind_payload({MIT: record}, [identity_claim(record), matching])

        record["relations"][0]["target"] = target
        changed_index = {**target, "index": "software-commons/language-index"}
        differently_owned = claim(reference_key, MIT, "cross-index-relationship",
                                  "related-to:" + _claim_value(changed_index), {**scope, "target-revision": digest})
        with self.assertRaisesRegex(DataError, "does not bind the canonical field"):
            _bind_payload({MIT: record}, [identity_claim(record), differently_owned])

    def test_external_exception_for_requires_an_exception_owner(self):
        exception = entity(kind="exception")
        target = {"index": "software-commons/external-license-index", "id": OTHER, "revision": SOURCE}
        binding = reference("external-exception-for")
        exception["relations"] = [{"type": "exception-for", "target": target, "claim": binding}]
        exact = claim(binding, MIT, "cross-index-relationship", "exception-for:" + _claim_value(target),
                      {"target-revision": SOURCE})
        self.assertIn(exact, _bind_payload({MIT: exception}, [identity_claim(exception), exact]))

        license_owner = {**exception, "kind": "license"}
        with self.assertRaisesRegex(DataError, "exception-for"):
            _bind_payload({MIT: license_owner}, [identity_claim(license_owner), exact])

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
        self.lead = {"id": CANDIDATE, "disposition": "unresolved", "reason": "Publisher fixture",
                     "origin": {"kind": "publisher", "identifier": "Fixture Field Terms 1.0",
                                "name": "Fixture Field Terms", "revision": "1.0",
                                "source": "https://example.invalid/terms"},
                     "history": [{"reason": "Preserved discovery note"}]}
        self.lead_path = f"registry/candidates/{CANDIDATE[:2]}/{CANDIDATE}.json"
        self.write(self.lead_path, self.lead)
        self.source = self.write("research/sources/first.json", {"source": "first"})
        self.snapshot = self.write("registry/coverage/snapshots/first.json", {
            "snapshot": "first", "source_manifest": "research/sources/first.json",
        })
        self.commit("Synthetic domain snapshot")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.catalog = Catalog(self.root)

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

    def select_fixture(self, frozen, payload):
        self.write("sces/publication.json", {"release": "synthetic-fixture"})
        report = {
            "repository": "software-commons/license-index", "dataset": "license-index",
            "schema_version": "1.0.0", "synthetic": False, "source_commit": frozen,
        }
        self.write("sces/releases/synthetic-fixture/qualification.json", report)
        self.write("sces/releases/synthetic-fixture/claims.json", payload)
        return report

    def spdx_admission(self, identifier="MIT", revision=SOURCE, release="3.2.0", *, kind="license",
                       candidate_ids=(OTHER,)):
        row = {**entity(kind=kind), "candidate_ids": list(candidate_ids)}
        crosswalk = {"origin": "spdx", "revision": revision, "key": identifier}
        scope = {"upstream-release": release}
        binding = reference("crosswalk")
        row["crosswalks"] = [{**crosswalk, "claim": binding, "scope": scope}]
        self.write(self.path.relative_to(self.root), row)
        return [claim(binding, MIT, "spdx-membership", _claim_value(crosswalk),
                      {**scope, "data-revision": revision}), identity_claim(row)]

    def spdx_lead(self, identifier="MIT", revision=SOURCE, release="3.2.0"):
        origin = {
            "kind": "spdx", "identifier": identifier, "name": "Fixture License", "source": revision,
            "release": release, "list_kind": "license", "deprecated": False,
            "metadata": {"licenseId": identifier, "name": "Fixture License", "isDeprecatedLicenseId": False},
            "artifacts": {"detail": {"path": f"json/details/{identifier}.json", "sha256": "a" * 64, "bytes": 1}},
        }
        return {**self.lead, "id": OTHER, "origin": origin, "history": []}

    def publisher_crosswalk(self, candidate_id=CANDIDATE):
        origin = self.lead["origin"]
        provenance = {"candidate_id": candidate_id, "origin": origin}
        exact_json = json.dumps(provenance, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
        return {
            "origin": origin["source"], "revision": "sha256:" + "c" * 64, "key": origin["identifier"],
            "claim": reference("publisher-crosswalk"),
            "scope": {"discovery-origin": "sha256:" + sha256(exact_json.encode("utf-8")).hexdigest()},
        }

    def publisher_binding(self, crosswalk):
        value = {field: crosswalk[field] for field in ("origin", "revision", "key")}
        scope = {**crosswalk.get("scope", {}), "revision": crosswalk["revision"]}
        return claim(crosswalk["claim"], MIT, "instrument-identity", _claim_value(value), scope)

    def test_active_admission_cannot_use_a_candidate_added_after_freeze(self):
        payload = self.spdx_admission()
        self.commit("Freeze the entity without its named discovery record")
        frozen = self.git("rev-parse", "HEAD").strip()
        self.write(f"registry/candidates/{OTHER[:2]}/{OTHER}.json", self.spdx_lead())
        self.select_fixture(frozen, payload)
        with patch("tools.qualification._validate_policy"):
            with self.assertRaisesRegex(DataError, "candidate|provenance"):
                qualified(Catalog(self.root), self.root)

    def test_active_spdx_claim_must_match_a_linked_exact_origin(self):
        self.write(f"registry/candidates/{OTHER[:2]}/{OTHER}.json", self.spdx_lead())
        for case in ({"candidate_ids": (CANDIDATE,)}, {"identifier": "mit"}, {"revision": "b" * 40},
                     {"release": "3.3.0"}, {"kind": "exception"}):
            with self.subTest(case=case):
                payload = self.spdx_admission(**case)
                self.commit("Freeze a crosswalk whose claim agrees with its unsupported field")
                self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)
                with patch("tools.qualification._validate_policy"):
                    with self.assertRaisesRegex(DataError, "candidate|provenance|origin"):
                        qualified(Catalog(self.root), self.root)

    def test_active_admission_rejects_an_unrelated_exported_candidate_id(self):
        self.write(f"registry/candidates/{OTHER[:2]}/{OTHER}.json", self.spdx_lead())
        payload = self.spdx_admission()
        self.commit("Freeze the entity with its only qualified discovery lead")
        report = self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)

        with patch("tools.qualification._validate_policy"):
            self.assertEqual(qualified(Catalog(self.root), self.root), (report, payload))

        mixed_payload = self.spdx_admission(candidate_ids=(OTHER, CANDIDATE))
        self.assertEqual(mixed_payload, payload)
        self.commit("Freeze the same claims with another unrelated publisher lead")
        self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)

        with patch("tools.qualification._validate_policy"):
            with self.assertRaisesRegex(DataError, f"discovery candidate {CANDIDATE}.*crosswalk"):
                qualified(Catalog(self.root), self.root)

    def test_active_spdx_crosswalk_cannot_support_two_linked_candidate_ids(self):
        original = self.spdx_lead()
        alias_id = "456789abcdef4012b123456789abcdef"
        alias = {**self.spdx_lead(identifier="mit", revision="b" * 40, release="3.3.0"), "id": alias_id,
                 "history": [{"origin": original["origin"]}]}
        candidates = {OTHER: original, alias_id: alias}
        for candidate_id, candidate in candidates.items():
            self.write(f"registry/candidates/{candidate_id[:2]}/{candidate_id}.json", candidate)
        payload = self.spdx_admission(candidate_ids=(OTHER, alias_id))
        self.commit("Freeze two candidate IDs that share one exact SPDX origin")
        self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)

        # Catalog loading ordinarily rejects these duplicate current identifiers too.
        catalog = SimpleNamespace(root=self.root, entities={MIT: json.loads(self.path.read_bytes())},
                                  candidates=candidates)
        with patch("tools.qualification._validate_policy"):
            with self.assertRaisesRegex(DataError, "ambiguous SPDX crosswalk"):
                qualified(catalog, self.root)

    def test_active_admission_rejects_incompatible_discovery_history(self):
        borrowed = self.spdx_lead()["origin"]
        cases = (
            {**self.lead, "history": [{"origin": borrowed}]},
            {**self.spdx_lead(identifier="Other-License"), "id": CANDIDATE, "history": [{"origin": borrowed}]},
            {**self.spdx_lead(), "id": CANDIDATE,
             "origin": {**borrowed, "list_kind": "exception"}, "history": [{"origin": borrowed}]},
        )
        payload = self.spdx_admission(candidate_ids=(CANDIDATE,))
        for candidate in cases:
            with self.subTest(origin=candidate["origin"]):
                self.write(self.lead_path, candidate)
                self.commit("Freeze a lead with a borrowed historical origin")
                self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)
                with patch("tools.qualification._validate_policy"):
                    with self.assertRaisesRegex(DataError, "does not match a linked frozen discovery origin"):
                        qualified(Catalog(self.root), self.root)

    def test_active_admission_accepts_independently_bound_spdx_and_publisher_leads(self):
        self.write(f"registry/candidates/{OTHER[:2]}/{OTHER}.json", self.spdx_lead())
        payload = self.spdx_admission(candidate_ids=(OTHER, CANDIDATE))
        row = json.loads(self.path.read_bytes())
        crosswalk = self.publisher_crosswalk()
        row["crosswalks"].append(crosswalk)
        self.write(self.path.relative_to(self.root), row)
        payload.append(self.publisher_binding(crosswalk))
        self.commit("Freeze two discovery leads with their own qualified crosswalks")
        report = self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)

        origin = self.lead["origin"]
        updated = {**self.lead, "origin": {**origin, "name": "Publisher's revised description"},
                   "history": [*self.lead["history"], {"origin": origin}]}
        self.write(self.lead_path, updated)
        with patch("tools.qualification._validate_policy"):
            exported_report, bound = qualified(Catalog(self.root), self.root)
            self.assertEqual(exported_report, report)
            self.assertCountEqual(bound, payload)

    def test_active_publisher_candidate_requires_exact_origin_and_candidate_fingerprint(self):
        crosswalk = self.publisher_crosswalk()
        for case in (
            {**crosswalk, "scope": {}},
            self.publisher_crosswalk(candidate_id=OTHER),
            {**crosswalk, "origin": "https://elsewhere.invalid/terms"},
            {**crosswalk, "key": self.lead["origin"]["identifier"] + " alternate edition"},
        ):
            with self.subTest(crosswalk=case):
                row = {**self.row, "crosswalks": [case]}
                self.write(self.path.relative_to(self.root), row)
                self.commit("Freeze a publisher claim without the exact associated discovery provenance")
                payload = [identity_claim(row), self.publisher_binding(case)]
                self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)
                with patch("tools.qualification._validate_policy"):
                    with self.assertRaisesRegex(DataError, f"publisher crosswalk|discovery candidate {CANDIDATE}.*crosswalk"):
                        qualified(Catalog(self.root), self.root)

    def test_active_publisher_admission_rejects_an_extra_mismatched_crosswalk(self):
        matching = self.publisher_crosswalk()
        proposed = {**self.row, "crosswalks": [matching]}
        self.write(self.path.relative_to(self.root), proposed)
        self.commit("Freeze a publisher lead with its matching crosswalk")
        payload = [identity_claim(proposed), self.publisher_binding(matching)]
        report = self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)
        with patch("tools.qualification._validate_policy"):
            self.assertEqual(qualified(Catalog(self.root), self.root), (report, payload))

        unrelated = {**self.publisher_crosswalk(candidate_id=OTHER), "revision": "sha256:" + "d" * 64,
                     "claim": reference("second-publisher-crosswalk")}
        missing_scope = {key: value for key, value in unrelated.items() if key != "scope"}
        for second in (unrelated, missing_scope):
            with self.subTest(crosswalk=second):
                proposed["crosswalks"] = [matching, second]
                self.write(self.path.relative_to(self.root), proposed)
                self.commit("Freeze the matching crosswalk alongside the unrelated locator assertion")
                self.select_fixture(self.git("rev-parse", "HEAD").strip(), [*payload, self.publisher_binding(second)])
                with patch("tools.qualification._validate_policy"):
                    with self.assertRaisesRegex(DataError, "publisher crosswalk"):
                        qualified(Catalog(self.root), self.root)

    def test_active_publisher_crosswalk_cannot_use_another_edition_from_history(self):
        crosswalk = self.publisher_crosswalk()
        row = {**self.row, "crosswalks": [crosswalk]}
        self.write(self.path.relative_to(self.root), row)
        origin = self.lead["origin"]
        other_edition = {**self.lead, "origin": {**origin, "revision": "2.0"},
                         "history": [{"origin": origin}]}
        self.write(self.lead_path, other_edition)
        self.commit("Freeze a publisher lead whose history includes a conflicting edition")
        payload = [identity_claim(row), self.publisher_binding(crosswalk)]
        self.select_fixture(self.git("rev-parse", "HEAD").strip(), payload)

        with patch("tools.qualification._validate_policy"):
            with self.assertRaisesRegex(DataError, f"publisher crosswalk|discovery candidate {CANDIDATE}.*crosswalk"):
                qualified(Catalog(self.root), self.root)

    def test_active_admission_preserves_exact_historical_spdx_origin(self):
        historical = self.spdx_lead()
        later = self.spdx_lead(identifier="mit", revision="b" * 40, release="3.3.0")
        later["history"] = [{"origin": historical["origin"]}]
        later["membership"] = {"status": "removed", "source": "c" * 40, "release": "3.4.0"}
        path = f"registry/candidates/{OTHER[:2]}/{OTHER}.json"
        self.write(path, later)
        payload = self.spdx_admission(kind="related-instrument")
        self.commit("Freeze the exact earlier membership under the retained discovery UUID")
        frozen = self.git("rev-parse", "HEAD").strip()
        report = self.select_fixture(frozen, payload)
        restored = self.spdx_lead(revision="d" * 40, release="3.5.0")
        restored["history"] = [*later["history"], {"origin": later["origin"]},
                               {"membership": later["membership"]},
                               {"membership": {"status": "restored", "source": "d" * 40, "release": "3.5.0"}}]
        self.write(path, restored)
        with patch("tools.qualification._validate_policy"):
            self.assertEqual(qualified(Catalog(self.root), self.root), (report, payload))
            self.write(path, {**restored, "history": restored["history"][1:]})
            with self.assertRaisesRegex(DataError, "candidate|provenance|origin"):
                qualified(Catalog(self.root), self.root)

    def test_candidate_and_canonical_paths_are_never_reused_or_dropped(self):
        check_history(self.catalog, self.base)
        self.catalog.candidates.clear()
        with self.assertRaisesRegex(DataError, "candidates"):
            check_history(self.catalog, self.base)
        self.catalog.entities.clear()
        with self.assertRaisesRegex(DataError, "entities"):
            check_history(self.catalog, self.base)

    def test_permanent_publisher_lead_cannot_be_reassigned(self):
        for change in (dict(identifier="Another publisher's terms", source="https://elsewhere.invalid/terms"),
                       dict(revision="2.0"),
                       dict(kind="spdx", identifier="MIT", source=SOURCE, list_kind="license", deprecated=False)):
            with self.subTest(change=change):
                current = {**self.lead, "origin": {**self.lead["origin"], **change},
                           "history": [*self.lead["history"], {"origin": self.lead["origin"]}]}
                self.write(self.lead_path, current)
                with self.assertRaisesRegex(DataError, "cannot reassign a permanent publisher lead"):
                    check_history(Catalog(self.root), self.base)

    def test_publisher_lead_allows_enrichment_and_new_leads_with_preserved_provenance(self):
        origin = {**self.lead["origin"], "name": "Exact title of Fixture Field Terms",
                  "source": "https://example.invalid/terms/1.0.txt"}
        current = {**self.lead, "origin": origin, "reason": "Pinned exact publisher text",
                   "history": [*self.lead["history"], {"origin": self.lead["origin"], "reason": self.lead["reason"]}]}
        other = {**self.lead, "id": OTHER, "origin": {**origin, "identifier": "Fixture Field Terms 2.0", "revision": "2.0"}}
        self.write(f"registry/candidates/{OTHER[:2]}/{OTHER}.json", other)
        self.write(self.lead_path, current)
        check_history(Catalog(self.root), self.base)
        for history, message in ((self.lead["history"], "must retain the previous origin"),
                                 (current["history"][1:], "history must remain append-only")):
            with self.subTest(history=history):
                self.write(self.lead_path, {**current, "history": history})
                with self.assertRaisesRegex(DataError, message):
                    check_history(Catalog(self.root), self.base)

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
        source = "research/sources/fixture.json"
        self.write(source, {"data_commit": SOURCE, "xml_commit": SOURCE, "manifests": {},
                            "population": dict.fromkeys((
                                "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                "missing_text", "missing_template",
                            ), 0)})
        self.commit("Set discovery baseline")
        base = self.git("rev-parse", "HEAD").strip()
        catalog = Catalog(self.root)
        ledger = {"schema_version": "2.0.0", "source_manifest": source, "snapshot": COVERAGE,
                  "assessment": catalog.coverage()}
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
        self.commit("Set the pre-admission baseline without qualified entities")
        base = self.git("rev-parse", "HEAD").strip()
        archive = "registry/coverage/snapshots/archived.json"
        assessment = Catalog(self.root).coverage(schema_version="1.0.0")
        snapshot = {"schema_version": "1.0.0", "source_manifest": source, "snapshot": archive,
                    "assessment": assessment}
        self.write(archive, snapshot)
        self.write(COVERAGE, snapshot)
        self.commit("Introduce a truthful archive")
        archived_commit = self.git("rev-parse", "HEAD").strip()

        def select_current():
            self.write(self.lead_path, {**self.lead, "disposition": "excluded"})
            current = {"schema_version": "2.0.0", "source_manifest": source,
                       "snapshot": "registry/coverage/snapshots/current.json",
                       "assessment": Catalog(self.root).coverage()}
            self.write(current["snapshot"], current)
            self.write(COVERAGE, current)
            self.commit("Publish a different truthful current assessment")
            return current

        current = select_current()
        validate(Catalog(self.root), base=base)

        current_base = self.git("rev-parse", "HEAD").strip()
        dropped = "registry/coverage/snapshots/transient.json"
        transient = {**current, "snapshot": dropped}
        self.write(dropped, transient)
        self.write(COVERAGE, transient)
        self.commit("Record an intervening archive")
        (self.root / dropped).unlink()
        self.write(COVERAGE, current)
        self.commit("Restore the baseline ledger and drop the intervening archive")
        validate_discovery(Catalog(self.root))
        with self.assertRaisesRegex(DataError, "transient.json: incoming coverage snapshot is missing at the candidate tip"):
            validate(Catalog(self.root), base=current_base)

        self.git("reset", "--hard", archived_commit)
        assessment["catalog"]["beyond_spdx_leads"] = 99
        self.write(archive, snapshot)
        self.write(COVERAGE, snapshot)
        self.commit("Change an already introduced historical archive")
        select_current()
        validate_discovery(Catalog(self.root))
        with self.assertRaisesRegex(DataError, "archived.json: incoming snapshot bytes changed"):
            validate(Catalog(self.root), base=base)

    def test_trusted_archive_cannot_be_overwritten_and_restored_in_incoming_history(self):
        self.path.unlink()
        source = "research/sources/fixture.json"
        self.write(source, {"data_commit": SOURCE, "xml_commit": SOURCE, "manifests": {},
                            "population": dict.fromkeys((
                                "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                "missing_text", "missing_template",
                            ), 0)})
        archive = self.snapshot.relative_to(self.root).as_posix()
        older = {"schema_version": "2.0.0", "source_manifest": source, "snapshot": archive,
                 "method": "Synthetic older assessment", "assessment": Catalog(self.root).coverage()}

        def record(ledger):
            self.write(ledger["snapshot"], ledger)
            self.write(COVERAGE, ledger)

        record(older)
        self.commit("Record the older fixture assessment")
        boundary = self.git("rev-parse", "HEAD").strip()
        trusted = {**older, "method": "Synthetic trusted assessment"}
        record(trusted)
        self.commit("Record the trusted base assessment")
        base = self.git("rev-parse", "HEAD").strip()

        def checkout_test_merge():
            head = self.git("rev-parse", "HEAD").strip()
            self.git("add", "-A")
            tree = self.git("write-tree").strip()
            merge = self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                             "-c", "commit.gpgsign=false",
                             "commit-tree", tree, "-p", base, "-p", head, "-m", "Synthetic test merge").strip()
            self.git("checkout", "--quiet", "--detach", merge)

        self.git("checkout", "--quiet", "--detach", boundary)
        self.write("unrelated.json", {"fixture": "ordinary work from the older parent"})
        self.commit("Leave the older snapshot unchanged")
        record(trusted)
        checkout_test_merge()
        validate(Catalog(self.root), base=base)

        self.git("checkout", "--quiet", "--detach", base)
        self.write(self.lead_path, {**self.lead, "disposition": "excluded"})
        rewritten = {**trusted, "assessment": Catalog(self.root).coverage()}
        record(rewritten)
        self.commit("Overwrite the trusted archive")
        overwrite = self.git("rev-parse", "HEAD").strip()

        self.write(archive, trusted)
        record({**rewritten, "snapshot": "registry/coverage/snapshots/subsequent.json"})
        self.commit("Restore the trusted bytes and record the next assessment")
        checkout_test_merge()
        validate_discovery(Catalog(self.root))
        with self.assertRaisesRegex(DataError, f"prior coverage snapshot was modified or removed.*{overwrite}"):
            validate(Catalog(self.root), base=base)

    def test_strict_validation_replays_each_incoming_snapshot_at_its_own_source_pins(self):
        (self.root / f"registry/entities/{MIT[:2]}/{MIT}.json").unlink()
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
            snapshot = {"schema_version": "2.0.0", "source_manifest": source_path, "snapshot": path,
                        "assessment": Catalog(self.root).coverage()}
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
        crosswalk = self.publisher_crosswalk()
        row = {**self.row, "crosswalks": [crosswalk]}
        self.write(self.path.relative_to(self.root), row)
        self.commit("Freeze a qualified publisher discovery link")
        frozen = self.git("rev-parse", "HEAD").strip()
        payload = [identity_claim(row), self.publisher_binding(crosswalk)]
        report = self.select_fixture(frozen, payload)
        with self.assertRaisesRegex(DataError, "requires --policy"):
            qualified(self.catalog, None)
        with patch("tools.qualification._validate_policy") as validate:
            result = qualified(self.catalog, self.root, base=self.base)
            self.assertEqual(result, (report, payload))
            validate.assert_called_once_with(self.root, self.root, self.base)
            self.path.write_bytes(self.path.read_bytes() + b"\n")
            with self.assertRaisesRegex(DataError, "bytes differ"):
                qualified(self.catalog, self.root)
            self.write("sces/releases/synthetic-fixture/qualification.json", {**report, "synthetic": True})
            with self.assertRaisesRegex(DataError, "synthetic"):
                qualified(self.catalog, self.root)

    def test_discovery_and_checked_release_views_report_separate_counts(self):
        crosswalk = self.publisher_crosswalk()
        alias = {"name": "Fixture Alias", "claim": reference("qualified-alias")}
        row = {**self.row, "crosswalks": [crosswalk], "aliases": [alias]}
        self.write(self.path.relative_to(self.root), row)
        self.commit("Freeze a qualified publisher discovery link")
        frozen = self.git("rev-parse", "HEAD").strip()
        catalog = Catalog(self.root)
        source = "research/sources/fixture.json"
        snapshot = "registry/coverage/snapshots/discovery.json"
        self.write(source, {"data_commit": SOURCE, "xml_commit": SOURCE, "manifests": {},
                            "population": dict.fromkeys((
                                "licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions",
                                "missing_text", "missing_template",
                            ), 0)})
        saved = {"schema_version": "2.0.0", "source_manifest": source, "snapshot": snapshot,
                 "assessment": catalog.coverage()}
        self.write(snapshot, saved)
        self.write("registry/coverage/current.json", saved)
        selected = [identity_claim(row), self.publisher_binding(crosswalk),
                    claim(alias["claim"], MIT, "instrument-identity", alias["name"])]

        def invoke(*arguments):
            return execute(catalog, parser().parse_args(arguments))[0]

        policy_flag = ("--policy", str(self.root))
        with self.assertRaisesRegex(DataError, "requires --policy"):
            invoke("show", "--qualified", alias["name"])
        self.select_fixture(frozen, selected)
        with patch("tools.qualification._validate_policy") as check:
            self.assertEqual(invoke("coverage")["catalog"]["accepted_entities"], 0)
            self.assertEqual(invoke("export")["status"], "development-discovery")
            self.assertEqual(invoke("show", "Fixture Field Terms 1.0")["record"]["id"], CANDIDATE)
            with self.assertRaisesRegex(DataError, "unknown catalog identifier"):
                invoke("show", alias["name"])
            check.assert_not_called()
            validated = invoke("validate", *policy_flag)
            self.assertEqual(validated["coverage"]["catalog"]["accepted_entities"], 1)
            counters = validated["coverage"]["qualification"]
            self.assertEqual(counters["selected_claims"], 3)
            self.assertEqual(counters["recorded_independently_reviewed_claims"], 0)
            self.assertEqual(invoke("coverage", *policy_flag), validated["coverage"])
            exported = invoke("export", "--qualified", *policy_flag)
            self.assertEqual(set(exported), {"release", "entities", "claims"})
            self.assertEqual(exported["entities"], [row])
            self.assertEqual(len(exported["claims"]), 3)
            self.assertEqual(invoke("show", "--qualified", *policy_flag, "FIXTURE ALIAS"),
                             {"entity": row, "incoming_relations": []})
            check.side_effect = DataError("fixture policy rejected")
            with self.assertRaisesRegex(DataError, "fixture policy rejected"):
                invoke("export", *policy_flag)
            with self.assertRaisesRegex(DataError, "fixture policy rejected"):
                invoke("show", "--qualified", *policy_flag, alias["name"])

    def test_recorded_coverage_uses_exact_current_review_state(self):
        claim = {"kind": "claim", "id": "fixture", "revision": 1}
        record = self.write("sces/records/claim/fixture--1.json", claim)
        review_refs = {}
        for field, phase in (("research", "research"), ("review", "independent-review")):
            ref = {"kind": "verification", "id": f"fixture-{field}", "revision": 1}
            self.write(f"sces/records/verification/fixture-{field}--1.json", {
                **ref, "claim": claim, "claim_sha256": sha256(record.read_bytes()).hexdigest(),
                "phase": phase, "run": {"execution": f"execution-{field}"}, "conclusion": "supported",
            })
            review_refs[field] = ref
        disposition = {"kind": "disposition", "id": "fixture-status", "revision": 1, "target": claim,
                       "evidence": "supported", "verification": "independently-reviewed", **review_refs}
        self.write("sces/records/disposition/fixture-status--1.json", disposition)
        counters = Catalog(self.root).coverage()["qualification"]
        self.assertEqual((counters["recorded_claim_revisions"], counters["recorded_independently_reviewed_claims"],
                          counters["recorded_invalidated_claim_revisions"], counters["selected_claims"]), (1, 1, 0, 0))

        original = record.read_bytes()
        record.write_bytes(original + b"\n")
        self.assertEqual(Catalog(self.root).coverage()["qualification"]["recorded_independently_reviewed_claims"], 0)
        record.write_bytes(original)

        self.write("sces/records/disposition/fixture-status--2.json", {
            **disposition, "revision": 2, "evidence": "insufficient", "verification": "invalidated",
        })
        counters = Catalog(self.root).coverage()["qualification"]
        self.assertEqual((counters["recorded_independently_reviewed_claims"],
                          counters["recorded_invalidated_claim_revisions"], counters["selected_claims"]), (0, 1, 0))

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
