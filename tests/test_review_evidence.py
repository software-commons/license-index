"""Synthetic Git-object fixtures for the protected SCES review inputs."""

from base64 import b64encode
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from tools.qualification import POLICY_DIGEST, _blob_hash, _canonical
from tools.records import DataError, NoRedirects, decode, encode
from tools.review_evidence import _fetch_frozen_records, _frozen_inputs, _retrieve_frozen_records, capture_selected_evidence
from tools.review_snapshot import REPOSITORY, SnapshotError, _GIT_TIMEOUT, _git, _isolated_git_environment


SELECTION = "sces/publication.json"
RELEASE = "sces/releases/test-release/"
CLAIM = "sces/records/claim/selected--1.json"
UNSELECTED = "sces/records/claim/unselected--1.json"
SOURCE = "sces/records/source/original--1.json"
SOURCE_ARTIFACT = "sces/artifacts/citation.txt"
REVIEW = "sces/records/verification/selected-review--1.json"


def ref(kind, name):
    return {"kind": kind, "id": name, "revision": 1}


def digest(blob):
    return sha256(blob).hexdigest()


def fixture(*, reused_execution_for=None):
    inputs = {"sces/adoption.json": _canonical({"policy": "SCES-1.0", "policy_sha256": POLICY_DIGEST,
                                               "mode": "index", "repository": REPOSITORY}),
              SOURCE_ARTIFACT: b"Exact inherited citation bytes.\n"}

    def record(identity, **data):
        path = f"sces/records/{identity['kind']}/{identity['id']}--1.json"
        row = {**identity, **data}
        inputs[path] = _canonical(row)
        return row

    origin = ref("source", "original")
    upstream = ref("source", "upstream")
    record(origin, upstream=[upstream], artifact={"path": SOURCE_ARTIFACT, "sha256": digest(inputs[SOURCE_ARTIFACT])})
    record(upstream, upstream=[])
    summaries = []
    selected = ref("claim", "selected")
    premise = ref("claim", "premise")
    selected_row = record(selected, value="selected value")
    record(premise, value="supporting premise")
    selected_dependency = record(ref("dependency", "selected-premise"), claim=selected, basis=premise, relation="premise")
    record(ref("dependency", "premise-origin"), claim=premise, basis=origin, relation="support")
    record(ref("conflict", "selected-conflict"), claim=selected)
    for claim in (premise, selected):
        name = claim["id"]
        executions = {}
        for phase, suffix in (("research", "research"), ("independent-review", "review")):
            run = name + "-" + suffix
            execution = f"{name}-research" if name == reused_execution_for else run
            identity = ref("verification", run)
            trace_path = f"sces/artifacts/{run}.jsonl"
            inputs[trace_path] = _canonical({"fixture": run})
            start = "00:00:00" if phase == "research" else "00:01:00"
            end = "00:01:00" if phase == "research" else "00:02:00"
            claim_digest = digest(inputs[f"sces/records/claim/{name}--1.json"])
            row = record(identity, claim=claim, claim_sha256=claim_digest, phase=phase, conclusion="supported",
                         acquisitions=[{"capture": run}], run={
                "execution": execution, "started": f"2026-10-01T{start}Z", "completed": f"2026-10-01T{end}Z",
                "trace": {"path": trace_path, "sha256": digest(inputs[trace_path])},
            })
            summaries.append({"record": identity, "phase": phase, "execution": execution,
                              "result": "supported", "record_sha256": digest(_canonical(row))})
            executions[suffix] = identity
        record(ref("disposition", name + "-disposition"), target=claim, evidence="supported",
               verification="independently-reviewed", **executions)

    def publication(source_commit, *, previous_report=None, release="test-release", dataset="test-index"):
        release_path = f"sces/releases/{release}/"
        selection = {"release": release, "dataset": dataset, "schema_version": "1.0.0",
                     "source_commit": source_commit, "claims": [selected]}
        if previous_report is not None:
            selection["previous_report"] = previous_report
        selection_bytes = _canonical(selection)
        claims_bytes = _canonical([{"claim": selected_row, "dependencies": [selected_dependency]}])
        report = {**selection, "policy": "SCES-1.0", "policy_sha256": POLICY_DIGEST, "synthetic": False,
                  "repository": REPOSITORY, "selection_sha256": digest(selection_bytes), "verifications": summaries,
                  "artifacts": [{"path": release_path + "claims.json", "sha256": digest(claims_bytes)}],
                  "inputs_sha256": digest(_canonical({path: digest(raw) for path, raw in inputs.items()}))}
        return {SELECTION: selection_bytes, release_path + "claims.json": claims_bytes,
                release_path + "qualification.json": _canonical(report)}

    return inputs, publication


class CaptureSelectedEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        _git(self.root, "init", "--quiet", "--template=")

    def commit(self, files, message):
        for path, blob in files.items():
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(blob)
        _git(self.root, "add", "sces")
        _git(self.root, "commit", "--quiet", "-m", message,
             config=("user.name=Synthetic review fixture", "user.email=fixture@example.invalid", "commit.gpgsign=false"))
        return _git(self.root, "rev-parse", "HEAD").decode("ascii").strip()

    def test_selection_only_commit_stages_unchanged_closure_but_no_unrelated_records(self):
        inputs, make_publication = fixture()
        baseline = self.commit({**inputs, UNSELECTED: _canonical(ref("claim", "unselected"))}, "inherited evidence")
        self.assertEqual(capture_selected_evidence(self.root, baseline, REPOSITORY, base=baseline), {})
        publication = make_publication(baseline)
        candidate = self.commit(publication, "select previously committed evidence")
        changed = _git(self.root, "diff", "--name-only", baseline, candidate).decode().splitlines()
        self.assertNotIn(CLAIM, changed)
        self.assertNotIn(REVIEW, changed)
        staged = capture_selected_evidence(self.root, candidate, REPOSITORY, base=baseline)
        self.assertEqual(staged, {**inputs, **publication})
        self.assertNotIn(UNSELECTED, staged)

    def test_large_candidate_and_frozen_registries_stage_only_the_small_selected_closure(self):
        inputs, make_publication = fixture()
        unrelated = {}
        for serial in range(6):
            name = f"unrelated-{serial}"
            path = f"sces/records/claim/{name}--1.json"
            unrelated[path] = _canonical({**ref("claim", name), "fixture": "x" * (3 * 1024 * 1024)})
        self.assertGreater(sum(map(len, unrelated.values())), 16 * 1024 * 1024)
        source = self.commit({**inputs, **unrelated}, "freeze small selected evidence in a large registry")
        publication = make_publication(source)
        changed_path = "sces/records/claim/unrelated-0--1.json"
        candidate = self.commit({**publication, changed_path: unrelated[changed_path].replace(b"xxxx", b"yyyy", 1)},
                                "select the frozen closure and change an unrelated record")
        self.assertEqual(capture_selected_evidence(self.root, candidate, REPOSITORY, base=source), {**inputs, **publication})

    def test_selected_record_bytes_still_obey_the_staging_cap(self):
        inputs, make_publication = fixture()
        source_path = "sces/records/source/original--1.json"
        inputs[source_path] = _canonical({**decode(inputs[source_path]), "fixture": "x" * 32768})
        source = self.commit(inputs, "freeze a large selected source in a small registry")
        publication = make_publication(source)
        report_path = RELEASE + "qualification.json"
        report = decode(publication[report_path])
        report["inputs_sha256"] = digest(_canonical({path: digest(raw) for path, raw in inputs.items()}))
        candidate = self.commit({**publication, report_path: _canonical(report)}, "select the verified large source")
        self.assertEqual(capture_selected_evidence(self.root, candidate, REPOSITORY, base=source)[source_path], inputs[source_path])
        with patch("tools.review_evidence._MAX_EVIDENCE", 16384):
            with self.assertRaisesRegex(DataError, "SCES selected evidence exceeds the review capture limit"):
                capture_selected_evidence(self.root, candidate, REPOSITORY, base=source)

    def test_uppercase_history_path_stays_outside_selected_evidence(self):
        inputs, make_publication = fixture()
        readme = "sces/artifacts/candidate-history/README.md"
        document = b"Human-readable historical provenance.\n"
        frozen = self.commit({**inputs, readme: document}, "freeze evidence and historical documentation")
        publication = make_publication(frozen)
        candidate = self.commit(publication, "select evidence independently of the historical README")
        self.assertEqual(capture_selected_evidence(self.root, candidate, REPOSITORY, base=frozen), {**inputs, **publication})

        source = decode(inputs[SOURCE])
        source["artifact"] = {"path": readme, "sha256": digest(document)}
        invalid = self.commit({SOURCE: _canonical(source)}, "try uppercase artifact declaration")
        with self.assertRaisesRegex(DataError, "invalid SCES artifact reference"):
            capture_selected_evidence(self.root, invalid, REPOSITORY, base=frozen)

    def test_missing_inherited_verification_or_artifact_is_rejected(self):
        inputs, make_publication = fixture()
        baseline = self.commit(inputs, "freeze selected evidence")
        (self.root / REVIEW).unlink()
        candidate = self.commit(make_publication(baseline), "omit inherited verification")
        with self.assertRaisesRegex(DataError, "lacks current independent verification"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=baseline)
        candidate = self.commit({REVIEW: inputs[REVIEW], SOURCE_ARTIFACT: b"wrong citation bytes"}, "alter citation")
        with self.assertRaisesRegex(DataError, "selected artifact digest mismatch"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=baseline)

    def test_qualification_cannot_omit_review_or_claim_dependencies(self):
        inputs, make_publication = fixture()
        baseline = self.commit(inputs, "freeze selected evidence")
        publication = make_publication(baseline)
        path = RELEASE + "qualification.json"
        report = decode(publication[path])
        report["verifications"].pop()
        candidate = self.commit({**inputs, **publication, path: _canonical(report)}, "omit verification in report")
        with self.assertRaisesRegex(DataError, "omits or changes selected verification records"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=baseline)
        report = decode(publication[path])
        claims_path = RELEASE + "claims.json"
        incomplete = decode(publication[claims_path])
        incomplete[0]["dependencies"] = []
        altered = _canonical(incomplete)
        report["artifacts"][0]["sha256"] = digest(altered)
        candidate = self.commit({path: _canonical(report), claims_path: altered}, "omit dependency in payload")
        with self.assertRaisesRegex(DataError, "omits or changes selected evidence"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=baseline)

    def test_reusing_research_execution_fails_for_selected_and_inherited_claims(self):
        baseline = self.commit({"sces/artifacts/fixture.txt": b"fixture\n"}, "prepare independent fixtures")
        for claim in ("selected", "premise"):
            with self.subTest(claim=claim):
                _git(self.root, "switch", "--quiet", "--detach", baseline)
                inputs, make_publication = fixture(reused_execution_for=claim)
                frozen = self.commit(inputs, "freeze review records with reused execution")
                candidate = self.commit(make_publication(frozen), "publish the accurately rehashed report")
                with self.assertRaisesRegex(DataError, "execution"):
                    capture_selected_evidence(self.root, candidate, REPOSITORY, base=frozen)

    def test_successor_requires_the_direct_base_report_at_its_unchanged_bytes(self):
        inputs, make_publication = fixture()
        path = "sces/releases/previous-release/qualification.json"
        older_path = "sces/releases/older-release/qualification.json"
        frozen = self.commit(inputs, "freeze research inputs without the publication report")
        older = make_publication(frozen, release="older-release")
        self.commit(older, "publish the older release")
        older_link = {"path": older_path, "sha256": digest(older[older_path])}
        direct = make_publication(frozen, release="previous-release", previous_report=older_link)
        base = self.commit(direct, "publish the direct predecessor")
        previous = direct[path]
        link = {"path": path, "sha256": digest(previous)}
        candidate = self.commit(make_publication(frozen, previous_report=link), "select evidence with exact predecessor")
        staged = capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)
        self.assertEqual(staged[path], previous)
        claims_path = "sces/releases/previous-release/claims.json"
        self.assertEqual(staged[claims_path], direct[claims_path])
        with self.assertRaisesRegex(DataError, "base"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

        unchanged = self.commit({"sces/artifacts/unrelated.txt": b"unrelated\n"}, "preserve active selection")
        self.assertEqual(capture_selected_evidence(self.root, unchanged, REPOSITORY, base=candidate)[path], previous)
        rewrite = self.commit(make_publication(frozen, previous_report=older_link), "change active lineage")
        with self.assertRaisesRegex(DataError, "must preserve exact verified base release"):
            capture_selected_evidence(self.root, rewrite, REPOSITORY, base=candidate)

        changed = _canonical({"release": "previous-release", "fixture": "candidate replacement"})
        replacement = {"path": path, "sha256": digest(changed)}
        for predecessor, extra, message in (
            (None, {}, "successor must identify the verified base release"),
            (older_link, {}, "successor must identify the verified base release"),
            (replacement, {path: changed}, "must preserve exact verified base release"),
        ):
            with self.subTest(predecessor=predecessor):
                _git(self.root, "switch", "--quiet", "--detach", base)
                publication = make_publication(frozen, previous_report=predecessor)
                candidate = self.commit({**publication, **extra}, "select successor with matching internal hashes")
                with self.assertRaisesRegex(DataError, message):
                    capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_successor_and_its_predecessor_must_match_the_base_selection_dataset(self):
        inputs, make_publication = fixture()
        source = self.commit(inputs, "freeze evidence")
        publication = make_publication(source)
        base = self.commit(publication, "publish a release on the protected base")
        path = RELEASE + "qualification.json"
        link = {"path": path, "sha256": digest(publication[path])}
        renamed = self.commit(make_publication(source, release="successor", previous_report=link, dataset="other-index"),
                              "reuse base report while renaming dataset")
        with self.assertRaisesRegex(DataError, "must retain the verified base dataset"):
            capture_selected_evidence(self.root, renamed, REPOSITORY, base=base)

        _git(self.root, "switch", "--quiet", "--detach", source)
        bad_report = _canonical({**decode(publication[path]), "dataset": "other-index"})
        base = self.commit({**publication, path: bad_report}, "store a prior report with the wrong dataset")
        wrong_lineage = self.commit(make_publication(source, release="successor", previous_report={**link, "sha256": digest(bad_report)}),
                                    "reference the exact but unrelated protected report")
        with self.assertRaisesRegex(DataError, "previous report names a different dataset"):
            capture_selected_evidence(self.root, wrong_lineage, REPOSITORY, base=base)

    def test_removing_active_selection_binds_exact_protected_qualification_and_matching_advice(self):
        inputs, make_publication = fixture()
        source = self.commit(inputs, "freeze evidence")
        publication = make_publication(source)
        base = self.commit(publication, "publish the active release")
        path = RELEASE + "qualification.json"
        advice_path = "sces/advisories/test-release.json"
        report = publication[path]
        link = {"path": path, "sha256": digest(report)}
        advice = {"report": link, "affected": [ref("claim", "selected")], "reason": "Synthetic withdrawal",
                  "recorded": "2026-10-02T00:00:00Z"}
        replacement = _canonical({**decode(report), "fixture": "candidate rewrite"})
        wrong_digest = {**advice, "report": {**link, "sha256": "f" * 64}}
        rehashed = {**advice, "report": {**link, "sha256": digest(replacement)}}
        for files, message in (
            ({}, "requires a new withdrawal advisory"),
            ({"sces/advisories/other.json": _canonical(advice)}, "requires a new withdrawal advisory"),
            ({advice_path: _canonical(wrong_digest)}, "does not bind the exact verified base qualification"),
            ({advice_path: _canonical(rehashed), path: replacement}, "must preserve exact verified base release"),
            ({advice_path: _canonical({**advice, "affected": [ref("claim", "other")]})}, "lists invalid affected claims"),
            ({advice_path: _canonical({**advice, "recorded": "9999-01-01T00:00:00Z"})}, "timestamp is in the future"),
        ):
            with self.subTest(message=message, paths=sorted(files)):
                _git(self.root, "switch", "--quiet", "--detach", base)
                (self.root / SELECTION).unlink()
                candidate = self.commit(files, "try removing the active selection")
                with self.assertRaisesRegex(DataError, message):
                    capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

        _git(self.root, "switch", "--quiet", "--detach", base)
        (self.root / SELECTION).unlink()
        candidate = self.commit({advice_path: _canonical(advice)}, "withdraw the exact active qualification")
        self.assertEqual(capture_selected_evidence(self.root, candidate, REPOSITORY, base=base),
                         {"base:sces/publication.json": publication[SELECTION],
                          "sces/adoption.json": inputs["sces/adoption.json"],
                          RELEASE + "claims.json": publication[RELEASE + "claims.json"],
                          path: report, advice_path: _canonical(advice)})
        with self.assertRaisesRegex(DataError, "requires the exact verified pull-request base"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

        for paths in ((advice_path,), (path,), (advice_path, path, RELEASE + "claims.json")):
            with self.subTest(paths=paths):
                _git(self.root, "switch", "--quiet", "--detach", candidate)
                for removed in paths:
                    (self.root / removed).unlink()
                erased = self.commit({}, "try erasing inherited withdrawal history while inactive")
                with self.assertRaisesRegex(DataError, "must preserve exact verified base release and withdrawal"):
                    capture_selected_evidence(self.root, erased, REPOSITORY, base=candidate)

        _git(self.root, "switch", "--quiet", "--detach", candidate)
        replay = self.commit({SELECTION: publication[SELECTION]}, "try reselecting the already advised release")
        with self.assertRaisesRegex(DataError, "active publication is already withdrawn"):
            capture_selected_evidence(self.root, replay, REPOSITORY, base=candidate)

        _git(self.root, "switch", "--quiet", "--detach", candidate)
        kept = self.commit({"sces/artifacts/idle.txt": b"unrelated review"}, "keep withdrawal history while inactive")
        self.assertEqual(capture_selected_evidence(self.root, kept, REPOSITORY, base=candidate), {})
        revived = self.commit(make_publication(source, release="revived", previous_report=link),
                              "reactivate using the retained withdrawal")
        self.assertEqual(capture_selected_evidence(self.root, revived, REPOSITORY, base=kept)[advice_path],
                         _canonical(advice))

    def test_reactivation_requires_an_exact_withdrawal_advisory(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze evidence")
        archive = make_publication(frozen, release="withdrawn")
        path = "sces/releases/withdrawn/qualification.json"
        advisory = "sces/advisories/withdrawn.json"
        link = {"path": path, "sha256": digest(archive[path])}
        successor = make_publication(frozen, previous_report=link)
        del archive[SELECTION]
        base = self.commit(archive, "archive report without an active selection or advisory")
        for predecessor in (None, link):
            with self.subTest(predecessor=predecessor):
                _git(self.root, "switch", "--quiet", "--detach", base)
                candidate = self.commit(make_publication(frozen, previous_report=predecessor),
                                        "try publishing over an unadvised protected archive")
                with self.assertRaisesRegex(DataError, "inactive base contains a qualification without its withdrawal advisory"):
                    capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

        advice = {"report": link, "affected": [ref("claim", "selected")], "reason": "Synthetic withdrawal",
                  "recorded": "2026-10-01T00:00:00Z"}
        _git(self.root, "switch", "--quiet", "--detach", base)
        unbound = {**advice, "report": {**link, "sha256": "f" * 64}}
        unbound_base = self.commit({advisory: _canonical(unbound)}, "archive advisory with different report digest")
        candidate = self.commit(successor, "claim lineage to an unbound archived report")
        with self.assertRaisesRegex(DataError, "withdrawal advisory does not bind"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=unbound_base)

        _git(self.root, "switch", "--quiet", "--detach", base)
        advised_base = self.commit({advisory: _canonical(advice)}, "record exact withdrawal on the verified base")
        omission = self.commit(make_publication(frozen), "omit the predecessor from both selection and report")
        with self.assertRaisesRegex(DataError, "withdrawn"):
            capture_selected_evidence(self.root, omission, REPOSITORY, base=advised_base)

        _git(self.root, "switch", "--quiet", "--detach", advised_base)
        candidate = self.commit(successor, "link to the advised withdrawn archive")
        captured = capture_selected_evidence(self.root, candidate, REPOSITORY, base=advised_base)
        self.assertEqual(captured[path], archive[path])
        self.assertEqual(captured[advisory], _canonical(advice))

        _git(self.root, "switch", "--quiet", "--detach", base)
        unrelated = _canonical({**decode(archive[path]), "dataset": "INVALID DATASET"})
        altered_advice = {**advice, "report": {**link, "sha256": digest(unrelated)}}
        invalid_base = self.commit({path: unrelated, advisory: _canonical(altered_advice)},
                                   "seed legacy inactive history with an invalid dataset label")
        candidate = self.commit(make_publication(frozen), "try treating invalid history as a new dataset")
        with self.assertRaisesRegex(DataError, "invalid protected SCES qualification dataset"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=invalid_base)

    def test_claims_only_in_inactive_base_cannot_be_treated_as_empty_history(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze evidence")
        archive = make_publication(frozen, release="incomplete")
        claims = "sces/releases/incomplete/claims.json"
        base = self.commit({claims: archive[claims]}, "retain an incomplete inactive archive")
        candidate = self.commit(make_publication(frozen), "attempt a new root over incomplete history")
        with self.assertRaisesRegex(DataError, "inactive base contains an incomplete archived release bundle"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_inactive_predecessor_follows_verified_lineage_independently_of_advisory_time(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze evidence")

        def archive(slug, recorded, predecessor=None):
            files = make_publication(frozen, previous_report=predecessor, release=slug)
            path = f"sces/releases/{slug}/qualification.json"
            link = {"path": path, "sha256": digest(files[path])}
            advisory = _canonical({"report": link, "affected": [ref("claim", "selected")],
                                   "reason": "Synthetic withdrawal", "recorded": recorded})
            return files, link, {f"sces/advisories/{slug}.json": advisory}

        first, first_link, first_advice = archive("older", "2026-10-02T00:00:00Z")
        initial = self.commit(first, "publish the first release")
        latest, latest_link, latest_advice = archive("newest", "2026-10-02T00:00:00Z", first_link)
        replaces_first = self.commit({**latest, **first_advice}, "replace and withdraw the old active release")
        staged = capture_selected_evidence(self.root, replaces_first, REPOSITORY, base=initial)
        self.assertEqual(staged["base:sces/publication.json"], first[SELECTION])

        _git(self.root, "switch", "--quiet", "--detach", initial)
        unadvised = self.commit(latest, "replace without withdrawing the prior release yet")
        (self.root / SELECTION).unlink()
        partial = self.commit(latest_advice, "leave an older unadvised release without an active selection")
        # The pinned SCES unadvised-withdrawal gate applies to every retained release.
        with self.assertRaisesRegex(DataError, "inactive publication retains a qualification without a withdrawal advisory"):
            capture_selected_evidence(self.root, partial, REPOSITORY, base=unadvised)
        _git(self.root, "switch", "--quiet", "--detach", unadvised)
        active = self.commit(first_advice, "append historical withdrawal without changing active selection")
        staged = capture_selected_evidence(self.root, active, REPOSITORY, base=unadvised)
        first_advisory_path, = first_advice
        self.assertEqual(staged[first_advisory_path], first_advice[first_advisory_path])

        successor = make_publication(frozen, previous_report=latest_link)
        for timestamp in ("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"):
            with self.subTest(timestamp=timestamp):
                _git(self.root, "switch", "--quiet", "--detach", active)
                _, _, latest_advice = archive("newest", timestamp, first_link)
                (self.root / SELECTION).unlink()
                withdrawn = self.commit(latest_advice, "withdraw the newer release")
                staged = capture_selected_evidence(self.root, withdrawn, REPOSITORY, base=active)
                self.assertIn("sces/advisories/newest.json", staged)
                older_selection = make_publication(frozen, previous_report=first_link)
                previous = self.commit(older_selection, "select an older ancestor")
                with self.assertRaisesRegex(DataError, "reactivation must identify the verified dataset's latest withdrawn"):
                    capture_selected_evidence(self.root, previous, REPOSITORY, base=withdrawn)
                _git(self.root, "switch", "--quiet", "--detach", withdrawn)
                candidate = self.commit(successor, "link to the newest qualified descendant")
                staged = capture_selected_evidence(self.root, candidate, REPOSITORY, base=withdrawn)
                self.assertEqual(staged[latest_link["path"]], latest[latest_link["path"]])

        _git(self.root, "switch", "--quiet", "--detach", withdrawn)
        unrelated, _, advice = archive("disconnected", "2026-10-03T00:00:00Z")
        del unrelated[SELECTION]
        ambiguous = self.commit({**unrelated, **advice}, "seed legacy history with another same-dataset root")
        candidate = self.commit(successor, "attempt reactivation with multiple protected lineage tips")
        with self.assertRaisesRegex(DataError, "no unique successor tip"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=ambiguous)

    def test_reactivation_checks_large_archive_without_staging_its_entire_history(self):
        inputs, make_publication = fixture()
        source = self.commit(inputs, "freeze evidence")
        history, sizes, previous = {}, [], None
        for serial in range(5):
            slug = f"archive-{serial}"
            files = make_publication(source, release=slug, previous_report=previous)
            del files[SELECTION]
            report_path = f"sces/releases/{slug}/qualification.json"
            if serial < 4:
                files[report_path] = _canonical({**decode(files[report_path]), "limitations": ["x" * 4000]})
            previous = {"path": report_path, "sha256": digest(files[report_path])}
            advisory_path = f"sces/advisories/{slug}.json"
            files[advisory_path] = _canonical({"report": previous, "affected": [ref("claim", "selected")],
                                                "reason": "Synthetic withdrawal", "recorded": "2026-10-01T00:00:00Z"})
            history.update(files)
            sizes.append(sum(map(len, files.values())))

        base = self.commit(history, "retain an inactive archive of individually bounded releases")
        candidate = self.commit(make_publication(source, previous_report=previous), "reactivate the qualified tip")
        expected = capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)
        staging_limit = sum(map(len, expected.values())) + 1024
        self.assertLess(max(sizes), staging_limit)
        self.assertGreater(sum(sizes), staging_limit)
        with patch("tools.review_evidence._MAX_EVIDENCE", staging_limit):
            captured = capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)
        self.assertEqual(captured, expected)
        self.assertEqual(captured[report_path], history[report_path])
        self.assertEqual(captured[advisory_path], history[advisory_path])
        self.assertNotIn("sces/releases/archive-0/qualification.json", captured)
        with (patch("tools.review_evidence._MAX_BLOB", max(map(len, history.values())) - 1),
              self.assertRaisesRegex(DataError, "incomplete or oversized SCES Git blob")):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_another_datasets_advised_archive_cannot_hide_replaced_claims_bytes(self):
        inputs, make_publication = fixture()
        source = self.commit(inputs, "freeze evidence")
        publication = make_publication(source)
        archive = make_publication(source, release="corrupt", dataset="different-index")
        del archive[SELECTION]
        path = "sces/releases/corrupt/qualification.json"
        payload = "sces/releases/corrupt/claims.json"
        archive[payload] = _canonical([])
        advisory = _canonical({"report": {"path": path, "sha256": digest(archive[path])},
                               "affected": [ref("claim", "selected")], "reason": "Synthetic withdrawal",
                               "recorded": "2026-10-01T00:00:00Z"})
        base = self.commit({**archive, "sces/advisories/corrupt.json": advisory}, "seed malformed protected archive")
        candidate = self.commit(publication, "try a separate dataset bootstrap without a lineage pointer")
        with self.assertRaisesRegex(DataError, "archived claims payload does not match the exact qualification artifact"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_pairs_reject_changed_claim_digest_shared_traces_and_shared_capture(self):
        baseline = self.commit({"sces/artifacts/fixture.txt": b"fixture\n"}, "prepare independent fixtures")
        for name, field, message in (
            ("selected", "claim_sha256", "does not bind the exact claim revision bytes"),
            ("premise", "claim_sha256", "does not bind the exact claim revision bytes"),
            ("premise", "trace-path", "require distinct trace paths and digests"),
            ("premise", "trace-sha", "require distinct trace paths and digests"),
            ("premise", "capture", "share an acquisition capture"),
        ):
            with self.subTest(name=name, field=field):
                _git(self.root, "switch", "--quiet", "--detach", baseline)
                inputs, make_publication = fixture()
                path = f"sces/records/verification/{name}-review--1.json"
                row = decode(inputs[path])
                research = decode(inputs[f"sces/records/verification/{name}-research--1.json"])
                if field == "claim_sha256":
                    row[field] = "f" * 64
                elif field == "capture":
                    row["acquisitions"] = research["acquisitions"]
                else:
                    descriptor = "path" if field == "trace-path" else "sha256"
                    row["run"]["trace"][descriptor] = research["run"]["trace"][descriptor]
                inputs[path] = _canonical(row)
                base = self.commit(inputs, "freeze invalid verification records")
                publication = make_publication(base)
                candidate = self.commit(publication, "attempt to qualify the invalid verification pair")
                with self.assertRaisesRegex(DataError, message):
                    capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_latest_research_cannot_be_paired_with_a_review_that_started_earlier(self):
        inputs, make_publication = fixture()
        research_path = "sces/records/verification/premise-research--1.json"
        later_path = "sces/records/verification/premise-research--2.json"
        disposition = "sces/records/disposition/premise-disposition--1.json"
        later = decode(inputs[research_path])
        later["revision"] = 2
        later["run"].update(execution="later-premise-research", completed="2026-10-01T00:01:30Z")
        earlier_trace = later["run"]["trace"]["path"]
        later_trace = "sces/artifacts/later-premise-research.jsonl"
        inputs[later_trace] = _canonical({"fixture": "later-premise-research"})
        later["run"]["trace"] = {"path": later_trace, "sha256": digest(inputs[later_trace])}
        later["acquisitions"] = [{"capture": "later-premise-research"}]
        inputs[later_path] = _canonical(later)
        later_reference = {**ref("verification", "premise-research"), "revision": 2}
        inputs[disposition] = _canonical({**decode(inputs[disposition]), "research": later_reference})
        base = self.commit(inputs, "freeze newer research beside the previous review")
        publication = make_publication(base)
        report_path = RELEASE + "qualification.json"
        report = decode(publication[report_path])
        active_inputs = {path: digest(blob) for path, blob in inputs.items() if path not in {research_path, earlier_trace}}
        report["inputs_sha256"] = digest(_canonical(active_inputs))
        for summary in report["verifications"]:
            if summary["record"]["id"] == later["id"]:
                summary.update(record=later_reference, execution=later["run"]["execution"],
                               record_sha256=digest(inputs[later_path]))
        candidate = self.commit({**publication, report_path: _canonical(report)}, "try the independently stale verification pair")
        with self.assertRaisesRegex(DataError, "independent review started before the latest research execution completed"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_predecessor_introduced_in_frozen_history_cannot_replace_verified_base(self):
        inputs, make_publication = fixture()
        base = self.commit(inputs, "verified base without a predecessor")
        path = "sces/releases/previous-release/qualification.json"
        previous = _canonical({"release": "previous-release"})
        frozen = self.commit({path: previous}, "add a predecessor after the verified base")
        candidate = self.commit(make_publication(frozen, previous_report={"path": path, "sha256": digest(previous)}),
                                "point to the newly added report")
        with self.assertRaisesRegex(DataError, "outside the active qualification"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_self_consistent_candidate_evidence_must_still_match_the_frozen_commit(self):
        inputs, make_publication = fixture()
        baseline = self.commit(inputs, "freeze selected evidence")
        inputs[SOURCE_ARTIFACT] = b"Later substituted source bytes.\n"
        origin = decode(inputs[SOURCE])
        origin["artifact"]["sha256"] = digest(inputs[SOURCE_ARTIFACT])
        inputs[SOURCE] = _canonical(origin)
        candidate = self.commit({**inputs, **make_publication(baseline)}, "recalculate candidate source digests")
        with self.assertRaisesRegex(DataError, "selected artifact descriptors differ from the frozen source commit"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=baseline)

    def test_rebuilt_report_cannot_hide_a_frozen_conflict(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze the selected claim with its conflict")
        conflict = "sces/records/conflict/selected-conflict--1.json"
        del inputs[conflict]
        (self.root / conflict).unlink()
        candidate = self.commit(make_publication(frozen), "omit conflict and rebuild report digests")
        with self.assertRaisesRegex(DataError, "selected record membership differs from the frozen source commit"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=frozen)

    def test_rebuilt_report_cannot_hide_a_frozen_dependency(self):
        inputs, make_publication = fixture()
        omitted = "sces/records/dependency/selected-extra--1.json"
        extra = _canonical({**ref("dependency", "selected-extra"), "claim": ref("claim", "selected"),
                            "basis": ref("source", "original"), "relation": "support"})
        frozen = self.commit({**inputs, omitted: extra}, "freeze the additional supporting dependency")
        (self.root / omitted).unlink()
        candidate = self.commit(make_publication(frozen), "publish the smaller candidate and rebuilt report")
        with self.assertRaisesRegex(DataError, "selected record membership differs from the frozen source commit"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=frozen)

    def test_same_membership_cannot_change_frozen_record_bytes(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze selected evidence")
        path = "sces/records/dependency/selected-premise--1.json"
        inputs[path] = b"\n" + inputs[path]
        candidate = self.commit({**inputs, **make_publication(frozen)}, "change only the selected record bytes")
        with self.assertRaisesRegex(DataError, f"differs from its frozen source commit: {path}"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=frozen)

    def test_frozen_source_commit_cannot_be_a_tree_object(self):
        inputs, make_publication = fixture()
        base = self.commit(inputs, "freeze selected evidence")
        tree = _git(self.root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
        candidate = self.commit(make_publication(tree), "select a tree instead of a commit")
        with self.assertRaisesRegex(DataError, "not a commit object"):
            capture_selected_evidence(self.root, candidate, REPOSITORY, base=base)

    def test_missing_frozen_source_fetch_uses_the_fixed_license_remote_and_exact_sha(self):
        inputs, make_publication = fixture()
        unrelated = _canonical(ref("claim", "unselected"))
        baseline = self.commit({**inputs, UNSELECTED: unrelated}, "freeze evidence with an unrelated record")
        publication = make_publication(baseline)
        (self.root / UNSELECTED).unlink()
        base = self.commit({}, "retain the exact base separately from frozen evidence")
        candidate = self.commit(publication, "select previously committed evidence")
        _git(self.root, "config", "uploadpack.allowFilter", "true")
        _git(self.root, "config", "uploadpack.allowReachableSHA1InWant", "true")
        upstream = self.root.resolve().as_uri()
        unrelated_oid = _blob_hash(unrelated, "sha1")
        fetches = []

        def local_git(directory, operation, *arguments, config=(), **options):
            if operation == "fetch":
                fetches.append((arguments, config))
                arguments = (*arguments[:-2], upstream, arguments[-1])
                config = (*config, "protocol.file.allow=always")
            return _git(directory, operation, *arguments, config=config, **options)

        def obtain_missing(repository, commit, paths, limit):
            self.assertEqual((repository, commit, paths), (REPOSITORY, baseline, {UNSELECTED: unrelated_oid}))
            self.assertGreaterEqual(limit, len(unrelated))
            with self.assertRaises(SnapshotError):
                _git(shallow, "cat-file", "-t", unrelated_oid)
            return {UNSELECTED: unrelated}

        with TemporaryDirectory() as directory:
            shallow = Path(directory).resolve()
            _git(shallow, "init", "--bare", "--quiet", "--template=")
            _git(shallow, "fetch", "--quiet", "--depth=2", upstream, candidate, config=("protocol.file.allow=always",))
            with self.assertRaises(SnapshotError):
                _git(shallow, "cat-file", "-t", baseline)
            old_git_environment = _isolated_git_environment()
            old_git_environment.pop("GIT_NO_LAZY_FETCH")
            with (patch("tools.review_evidence._git", side_effect=local_git),
                  patch("tools.review_snapshot._isolated_git_environment", return_value=old_git_environment),
                  patch("tools.review_evidence._fetch_frozen_records", side_effect=obtain_missing) as fallback):
                self.assertEqual(capture_selected_evidence(shallow, candidate, REPOSITORY, base=base), {**inputs, **publication})

        fallback.assert_called_once()
        self.assertEqual(fetches, [((
            "--quiet", "--depth=1", "--filter=blob:none", "--no-tags", "--no-recurse-submodules",
            "--no-auto-maintenance", "--", "https://github.com/software-commons/license-index.git", baseline,
        ), ("http.followRedirects=false", "fetch.fsckObjects=true", "protocol.allow=never", "protocol.https.allow=always"))])

    def test_frozen_source_fetch_rejects_a_different_sha(self):
        responses = [SnapshotError("object missing"), b"", b"", b"a" * 40 + b"\n"]
        with patch("tools.review_evidence._git", side_effect=responses):
            with self.assertRaisesRegex(DataError, "did not fetch the exact frozen SCES source commit"):
                _frozen_inputs(self.root, "b" * 40)

    def test_directory_at_selection_path_is_not_silently_treated_as_absence(self):
        candidate = self.commit({SELECTION + "/marker": b"not a publication selection"}, "unsupported selection path")
        with self.assertRaisesRegex(DataError, "selection is not a regular"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)


class FrozenRecordTransportTests(unittest.TestCase):
    def test_worker_reads_only_the_fixed_https_path_with_no_proxy_redirects_or_oversize(self):
        commit, raw = "b" * 40, b"{}\n"
        payload = encode({"repository": REPOSITORY, "commit": commit, "paths": [UNSELECTED], "limit": len(raw)})
        url = f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{UNSELECTED}"
        for status, content in ((200, raw), (302, raw), (200, raw + b"x")):
            with self.subTest(status=status, length=len(content)):
                response = MagicMock(status=status, headers={})
                response.__enter__.return_value = response
                response.geturl.return_value = url
                response.read.return_value = content
                output = BytesIO()
                with (patch("tools.review_evidence.sys.stdin", SimpleNamespace(buffer=BytesIO(payload))),
                      patch("tools.review_evidence.sys.stdout", SimpleNamespace(buffer=output)),
                      patch("tools.review_evidence.build_opener") as opener):
                    opener.return_value.open.return_value = response
                    if status == 200 and content == raw:
                        _retrieve_frozen_records()
                    else:
                        with self.assertRaises(DataError):
                            _retrieve_frozen_records()
                    proxy, redirect = opener.call_args.args
                    self.assertEqual(proxy.proxies, {})
                    self.assertIsInstance(redirect, NoRedirects)
                    self.assertIsNone(redirect.redirect_request(None, None, 302, "", {}, "https://example.invalid/"))
                    query, = opener.return_value.open.call_args.args
                    self.assertEqual(query.full_url, url)
                    self.assertEqual(query.get_method(), "GET")
                    self.assertEqual(query.get_header("Accept-encoding"), "identity")
                    if status == 200:
                        response.read.assert_called_once_with(len(raw) + 1)
                    else:
                        response.read.assert_not_called()
                if status == 200 and content == raw:
                    self.assertEqual(decode(output.getvalue()), {UNSELECTED: b64encode(raw).decode("ascii")})

    def test_parent_recomputes_exact_blob_oid_and_enforces_isolated_worker_deadline(self):
        commit, raw = "b" * 40, b"{}\n"
        expected = {UNSELECTED: _blob_hash(raw, "sha1")}
        options = ((raw, None), (b"{} ", "does not match its Git object"), (raw + b"x", "capture limit"))
        for content, error in options:
            result = CompletedProcess([], 0, encode({UNSELECTED: b64encode(content).decode("ascii")}))
            with self.subTest(length=len(content)), patch("tools.review_evidence.subprocess.run", return_value=result) as run:
                if error:
                    with self.assertRaisesRegex(DataError, error):
                        _fetch_frozen_records(REPOSITORY, commit, expected, len(raw))
                else:
                    self.assertEqual(_fetch_frozen_records(REPOSITORY, commit, expected, len(raw)), {UNSELECTED: raw})
                invocation = run.call_args
                self.assertEqual(invocation.args[0][1:5], ["-I", "-S", "-B", "-c"])
                self.assertEqual(invocation.kwargs["timeout"], _GIT_TIMEOUT)
                self.assertLessEqual(set(invocation.kwargs["env"]), {"SYSTEMROOT", "WINDIR"})
        with patch("tools.review_evidence.subprocess.run", side_effect=TimeoutExpired("fixture", 90)):
            with self.assertRaisesRegex(DataError, "retrieval could not complete"):
                _fetch_frozen_records(REPOSITORY, commit, expected, len(raw))
