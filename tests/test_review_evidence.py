"""Synthetic Git-object fixtures for the protected SCES review inputs."""

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.qualification import POLICY_DIGEST, _canonical
from tools.records import DataError, decode
from tools.review_evidence import _frozen_inputs, capture_selected_evidence
from tools.review_snapshot import REPOSITORY, SnapshotError, _git


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


def fixture():
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
            identity = ref("verification", run)
            trace_path = f"sces/artifacts/{run}.jsonl"
            inputs[trace_path] = b'{"fixture":"inert trace"}\n'
            row = record(identity, claim=claim, phase=phase, conclusion="supported", run={
                "execution": run, "completed": "2026-10-01T00:00:00Z",
                "trace": {"path": trace_path, "sha256": digest(inputs[trace_path])},
            })
            summaries.append({"record": identity, "phase": phase, "execution": run,
                              "result": "supported", "record_sha256": digest(_canonical(row))})
            executions[suffix] = identity
        record(ref("disposition", name + "-disposition"), target=claim, evidence="supported",
               verification="independently-reviewed", **executions)

    def publication(source_commit):
        selection = {"release": "test-release", "dataset": "test-index", "schema_version": "1.0.0",
                     "source_commit": source_commit, "claims": [selected]}
        selection_bytes = _canonical(selection)
        claims_bytes = _canonical([{"claim": selected_row, "dependencies": [selected_dependency]}])
        report = {**selection, "policy": "SCES-1.0", "policy_sha256": POLICY_DIGEST, "synthetic": False,
                  "repository": REPOSITORY, "selection_sha256": digest(selection_bytes), "verifications": summaries,
                  "artifacts": [{"path": RELEASE + "claims.json", "sha256": digest(claims_bytes)}],
                  "inputs_sha256": digest(_canonical({path: digest(raw) for path, raw in inputs.items()}))}
        return {SELECTION: selection_bytes, RELEASE + "claims.json": claims_bytes,
                RELEASE + "qualification.json": _canonical(report)}

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
        self.assertEqual(capture_selected_evidence(self.root, baseline, REPOSITORY), {})
        publication = make_publication(baseline)
        candidate = self.commit(publication, "select previously committed evidence")
        changed = _git(self.root, "diff", "--name-only", baseline, candidate).decode().splitlines()
        self.assertNotIn(CLAIM, changed)
        self.assertNotIn(REVIEW, changed)
        staged = capture_selected_evidence(self.root, candidate, REPOSITORY)
        self.assertEqual(staged, {**inputs, **publication})
        self.assertNotIn(UNSELECTED, staged)

    def test_missing_inherited_verification_or_artifact_is_rejected(self):
        inputs, make_publication = fixture()
        baseline = self.commit(inputs, "freeze selected evidence")
        (self.root / REVIEW).unlink()
        candidate = self.commit(make_publication(baseline), "omit inherited verification")
        with self.assertRaisesRegex(DataError, "lacks current independent verification"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)
        candidate = self.commit({REVIEW: inputs[REVIEW], SOURCE_ARTIFACT: b"wrong citation bytes"}, "alter citation")
        with self.assertRaisesRegex(DataError, "selected artifact digest mismatch"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_qualification_cannot_omit_review_or_claim_dependencies(self):
        inputs, make_publication = fixture()
        baseline = self.commit(inputs, "freeze selected evidence")
        publication = make_publication(baseline)
        path = RELEASE + "qualification.json"
        report = decode(publication[path])
        report["verifications"].pop()
        candidate = self.commit({**inputs, **publication, path: _canonical(report)}, "omit verification in report")
        with self.assertRaisesRegex(DataError, "omits or changes selected verification records"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)
        report = decode(publication[path])
        claims_path = RELEASE + "claims.json"
        incomplete = decode(publication[claims_path])
        incomplete[0]["dependencies"] = []
        altered = _canonical(incomplete)
        report["artifacts"][0]["sha256"] = digest(altered)
        candidate = self.commit({path: _canonical(report), claims_path: altered}, "omit dependency in payload")
        with self.assertRaisesRegex(DataError, "omits or changes selected evidence"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_self_consistent_candidate_evidence_must_still_match_the_frozen_commit(self):
        inputs, make_publication = fixture()
        baseline = self.commit(inputs, "freeze selected evidence")
        inputs[SOURCE_ARTIFACT] = b"Later substituted source bytes.\n"
        origin = decode(inputs[SOURCE])
        origin["artifact"]["sha256"] = digest(inputs[SOURCE_ARTIFACT])
        inputs[SOURCE] = _canonical(origin)
        candidate = self.commit({**inputs, **make_publication(baseline)}, "recalculate candidate source digests")
        with self.assertRaisesRegex(DataError, "frozen source commit: sces/artifacts/citation.txt"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_frozen_source_commit_cannot_be_a_tree_object(self):
        inputs, make_publication = fixture()
        self.commit(inputs, "freeze selected evidence")
        tree = _git(self.root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
        candidate = self.commit(make_publication(tree), "select a tree instead of a commit")
        with self.assertRaisesRegex(DataError, "not a commit object"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_missing_frozen_source_fetch_uses_the_fixed_license_remote_and_exact_sha(self):
        source = "b" * 40
        with patch("tools.review_evidence._git") as git:
            git.side_effect = [SnapshotError("object missing"), b"", f"{source}\n".encode("ascii"), b"commit\n", b""]
            self.assertEqual(_frozen_inputs(self.root, source), {})
            self.assertEqual(git.call_args_list[1].args, (
                self.root, "fetch", "--quiet", "--depth=1", "--filter=blob:none", "--no-tags",
                "--no-recurse-submodules", "--no-auto-maintenance", "--",
                "https://github.com/software-commons/license-index.git", source,
            ))
            self.assertEqual(git.call_args_list[1].kwargs["config"], (
                "http.followRedirects=false", "fetch.fsckObjects=true", "protocol.allow=never", "protocol.https.allow=always",
            ))
            git.side_effect = [SnapshotError("object missing"), b"", b"a" * 40 + b"\n"]
            with self.assertRaisesRegex(DataError, "did not fetch the exact frozen SCES source commit"):
                _frozen_inputs(self.root, source)

    def test_directory_at_selection_path_is_not_silently_treated_as_absence(self):
        candidate = self.commit({SELECTION + "/marker": b"not a publication selection"}, "unsupported selection path")
        with self.assertRaisesRegex(DataError, "selection is not a regular"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)
