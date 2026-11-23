"""Synthetic Git-object fixtures for the protected SCES review inputs."""

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.qualification import POLICY_DIGEST, _canonical
from tools.records import DataError, decode
from tools.review_evidence import capture_selected_evidence
from tools.review_snapshot import _git


REPOSITORY = "software-commons/test-index"
SELECTION = "sces/publication.json"
RELEASE = "sces/releases/test-release/"
CLAIM = "sces/records/claim/selected--1.json"
UNSELECTED = "sces/records/claim/unselected--1.json"
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
    selection = {"release": "test-release", "dataset": "test-index", "schema_version": "1.0.0",
                 "source_commit": "b" * 40, "claims": [selected]}
    selection_bytes = _canonical(selection)
    claims_bytes = _canonical([{"claim": selected_row, "dependencies": [selected_dependency]}])
    report = {**selection, "policy": "SCES-1.0", "policy_sha256": POLICY_DIGEST, "synthetic": False,
              "repository": REPOSITORY, "selection_sha256": digest(selection_bytes), "verifications": summaries,
              "artifacts": [{"path": RELEASE + "claims.json", "sha256": digest(claims_bytes)}],
              "inputs_sha256": digest(_canonical({path: digest(raw) for path, raw in inputs.items()}))}
    publication = {SELECTION: selection_bytes, RELEASE + "claims.json": claims_bytes,
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
        inputs, publication = fixture()
        baseline = self.commit({**inputs, UNSELECTED: _canonical(ref("claim", "unselected"))}, "inherited evidence")
        self.assertEqual(capture_selected_evidence(self.root, baseline, REPOSITORY), {})
        candidate = self.commit(publication, "select previously committed evidence")
        changed = _git(self.root, "diff", "--name-only", baseline, candidate).decode().splitlines()
        self.assertNotIn(CLAIM, changed)
        self.assertNotIn(REVIEW, changed)
        staged = capture_selected_evidence(self.root, candidate, REPOSITORY)
        self.assertEqual(staged, {**inputs, **publication})
        self.assertNotIn(UNSELECTED, staged)

    def test_missing_inherited_verification_or_artifact_is_rejected(self):
        inputs, publication = fixture()
        del inputs[REVIEW]
        candidate = self.commit({**inputs, **publication}, "omit inherited verification")
        with self.assertRaisesRegex(DataError, "lacks current independent verification"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)
        correct, _ = fixture()
        candidate = self.commit({REVIEW: correct[REVIEW], SOURCE_ARTIFACT: b"wrong citation bytes"}, "alter citation")
        with self.assertRaisesRegex(DataError, "selected artifact digest mismatch"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_qualification_cannot_omit_review_or_claim_dependencies(self):
        inputs, publication = fixture()
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

    def test_directory_at_selection_path_is_not_silently_treated_as_absence(self):
        candidate = self.commit({SELECTION + "/marker": b"not a publication selection"}, "unsupported selection path")
        with self.assertRaisesRegex(DataError, "selection is not a regular"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)
