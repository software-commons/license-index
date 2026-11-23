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

    def test_uppercase_history_path_stays_outside_selected_evidence(self):
        inputs, make_publication = fixture()
        readme = "sces/artifacts/candidate-history/README.md"
        document = b"Human-readable historical provenance.\n"
        frozen = self.commit({**inputs, readme: document}, "freeze evidence and historical documentation")
        publication = make_publication(frozen)
        candidate = self.commit(publication, "select evidence independently of the historical README")
        self.assertEqual(capture_selected_evidence(self.root, candidate, REPOSITORY), {**inputs, **publication})

        source = decode(inputs[SOURCE])
        source["artifact"] = {"path": readme, "sha256": digest(document)}
        invalid = self.commit({SOURCE: _canonical(source)}, "try uppercase artifact declaration")
        with self.assertRaisesRegex(DataError, "invalid SCES artifact reference"):
            capture_selected_evidence(self.root, invalid, REPOSITORY)

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
        with self.assertRaisesRegex(DataError, "selected artifact descriptors differ from the frozen source commit"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_rebuilt_report_cannot_hide_a_frozen_conflict(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze the selected claim with its conflict")
        conflict = "sces/records/conflict/selected-conflict--1.json"
        del inputs[conflict]
        (self.root / conflict).unlink()
        candidate = self.commit(make_publication(frozen), "omit conflict and rebuild report digests")
        with self.assertRaisesRegex(DataError, "selected record membership differs from the frozen source commit"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_rebuilt_report_cannot_hide_a_frozen_dependency(self):
        inputs, make_publication = fixture()
        omitted = "sces/records/dependency/selected-extra--1.json"
        extra = _canonical({**ref("dependency", "selected-extra"), "claim": ref("claim", "selected"),
                            "basis": ref("source", "original"), "relation": "support"})
        frozen = self.commit({**inputs, omitted: extra}, "freeze the additional supporting dependency")
        (self.root / omitted).unlink()
        candidate = self.commit(make_publication(frozen), "publish the smaller candidate and rebuilt report")
        with self.assertRaisesRegex(DataError, "selected record membership differs from the frozen source commit"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_same_membership_cannot_change_frozen_record_bytes(self):
        inputs, make_publication = fixture()
        frozen = self.commit(inputs, "freeze selected evidence")
        inputs[CLAIM] = b"\n" + inputs[CLAIM]
        candidate = self.commit({**inputs, **make_publication(frozen)}, "change only the selected record bytes")
        with self.assertRaisesRegex(DataError, f"differs from its frozen source commit: {CLAIM}"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_frozen_source_commit_cannot_be_a_tree_object(self):
        inputs, make_publication = fixture()
        self.commit(inputs, "freeze selected evidence")
        tree = _git(self.root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
        candidate = self.commit(make_publication(tree), "select a tree instead of a commit")
        with self.assertRaisesRegex(DataError, "not a commit object"):
            capture_selected_evidence(self.root, candidate, REPOSITORY)

    def test_missing_frozen_source_fetch_uses_the_fixed_license_remote_and_exact_sha(self):
        inputs, make_publication = fixture()
        unrelated = _canonical(ref("claim", "unselected"))
        baseline = self.commit({**inputs, UNSELECTED: unrelated}, "freeze evidence with an unrelated record")
        publication = make_publication(baseline)
        (self.root / UNSELECTED).unlink()
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
            _git(shallow, "fetch", "--quiet", "--depth=1", upstream, candidate, config=("protocol.file.allow=always",))
            with self.assertRaises(SnapshotError):
                _git(shallow, "cat-file", "-t", baseline)
            old_git_environment = _isolated_git_environment()
            old_git_environment.pop("GIT_NO_LAZY_FETCH")
            with (patch("tools.review_evidence._git", side_effect=local_git),
                  patch("tools.review_snapshot._isolated_git_environment", return_value=old_git_environment),
                  patch("tools.review_evidence._fetch_frozen_records", side_effect=obtain_missing) as fallback):
                self.assertEqual(capture_selected_evidence(shallow, candidate, REPOSITORY), {**inputs, **publication})

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
