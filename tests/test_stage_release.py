"""Test candidate packaging with synthetic artifacts and a mocked policy boundary."""

from hashlib import sha256
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from tools.li_install import InstallError
from tools.qualification import POLICY_DIGEST
from tools.records import DataError, encode
from tools.stage_release import stage
from tools.verify_release import GATES, verify


class ReleaseStageTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.catalog = SimpleNamespace(root=self.root)
        self.output = self.root / "candidate.zip"
        self.release = "fixture"
        self.stem = f"sces/releases/{self.release}"
        self.selection = {"release": self.release, "source_commit": "a" * 40}
        claim = {"kind": "claim", "id": "fixture", "revision": 1}
        self.claims = [{"claim": claim, "dependencies": []}]
        self.selection_file = self.write("sces/publication.json", self.selection)
        self.payload = self.write(f"{self.stem}/claims.json", self.claims)
        self.report = {
            **self.selection, "repository": "software-commons/license-index", "dataset": "license-index",
            "dataset_version": "fixture", "schema_version": "1.0.0", "policy_sha256": POLICY_DIGEST,
            "policy": "SCES-1.0", "synthetic": False, "gates": GATES.copy(), "claims": [claim],
            "review_kind": "separate-codex-executions", "outcome": "structure-and-recorded-review-qualified",
            "coverage": {"selected": 1},
            "selection_sha256": sha256(self.selection_file.read_bytes()).hexdigest(),
            "artifacts": [{"path": f"{self.stem}/claims.json", "sha256": sha256(self.payload.read_bytes()).hexdigest()}],
        }
        self.report_file = self.write(f"{self.stem}/qualification.json", self.report)
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Synthetic trusted base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("add", "sces")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Synthetic release artifacts")
        self.commit = self.git("rev-parse", "HEAD").strip()
        policy_boundary = patch("tools.stage_release.validate", return_value=(self.report, self.claims))
        self.validate = policy_boundary.start()
        self.addCleanup(policy_boundary.stop)
        schema_bytes = b"synthetic schema\n"
        schema = patch("tools.stage_release.policy_schema", return_value=schema_bytes)
        schema.start()
        self.addCleanup(schema.stop)
        schema_pin = patch("tools.verify_release.CONTRACTS_SHA256", sha256(schema_bytes).hexdigest())
        schema_pin.start()
        self.addCleanup(schema_pin.stop)

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encode(value))
        return path

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.root), *arguments], check=True,
                              capture_output=True, text=True).stdout

    def test_exact_bytes_and_checksums_are_reproducible(self):
        request = stage(self.catalog, self.root, self.output, base=self.base)
        self.validate.assert_called_once_with(self.catalog, base=self.base, policy=self.root)
        self.assertEqual(request["status"], "awaiting-separate-release-authorization")
        self.assertEqual(request["publication_candidate_commit"], self.commit)
        self.assertEqual(request["history_base_commit"], self.base)
        self.assertEqual(request["source_commit"], "a" * 40)
        self.assertEqual(request["archive"]["sha256"], sha256(self.output.read_bytes()).hexdigest())
        with ZipFile(self.output) as bundle:
            self.assertEqual(set(bundle.namelist()), {
                "claims.json", "qualification.json", "sces-contracts.schema.json", "SHA256SUMS",
            })
            self.assertEqual(bundle.read("claims.json"), self.payload.read_bytes())
            self.assertEqual(bundle.read("qualification.json"), self.report_file.read_bytes())
            for line in bundle.read("SHA256SUMS").decode().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(digest, sha256(bundle.read(name)).hexdigest())
        repeat = self.root / "repeat.zip"
        stage(self.catalog, self.root, repeat, base=self.base)
        self.assertEqual(repeat.read_bytes(), self.output.read_bytes())
        raw = encode(request)
        observed = verify(raw, sha256(raw).hexdigest(), archive_path=self.output)
        self.assertEqual(observed["selected_claims"], 1)
        self.assertEqual(observed["publication_commit"], self.commit)
        with self.assertRaises(InstallError):
            stage(self.catalog, self.root, self.output, base=self.base)

    def test_no_active_release_or_policy_failure_preserves_no_output(self):
        self.validate.return_value = (None, [])
        with self.assertRaisesRegex(DataError, "no active SCES"):
            stage(self.catalog, self.root, self.output, base=self.base)
        self.validate.side_effect = DataError("fixture policy rejection")
        with self.assertRaisesRegex(DataError, "policy rejection"):
            stage(self.catalog, self.root, self.output, base=self.base)
        self.assertFalse(self.output.exists())

    def test_even_equivalent_dirty_json_is_rejected(self):
        self.payload.write_bytes(self.payload.read_bytes() + b"\n")
        with self.assertRaisesRegex(DataError, "differs from the candidate commit"):
            stage(self.catalog, self.root, self.output, base=self.base)
        self.assertFalse(self.output.exists())

    def test_git_replacement_cannot_stage_different_artifacts_under_the_candidate_sha(self):
        self.payload.write_bytes(self.payload.read_bytes() + b"\n")
        self.report["artifacts"][0]["sha256"] = sha256(self.payload.read_bytes()).hexdigest()
        self.report_file.write_bytes(encode(self.report))
        self.git("add", "sces")
        tree = self.git("write-tree").strip()
        replacement = self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                               "commit-tree", tree, "-p", self.base, "-m", "Synthetic replacement").strip()
        self.git("replace", self.commit, replacement)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.commit)
        self.assertEqual(self.git("show", f"{self.commit}:{self.stem}/claims.json").encode(), self.payload.read_bytes())
        with self.assertRaisesRegex(DataError, "differs from the candidate commit"):
            stage(self.catalog, self.root, self.output, base=self.base)
        self.validate.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_git_graft_cannot_supply_a_false_predecessor(self):
        tree = self.git("rev-parse", "HEAD^{tree}").strip()
        unrelated = self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                             "commit-tree", tree, "-m", "Synthetic unrelated commit").strip()
        (self.root / ".git/info/grafts").write_bytes(f"{self.commit} {unrelated}\n".encode("ascii"))
        self.git("merge-base", "--is-ancestor", unrelated, self.commit)
        with self.assertRaisesRegex(DataError, "Git failed"):
            stage(self.catalog, self.root, self.output, base=unrelated)
        self.validate.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_local_only_validation_inputs_are_rejected_before_validation(self):
        for relative in ("sces/records/fixture.json", "registry/entities/fixture.json"):
            with self.subTest(relative=relative):
                local = self.write(relative, {})
                with self.assertRaisesRegex(DataError, "paths differ from the candidate commit"):
                    stage(self.catalog, self.root, self.output, base=self.base)
                self.validate.assert_not_called()
                self.assertFalse(self.output.exists())
                local.unlink()

    def assert_protected_output_rejected(self, output):
        with patch("tools.stage_release.collect") as collect:
            with self.assertRaisesRegex(DataError, "outside the validated input directories"):
                stage(self.catalog, self.root, output, base=self.base)
        collect.assert_not_called()
        self.validate.assert_not_called()
        self.assertFalse(output.exists())

    def test_output_under_validated_input_directory_is_rejected_before_collection(self):
        for section in ("sces", "registry", "research", "legal-texts"):
            with self.subTest(section=section):
                parent = self.root / section / "staging"
                parent.mkdir(parents=True)
                self.assert_protected_output_rejected(parent / "candidate.zip")
                self.assertEqual(list(parent.iterdir()), [])

    def test_output_parent_symlink_into_validated_inputs_is_rejected_before_collection(self):
        destination = self.root / "registry"
        destination.mkdir()
        with TemporaryDirectory() as outside:
            alias = Path(outside).resolve() / "alias"
            try:
                alias.symlink_to(destination, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            self.assert_protected_output_rejected(alias / "candidate.zip")
            self.assertEqual(list(destination.iterdir()), [])

    def test_checked_views_cannot_be_replaced_with_a_different_payload(self):
        self.validate.return_value = (self.report, [{"claim": {"id": "different"}}])
        with self.assertRaisesRegex(DataError, "differ from the checked release"):
            stage(self.catalog, self.root, self.output, base=self.base)
        self.assertFalse(self.output.exists())

    def test_candidate_cannot_supply_its_own_trusted_history(self):
        with self.assertRaisesRegex(DataError, "trusted predecessor"):
            stage(self.catalog, self.root, self.output, base=self.commit)
        self.validate.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_archive_filename_must_survive_github_upload(self):
        output = self.root / "candidate version.zip"
        with self.assertRaisesRegex(DataError, "GitHub-safe ZIP filename"):
            stage(self.catalog, self.root, output, base=self.base)
        self.validate.assert_not_called()
        self.assertFalse(output.exists())
