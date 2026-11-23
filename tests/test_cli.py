"""Exercise the installed entry point and development data from the command line."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

from tools.records import ROOT


def command(*args, root=ROOT):
    return subprocess.run(
        [sys.executable, "-B", "-m", "tools.index", *map(str, args)],
        capture_output=True,
        cwd=root,
        check=False,
    )


class ToolTests(unittest.TestCase):
    def json_output(self, *args):
        process = command("--json", *args)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        return json.loads(process.stdout)

    def test_population_search_and_historical_identity(self):
        coverage = self.json_output("coverage")
        source = json.loads((ROOT / "research/sources/spdx-3.29.0.json").read_bytes())
        self.assertEqual(coverage["catalog"]["spdx_licenses"], source["population"]["licenses"])
        self.assertEqual(coverage["catalog"]["spdx_exceptions"], source["population"]["exceptions"])
        self.assertEqual(coverage["authentic_text"]["spdx_text_references"],
                         source["population"]["licenses"] + source["population"]["exceptions"])
        self.assertTrue(any(item["record"]["origin"]["identifier"] == "Apache-2.0"
                            for item in self.json_output("search", "apache", "--kind", "license")))
        old = self.json_output("show", "GPL-2.0+")
        self.assertTrue(old["record"]["origin"]["deprecated"])
        self.assertEqual(old["catalog_status"], "discovery")
        self.assertIsNone(self.json_output("show", "llvm-exception")["text_package"])

    def test_launcher_runs_from_another_project(self):
        with TemporaryDirectory() as temporary:
            if os.name == "nt":
                launcher = ROOT / "license-index.cmd"
                shell = os.environ.get("COMSPEC", "cmd.exe")
                invocation = f'"{shell}" /d /s /c ""{launcher}" --version"'
            else:
                invocation = ["/bin/sh", str(ROOT / "license-index"), "--version"]
            result = subprocess.run(invocation, cwd=temporary, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(result.stdout.startswith(b"license-index "))

    def test_install_and_preserve_unrelated_file(self):
        with TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve()
            target = folder / "LICENSE"
            other = folder / "NOTICE"
            other.write_bytes(b"keep me")
            baseline = (ROOT / "LICENSE").read_bytes()
            self.assertEqual(command("text", "Apache-2.0").stdout, baseline)
            preview = self.json_output("add", "Apache-2.0", "--output", target, "--dry-run")
            self.assertFalse(preview["written"])
            self.assertFalse(target.exists())
            installed = self.json_output("add", "Apache-2.0", "--output", target)
            self.assertEqual(installed["output_sha256"], hashlib.sha256(baseline).hexdigest())
            self.assertEqual(command("add", "Apache-2.0", "--output", target).returncode, 1)
            self.assertEqual(target.read_bytes(), baseline)
            self.assertEqual(other.read_bytes(), b"keep me")

    def test_compound_exception_and_corrupt_input_refused(self):
        with TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve()
            target = folder / "LICENSE"
            text = folder / "text" / "MIT.txt"
            text.parent.mkdir()
            missing = command("text", "MIT", "--artifact-root", folder, "--json")
            self.assertEqual(missing.returncode, 1)
            self.assertIn("pinned source text is missing", json.loads(missing.stderr)["error"])
            text.write_bytes(b"not the pinned text")
            for value, parameters in (
                ("MIT AND Apache-2.0", []),
                ("LLVM-exception", []),
                ("MIT", ["--artifact-root", folder, "--holder", "Example", "--year", "2026"]),
            ):
                result = command("add", value, "--output", target, *parameters, "--json")
                self.assertEqual(result.returncode, 1)
                self.assertIn("error", json.loads(result.stderr))
                self.assertFalse(target.exists())

    def test_comparison_preserves_missing_dimensions_and_sources(self):
        compared = self.json_output("compare", "MIT", "Apache-2.0", "0BSD")
        self.assertEqual(compared["status"], "provisional")
        entries = {value["identifier"]: value["dimensions"] for value in compared["records"]}
        self.assertEqual(entries["MIT"]["patent_grant"]["state"], "unresolved")
        self.assertEqual(entries["Apache-2.0"]["patent_grant"]["state"], "permission")
        self.assertTrue(entries["Apache-2.0"]["patent_grant"]["sources"])
        self.assertEqual(entries["Apache-2.0"]["termination"]["state"], "condition")
        sources = self.json_output("sources", "MIT")
        self.assertTrue(sources["research_citations"])
        self.assertIn("sha256", sources["origin"]["artifacts"]["text"])

    def test_development_export_is_deterministic_and_qualified_export_fails_closed(self):
        first = command("export")
        second = command("export")
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout)["status"], "development-discovery")
        rejected = command("export", "--qualified")
        self.assertEqual(rejected.returncode, 1)
        diagnostic = (b"requires --policy" if (ROOT / "sces/publication.json").exists()
                      else b"no active SCES-qualified release")
        self.assertIn(diagnostic, rejected.stderr)

    def test_review_plan_is_deterministic_and_keeps_uncertainty(self):
        first = self.json_output("review-plan", "MIT")
        self.assertEqual(first, self.json_output("review-plan", "mit"))
        self.assertEqual(first["status"], "provisional-review-plan")
        profile, = first["profiles"]
        patent = next(item for item in profile["facets"] if item["facet"] == "patent_grant")
        self.assertEqual(patent["next_step"], "resolve-scope")
        self.assertEqual(len(patent["draft_sha256"]), 64)

    def test_offline_zip_is_reproducible_and_usable(self):
        with TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve()
            archive = folder / "a.zip"
            duplicate = folder / "b.zip"
            for path in (archive, duplicate):
                result = command("bundle", path)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(archive.read_bytes(), duplicate.read_bytes())
            unpacked = folder / "unpacked"
            with ZipFile(archive) as package:
                self.assertNotIn("sces/publication.json", package.namelist())
                self.assertNotIn("tools/review_gate.py", package.namelist())
                package.extractall(unpacked)
            self.assertEqual(command("text", "Apache-2.0", root=unpacked).stdout,
                             (ROOT / "LICENSE").read_bytes())
            self.assertEqual(command("coverage", root=unpacked).returncode, 0)
            selection = unpacked / "sces" / "publication.json"
            selection.parent.mkdir()
            selection.write_text("invalid selection", encoding="utf-8")
            entity = unpacked / "registry" / "entities" / "ab" / "invalid.json"
            entity.parent.mkdir(parents=True)
            entity.write_text("invalid entity", encoding="utf-8")
            self.assertEqual(command("export", root=unpacked).returncode, 0)
            self.assertEqual(command("bundle", folder / "discovery.zip", root=unpacked).returncode, 0)
            self.assertEqual(command("validate", root=unpacked).returncode, 1)
            selection.unlink()
            self.assertEqual(command("validate", root=unpacked).returncode, 1)


if __name__ == "__main__":
    unittest.main()
