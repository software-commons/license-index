"""Exercise the installed entry point and development data from the command line."""

import hashlib
import json
import os
from pathlib import Path
import re
from shutil import copytree
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from tools.distribution import discovery_export, validate_profiles, validate_texts
from tools.index import install_target, parser, text_or_add
from tools.records import ROOT, Catalog, DataError, encode
from tools.review_plan import admission_packet, build_plan


def command(*args, root=ROOT):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(root / "tools/run_isolated.py"), "index", *map(str, args)],
        capture_output=True,
        cwd=root,
        check=False,
    )


class ToolTests(unittest.TestCase):
    def json_output(self, *args):
        process = command("--json", *args)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        return json.loads(process.stdout)

    def discovery_counts(self):
        if (ROOT / "sces/publication.json").is_file():
            rejected = command("coverage")
            self.assertEqual(rejected.returncode, 1)
            self.assertIn(b"requires --policy", rejected.stderr)
            return Catalog(ROOT).coverage()
        return self.json_output("coverage")

    def test_lgplv3_recipe_cannot_bypass_companion_gate(self):
        catalog = Catalog(ROOT)
        catalog.packaged["LGPL-3.0-only"]["install"] = "unchanged"
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "COPYING.LESSER"
            args = parser().parse_args(["add", "LGPL-3.0-only", "--output", str(output)])
            with self.assertRaisesRegex(DataError, "Include both publisher texts"):
                text_or_add(catalog, args)
            args.gplv3_text = ROOT / "legal-texts/gpl-3.0.txt"
            with self.assertRaisesRegex(DataError, "incorrect GPLv3 companion requirement"):
                text_or_add(catalog, args)
            self.assertFalse(output.exists())

    def test_install_refuses_another_edition_or_version_notice(self):
        catalog = Catalog(ROOT)
        with TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "LICENSE"
            for requested, different in (
                ("EPL-1.0", "EPL-2.0"),
                ("GPL-1.0-only", "GPL-3.0-only"),
                ("GPL-2.0-only", "GPL-2.0-or-later"),
            ):
                with self.subTest(requested=requested), patch.dict(
                    catalog.packaged, {requested: catalog.packaged[different]}
                ):
                    args = parser().parse_args(["add", requested, "--output", str(output)])
                    with self.assertRaisesRegex(DataError, re.escape(requested)):
                        text_or_add(catalog, args)
                    self.assertFalse(output.exists())

    def test_installation_coverage_respects_spdx_lifecycle(self):
        catalog = Catalog(ROOT)
        for identifier, coverage_field in (
            ("MIT", "requires_verified_spdx_input"),
            ("Apache-2.0", "offline"),
            ("LGPL-3.0-only", "requires_verified_companion"),
        ):
            row = catalog.resolve(identifier)
            with self.subTest(identifier=identifier, status="current"):
                self.assertIs(install_target(catalog, identifier), row)
                self.assertIn(identifier, catalog.coverage()["installation"][coverage_field])
            for status, changed, update in (
                ("removed", row, {"membership": {"status": "removed"}}),
                ("deprecated", row["origin"], {"deprecated": True}),
            ):
                with self.subTest(identifier=identifier, status=status), patch.dict(changed, update):
                    with self.assertRaisesRegex(DataError, "current, nondeprecated identifier"):
                        install_target(catalog, identifier)
                    self.assertNotIn(identifier, catalog.coverage()["installation"][coverage_field])

    def test_population_search_and_historical_identity(self):
        coverage = self.discovery_counts()
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

    def test_human_list_and_search_label_discovery_dispositions(self):
        for query, disposition in (("Countdown", "excluded"), ("Commons Clause", "non-license")):
            with self.subTest(query=query):
                result = command("search", query)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                row, = result.stdout.decode("utf-8").splitlines()
                self.assertIn(f"[discovery candidate, {disposition}]", row)

        listing = command("list", "--kind", "other")
        self.assertEqual(listing.returncode, 0, listing.stderr.decode())
        rows = listing.stdout.decode("utf-8").splitlines()
        self.assertGreater(len(rows), 1)
        self.assertTrue(all("[discovery candidate, " in row for row in rows))

    def test_shared_spdx_and_publisher_identifier_requires_a_candidate_uuid(self):
        catalog = Catalog(ROOT)
        spdx = catalog.resolve("MIT")
        publishers = [row for row in catalog.non_spdx if row["origin"]["kind"] == "publisher"]
        for publisher, identifier in zip(publishers[:2], ("mit", "gpl-3.0-only"), strict=True):
            colliding = {**publisher, "origin": {**publisher["origin"], "identifier": identifier}}
            catalog.candidates[colliding["id"]] = colliding
            catalog.non_spdx[catalog.non_spdx.index(publisher)] = colliding
        publisher_mit = catalog.candidates[publishers[0]["id"]]

        with self.assertRaisesRegex(DataError, "ambiguous candidate identifier: MIT"):
            catalog.resolve("MIT")
        with self.assertRaisesRegex(DataError, "ambiguous candidate identifier: mit"):
            install_target(catalog, "mit")
        self.assertIs(catalog.resolve(publisher_mit["id"]), publisher_mit)
        self.assertIs(install_target(catalog, spdx["id"]), spdx)
        with self.assertRaisesRegex(DataError, "no provisional profile to review"):
            build_plan(catalog, [publisher_mit["id"]])
        self.assertIsNone(catalog.spdx_exact("mit"))
        validate_profiles(catalog)
        validate_texts(catalog)

    def test_coverage_binds_individual_dimension_assessments(self):
        catalog = Catalog(ROOT)
        permissions = {"state": "unresolved", "text": "Fixture permission", "sources": []}
        restrictions = {"state": "inapplicable", "text": "Fixture restriction", "sources": []}
        catalog.profiles = {
            "MIT": {"dimensions": {"permissions": permissions, "restrictions": restrictions},
                    "scenarios": [{"text": "One fixture scenario"}]},
        }
        legacy = catalog.coverage(schema_version="2.0.0")["research"]
        original = catalog.coverage()["research"]
        self.assertEqual(original["dimensions"], 2)
        self.assertEqual(original["scenarios"], 1)
        self.assertEqual(original["dimension_states"], {"inapplicable": 1, "unresolved": 1})
        with patch.dict(permissions, {"state": "inapplicable"}), patch.dict(restrictions, {"state": "unresolved"}):
            reassessed = catalog.coverage()["research"]
            self.assertEqual(catalog.coverage(schema_version="2.0.0")["research"], legacy)
        self.assertEqual(reassessed["dimension_states"], original["dimension_states"])
        self.assertNotEqual(reassessed["dimension_assessments_sha256"], original["dimension_assessments_sha256"])

    def test_launcher_runs_from_another_project(self):
        with TemporaryDirectory() as temporary:
            environment = None
            project = Path(temporary)
            if os.name == "nt":
                install = project / "License Index!"
                install.mkdir()
                (install / "license-index.cmd").write_bytes((ROOT / "license-index.cmd").read_bytes())
                copytree(ROOT / "tools", install / "tools")
                python_home = Path(sys.executable).parent
                environment = dict(os.environ, PATH=os.pathsep.join(map(str, (install, python_home))))
                shell = os.environ.get("COMSPEC", "cmd.exe")
                invocation = [shell, "/d", "/v:on", "/c", "license-index.cmd", "--version"]
            else:
                invocation = ["/bin/sh", str(ROOT / "license-index"), "--version"]
            result = subprocess.run(invocation, cwd=project, env=environment, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(result.stdout.startswith(b"license-index "))

    def test_required_entry_point_isolates_root_and_environment_imports(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            copytree(ROOT / "tools", root / "tools")
            (root / "json.py").write_text("SYNTHETIC_SHADOW = True\n", encoding="utf-8")
            (root / "pathlib.py").write_text("SYNTHETIC_SHADOW = True\n", encoding="utf-8")
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_imports.py").write_text(
                "import json\n"
                "from pathlib import Path\n"
                "import sys\n"
                "import unittest\n"
                "import tools\n"
                "class Imports(unittest.TestCase):\n"
                "    def test_import_paths(self):\n"
                "        root = Path(__file__).resolve().parents[1]\n"
                "        self.assertEqual(list(tools.__path__), [str(root / 'tools')])\n"
                "        self.assertNotIn(str(root), sys.path)\n"
                "        self.assertNotEqual(Path(json.__file__).parent, root)\n",
                encoding="utf-8",
            )
            invocation = [sys.executable, "-I", "-B", str(root / "tools/run_isolated.py")]
            environment = {**os.environ, "PYTHONPATH": str(root)}
            for args, expected in ((["index", "--version"], b"license-index "), (["tests"], b"Ran 1 test")):
                with self.subTest(args=args):
                    result = subprocess.run([*invocation, *args], cwd=root, env=environment, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertIn(expected, result.stdout + result.stderr)

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
            if os.name == "posix":
                target.write_bytes(b"original notice")
                replaced = self.json_output("add", "Apache-2.0", "--output", target, "--force")
                self.assertEqual(Path(replaced["preserved_output"]).read_bytes(), b"original notice")
                self.assertEqual(target.read_bytes(), baseline)

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
        lgpl = self.json_output("compare", "LGPL-2.0-only", "LGPL-2.1-only")
        self.assertEqual(lgpl["status"], "provisional")
        older, newer = [record["dimensions"]["linked_works"] for record in lgpl["records"]]
        self.assertEqual(older["sources"][0]["locator"], "§6 and §6(a)–(d)")
        self.assertIn("shared-library mechanism", newer["text"])
        self.assertEqual(newer["sources"][0]["locator"], "§6 and §6(b)")
        eclipse = self.json_output("compare", "CPL-1.0", "EPL-1.0", "EPL-2.0")
        self.assertEqual(eclipse["status"], "provisional")
        editions = {row["identifier"]: row["dimensions"] for row in eclipse["records"]}
        self.assertIn("litigation against a Contributor", editions["CPL-1.0"]["termination"]["text"])
        self.assertIn("Program itself", editions["EPL-1.0"]["termination"]["text"])
        self.assertIn("subsequent distribution", editions["EPL-2.0"]["alternate_license"]["text"])
        documentation = self.json_output("compare", "GFDL-1.1-only", "GFDL-1.2-only", "GFDL-1.3-only")
        self.assertEqual(documentation["status"], "provisional")
        gfdl = {row["identifier"]: row["dimensions"] for row in documentation["records"]}
        self.assertIn("examples of Opaque formats", gfdl["GFDL-1.1-only"]["format_classification"]["text"])
        self.assertIn("designed for human modification", gfdl["GFDL-1.2-only"]["format_classification"]["text"])
        self.assertIn("before 1 August 2009", gfdl["GFDL-1.3-only"]["historical_relicensing"]["text"])
        exceptions = self.json_output("compare", "GCC-exception-3.1", "Linux-syscall-note")
        self.assertEqual(exceptions["status"], "provisional")
        gcc, linux = [row["dimensions"] for row in exceptions["records"]]
        self.assertIn("all Target Code", gcc["exception_scope"]["text"])
        self.assertIn("ordinary use", linux["exception_scope"]["text"])
        odbl = self.json_output("explain", "ODbL-1.0")["profile"]
        self.assertIn("Public Use of a Produced Work", odbl["dimensions"]["share_alike"]["text"])
        sources = self.json_output("sources", "MIT")
        self.assertTrue(sources["research_citations"])
        self.assertIn("sha256", sources["origin"]["artifacts"]["text"])

    def test_comparison_treats_unprofiled_entries_as_unresolved(self):
        compared = self.json_output("compare", "GFDL-1.1-only", "GFDL-1.3-invariants-or-later")
        self.assertEqual(compared["status"], "provisional")
        profiled, unprofiled = compared["records"]
        profiled_dimensions = profiled["dimensions"]
        unprofiled_dimensions = unprofiled["dimensions"]
        self.assertEqual(unprofiled["identifier"], "GFDL-1.3-invariants-or-later")
        self.assertEqual(profiled_dimensions.keys(), unprofiled_dimensions.keys())
        self.assertTrue(profiled_dimensions["format_classification"]["sources"])
        for dimension in unprofiled_dimensions.values():
            self.assertEqual(dimension["state"], "unresolved")
            self.assertEqual(dimension["sources"], [])

    def test_development_export_is_deterministic_and_qualified_export_fails_closed(self):
        if (ROOT / "sces/publication.json").is_file():
            for flags in ((), ("--qualified",)):
                rejected = command("export", *flags)
                self.assertEqual(rejected.returncode, 1)
                self.assertIn(b"requires --policy", rejected.stderr)
            return
        first = command("export")
        second = command("export")
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout)["status"], "development-discovery")
        rejected = command("export", "--qualified")
        self.assertEqual(rejected.returncode, 1)
        self.assertIn(b"no active SCES-qualified release", rejected.stderr)

    def test_review_plan_is_deterministic_and_keeps_uncertainty(self):
        first = self.json_output("review-plan", "MIT")
        self.assertEqual(first, self.json_output("review-plan", "mit"))
        self.assertEqual(first["status"], "provisional-review-plan")
        profile, = first["profiles"]
        patent = next(item for item in profile["facets"] if item["facet"] == "patent_grant")
        self.assertEqual(patent["next_step"], "resolve-scope")
        self.assertEqual(len(patent["draft_sha256"]), 64)

    def test_admission_plan_accounts_for_the_full_discovery_ledger(self):
        plan = self.json_output("review-plan", "--admission")
        self.assertEqual(plan["status"], "discovery-admission-plan")
        self.assertEqual(plan["selected"], len({item["candidate_id"] for item in plan["candidates"]}))
        coverage = self.discovery_counts()["catalog"]
        self.assertEqual(plan["by_population"]["listed"], coverage["spdx_licenses"] + coverage["spdx_exceptions"])
        self.assertEqual(plan["by_population"]["publisher-lead"], coverage["beyond_spdx_leads"])
        self.assertEqual(plan["by_population"].get("historical-only", 0), coverage["spdx_historical_only"])
        self.assertEqual(plan["listed_deprecated"],
                         coverage["spdx_deprecated_licenses"] + coverage["spdx_deprecated_exceptions"])
        observed = plan["current_census"]
        manifest_bytes = (ROOT / observed["manifest_path"]).read_bytes()
        self.assertEqual(observed["manifest_sha256"], hashlib.sha256(manifest_bytes).hexdigest())
        for name, descriptor in observed["membership_lists"].items():
            expected = json.loads(manifest_bytes)["manifests"][name]
            self.assertEqual({key: value for key, value in descriptor.items() if key != "url"}, expected)
            self.assertIn(f"/{observed['data_commit']}/{expected['path']}", descriptor["url"])

    def test_admission_plan_preserves_legacy_scope_and_unprofiled_leads(self):
        identifiers = ("GPL-2.0-with-classpath-exception", "LLVM-exception", "Commons Clause License Condition v1.0",
                       "GCC-exception-2.0", "Zlib")
        plan = self.json_output("review-plan", "--admission", *identifiers)
        self.assertEqual(plan, self.json_output("review-plan", "--admission", *reversed(identifiers), "llvm-exception"))
        packets = {item["identifier"]: item for item in plan["candidates"]}
        legacy = packets[identifiers[0]]
        record = json.loads((ROOT / legacy["record_path"]).read_bytes())
        self.assertEqual(legacy["record_json_sha256"], hashlib.sha256(encode(record)).hexdigest())
        self.assertEqual(legacy["upstream"]["replacement_guidance"], record["origin"]["upstream_replacements"])
        replacement = legacy["upstream"]["artifacts"]["replacement_source"]
        self.assertIn(legacy["upstream"]["data_commit"], replacement["url"])
        self.assertTrue(replacement["url"].endswith(replacement["path"]))
        self.assertIn("identifier-deprecation", legacy["work"])
        llvm = packets[identifiers[1]]
        self.assertEqual(llvm["kind"], "exception")
        self.assertIn("exception-relationship", llvm["work"])
        self.assertEqual(llvm["explanation_status"], "provisional")
        publisher = packets[identifiers[2]]
        self.assertEqual(publisher["disposition"], "non-license")
        publisher_record = json.loads((ROOT / publisher["record_path"]).read_bytes())
        self.assertEqual(publisher["record_json_sha256"], hashlib.sha256(encode(publisher_record)).hexdigest())
        self.assertNotIn("upstream", publisher)
        self.assertIn("scope-disposition", publisher["work"])
        self.assertEqual(packets[identifiers[3]]["explanation_status"], "unresearched")
        self.assertEqual(packets[identifiers[4]]["kind"], "license")
        self.assertEqual(packets[identifiers[4]]["explanation_status"], "unresearched")

    def test_admission_packet_distinguishes_older_origin_and_removal(self):
        catalog = Catalog(ROOT)
        current = catalog.resolve("LLVM-exception")
        older = {**current, "origin": {**current["origin"], "source": "a" * 40}}
        listed = admission_packet(catalog, older)
        self.assertEqual(listed["population"], "listed")
        self.assertIn("/" + "a" * 40 + "/", listed["upstream"]["origin_membership_list"])
        self.assertIn("current census", listed["work"]["spdx-membership"])
        removed = admission_packet(catalog, {**older, "membership": {"status": "removed"}})
        self.assertEqual(removed["population"], "historical-only")
        self.assertIn("former membership", removed["work"]["spdx-membership"])
        self.assertIn("for absence", removed["work"]["spdx-membership"])

    def test_offline_zip_is_reproducible_and_usable(self):
        with TemporaryDirectory() as temporary:
            folder = Path(temporary).resolve()
            archive = folder / "a.zip"
            duplicate = folder / "b.zip"
            if (ROOT / "sces/publication.json").is_file():
                rejected = command("bundle", archive)
                self.assertEqual(rejected.returncode, 1)
                self.assertIn(b"requires --policy", rejected.stderr)
                self.assertFalse(archive.exists())
                return
            for path in (archive, duplicate):
                result = command("bundle", path)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(archive.read_bytes(), duplicate.read_bytes())
            unpacked = folder / "unpacked"
            with ZipFile(archive) as package:
                snapshot = json.loads(package.read("registry/coverage/current.json"))
                predecessor = snapshot["predecessor"]
                self.assertEqual(hashlib.sha256(package.read(predecessor["snapshot"])).hexdigest(),
                                 predecessor["sha256"])
                self.assertNotIn("sces/publication.json", package.namelist())
                self.assertFalse(any(name.startswith("sces/records/") for name in package.namelist()))
                self.assertNotIn("tools/audit_claims.py", package.namelist())
                self.assertNotIn("tools/audit_receipts.py", package.namelist())
                self.assertNotIn("tools/capture_source.py", package.namelist())
                self.assertNotIn("tools/public_source_mcp.py", package.namelist())
                self.assertNotIn("tools/review_gate.py", package.namelist())
                self.assertNotIn("tools/review_commission.py", package.namelist())
                self.assertNotIn("tools/review_queue.py", package.namelist())
                self.assertNotIn("tools/stage_release.py", package.namelist())
                self.assertNotIn("tools/verify_release.py", package.namelist())
                self.assertNotIn("tools/release_download.py", package.namelist())
                self.assertNotIn("tools/review_evidence.py", package.namelist())
                self.assertNotIn("tools/review_protection.py", package.namelist())
                manifest = json.loads(package.read("legal-texts/manifest.json"))
                for identifier in ("CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC-BY-ND-4.0",
                                   "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0"):
                    package_source = manifest[identifier]
                    text = package.read(package_source["path"])
                    self.assertEqual(hashlib.sha256(text).hexdigest(), package_source["sha256"])
                    self.assertEqual(package_source["install"], "unchanged")
                for edition in ("1.1", "1.2", "1.3"):
                    path = f"legal-texts/fdl-{edition}.txt"
                    expected = (ROOT / path).read_bytes()
                    self.assertEqual(package.read(path), expected)
                    for variant in ("", "-invariants", "-no-invariants"):
                        for version_choice in ("only", "or-later"):
                            identifier = f"GFDL-{edition}{variant}-{version_choice}"
                            with self.subTest(identifier=identifier):
                                self.assertEqual(manifest[identifier]["path"], path)
                                self.assertEqual(manifest[identifier]["install"], "unchanged")
                                self.assertEqual(manifest[identifier]["sha256"], hashlib.sha256(expected).hexdigest())
                package.extractall(unpacked)
            for name in ("research/sources/private/backup.md", "research/sources/unselected.json",
                         "legal-texts/.private", "legal-texts/backup.txt", "tools/local_draft.py", "docs/draft.md",
                         "registry/coverage/snapshots/unselected.json"):
                path = unpacked / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Synthetic file outside the distribution inventory", encoding="utf-8")
            repacked = folder / "repacked.zip"
            result = command("bundle", repacked, root=unpacked)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(archive.read_bytes(), repacked.read_bytes())
            self.assertEqual(command("text", "Apache-2.0", root=unpacked).stdout,
                             (ROOT / "LICENSE").read_bytes())
            exception = "GCC-exception-3.1"
            expected = (ROOT / "legal-texts/gcc-runtime-exception-3.1.txt").read_bytes()
            self.assertEqual(command("text", exception, root=unpacked).stdout, expected)
            self.assertNotIn("install", manifest[exception])
            exception_output = folder / "COPYING.RUNTIME"
            rejected = command("add", exception, "--output", exception_output, root=unpacked)
            self.assertEqual(rejected.returncode, 1)
            self.assertIn(b"standalone license", rejected.stderr)
            self.assertFalse(exception_output.exists())
            for identifier, text_name in (
                ("AGPL-3.0-only", "agpl-3.0.txt"),
                ("AGPL-3.0-or-later", "agpl-3.0.txt"),
                ("CC-BY-4.0", "cc-by-4.0.txt"),
                ("CC-BY-NC-4.0", "cc-by-nc-4.0.txt"),
                ("CC-BY-NC-ND-4.0", "cc-by-nc-nd-4.0.txt"),
                ("CC-BY-NC-SA-4.0", "cc-by-nc-sa-4.0.txt"),
                ("CC-BY-ND-4.0", "cc-by-nd-4.0.txt"),
                ("CC-BY-SA-4.0", "cc-by-sa-4.0.txt"),
                ("CC0-1.0", "cc0-1.0.txt"),
                ("EPL-1.0", "epl-1.0.txt"),
                ("EPL-2.0", "epl-2.0.txt"),
                ("GFDL-1.1-only", "fdl-1.1.txt"),
                ("GFDL-1.2-invariants-or-later", "fdl-1.2.txt"),
                ("GFDL-1.3-no-invariants-only", "fdl-1.3.txt"),
                ("GPL-1.0-only", "gpl-1.0.txt"),
                ("GPL-1.0-or-later", "gpl-1.0.txt"),
                ("GPL-2.0-or-later", "gpl-2.0.txt"),
                ("GPL-3.0-or-later", "gpl-3.0.txt"),
                ("LGPL-2.0-only", "lgpl-2.0.txt"),
                ("LGPL-2.0-or-later", "lgpl-2.0.txt"),
                ("LGPL-2.1-only", "lgpl-2.1.txt"),
                ("LGPL-2.1-or-later", "lgpl-2.1.txt"),
                ("PolyForm-Noncommercial-1.0.0", "polyform-noncommercial-1.0.0.md"),
                ("PolyForm-Small-Business-1.0.0", "polyform-small-business-1.0.0.md"),
            ):
                with self.subTest(identifier=identifier):
                    expected = (ROOT / "legal-texts" / text_name).read_bytes()
                    self.assertEqual(command("text", identifier, root=unpacked).stdout, expected)
                    output = folder / f"{identifier}.LICENSE"
                    result = command("add", identifier, "--output", output, root=unpacked)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual(output.read_bytes(), expected)
                    existing = b"Existing project license notice\n"
                    output.write_bytes(existing)
                    rejected = command("add", identifier, "--output", output, root=unpacked)
                    self.assertEqual(rejected.returncode, 1)
                    self.assertIn(b"Output already exists", rejected.stderr)
                    self.assertEqual(output.read_bytes(), existing)
            preview = command("add", "GPL-2.0-or-later", "--output", folder / "COPYING", "--dry-run",
                              "--json", root=unpacked)
            self.assertEqual(preview.returncode, 0, preview.stderr.decode())
            result = json.loads(preview.stdout)
            self.assertFalse(result["written"])
            self.assertFalse((folder / "COPYING").exists())
            self.assertIn("version 2 or any later version", result["application"])
            for identifier, notice in (("GPL-1.0-only", "version 1 only"),
                                       ("GPL-1.0-or-later", "version 1 or any later version"),
                                       ("LGPL-2.0-only", "version 2 only"),
                                       ("LGPL-2.0-or-later", "version 2 or any later version"),
                                       ("LGPL-2.1-only", "version 2.1 only"),
                                       ("LGPL-2.1-or-later", "version 2.1 or any later version"),
                                       ("GFDL-1.1-only", "version 1.1 only"),
                                       ("GFDL-1.2-invariants-or-later", "at least one Invariant Section"),
                                       ("GFDL-1.3-no-invariants-only", "no Invariant Sections"),
                                       ("CC-BY-NC-ND-4.0", "limits on sharing Adapted Material"),
                                       ("CC-BY-SA-4.0", "ShareAlike"),
                                       ("PolyForm-Noncommercial-1.0.0", "Required Notice"),
                                       ("PolyForm-Small-Business-1.0.0", "Small Business definition")):
                with self.subTest(identifier=identifier):
                    preview = command("add", identifier, "--output", folder / "COPYING", "--dry-run",
                                      "--json", root=unpacked)
                    self.assertEqual(preview.returncode, 0, preview.stderr.decode())
                    result = json.loads(preview.stdout)
                    self.assertIn(notice, result["application"])
                    self.assertEqual(result["output_sha256"], manifest[identifier]["sha256"])
                    self.assertEqual(hashlib.sha256(result["text"].encode()).hexdigest(), result["output_sha256"])
                    self.assertFalse((folder / "COPYING").exists())
            publisher_text = unpacked / "legal-texts/lgpl-2.0.txt"
            original = publisher_text.read_bytes()
            publisher_text.write_bytes(original[:1] + b"!" + original[2:])
            changed = command("text", "LGPL-2.0-or-later", root=unpacked)
            self.assertEqual(changed.returncode, 1)
            self.assertFalse(changed.stdout)
            self.assertIn(b"artifact size or SHA-256 mismatch", changed.stderr)
            publisher_text.write_bytes(original)
            base_output = folder / "COPYING"
            base = (ROOT / "legal-texts/gpl-3.0.txt").read_bytes()
            result = command("add", "GPL-3.0-only", "--output", base_output, root=unpacked)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(base_output.read_bytes(), base)
            base_mtime = base_output.stat().st_mtime_ns
            for identifier, notice in (("LGPL-3.0-only", "version 3 only"),
                                       ("LGPL-3.0-or-later", "version 3 or any later version")):
                with self.subTest(identifier=identifier):
                    expected = (ROOT / "legal-texts" / "lgpl-3.0.txt").read_bytes()
                    self.assertEqual(command("text", identifier, root=unpacked).stdout, expected)
                    output = folder / f"{identifier}.COPYING.LESSER"
                    args = ("add", identifier, "--output", output)
                    rejected = command(*args, root=unpacked)
                    self.assertEqual(rejected.returncode, 1)
                    self.assertIn(b"Include both publisher texts", rejected.stderr)
                    self.assertFalse(output.exists())
                    args += ("--gplv3-text", base_output)
                    preview = command(*args, "--dry-run", "--json", root=unpacked)
                    self.assertEqual(preview.returncode, 0, preview.stderr.decode())
                    result = json.loads(preview.stdout)
                    self.assertEqual(result["gplv3_text"], {"path": str(base_output),
                                                          "sha256": hashlib.sha256(base).hexdigest()})
                    self.assertEqual(result["text"].encode(), expected)
                    self.assertFalse(result["written"])
                    self.assertIn(notice, result["application"])
                    self.assertFalse(output.exists())
                    installed = command(*args, root=unpacked)
                    self.assertEqual(installed.returncode, 0, installed.stderr.decode())
                    self.assertEqual(output.read_bytes(), expected)
                    output.write_bytes(b"keep existing")
                    self.assertEqual(command(*args, root=unpacked).returncode, 1)
                    self.assertEqual(output.read_bytes(), b"keep existing")
                    replaced = command(*args, "--force", root=unpacked)
                    self.assertEqual(replaced.returncode, 0, replaced.stderr.decode())
                    self.assertEqual(output.read_bytes(), expected)
            rejected = command("add", "LGPL-3.0-only", "--gplv3-text", base_output, "--output", base_output,
                               "--force", root=unpacked)
            self.assertEqual(rejected.returncode, 1)
            self.assertIn(b"must be distinct", rejected.stderr)
            rejected = command("add", "MIT", "--fetch", "--gplv3-text", base_output, "--output", folder / "LICENSE",
                               root=unpacked)
            self.assertEqual(rejected.returncode, 1)
            self.assertIn(b"applies only to LGPL", rejected.stderr)
            self.assertFalse((folder / "LICENSE").exists())
            self.assertEqual(base_output.read_bytes(), base)
            self.assertEqual(base_output.stat().st_mtime_ns, base_mtime)
            frozen_counts = json.loads((unpacked / "registry/coverage/current.json").read_bytes())["assessment"]
            coverage = command("coverage", "--json", root=unpacked)
            self.assertEqual(coverage.returncode, 0, coverage.stderr.decode())
            bundled_counts = json.loads(coverage.stdout)
            self.assertEqual(bundled_counts["catalog"]["candidate_dispositions"],
                             frozen_counts["catalog"]["candidate_dispositions"])
            bundled_evidence = bundled_counts["qualification"]
            self.assertEqual(bundled_evidence.pop("recorded_evidence_basis"), "distribution-snapshot")
            self.assertEqual(bundled_evidence.pop("selection_basis"), "unverified-distribution-snapshot")
            self.assertEqual(bundled_evidence.pop("recorded_selection"), {
                "accepted_entities": frozen_counts["catalog"]["accepted_entities"],
                "selected_claims": frozen_counts["qualification"]["selected_claims"],
                "status": frozen_counts["qualification"]["status"],
            })
            self.assertEqual(bundled_evidence, frozen_counts["qualification"])
            # This fixture checks how an offline reader labels recorded counts from an active source.
            current = unpacked / "registry/coverage/current.json"
            recorded = json.loads(current.read_bytes())
            recorded["assessment"]["catalog"]["accepted_entities"] = 1
            recorded["assessment"]["qualification"].update(selected_claims=1, status="qualified-selection")
            revised_snapshot = encode(recorded)
            current.write_bytes(revised_snapshot)
            (unpacked / recorded["snapshot"]).write_bytes(revised_snapshot)
            (unpacked / "catalog.json").write_bytes(encode(discovery_export(Catalog(unpacked))))
            observed = command("validate", "--json", root=unpacked)
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            assessment = json.loads(observed.stdout)["coverage"]
            self.assertEqual(assessment["catalog"]["accepted_entities"], 0)
            self.assertEqual(assessment["qualification"]["selected_claims"], 0)
            self.assertEqual(assessment["qualification"]["recorded_selection"], {
                "accepted_entities": 1, "selected_claims": 1, "status": "qualified-selection",
            })
            planned = command("review-plan", "--admission", "GCC-exception-3.1", root=unpacked)
            self.assertEqual(planned.returncode, 0, planned.stderr.decode())
            candidate, = json.loads(planned.stdout)["candidates"]
            self.assertEqual(candidate["identifier"], "GCC-exception-3.1")
            self.assertIn("exception-relationship", candidate["work"])
            selection = unpacked / "sces" / "publication.json"
            selection.parent.mkdir()
            selection.write_text("invalid selection", encoding="utf-8")
            entity = unpacked / "registry" / "entities" / "ab" / "invalid.json"
            entity.parent.mkdir(parents=True)
            entity.write_text("invalid entity", encoding="utf-8")
            self.assertEqual(command("export", root=unpacked).returncode, 1)
            self.assertEqual(command("bundle", folder / "discovery.zip", root=unpacked).returncode, 1)
            self.assertEqual(command("validate", root=unpacked).returncode, 1)
            selection.unlink()
            self.assertEqual(command("validate", root=unpacked).returncode, 1)


if __name__ == "__main__":
    unittest.main()
