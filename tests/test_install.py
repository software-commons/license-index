import errno
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.li_install import InstallError, parse_expression, render, write_license


LICENSES = {"MIT", "Apache-2.0", "GPL-2.0", "GPL-2.0+", "GPL-2.0-only"}
EXCEPTIONS = {"Classpath-exception-2.0"}
MIT_TEXT = (
    b"MIT License\r\n\r\nCopyright (c) <year> <copyright holders>\r\n\r\n"
    b"Example fixture with <year> and <copyright holders> in unrelated text.\r\n"
)


class ExpressionTests(unittest.TestCase):
    def parse(self, expression):
        return parse_expression(expression, LICENSES, EXCEPTIONS)

    def test_known_id_resolves_case_insensitively(self):
        result = self.parse(" (mIt) ")
        self.assertEqual(result["single_license_id"], "MIT")
        self.assertEqual(result["license_ids"], ["MIT"])
        self.assertEqual(result["specification"], "3.0.1")

    def test_precedence_parentheses_and_standard_exception(self):
        result = self.parse("MIT or Apache-2.0 AND (GPL-2.0-only with classpath-EXCEPTION-2.0)")
        self.assertIsNone(result["single_license_id"])
        self.assertEqual(result["license_ids"], ["Apache-2.0", "GPL-2.0-only", "MIT"])
        self.assertEqual(result["exception_ids"], ["Classpath-exception-2.0"])
        self.assertEqual(result["tree"]["kind"], "or")
        self.assertEqual(result["tree"]["operands"][1]["kind"], "and")
        self.assertEqual(result["tree"]["operands"][1]["operands"][1]["kind"], "with")
        result = self.parse("(MIT OR Apache-2.0)AND(GPL-2.0-only)")
        self.assertEqual(result["tree"]["kind"], "and")
        self.assertEqual(result["tree"]["operands"][0]["kind"], "or")

    def test_later_version_operator_and_deprecated_catalog_id_are_distinct(self):
        result = self.parse("gpl-2.0+")
        self.assertIsNone(result["single_license_id"])
        self.assertEqual(result["tree"]["id"], "GPL-2.0")
        self.assertTrue(result["tree"]["or_later"])
        self.assertEqual(result["tree"]["listed_legacy_id"], "GPL-2.0+")

    def test_document_scoped_references_remain_unresolved(self):
        result = self.parse("DocumentRef-spec:LicenseRef-Custom WITH AdditionRef-Notice")
        self.assertEqual(result["license_ids"], [])
        self.assertEqual(result["exception_ids"], [])
        self.assertEqual(
            result["unresolved_references"],
            ["AdditionRef-Notice", "DocumentRef-spec:LicenseRef-Custom"],
        )
        self.assertFalse(result["tree"]["license"]["resolved"])
        self.assertFalse(result["tree"]["addition"]["resolved"])
        self.assertIsNone(result["single_license_id"])

    def test_invalid_expression_syntax(self):
        for expression in (
            "",
            " made-up-id ",
            "MIT +",
            "MIT++",
            "MIT+AND Apache-2.0",
            "MIT AnD Apache-2.0",
            "(MIT OR Apache-2.0",
            "MIT OR Apache-2.0)",
            "MIT OR",
            "MIT\nAND Apache-2.0",
            "MIT & Apache-2.0",
            "MIT Apache-2.0",
            "Classpath-exception-2.0",
            "MIT WITH MIT",
            "MIT WITH (Classpath-exception-2.0)",
            "(MIT) WITH Classpath-exception-2.0",
            "MIT WITH Classpath-exception-2.0 WITH Classpath-exception-2.0",
            "LicenseRef-Custom+",
            "licenseref-Custom",
            "DocumentRef-:LicenseRef-Custom",
            "MIT WITH LicenseRef-Custom",
            "(" * 101 + "MIT" + ")" * 101,
        ):
            with self.subTest(expression=expression), self.assertRaises(InstallError):
                self.parse(expression)


class RenderTests(unittest.TestCase):
    def test_mit_only_replaces_notice_and_preserves_crlf_and_unicode(self):
        data = render(MIT_TEXT, "mit-notice", holder="Société 株式会社", year="2026")
        old_notice = b"Copyright (c) <year> <copyright holders>"
        new_notice = "Copyright (c) 2026 Société 株式会社".encode("utf-8")
        self.assertEqual(data, MIT_TEXT.replace(old_notice, new_notice, 1))

    def test_preview_without_parameters_returns_pinned_placeholders(self):
        self.assertEqual(render(MIT_TEXT, "mit-notice", holder=None, year=None, preview=True), MIT_TEXT)
        with self.assertRaises(InstallError):
            render(MIT_TEXT, "mit-notice", holder=None, year="2026", preview=True)
        with self.assertRaises(InstallError):
            render(MIT_TEXT, "mit-notice", holder=None, year=None)

    def test_exact_notice_required(self):
        for text in (
            b"Copyright (c) 2026 Existing Owner\n",
            MIT_TEXT * 2,
            MIT_TEXT.replace(b"<year>", b"<yyyy>", 1),
            MIT_TEXT.replace(b"<copyright holders>\r\n", b"<copyright holders> and Others\r\n", 1),
        ):
            with self.subTest(text=text), self.assertRaises(InstallError):
                render(text, "mit-notice", holder="Example Corp.", year="2026")

    def test_placeholder_and_injection_inputs_fail(self):
        for holder in (
            "", " \t", " Existing Owner", "Existing Owner\nAdded line", "Existing Owner\0",
            "Existing Owner\u2028Added line", "Existing Owner\u202e", "<copyright holders>", "[holder]",
        ):
            with self.subTest(holder=holder), self.assertRaises(InstallError):
                render(MIT_TEXT, "mit-notice", holder=holder, year="2026")
        for year in ("0000", "26", "20260", "２０２６", "2026\n"):
            with self.subTest(year=year), self.assertRaises(InstallError):
                render(MIT_TEXT, "mit-notice", holder="Example Corp.", year=year)

    def test_unchanged_mode_preserves_every_byte_and_rejects_substitution(self):
        source = b"Appendix notice: Copyright [yyyy] [name of copyright owner]\r\n"
        self.assertEqual(render(source, "unchanged", holder=None, year=None), source)
        with self.assertRaises(InstallError):
            render(source, "unchanged", holder="Example Corp.", year="2026")
        with self.assertRaises(InstallError):
            render(source, "matching-template", holder=None, year=None)


class InstallTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name).resolve()
        self.output = self.directory / "LIZENZ München"

    def test_atomic_install_no_overwrite_and_explicit_force(self):
        sibling = self.directory / "other.txt"
        sibling.write_bytes(b"preserve")
        write_license(self.output, b"first\r\n")
        self.assertEqual(self.output.read_bytes(), b"first\r\n")
        with self.assertRaisesRegex(InstallError, "already exists"):
            write_license(self.output, b"second\n")
        self.assertEqual(self.output.read_bytes(), b"first\r\n")
        write_license(self.output, b"second\n", force=True)
        self.assertEqual(self.output.read_bytes(), b"second\n")
        self.assertEqual(sibling.read_bytes(), b"preserve")
        self.assertEqual(set(self.directory.iterdir()), {self.output, sibling})

    def test_dry_run_creates_nothing_and_preserves_existing_file(self):
        write_license(self.output, b"preview", dry_run=True)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.output.write_bytes(b"existing")
        write_license(self.output, b"preview", dry_run=True)
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_unsafe_path_is_rejected_even_for_dry_run(self):
        for path in (
            self.directory / "subdirectory" / ".." / "LICENSE",
            self.directory / "NUL.txt",
            self.directory / "LPT9",
            self.directory / "CON .txt",
            self.directory / "LICENSE.",
            self.directory / "LICENSE ",
            self.directory / "LICENSE:stream",
            self.directory / "LICENSE\u000a.txt",
            self.directory / "missing" / "LICENSE",
            self.directory,
        ):
            with self.subTest(path=path), self.assertRaises(InstallError):
                write_license(path, b"preview", force=True, dry_run=True)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_symbolic_targets_and_parents_are_rejected(self):
        real_path = self.directory / "real"
        real_path.mkdir()
        original = real_path / "original"
        original.write_bytes(b"keep")
        linked_directory = self.directory / "link"
        try:
            self.output.symlink_to(original)
            linked_directory.symlink_to(real_path, target_is_directory=True)
        except OSError as failure:
            self.skipTest(f"Symbolic links unavailable: {failure}")
        with self.assertRaises(InstallError):
            write_license(self.output, b"replacement", force=True)
        with self.assertRaises(InstallError):
            write_license(linked_directory / "LICENSE", b"replacement", force=True)
        self.assertEqual(list(real_path.iterdir()), [original])
        self.assertEqual(original.read_bytes(), b"keep")

    @unittest.skipUnless(os.name == "nt", "Windows junction behavior")
    def test_windows_directory_junction_is_rejected(self):
        from _winapi import CreateJunction

        real_path = self.directory / "real"
        real_path.mkdir()
        linked_directory = self.directory / "link"
        try:
            CreateJunction(str(real_path), str(linked_directory))
        except PermissionError:
            self.skipTest("Windows junction creation is unavailable in this environment")
        with self.assertRaisesRegex(InstallError, "regular directory"):
            write_license(linked_directory / "LICENSE", b"replacement", force=True)
        self.assertEqual(list(real_path.iterdir()), [])

    def test_failed_sync_leaves_existing_target_and_cleans_temporary(self):
        self.output.write_bytes(b"existing")
        with patch("tools.li_install.os.fsync", side_effect=OSError(errno.ENOSPC, "disk full")):
            with self.assertRaises(InstallError):
                write_license(self.output, b"new", force=True)
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_interruption_before_commit_leaves_no_target_or_temporary(self):
        with patch("tools.li_install.os.fsync", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                write_license(self.output, b"new")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_concurrent_new_file_cannot_be_clobbered(self):
        commit = os.rename if os.name == "nt" else os.link

        def add_concurrent_file(*args, **kwargs):
            self.output.write_bytes(b"new from another writer")
            return commit(*args, **kwargs)

        commit_name = "rename" if os.name == "nt" else "link"
        with patch(f"tools.li_install.os.{commit_name}", side_effect=add_concurrent_file):
            with self.assertRaisesRegex(InstallError, "already exists"):
                write_license(self.output, b"our license")
        self.assertEqual(self.output.read_bytes(), b"new from another writer")
        self.assertEqual(list(self.directory.iterdir()), [self.output])
