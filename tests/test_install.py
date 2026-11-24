import errno
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.li_install import (
    InstallError, _WindowsInstall, _complete_file, parse_expression, render, verify_gplv3_companion, write_license,
)


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
        self.assertIsNone(write_license(self.output, b"first\r\n"))
        self.assertEqual(self.output.read_bytes(), b"first\r\n")
        with self.assertRaisesRegex(InstallError, "already exists"):
            write_license(self.output, b"second\n")
        self.assertEqual(self.output.read_bytes(), b"first\r\n")
        previous = write_license(self.output, b"second\n", force=True)
        self.assertEqual(self.output.read_bytes(), b"second\n")
        self.assertEqual(sibling.read_bytes(), b"preserve")
        expected = {self.output, sibling}
        if os.name == "posix":
            self.assertIsInstance(previous, Path)
            self.assertEqual(previous.read_bytes(), b"first\r\n")
            self.assertEqual(stat.S_IMODE(previous.parent.stat().st_mode), 0o700)
            expected.add(previous.parent)
        else:
            self.assertIsNone(previous)
        self.assertEqual(set(self.directory.iterdir()), expected)

    def test_dry_run_creates_nothing_and_preserves_existing_file(self):
        write_license(self.output, b"preview", dry_run=True)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.output.write_bytes(b"existing")
        write_license(self.output, b"preview", dry_run=True)
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_companion_requires_the_exact_regular_file(self):
        base = self.directory / "COPYING"
        expected = b"GPLv3 fixture\n"
        with self.assertRaisesRegex(InstallError, "Could not verify GPLv3 companion"):
            verify_gplv3_companion(self.output, base, expected)
        base.mkdir()
        with self.assertRaisesRegex(InstallError, "regular file"):
            verify_gplv3_companion(self.output, base, expected)
        base.rmdir()
        for invalid in (b"gPLv3 fixture\n", b"GPLv3 fixture\r\n"):
            with self.subTest(invalid=invalid):
                base.write_bytes(invalid)
                with self.assertRaisesRegex(InstallError, "exact bundled GPL version 3"):
                    verify_gplv3_companion(self.output, base, expected)
        base.write_bytes(expected)
        verify_gplv3_companion(self.output, base, expected)
        self.assertEqual(base.read_bytes(), expected)
        self.assertFalse(self.output.exists())

    def test_companion_and_output_must_have_distinct_paths(self):
        base = self.directory / "COPYING"
        base.write_bytes(b"base")
        with self.assertRaisesRegex(InstallError, "must be distinct"):
            verify_gplv3_companion(base, base, b"base")
        self.assertEqual(base.read_bytes(), b"base")

    def test_hard_link_to_companion_cannot_be_the_output(self):
        base = self.directory / "COPYING"
        base.write_bytes(b"base")
        try:
            os.link(base, self.output)
        except OSError as failure:
            self.skipTest(f"Hard links unavailable: {failure}")
        with self.assertRaisesRegex(InstallError, "must be distinct"):
            verify_gplv3_companion(self.output, base, b"base")
        self.assertEqual(base.read_bytes(), b"base")
        self.assertEqual(self.output.read_bytes(), b"base")

    def test_companion_is_rechecked_after_staging(self):
        base = self.directory / "COPYING"
        base.write_bytes(b"base")
        self.output.write_bytes(b"existing")

        def change_companion_after_staging(descriptor, content):
            _complete_file(descriptor, content)
            base.write_bytes(b"changed by another process")

        def verify(stat_output):
            verify_gplv3_companion(self.output, base, b"base", stat_output=stat_output)

        with patch("tools.li_install._complete_file", side_effect=change_companion_after_staging):
            with self.assertRaisesRegex(InstallError, "exact bundled GPL version 3"):
                write_license(self.output, b"supplement", force=True, before_publish=verify)
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.assertEqual(set(self.directory.iterdir()), {self.output, base})

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
        with self.assertRaises(InstallError):
            verify_gplv3_companion(real_path / "LICENSE", self.output, b"keep")
        with self.assertRaises(InstallError):
            verify_gplv3_companion(real_path / "LICENSE", linked_directory / "original", b"keep")
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
        original = real_path / "COPYING"
        original.write_bytes(b"base")
        with self.assertRaisesRegex(InstallError, "regular directory"):
            verify_gplv3_companion(self.output, linked_directory / original.name, b"base")
        self.assertEqual(list(real_path.iterdir()), [original])

    @unittest.skipUnless(os.name == "nt", "Windows directory sharing")
    def test_windows_keeps_all_ancestors_pinned_before_staging(self):
        ancestor = self.directory / "ancestor"
        parent = ancestor / "parent"
        parent.mkdir(parents=True)
        output = parent / "LICENSE"
        stage = _WindowsInstall.stage
        checked = []

        def stage_after_rename_attempts(native, path, handles):
            for pinned in (parent, ancestor):
                with self.assertRaises(PermissionError):
                    pinned.rename(pinned.with_name(f"{pinned.name}-moved"))
                checked.append(pinned)
            return stage(native, path, handles)

        with patch.object(_WindowsInstall, "stage", stage_after_rename_attempts):
            write_license(output, b"protected directory")
        self.assertEqual(checked, [parent, ancestor])
        self.assertEqual(list(parent.iterdir()), [output])
        moved = ancestor.rename(self.directory / "ancestor-moved")
        self.assertEqual((moved / "parent" / output.name).read_bytes(), b"protected directory")

    @unittest.skipUnless(os.name == "nt", "Windows staged-file sharing")
    def test_windows_failure_discards_the_open_staged_file(self):
        neighbor = self.directory / "neighbor"
        neighbor.write_bytes(b"keep")

        def interrupt_after_sync(descriptor, content):
            _complete_file(descriptor, content)
            staged, = self.directory.glob(".license-index-*.tmp")
            with self.assertRaises(PermissionError):
                staged.rename(staged.with_suffix(".different"))
            raise KeyboardInterrupt

        with patch("tools.li_install._complete_file", side_effect=interrupt_after_sync):
            with self.assertRaises(KeyboardInterrupt):
                write_license(self.output, b"aborted")
        self.assertEqual(list(self.directory.iterdir()), [neighbor])
        self.assertEqual(neighbor.read_bytes(), b"keep")

    @unittest.skipUnless(os.name == "nt", "Windows rename interruption")
    def test_windows_interruption_after_parking_restores_the_original(self):
        self.output.write_bytes(b"prior")
        original = self.output.stat()
        rename = _WindowsInstall.rename

        def interrupt_after_parking(native, handle, name):
            rename(native, handle, name)
            if name.endswith(".previous"):
                raise KeyboardInterrupt

        with patch.object(_WindowsInstall, "rename", interrupt_after_parking):
            with self.assertRaises(KeyboardInterrupt):
                write_license(self.output, b"uncommitted", force=True)
        self.assertTrue(os.path.samestat(self.output.stat(), original))
        self.assertEqual(self.output.read_bytes(), b"prior")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    @unittest.skipUnless(os.name == "nt", "Windows rename interruption")
    def test_windows_interruption_after_rename_keeps_the_committed_output(self):
        self.output.write_bytes(b"prior")
        publish = _WindowsInstall.publish

        def interrupt_after_publish(native, handle, name, force):
            publish(native, handle, name, force)
            raise KeyboardInterrupt

        with patch.object(_WindowsInstall, "publish", interrupt_after_publish):
            with self.assertRaises(KeyboardInterrupt):
                write_license(self.output, b"committed", force=True)
        self.assertEqual(self.output.read_bytes(), b"committed")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    @unittest.skipUnless(os.name == "nt", "Windows no-clobber replacement")
    def test_windows_force_preserves_a_concurrent_destination_and_the_original(self):
        self.output.write_bytes(b"original")
        original = self.output.stat()
        publish = _WindowsInstall.publish
        concurrent = []

        def publish_with_new_destination(native, handle, name, force):
            self.assertFalse(force, "Windows replacement publication must not clobber")
            if not concurrent:
                self.assertEqual(name, self.output.name)
                with self.output.open("xb") as other_writer:
                    other_writer.write(b"concurrent")
                concurrent.append(self.output.stat())
            return publish(native, handle, name, force)

        with patch.object(_WindowsInstall, "publish", publish_with_new_destination):
            with self.assertRaises(InstallError) as failure:
                write_license(self.output, b"new license", force=True)

        identity, = concurrent
        self.assertTrue(os.path.samestat(self.output.stat(), identity))
        self.assertEqual(self.output.read_bytes(), b"concurrent")
        recovered, = set(self.directory.iterdir()) - {self.output}
        self.assertTrue(os.path.samestat(recovered.stat(), original))
        self.assertEqual(recovered.read_bytes(), b"original")
        self.assertIn(recovered.name, str(failure.exception))

    def test_failed_sync_leaves_existing_target_and_cleans_temporary(self):
        self.output.write_bytes(b"existing")
        with patch("tools.li_install.os.fsync", side_effect=OSError(errno.ENOSPC, "disk full")):
            with self.assertRaises(InstallError):
                write_license(self.output, b"new", force=True)
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    @unittest.skipUnless(os.name == "posix", "POSIX destination validation")
    def test_posix_force_respects_an_edit_to_the_open_destination(self):
        self.output.write_bytes(b"original")
        initial = self.output.lstat()
        os.utime(self.output, ns=(initial.st_atime_ns, initial.st_mtime_ns - 2_000_000_000))
        original = self.output.lstat()

        def finish_after_an_editor_saves(descriptor, content):
            _complete_file(descriptor, content)
            self.output.write_bytes(b"my edits")

        with patch("tools.li_install._complete_file", side_effect=finish_after_an_editor_saves):
            with self.assertRaisesRegex(InstallError, "Output changed during replacement"):
                write_license(self.output, b"license", force=True)

        self.assertTrue(os.path.samestat(original, self.output.lstat()))
        self.assertEqual(self.output.read_bytes(), b"my edits")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    @unittest.skipUnless(os.name == "posix", "POSIX destination validation")
    def test_posix_force_rechecks_destination_after_staging(self):
        referent = self.directory / "referent"
        referent.write_bytes(b"preserve")
        self.output.write_bytes(b"existing")

        def finish_with_link_at_destination(descriptor, content):
            _complete_file(descriptor, content)
            self.output.unlink()
            self.output.symlink_to(referent.name)

        with patch("tools.li_install._complete_file", side_effect=finish_with_link_at_destination):
            with self.assertRaisesRegex(InstallError, "Output must be a regular file path"):
                write_license(self.output, b"new", force=True)
        self.assertEqual(self.output.readlink(), Path(referent.name))
        self.assertEqual(referent.read_bytes(), b"preserve")
        self.assertEqual(set(self.directory.iterdir()), {self.output, referent})

    @unittest.skipUnless(os.name == "posix", "POSIX replacement descriptor")
    def test_posix_force_holds_both_file_descriptors_through_exchange(self):
        from tools.li_install import _exchange_posix

        self.output.write_bytes(b"original")
        original = self.output.stat()
        open_file = os.open
        dup_file = os.dup
        target_fds = []
        stage_fds = []
        exchanged = []

        def remember_target(name, flags, *args, **kwargs):
            descriptor = open_file(name, flags, *args, **kwargs)
            if name == self.output.name and kwargs.get("dir_fd") is not None:
                target_fds.append(descriptor)
            return descriptor

        def remember_stage(descriptor):
            pinned = dup_file(descriptor)
            stage_fds.append(pinned)
            return pinned

        def verify_pin(stage, temporary, directory, name):
            target_fd, = target_fds
            stage_fd, = stage_fds
            self.assertTrue(os.path.samestat(os.fstat(target_fd), original))
            fresh = os.stat(temporary, dir_fd=stage, follow_symlinks=False)
            self.assertTrue(os.path.samestat(os.fstat(stage_fd), fresh))
            _exchange_posix(stage, temporary, directory, name)
            self.assertTrue(os.path.samestat(os.fstat(target_fd), original))
            self.assertTrue(os.path.samestat(os.fstat(stage_fd), fresh))
            exchanged.append((target_fd, stage_fd))

        with (patch("tools.li_install.os.open", side_effect=remember_target),
              patch("tools.li_install.os.dup", side_effect=remember_stage),
              patch("tools.li_install._exchange_posix", side_effect=verify_pin)):
            previous = write_license(self.output, b"new license", force=True)

        descriptors, = exchanged
        for descriptor in descriptors:
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertEqual(self.output.read_bytes(), b"new license")
        self.assertTrue(os.path.samestat(previous.stat(), original))
        self.assertEqual(previous.read_bytes(), b"original")
        self.assertEqual(set(self.directory.iterdir()), {self.output, previous.parent})

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin", "POSIX recovery path")
    def test_posix_force_reports_verified_recovery_when_output_parent_moves(self):
        from tools.li_install import _exchange_posix

        parent = self.directory / "original"
        parent.mkdir()
        output = parent / "LICENSE"
        output.write_bytes(b"previous license")
        original = output.stat()
        moved = self.directory / "moved"

        def move_once(stage, temporary, directory, name):
            if not moved.exists():
                parent.rename(moved)
                parent.mkdir()
                output.write_bytes(b"unrelated license")
            _exchange_posix(stage, temporary, directory, name)

        with patch("tools.li_install._exchange_posix", side_effect=move_once):
            with self.assertRaisesRegex(InstallError, "Output changed during replacement") as failure:
                write_license(output, b"replacement license", force=True)

        self.assertEqual(output.read_bytes(), b"unrelated license")
        restored = moved / output.name
        self.assertTrue(os.path.samestat(restored.stat(), original))
        self.assertEqual(restored.read_bytes(), b"previous license")
        recovery, = moved.glob(".license-index-*.tmp/license")
        self.assertEqual(recovery.read_bytes(), b"replacement license")
        self.assertIn(f"Preserved a copy at {recovery}", str(failure.exception))

    @unittest.skipUnless(os.name == "posix", "POSIX atomic exchange")
    def test_posix_force_preserves_nonregular_entries_at_the_exchange_boundary(self):
        from tools.li_install import _exchange_posix

        referent = self.directory / "referent"
        referent.write_bytes(b"preserve")
        for kind in ("fifo", "symlink"):
            with self.subTest(kind=kind):
                output = self.directory / kind
                output.write_bytes(b"existing")
                identities = []
                exchanges = []
                previous_stages = set(self.directory.glob(".license-index-*.tmp"))

                def substitute_once(stage, temporary, directory, name):
                    if not identities:
                        output.unlink()
                        if kind == "fifo":
                            os.mkfifo(output)
                        else:
                            output.symlink_to(referent.name)
                        identities.append(output.lstat())
                    _exchange_posix(stage, temporary, directory, name)
                    exchanges.append(name)

                with patch("tools.li_install._exchange_posix", side_effect=substitute_once):
                    with self.assertRaises(InstallError) as failure:
                        write_license(output, b"new", force=True)
                identity, = identities
                final = output.lstat()
                self.assertTrue(os.path.samestat(identity, final))
                self.assertEqual(final.st_mode, identity.st_mode)
                if kind == "symlink":
                    self.assertEqual(output.readlink(), Path(referent.name))
                self.assertEqual(referent.read_bytes(), b"preserve")
                new_stages = set(self.directory.glob(".license-index-*.tmp")) - previous_stages
                if exchanges:
                    recovered_dir, = new_stages
                    recovered, = recovered_dir.iterdir()
                    self.assertEqual(recovered.read_bytes(), b"new")
                    self.assertIn(str(recovered), str(failure.exception))
                else:
                    self.assertEqual(new_stages, set())

    @unittest.skipUnless(os.name == "posix", "POSIX atomic exchange")
    def test_posix_force_preserves_same_inode_edit_at_exchange(self):
        from tools.li_install import _exchange_posix

        self.output.write_bytes(b"original")
        original = self.output.stat()
        edited = b"modified"
        edited_replacement = b"editor saved after publication"
        observations = []

        def edit_once(stage, temporary, directory, name):
            publishing = not observations
            if publishing:
                with self.output.open("r+b") as writer:
                    writer.write(edited)
                os.utime(self.output, ns=(original.st_atime_ns, original.st_mtime_ns))
                observed = self.output.stat()
                self.assertTrue(os.path.samestat(observed, original))
                self.assertEqual((observed.st_size, observed.st_mtime_ns),
                                 (original.st_size, original.st_mtime_ns))
                observations.append(observed)
            _exchange_posix(stage, temporary, directory, name)
            if publishing:
                self.output.write_bytes(edited_replacement)

        with patch("tools.li_install._exchange_posix", side_effect=edit_once):
            with self.assertRaisesRegex(InstallError, "Output changed during replacement") as failure:
                write_license(self.output, b"new license", force=True)

        observed, = observations
        self.assertTrue(os.path.samestat(self.output.stat(), observed))
        self.assertEqual(self.output.read_bytes(), edited)
        stage, = set(self.directory.iterdir()) - {self.output}
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
        recovered, = stage.iterdir()
        self.assertEqual(recovered.read_bytes(), edited_replacement)
        self.assertIn(str(recovered), str(failure.exception))

    @unittest.skipUnless(os.name == "posix", "POSIX atomic exchange recovery")
    def test_posix_force_retains_the_displaced_entry_if_the_published_name_moves(self):
        from tools.li_install import _exchange_posix

        self.output.write_bytes(b"existing")
        referent = self.directory / "referent"
        referent.write_bytes(b"preserve")
        exchanged = False

        def move_published_name(stage, temporary, directory, name):
            nonlocal exchanged
            if exchanged:
                return _exchange_posix(stage, temporary, directory, name)
            self.output.unlink()
            self.output.symlink_to(referent.name)
            _exchange_posix(stage, temporary, directory, name)
            exchanged = True
            self.output.unlink()

        with patch("tools.li_install._exchange_posix", side_effect=move_published_name):
            with self.assertRaises(InstallError) as failure:
                write_license(self.output, b"new", force=True)
        if not exchanged:
            self.skipTest("Atomic exchange of the synthetic regular file and symlink is unavailable")
        stage, = self.directory.glob(".license-index-*.tmp")
        retained, = stage.iterdir()
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
        self.assertEqual(retained.readlink(), Path(referent.name))
        self.assertIn(stage.name, str(failure.exception))
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.is_symlink())
        self.assertEqual(referent.read_bytes(), b"preserve")

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptor staging")
    def test_shared_posix_output_uses_a_private_same_filesystem_stage(self):
        shared = self.directory / "shared"
        shared.mkdir()
        shared.chmod(0o0777)
        controlled = self.directory / "controlled"
        controlled.mkdir(mode=0o700)
        output = shared / self.output.name
        foreign = shared / ".license-index-foreign.tmp"
        foreign.write_bytes(b"a separate writer's file")
        staged = []

        def inspect_stage(descriptor, content):
            directory, = controlled.iterdir()
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(os.fstat(descriptor).st_ino, (directory / "license").stat().st_ino)
            self.assertEqual(set(shared.iterdir()), {foreign, output} if output.exists() else {foreign})
            staged.append(directory)
            _complete_file(descriptor, content)

        with patch.dict(os.environ, {"TMPDIR": str(controlled)}):
            with patch("tools.li_install._complete_file", side_effect=inspect_stage):
                self.assertIsNone(write_license(output, b"initial"))
                previous = write_license(output, b"replacement", force=True)
        self.assertEqual(len(staged), 2)
        self.assertEqual(list(controlled.iterdir()), [staged[1]])
        self.assertEqual(previous.parent, staged[1])
        self.assertEqual(previous.read_bytes(), b"initial")
        self.assertEqual(output.read_bytes(), b"replacement")
        self.assertEqual(foreign.read_bytes(), b"a separate writer's file")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor cleanup")
    def test_posix_cleanup_keeps_a_different_directory_at_the_old_stage_name(self):
        moved = self.directory / "original-stage"
        replacements = []

        def interrupt_after_sync(descriptor, content):
            _complete_file(descriptor, content)
            stage, = self.directory.glob(".license-index-*.tmp")
            stage.rename(moved)
            stage.mkdir(mode=0o700)
            replacements.append(stage)
            raise KeyboardInterrupt

        with patch("tools.li_install._complete_file", side_effect=interrupt_after_sync):
            with self.assertRaises(KeyboardInterrupt):
                write_license(self.output, b"interrupted")
        self.assertFalse(self.output.exists())
        self.assertEqual(list(moved.iterdir()), [])
        self.assertEqual(len(replacements), 1)
        self.assertTrue(replacements[0].is_dir())

    def test_interruption_before_commit_leaves_no_target_or_temporary(self):
        with patch("tools.li_install.os.fsync", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                write_license(self.output, b"new")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_concurrent_new_file_cannot_be_clobbered(self):
        if os.name == "nt":
            commit, commit_path = _WindowsInstall.publish, "tools.li_install._WindowsInstall.publish"
        else:
            commit, commit_path = os.link, "tools.li_install.os.link"

        def add_concurrent_file(*args, **kwargs):
            self.output.write_bytes(b"new from another writer")
            return commit(*args, **kwargs)

        with patch(commit_path, new=add_concurrent_file):
            with self.assertRaisesRegex(InstallError, "already exists"):
                write_license(self.output, b"our license")
        self.assertEqual(self.output.read_bytes(), b"new from another writer")
        self.assertEqual(list(self.directory.iterdir()), [self.output])
