"""SPDX expression parsing and safe installation of selected license bytes."""

from contextlib import ExitStack, contextmanager
import errno
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import NamedTuple
import unicodedata


class InstallError(ValueError):
    """An invalid expression, unsupported rendering, or unsafe install target."""


LGPL_V3_SUPPLEMENT = "lgpl-v3-supplement"
LGPL_V3_IDS = frozenset({"LGPL-3.0-only", "LGPL-3.0-or-later"})


class _Token(NamedTuple):
    value: str
    start: int
    end: int


_TOKEN = re.compile(r"[a-zA-Z0-9.-]+(?::[a-zA-Z0-9.-]+)?|[()+]|[ \t]+")
_LICENSE_REF = re.compile(r"(?:DocumentRef-[a-zA-Z0-9.-]+:)?LicenseRef-[a-zA-Z0-9.-]+")
_ADDITION_REF = re.compile(r"(?:DocumentRef-[a-zA-Z0-9.-]+:)?AdditionRef-[a-zA-Z0-9.-]+")
_MIT_NOTICE = re.compile(br"(?m)^Copyright \(c\) <year> <copyright holders>(?=\r?$)")
_YEAR = re.compile(r"(?!0000)[0-9]{4}")
_HOLDER_PLACEHOLDER = re.compile(
    r"(?:\[|\{)\s*(?:year|holder|copyright holders?|name|fullname|name of copyright owner)"
    r"\s*(?:\]|\})",
    re.IGNORECASE,
)
_UNSAFE_CATEGORIES = {"Cc", "Cf", "Cs", "Zl", "Zp"}
_JOINERS = {"\u200c", "\u200d"}
_UNSAFE_PATH_CHARACTERS = frozenset('<>:"/\\|?*')
_RESERVED_PATH_STEM = re.compile(
    r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])",
    re.IGNORECASE,
)


class _ExpressionParser:
    def __init__(self, expression, licenses, exceptions):
        self.expression = expression
        self.licenses = {identifier.lower(): identifier for identifier in licenses}
        self.exceptions = {identifier.lower(): identifier for identifier in exceptions}
        self.tokens = self._tokenize(expression)
        self.position = 0
        self.license_ids = set()
        self.exception_ids = set()
        self.references = set()

    @staticmethod
    def _tokenize(expression):
        tokens = []
        offset = 0
        while offset < len(expression):
            match = _TOKEN.match(expression, offset)
            if match is None:
                raise InstallError(f"Invalid SPDX expression character at position {offset + 1}")
            if match[0][0] not in (" ", "\t"):
                tokens.append(_Token(match[0], offset, match.end()))
            offset = match.end()
        tokens.append(_Token("", offset, offset))
        return tokens

    def _peek(self):
        return self.tokens[self.position]

    def _take(self):
        token = self._peek()
        if token.value:
            self.position += 1
        return token

    def _operator(self, name, separators):
        token = self._peek()
        if token.value not in (name, name.lower()):
            return False
        before = self.expression[token.start - 1 : token.start] if token.start else ""
        after = self.expression[token.end : token.end + 1]
        if before not in separators or after not in separators:
            raise InstallError(f"Invalid separators around SPDX operator {name}")
        self._take()
        return True

    def _reference(self, value, kind):
        self.references.add(value)
        return {"kind": kind, "id": value, "resolved": False}

    def _simple(self):
        base = self._take()
        identifier = self.licenses.get(base.value.lower())
        if identifier:
            self.license_ids.add(identifier)
            term = {"kind": "license", "id": identifier, "or_later": False}
        elif _LICENSE_REF.fullmatch(base.value):
            term = self._reference(base.value, "license-reference")
        elif base.value.lower() in self.exceptions:
            raise InstallError(f"SPDX exception {base.value!r} must follow WITH")
        else:
            raise InstallError(f"Expected an SPDX license identifier or LicenseRef, got {base.value!r}")

        suffix = self._peek()
        if suffix.value == "+":
            if identifier is None or base.end != suffix.start:
                raise InstallError("SPDX '+' must immediately follow a listed license identifier")
            self._take()
            term["or_later"] = True
            legacy_id = self.licenses.get(f"{identifier.lower()}+")
            if legacy_id:
                term["listed_legacy_id"] = legacy_id
        return term

    def _addition(self):
        token = self._take()
        identifier = self.exceptions.get(token.value.lower())
        if identifier:
            self.exception_ids.add(identifier)
            return {"kind": "exception", "id": identifier}
        if _ADDITION_REF.fullmatch(token.value):
            return self._reference(token.value, "addition-reference")
        raise InstallError(f"Expected an SPDX exception identifier or AdditionRef, got {token.value!r}")

    def _term(self, depth):
        if self._peek().value == "(":
            if depth >= 100:
                raise InstallError("SPDX expression exceeds the supported nesting depth of 100")
            self._take()
            term = self._or(depth + 1)
            if self._take().value != ")":
                raise InstallError("Expected ')' to close SPDX expression group")
            return term
        term = self._simple()
        if self._operator("WITH", (" ", "\t")):
            return {"kind": "with", "license": term, "addition": self._addition()}
        return term

    def _combine(self, name, operand, depth):
        terms = [operand(depth)]
        while self._operator(name, (" ", "\t", "(", ")")):
            terms.append(operand(depth))
        if len(terms) == 1:
            return terms[0]
        return {"kind": name.lower(), "operands": terms}

    def _and(self, depth):
        return self._combine("AND", self._term, depth)

    def _or(self, depth):
        return self._combine("OR", self._and, depth)

    def parse(self):
        tree = self._or(0)
        if self._peek().value:
            raise InstallError(f"Unexpected SPDX expression token {self._peek().value!r}")
        return tree


def parse_expression(expression: str, licenses: set[str], exceptions: set[str]) -> dict:
    """Parse SPDX 3.0.1 Annex B syntax against the pinned list.

    References require their licensing document. Syntax alone does not establish
    that an exception applies to a license or that a combination is permitted.
    """
    parser = _ExpressionParser(expression, licenses, exceptions)
    tree = parser.parse()
    single_license_id = None
    if tree["kind"] == "license" and not tree["or_later"]:
        single_license_id = tree["id"]
    return {
        "specification": "3.0.1",
        "expression": expression,
        "tree": tree,
        "single_license_id": single_license_id,
        "license_ids": sorted(parser.license_ids),
        "exception_ids": sorted(parser.exception_ids),
        "unresolved_references": sorted(parser.references),
    }


def _unsafe_character(character):
    return unicodedata.category(character) in _UNSAFE_CATEGORIES and character not in _JOINERS


def render(
    text: bytes,
    mode: str,
    *,
    holder: str | None,
    year: str | None,
    preview: bool = False,
) -> bytes:
    """Return authorized output bytes from an already verified input text."""
    if mode == "unchanged":
        if holder is not None or year is not None:
            raise InstallError("This license is installed unchanged. Omit --holder and --year.")
        return text
    if mode != "mit-notice":
        raise InstallError("This license has no supported file-generation procedure")

    notices = list(_MIT_NOTICE.finditer(text))
    if len(notices) != 1:
        raise InstallError("The MIT text must contain exactly one supported copyright notice")
    if preview and holder is None and year is None:
        return text
    if holder is None or year is None:
        raise InstallError("MIT requires both --holder and --year")
    if not _YEAR.fullmatch(year):
        raise InstallError("The copyright year must be a four-digit ASCII year from 0001 to 9999")
    if (
        not holder
        or holder != holder.strip()
        or any(character in "<>" or _unsafe_character(character) for character in holder)
        or not any(not character.isspace() and character not in _JOINERS for character in holder)
        or _HOLDER_PLACEHOLDER.search(holder)
    ):
        raise InstallError("Provide an explicit, nonempty, single-line copyright holder")

    notice = notices[0]
    replacement = f"Copyright (c) {year} {holder}".encode("utf-8")
    return text[: notice.start()] + replacement + text[notice.end() :]


def _validate_path(output):
    if not output.name or (output.anchor and not output.is_absolute()):
        raise InstallError("Supply a filename or a fully qualified output path")
    if output.anchor.startswith(("\\\\?\\", "\\\\.\\")):
        raise InstallError("Windows device paths are not valid license output paths")
    parts = output.parts[1:] if output.anchor else output.parts
    for name in parts:
        stem = name.partition(".")[0].rstrip(" ")
        if (
            name == ".."
            or name.endswith((" ", "."))
            or _RESERVED_PATH_STEM.fullmatch(stem)
            or any(character in _UNSAFE_PATH_CHARACTERS or _unsafe_character(character) for character in name)
        ):
            raise InstallError(f"Unsafe output path component {name!r}")
    return output.absolute()


def _is_link(info):
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _check_target(get_stat, output, force, dry_run):
    try:
        info = get_stat()
    except FileNotFoundError:
        return
    if _is_link(info) or not stat.S_ISREG(info.st_mode):
        raise InstallError(f"Output must be a regular file path: {output}")
    if not force and not dry_run:
        raise InstallError(f"Output already exists: {output}. Use --force to replace it.")


def _complete_file(descriptor, content):
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _open_posix_parent(path):
    # Walk no-follow directory handles so replacing a path component cannot
    # redirect a subsequent operation to a different directory.
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor, directory_flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def _without_darwin_acl(directory):
    if sys.platform != "darwin":
        return True
    import ctypes

    # Extended ACLs can grant DELETE_CHILD independently of the BSD mode.
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    get_acl = libc.acl_get_fd_np
    get_acl.argtypes = (ctypes.c_int, ctypes.c_uint)
    get_acl.restype = ctypes.c_void_p
    free_acl = libc.acl_free
    free_acl.argtypes = (ctypes.c_void_p,)
    free_acl.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = get_acl(directory, 0x00000100)  # ACL_TYPE_EXTENDED
    if acl:
        free_acl(acl)
        return False
    return ctypes.get_errno() in {errno.ENOENT, errno.ENOTSUP}


def _trusted_posix_staging_parent(directory, owner):
    info = os.fstat(directory)
    shared = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    return (info.st_uid in {0, owner} and (not shared or info.st_mode & stat.S_ISVTX)
            and _without_darwin_acl(directory))


def _posix_staging_parent(directory, handles):
    owner = os.geteuid()
    if _trusted_posix_staging_parent(directory, owner):
        return directory
    # A shared output directory may be a valid destination. Stage under a
    # protected parent on the same filesystem so publication remains atomic.
    device = os.fstat(directory).st_dev
    candidates = (os.environ.get("TMPDIR"), "/tmp", "/var/tmp", Path.home())
    for name in filter(None, candidates):
        try:
            path = Path(name).resolve(strict=True)
            staging_parent = _open_posix_parent(path / "unused")
        except (OSError, RuntimeError):
            continue
        with ExitStack() as candidate:
            candidate.callback(os.close, staging_parent)
            if (os.fstat(staging_parent).st_dev == device
                    and _trusted_posix_staging_parent(staging_parent, owner)
                    and os.access(".", os.W_OK | os.X_OK, dir_fd=staging_parent)):
                handles.callback(candidate.pop_all().close)
                return staging_parent
    raise InstallError("No trusted same-filesystem staging directory is available for the shared output directory")


@contextmanager
def _private_posix_stage(parent):
    name = f".license-index-{secrets.token_hex(16)}.tmp"
    os.mkdir(name, mode=0o700, dir_fd=parent)
    try:
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except BaseException:
        os.rmdir(name, dir_fd=parent)
        raise
    with ExitStack() as handles:
        handles.callback(os.close, directory)
        identity = os.fstat(directory)
        try:
            if (identity.st_uid != os.geteuid() or identity.st_mode & 0o077
                    or not _without_darwin_acl(directory)):
                raise InstallError("The license staging directory is not private")
            yield directory
        finally:
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if os.path.samestat(identity, current) and _trusted_posix_staging_parent(parent, os.geteuid()):
                    os.rmdir(name, dir_fd=parent)
            except FileNotFoundError:
                pass


def _write_posix(output, content, force, dry_run, before_publish):
    with ExitStack() as handles:
        directory = _open_posix_parent(output)
        handles.callback(os.close, directory)

        def stat_target():
            return os.stat(output.name, dir_fd=directory, follow_symlinks=False)

        _check_target(stat_target, output, force, dry_run)
        if dry_run:
            return

        staging_parent = _posix_staging_parent(directory, handles)
        with _private_posix_stage(staging_parent) as stage:
            temporary = "license"
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=stage
            )
            try:
                _complete_file(descriptor, content)
                if before_publish is not None:
                    before_publish(stat_target)
                if force:
                    # Recheck after staging. POSIX rename cannot check the target type atomically.
                    _check_target(stat_target, output, force, dry_run=False)
                    os.replace(temporary, output.name, src_dir_fd=stage, dst_dir_fd=directory)
                else:
                    os.link(
                        temporary,
                        output.name,
                        src_dir_fd=stage,
                        dst_dir_fd=directory,
                        follow_symlinks=False,
                    )
            finally:
                try:
                    os.unlink(temporary, dir_fd=stage)
                except FileNotFoundError:
                    pass


def _check_windows_parent(output):
    for parent in reversed(output.parents):
        info = parent.lstat()
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise InstallError(f"Output parent must be a regular directory path: {parent}")
    return info.st_dev, info.st_ino


def _verify_companion_file(name, expected, *, directory=None, check_parent=None):
    initial = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if _is_link(initial) or not stat.S_ISREG(initial.st_mode):
        raise InstallError("GPLv3 companion must be a regular file without links")
    flags = os.O_RDONLY | (os.O_BINARY if directory is None else os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(opened, initial):
            raise InstallError("The GPLv3 companion changed during verification")
        if check_parent is not None:
            check_parent()
        if opened.st_size != len(expected) or stream.read(len(expected) + 1) != expected:
            raise InstallError("GPLv3 companion must match the exact bundled GPL version 3 text")
        if check_parent is not None:
            check_parent()
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (_is_link(current) or not os.path.samestat(opened, current)
                or (opened.st_size, opened.st_mtime_ns) != (current.st_size, current.st_mtime_ns)):
            raise InstallError("The GPLv3 companion changed during verification")
    return opened


def verify_gplv3_companion(output: Path, companion: Path, expected: bytes, *, stat_output=None) -> None:
    """Verify the existing GPL text and refuse to use its file as the supplement target."""
    output = _validate_path(output)
    companion = _validate_path(companion)
    if output == companion:
        raise InstallError("The LGPLv3 output must be distinct from the GPLv3 companion")
    try:
        if os.name == "nt":
            parent = _check_windows_parent(companion)

            def check_parent():
                if _check_windows_parent(companion) != parent:
                    raise InstallError("The GPLv3 companion directory changed during verification")

            verified = _verify_companion_file(companion, expected, check_parent=check_parent)
        else:
            directory = _open_posix_parent(companion)
            try:
                verified = _verify_companion_file(companion.name, expected, directory=directory)
            finally:
                os.close(directory)
        try:
            target = (stat_output or output.lstat)()
        except FileNotFoundError:
            return
        if os.path.samestat(verified, target):
            raise InstallError("The LGPLv3 output must be distinct from the GPLv3 companion")
    except OSError as failure:
        raise InstallError(f"Could not verify GPLv3 companion {companion}: {failure.strerror or failure}") from failure


class _WindowsInstall:
    """Documented Win32 handles for a pinned directory and its staged file."""

    _SHARE_READ = 0x00000001
    _LIST_DIRECTORY = 0x00000001
    _READ_ATTRIBUTES = 0x00000080
    _DELETE = 0x00010000
    _GENERIC_WRITE = 0x40000000
    _OPEN_REPARSE_POINT = 0x00200000
    _BACKUP_SEMANTICS = 0x02000000
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _RENAME_INFORMATION = 10
    _NAME_INFO = 2
    _DISPOSITION_INFO = 4
    _ATTRIBUTE_TAG_INFO = 9
    _DUPLICATE_SAME_ACCESS = 0x00000002

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._types = wintypes
        self._invalid_handle = ctypes.c_void_p(-1).value
        native = ctypes.WinDLL("kernel32", use_last_error=True)
        nt = ctypes.WinDLL("ntdll")
        handle, word, pointer = wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID
        self._create_file = native.CreateFileW
        self._create_file.argtypes = (wintypes.LPCWSTR, word, word, pointer, word, word, handle)
        self._create_file.restype = handle
        self.close = native.CloseHandle
        self.close.argtypes = (handle,)
        self.close.restype = wintypes.BOOL
        self._get_info = native.GetFileInformationByHandleEx
        self._get_info.argtypes = (handle, ctypes.c_int, pointer, word)
        self._get_info.restype = wintypes.BOOL
        self._set_info = native.SetFileInformationByHandle
        self._set_info.argtypes = (handle, ctypes.c_int, pointer, word)
        self._set_info.restype = wintypes.BOOL
        current_process = native.GetCurrentProcess
        current_process.argtypes = ()
        current_process.restype = handle
        self._process = current_process()
        self._duplicate = native.DuplicateHandle
        self._duplicate.argtypes = (handle, handle, handle, ctypes.POINTER(handle), word, wintypes.BOOL, word)
        self._duplicate.restype = wintypes.BOOL
        self._set_nt_info = nt.NtSetInformationFile
        self._set_nt_info.argtypes = (handle, pointer, pointer, word, ctypes.c_int)
        self._set_nt_info.restype = wintypes.LONG
        self._dos_error = nt.RtlNtStatusToDosError
        self._dos_error.argtypes = (wintypes.LONG,)
        self._dos_error.restype = word

    def _check(self, result):
        if not result:
            raise self._ctypes.WinError(self._ctypes.get_last_error())

    def _open(self, path, access, disposition, flags):
        handle = self._create_file(str(path), access, self._SHARE_READ, None, disposition, flags, None)
        self._check(handle if handle != self._invalid_handle else None)
        return handle

    def pin_directory(self, path, handles):
        handle = self._open(path, self._READ_ATTRIBUTES | self._LIST_DIRECTORY, self._OPEN_EXISTING,
                            self._BACKUP_SEMANTICS | self._OPEN_REPARSE_POINT)
        handles.callback(self.close, handle)
        info = (self._types.DWORD * 2)()
        self._check(self._get_info(handle, self._ATTRIBUTE_TAG_INFO, info, self._ctypes.sizeof(info)))
        attributes = info[0]
        if not attributes & stat.FILE_ATTRIBUTE_DIRECTORY or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise InstallError(f"Output parent must be a regular directory path: {path}")

    def stage(self, path, handles):
        handle = self._open(path, self._GENERIC_WRITE | self._DELETE, self._CREATE_NEW, self._OPEN_REPARSE_POINT)
        handles.callback(self.close, handle)
        return handle

    def write(self, handle, content):
        import msvcrt

        duplicate = self._types.HANDLE()
        self._check(self._duplicate(self._process, handle, self._process, self._ctypes.byref(duplicate),
                                    0, False, self._DUPLICATE_SAME_ACCESS))
        try:
            descriptor = msvcrt.open_osfhandle(duplicate.value, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            self.close(duplicate)
            raise
        _complete_file(descriptor, content)

    def publish(self, handle, name, force):
        ctypes, wintypes = self._ctypes, self._types

        class RenameInfo(ctypes.Structure):
            _fields_ = (("replace", wintypes.DWORD), ("directory", wintypes.HANDLE),
                        ("length", wintypes.DWORD), ("name", wintypes.WCHAR * 1))

        encoded = name.encode("utf-16-le")
        size = ctypes.sizeof(RenameInfo) + len(encoded) + 2
        buffer = ctypes.create_string_buffer(size)
        info = RenameInfo.from_buffer(buffer)
        info.replace = int(force)
        info.length = len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + RenameInfo.name.offset, encoded, len(encoded))
        # Native FileRenameInformation with a simple name and a null RootDirectory
        # renames within the opened source file's directory.
        status = (ctypes.c_void_p * 2)()
        result = self._set_nt_info(handle, status, buffer, size, self._RENAME_INFORMATION)
        if result < 0:
            raise ctypes.WinError(self._dos_error(result))

    def discard_stage(self, handle, temporary_name):
        ctypes = self._ctypes
        # An interruption can arrive just after rename succeeds. Check the
        # handle's current name before marking the staged object for deletion.
        word = self._types.DWORD
        offset = ctypes.sizeof(word)
        buffer = ctypes.create_string_buffer(offset + 65536)
        self._check(self._get_info(handle, self._NAME_INFO, buffer, len(buffer)))
        length = word.from_buffer(buffer).value
        if not length or length % 2 or length > len(buffer) - offset:
            raise OSError(errno.EIO, "Invalid staged-file name returned by Windows")
        current_name = buffer[offset:offset + length].decode("utf-16-le").rsplit("\\", 1)[-1]
        if current_name.casefold() == temporary_name.casefold():
            delete = ctypes.c_ubyte(1)
            self._check(self._set_info(handle, self._DISPOSITION_INFO, ctypes.byref(delete), ctypes.sizeof(delete)))


def _write_windows(output, content, force, dry_run, before_publish):
    native = _WindowsInstall()
    with ExitStack() as handles:
        # Deny write and delete sharing on each verified component before opening its child.
        for parent in reversed(output.parents):
            native.pin_directory(parent, handles)
        _check_target(output.lstat, output, force, dry_run)
        if dry_run:
            return

        temporary_name = f".license-index-{secrets.token_hex(16)}.tmp"
        if output.name.casefold() == temporary_name.casefold():
            temporary_name += ".stage"
        temporary = output.parent / temporary_name
        handle = native.stage(temporary, handles)
        published = False
        try:
            native.write(handle, content)
            if before_publish is not None:
                before_publish(output.lstat)
            _check_target(output.lstat, output, force, dry_run=False)
            native.publish(handle, output.name, force)
            published = True
        finally:
            if not published:
                native.discard_stage(handle, temporary_name)


def write_license(output: Path, content: bytes, *, force: bool = False, dry_run: bool = False,
                  before_publish=None) -> None:
    """Atomically write the selected target without creating directories."""
    output = _validate_path(output)
    writer = _write_windows if os.name == "nt" else _write_posix
    try:
        if before_publish is not None:
            before_publish(output.lstat)
        writer(output, content, force, dry_run, before_publish)
    except FileExistsError as failure:
        raise InstallError(f"Output already exists: {output}. Use --force to replace it.") from failure
    except OSError as failure:
        if failure.errno in (errno.ELOOP, errno.ENOTDIR):
            raise InstallError("The output parent must be an existing directory without links") from failure
        raise InstallError(f"Could not write license to {output}: {failure.strerror or failure}") from failure
