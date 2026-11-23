"""SPDX expression parsing and safe installation of selected license bytes."""

import errno
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import NamedTuple
import unicodedata


class InstallError(ValueError):
    """An invalid expression, unsupported rendering, or unsafe install target."""


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


def _write_posix(output, content, force, dry_run):
    # Walk no-follow directory handles so replacing a path component cannot
    # redirect a subsequent write to a different directory.
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(output.anchor, directory_flags)
    try:
        for part in output.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        _check_target(
            lambda: os.stat(output.name, dir_fd=directory, follow_symlinks=False),
            output,
            force,
            dry_run,
        )
        if dry_run:
            return

        temporary = f".license-index-{secrets.token_hex(16)}.tmp"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666, dir_fd=directory
        )
        try:
            _complete_file(descriptor, content)
            if force:
                os.replace(temporary, output.name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.link(
                    temporary,
                    output.name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
    finally:
        os.close(directory)


def _check_windows_parent(output):
    for parent in reversed(output.parents):
        info = parent.lstat()
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise InstallError(f"Output parent must be a regular directory path: {parent}")
    return info.st_dev, info.st_ino


def _write_windows(output, content, force, dry_run):
    parent_identity = _check_windows_parent(output)
    _check_target(output.lstat, output, force, dry_run)
    if dry_run:
        return

    descriptor, temporary = tempfile.mkstemp(prefix=".license-index-", suffix=".tmp", dir=output.parent)
    try:
        _complete_file(descriptor, content)
        if _check_windows_parent(output) != parent_identity:
            raise InstallError("The output directory changed during installation")
        _check_target(output.lstat, output, force, dry_run=False)
        if force:
            os.replace(temporary, output)
        else:
            # Windows rename fails atomically when the destination exists.
            os.rename(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_license(output: Path, content: bytes, *, force: bool = False, dry_run: bool = False) -> None:
    """Atomically write the selected target without creating directories."""
    output = _validate_path(output)
    writer = _write_windows if os.name == "nt" else _write_posix
    try:
        writer(output, content, force, dry_run)
    except FileExistsError as failure:
        raise InstallError(f"Output already exists: {output}. Use --force to replace it.") from failure
    except OSError as failure:
        if failure.errno in (errno.ELOOP, errno.ENOTDIR):
            raise InstallError("The output parent must be an existing directory without links") from failure
        raise InstallError(f"Could not write license to {output}: {failure.strerror or failure}") from failure
