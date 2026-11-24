"""Execute a fixed MIT reproduction method on a verified public tree in scratch."""

import argparse
from datetime import datetime, timezone
from hashlib import file_digest, sha1, sha256
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
from shutil import copyfile
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


PUBLIC_COMMIT = "4c67e9b85e218fe40e9b17f2bde7fb90da0b552b"
ARCHIVE_SIZE = 49486673
ARCHIVE_SHA256 = "5fe8c93bbceaac6d2a3df6cf9fe07abd9af2eca3ec37cf08e4aa74bb24a98683"
METHOD_SHA256 = "4ab610676414f43ec29dae882ce393c3ee187df2bb5e1b33cfc2c2d60fe07bcf"
MANIFEST_SHA256 = "bd3fd21516c63b08c4d81aafd5736ddc255fa4c82aafcc8b9df59f4913cd969d"
TOOL = "reproduce_public_mit_installer"
MAX_MESSAGE = 16384


def require(condition, description):
    if not condition:
        raise ValueError(description)


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(data):
    return sha256(data).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def isolated_environment():
    allowed = {"PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "LANG", "LC_ALL"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed} | {
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_GRAFT_FILE": os.devnull, "PYTHONNOUSERSITE": "1",
    }


def git_object(kind, contents):
    return sha1(f"{kind} {len(contents)}\0".encode() + contents, usedforsecurity=False).hexdigest()


def stage_public_tree(settings, destination, environment):
    def git(*arguments):
        return subprocess.check_output(
            [str(settings.git), "--no-replace-objects", "-c", "advice.graftFileDeprecated=false",
             "-C", str(settings.public_repository), *arguments],
            env=environment, timeout=30,
        )

    require(git_object("commit", git("cat-file", "commit", PUBLIC_COMMIT)) == PUBLIC_COMMIT,
            "Public commit bytes differ from the pin")
    entries = {}
    for line in git("ls-tree", "-rz", "--full-tree", PUBLIC_COMMIT).split(b"\0"):
        if line:
            metadata, name = line.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            require(kind == b"blob" and mode in {b"100644", b"100755"}, "Unsupported entry in public tree")
            entries[name.decode()] = oid.decode()

    members = {}
    with tarfile.open(fileobj=BytesIO(git("archive", "--format=tar", PUBLIC_COMMIT)), mode="r:") as archive:
        for file in archive:
            if file.isdir():
                continue
            name = PurePosixPath(file.name)
            require(file.isfile() and not name.is_absolute() and ".." not in name.parts
                    and "\\" not in file.name and ":" not in file.name and file.name not in members,
                    "Unsafe entry in public archive")
            with archive.extractfile(file) as stream:
                data = stream.read()
            require(git_object("blob", data) == entries.get(file.name), "Archived file differs from its Git object")
            path = destination.joinpath(*name.parts)
            require(path.resolve().is_relative_to(destination), "Archive entry escapes scratch worktree")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            members[file.name] = digest(data)
    require(members.keys() == entries.keys(), "Public archive has an unexpected file inventory")
    return digest(canonical(members)), len(members)


def reproduce(settings):
    started = utc_now()
    method = settings.method.read_bytes()
    require(digest(method) == METHOD_SHA256, "Reproduction method differs from the reviewed pin")
    require(settings.spdx_archive.stat().st_size == ARCHIVE_SIZE, "Unexpected public SPDX archive size")
    with settings.spdx_archive.open("rb") as archive:
        require(file_digest(archive, "sha256").hexdigest() == ARCHIVE_SHA256, "Public SPDX archive differs from the pin")

    environment = isolated_environment()
    with TemporaryDirectory(prefix="mit-probe-", dir=settings.scratch) as temporary:
        root = Path(temporary).resolve()
        target = root / "method"
        target.mkdir()
        environment.update({"TMP": temporary, "TEMP": temporary, "TMPDIR": temporary})
        manifest, count = stage_public_tree(settings, root / "license-index", environment)
        copyfile(settings.spdx_archive, root / "spdx-3.29.0.tar.gz")
        method_path = target / "reproduce_mit_cli.py"
        method_path.write_bytes(method)
        result = subprocess.run([sys.executable, "-I", "-B", str(method_path)], cwd=target,
                                env=environment, capture_output=True, timeout=180, check=True)
        require(result.stdout and len(result.stdout) <= MAX_MESSAGE and not result.stderr,
                "Unexpected reproduction process output")
        measured = json.loads(result.stdout)
    require(measured.get("archive_sha256") == ARCHIVE_SHA256
            and measured.get("detail_text_bytes_equal") is True and measured.get("notice_range") == [13, 53]
            and "exact write" in measured.get("cli_checks", []), "Incomplete exact-byte and actual-write observation")
    return {
        "status": "public-mit-reproduction-observation", "started_at": started, "completed_at": utc_now(),
        "public_commit": PUBLIC_COMMIT, "public_tree_manifest_sha256": manifest, "public_tree_files": count,
        "source_manifest_sha256": MANIFEST_SHA256, "method_sha256": METHOD_SHA256,
        "runner_sha256": digest(Path(__file__).read_bytes()), "python_version": sys.version.split()[0],
        "platform": sys.platform, "measurement_sha256": digest(canonical(measured)),
        "measurement_stdout_sha256": digest(result.stdout), "measurement": measured,
    }


def dispatch(message, settings):
    method = message.get("method")
    args = message.get("params", {})
    if method == "initialize":
        version = args.get("protocolVersion")
        return {"protocolVersion": version if version in {"2025-03-26", "2025-06-18", "2025-11-25"} else "2025-06-18",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "public-mit-reproduction", "version": "1"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [{"name": TOOL, "description": "Run the pinned public MIT CLI reproduction in a fresh scratch copy.",
                           "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]}
    if method == "tools/call" and args.get("name") == TOOL and args.get("arguments", {}) == {}:
        try:
            text = canonical(reproduce(settings)).decode().removesuffix("\n")
            return {"isError": False, "content": [{"type": "text", "text": text}]}
        except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError):
            return {"isError": True, "content": [{"type": "text", "text": "The fixed public MIT reproduction failed."}]}
    raise ValueError("Unsupported request")


def serve(settings):
    while line := sys.stdin.buffer.readline(MAX_MESSAGE + 1):
        if len(line) > MAX_MESSAGE:
            return 2
        request_id = None
        try:
            message = json.loads(line)
            if isinstance(message, dict) and "id" not in message:
                continue
            request_id = message.get("id")
            require(message.get("jsonrpc") == "2.0", "Expected JSON-RPC 2.0")
            reply = {"result": dispatch(message, settings)}
        except (AttributeError, ValueError, TypeError):
            reply = {"error": {"code": -32602, "message": "Invalid fixed reproduction request"}}
        sys.stdout.buffer.write(canonical({"jsonrpc": "2.0", "id": request_id, **reply}))
        sys.stdout.buffer.flush()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-repository", required=True, type=Path)
    parser.add_argument("--spdx-archive", required=True, type=Path)
    parser.add_argument("--method", required=True, type=Path)
    parser.add_argument("--git", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--stdio", action="store_true")
    settings = parser.parse_args()
    for name in ("public_repository", "spdx_archive", "method", "git", "scratch"):
        setattr(settings, name, getattr(settings, name).resolve(strict=True))
    require(settings.scratch.is_dir() and not settings.scratch.is_relative_to(settings.public_repository),
            "Scratch must be a separate existing directory outside the public repository")
    if settings.stdio:
        return serve(settings)
    sys.stdout.buffer.write(canonical(reproduce(settings)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
