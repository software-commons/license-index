"""Observe the exact CC0 installation behavior of a published License Index revision."""

import argparse
from hashlib import sha1, sha256
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile


COMMIT = "591c4a7021d646e89cedf64e77a36d1dc37870f6"
PUBLISHER_COMMIT = "91780e140892982eb3e0d530591ccbbca0d4690d"
TEXT_PATH = "legal-texts/cc0-1.0.txt"
TEXT_SHA256 = "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"
TEXT_BYTES = 7048
IDENTIFIER = "CC0-1.0"
TOOL = "reproduce_cc0_installer"
MESSAGE_LIMIT = 16384
GUARD = """
import runpy
import sys

def no_network(event, args):
    if event.startswith("socket."):
        raise SystemExit("Unexpected Python socket operation: " + event)

sys.addaudithook(no_network)
launcher = sys.argv.pop(1)
sys.argv[0] = launcher
runpy.run_path(launcher, run_name="__main__")
"""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git_object(kind, data):
    header = f"{kind} {len(data)}\0".encode()
    return sha1(header + data, usedforsecurity=False).hexdigest()


def stage_tree(repository, destination, environment):
    def git(*arguments):
        return subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(repository), *arguments],
            env=environment, timeout=30,
        )

    require(git_object("commit", git("cat-file", "commit", COMMIT)) == COMMIT,
            "Git commit bytes differ from the pinned public revision")
    entries = {}
    for record in git("ls-tree", "-rz", "--full-tree", COMMIT).split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        require(kind == b"blob" and mode in {b"100644", b"100755"}, "Unexpected tree entry")
        entries[raw_name.decode()] = oid.decode()

    remaining = entries.copy()
    with ZipFile(BytesIO(git("archive", "--format=zip", COMMIT))) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = PurePosixPath(member.filename)
            require(not name.is_absolute() and ".." not in name.parts and
                    "\\" not in member.filename and ":" not in member.filename,
                    "Unsafe archive path")
            content = archive.read(member)
            require(git_object("blob", content) == remaining.pop(member.filename, None),
                    "An archived entry differs from the pinned tree")
            path = destination.joinpath(*name.parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    require(not remaining, "Archive omitted entries in the pinned tree")
    return len(entries)


def observe(project, scratch, environment):
    def cli(*arguments):
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", GUARD, str(project / "tools/run_isolated.py"),
             "index", *arguments],
            cwd=scratch, env=environment, capture_output=True, timeout=30,
        )

    text_path = project / TEXT_PATH
    original = text_path.read_bytes()
    require(len(original) == TEXT_BYTES and sha256(original).hexdigest() == TEXT_SHA256,
            "Bundled bytes differ from the observed publisher input")
    output = scratch / "LICENSE"
    add = ("add", IDENTIFIER, "--output", str(output), "--json")

    extracted = cli("text", IDENTIFIER)
    require(extracted.returncode == 0 and extracted.stdout == original, "Exact text retrieval failed")
    preview = cli(*add, "--dry-run")
    require(preview.returncode == 0 and not output.exists(), "Dry run failed or created a destination")
    report = json.loads(preview.stdout)
    require(report["dry_run"] and not report["written"] and report["text"].encode() == original,
            "Dry-run report differs from the exact text")
    source = report["source"]
    require(source["revision"] == PUBLISHER_COMMIT and source["install"] == "unchanged" and
            source["sha256"] == TEXT_SHA256 and source["path"] == TEXT_PATH,
            "Dry run used a different publisher source or recipe")

    written = cli(*add)
    require(written.returncode == 0 and output.read_bytes() == original, "Written file differs from the input")
    require(json.loads(written.stdout)["output_sha256"] == TEXT_SHA256, "Reported output digest differs")
    output.write_bytes(b"existing output fixture\n")
    refusal = cli(*add)
    require(refusal.returncode == 1 and b"Output already exists" in refusal.stderr and
            output.read_bytes() == b"existing output fixture\n", "Existing output was not safely refused")
    output.unlink()

    parameters = cli(*add, "--holder", "Fixture", "--year", "2026")
    require(parameters.returncode == 1 and b"This license is installed unchanged" in parameters.stderr and
            not output.exists(), "Notice substitution parameters were not refused")
    text_path.write_bytes(b"X" + original[1:])
    altered = cli(*add)
    require(altered.returncode == 1 and b"SHA-256 mismatch" in altered.stderr and not output.exists(),
            "Altered bundled text was not refused")
    return {
        "input_bytes": len(original),
        "input_path": TEXT_PATH,
        "input_sha256": TEXT_SHA256,
        "output_bytes": len(original),
        "output_sha256": TEXT_SHA256,
        "publisher_revision": PUBLISHER_COMMIT,
        "recipe": "unchanged",
        "checks": ["byte-exact text", "byte-exact preview without write", "byte-exact new file",
                   "existing-file refusal with preservation", "notice-parameter refusal",
                   "same-length altered-input refusal", "Python socket calls prohibited in CLI"],
    }


def reproduce(repository, scratch):
    inherited = {"PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in inherited}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    with TemporaryDirectory(prefix="cc0-", dir=scratch) as folder:
        root = Path(folder).resolve()
        checkout = root / "index"
        tests = root / "tests"
        tests.mkdir()
        environment.update({"TMP": folder, "TEMP": folder, "TMPDIR": folder})
        inventory = stage_tree(repository, checkout, environment)
        measurement = observe(checkout, tests, environment)
    return {
        "index_revision": COMMIT,
        "tree_file_count": inventory,
        "platform": sys.platform,
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "python": sys.version.split()[0],
        "method_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "measurement": measurement,
    }


def tool_reply(request, repository, scratch):
    method = request.get("method")
    params = request.get("params", {})
    if method == "initialize":
        return {"protocolVersion": params["protocolVersion"], "capabilities": {"tools": {}},
                "serverInfo": {"name": "cc0-installer-reproduction", "version": "1"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [{"name": TOOL, "description": "Replay the fixed public CC0 installer fixture.",
                           "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]}
    if method == "tools/call" and params.get("name") == TOOL and params.get("arguments", {}) == {}:
        result = reproduce(repository, scratch)
        return {"isError": False, "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}
    raise ValueError("Unknown fixed reproduction request")


def serve(repository, scratch):
    while line := sys.stdin.buffer.readline(MESSAGE_LIMIT + 1):
        if len(line) > MESSAGE_LIMIT:
            return 2
        request_id = None
        try:
            request = json.loads(line)
            require(isinstance(request, dict), "Expected a JSON-RPC request object")
            if "id" not in request:
                continue
            request_id = request["id"]
            require(request["jsonrpc"] == "2.0", "Expected JSON-RPC 2.0")
            response = {"result": tool_reply(request, repository, scratch)}
        except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
            response = {"error": {"code": -32602, "message": "The fixed reproduction request failed."}}
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, **response}), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--stdio", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    scratch = args.scratch.resolve(strict=True)
    require(scratch.is_dir() and not scratch.is_relative_to(repository),
            "Use a scratch directory outside the repository")
    if args.stdio:
        return serve(repository, scratch)
    print(json.dumps(reproduce(repository, scratch), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
