"""Capture an exact GitHub pull-request merge candidate without checking it out."""

from contextlib import nullcontext
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryFile
from threading import Event, Timer
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


REPOSITORY = "software-commons/license-index"
REPOSITORY_ID = 1468281504
BASE_REF = "main"
MAX_DIFF_BYTES = 8 * 1024 * 1024
_MAX_API_BYTES = 2 * 1024 * 1024
_REMOTE_URL = f"https://github.com/{REPOSITORY}.git"
_API_URL = "https://api.github.com"
_SHA = re.compile(r"[0-9a-f]{40}")
_API_TIMEOUT = 20
_GIT_TIMEOUT = 90
CONTROL_PATHS = (
    ".github", ".gitattributes", "AGENTS.md", "docs/CODEX_GATE.md", "docs/GOVERNANCE_REVIEW.md",
    "docs/PUBLICATION.md", "legal-texts", "license-index", "license-index.cmd", "research/review",
    "research/reviews", "research/sources", "research/tools", "schemas", "sces/adoption.json",
    "sces/advisories", "sces/publication.json", "sces/releases", "tests", "tools",
)


class SnapshotError(ValueError):
    """GitHub or the captured Git objects could not establish the review target."""


def complete_rows(response, key):
    """Reject incomplete GitHub listings before making scope decisions."""
    if not isinstance(response, dict):
        raise SnapshotError(f"GitHub returned malformed {key}")
    rows = response.get(key)
    if not isinstance(rows, list) or type(response.get("total_count")) is not int:
        raise SnapshotError(f"GitHub returned malformed {key}")
    if len(rows) != response["total_count"]:
        raise SnapshotError(f"GitHub returned only part of the {key} listing")
    return rows


def token_is_target_only(github, repository_id, repository):
    rows = complete_rows(github._get_json("/installation/repositories?per_page=100"), "repositories")
    if len(rows) != 1 or not isinstance(rows[0], dict):
        return False
    row, = rows
    return type(row.get("id")) is int and row["id"] == repository_id and row.get("full_name") == repository


def _is_sha(value):
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


@dataclass(frozen=True)
class PullSnapshot:
    repository_id: int
    number: int
    base: str
    head: str
    merge: str

    def __post_init__(self):
        if type(self.repository_id) is not int or self.repository_id != REPOSITORY_ID:
            raise SnapshotError("GitHub returned an unexpected repository identifier")
        if type(self.number) is not int or self.number < 1:
            raise SnapshotError("Expected a positive pull-request number")
        objects = (self.base, self.head, self.merge)
        if not all(_is_sha(item) for item in objects) or len(set(objects)) != 3:
            raise SnapshotError("Expected distinct full base, head, and test-merge SHAs")


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class GitHub:
    """Read the fixed repository from GitHub without following redirects."""

    def __init__(self, bearer=None):
        self._headers = {
            "Accept": "application/vnd.github+json",
            "Cache-Control": "no-cache",
            "User-Agent": "software-commons-review",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if bearer is not None:
            self._headers["Authorization"] = f"Bearer {bearer}"
        self._opener = build_opener(_NoRedirects())

    def _get_json(self, path):
        request = Request(_API_URL + path, headers=self._headers, method="GET")
        try:
            with self._opener.open(request, timeout=_API_TIMEOUT) as response:
                payload = response.read(_MAX_API_BYTES + 1)
        except HTTPError as error:
            raise SnapshotError(f"GitHub could not supply the review target (HTTP {error.code})") from None
        except (URLError, TimeoutError):
            raise SnapshotError("GitHub could not supply the review target") from None
        if len(payload) > _MAX_API_BYTES:
            raise SnapshotError("GitHub review-target response exceeds the capture limit")
        try:
            return json.loads(payload)
        except (ValueError, UnicodeError):
            raise SnapshotError("GitHub supplied invalid review-target JSON") from None

    def get_pull(self, number):
        if type(number) is not int or number < 1:
            raise SnapshotError("Expected a positive pull-request number")
        item = self._get_json(f"/repos/{REPOSITORY}/pulls/{number}")
        if not isinstance(item, dict) or type(item.get("number")) is not int or item["number"] != number:
            raise SnapshotError("GitHub returned a different pull request")
        if item.get("state") != "open" or item.get("draft") is not False:
            raise SnapshotError("Review requires an open, non-draft pull request")
        base, head = item.get("base"), item.get("head")
        if not isinstance(base, dict) or not isinstance(head, dict) or base.get("ref") != BASE_REF:
            raise SnapshotError("Pull request does not target the configured base branch")
        repository = base.get("repo")
        if not isinstance(repository, dict) or repository.get("full_name") != REPOSITORY:
            raise SnapshotError("Pull request does not target the configured repository")
        if item.get("mergeable") is not True:
            raise SnapshotError("GitHub has not established a mergeable test commit")
        return PullSnapshot(
            repository.get("id"), number, base.get("sha"), head.get("sha"), item.get("merge_commit_sha"),
        )


def _isolated_git_environment():
    result = {name: value for name, value in os.environ.items() if not name.upper().startswith("GIT_")}
    result.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return result


def _git(directory, operation, *arguments, limit=4096, config=(), input_data=None):
    command = ["git", "--no-pager", "-C", str(directory)]
    for setting in config:
        command.extend(("-c", setting))
    command.extend((operation, *arguments))
    deadline = Event()
    try:
        with (nullcontext(subprocess.DEVNULL) if input_data is None else TemporaryFile()) as source:
            if input_data is not None:
                source.write(input_data)
                source.seek(0)
            process = subprocess.Popen(
                command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=_isolated_git_environment(),
            )
    except OSError as error:
        raise SnapshotError("Cannot start Git for isolated review capture") from error

    def timeout():
        deadline.set()
        if process.poll() is None:
            process.kill()

    timer = Timer(_GIT_TIMEOUT, timeout)
    timer.start()
    try:
        with process.stdout as output:
            data = output.read(limit + 1)
            if len(data) > limit:
                raise SnapshotError("Git output exceeds the configured review capture limit")
        return_code = process.wait()
        if deadline.is_set():
            raise SnapshotError(f"Git {operation} timed out during review capture")
        if return_code:
            raise SnapshotError(f"Git {operation} failed during review capture (exit {return_code})")
        return data
    finally:
        timer.cancel()
        timer.join()
        if process.poll() is None:
            process.kill()
        process.wait()


def _commit_headers(directory, commit):
    raw = _git(directory, "cat-file", "commit", commit, limit=65536)
    return raw.split(b"\n\n", 1)[0].splitlines()


def _parents(headers):
    return [line.removeprefix(b"parent ") for line in headers if line.startswith(b"parent ")]


def _merge_tree(directory, snapshot):
    headers = _commit_headers(directory, snapshot.merge)
    parents = _parents(headers)
    if parents != [snapshot.base.encode("ascii"), snapshot.head.encode("ascii")]:
        raise SnapshotError("Test merge commit does not have the exact ordered base and head parents")
    trees = [line.removeprefix(b"tree ") for line in headers if line.startswith(b"tree ")]
    if len(trees) != 1 or re.fullmatch(rb"[0-9a-f]{40}", trees[0]) is None:
        raise SnapshotError("Test merge commit does not identify an exact tree")
    return trees[0].decode("ascii")


def capture_diff(snapshot, directory: Path, *, queue_ref=None, linear_head=False) -> tuple[str, bytes]:
    """Capture the exact tree and base-to-candidate patch in an empty directory."""
    if not isinstance(snapshot, PullSnapshot):
        raise SnapshotError("Expected a validated pull-request snapshot")
    ref = f"refs/pull/{snapshot.number}/merge"
    if queue_ref is not None:
        prefix = f"refs/heads/gh-readonly-queue/{BASE_REF}/pr-{snapshot.number}-"
        if not isinstance(queue_ref, str) or not queue_ref.startswith(prefix) or not _is_sha(queue_ref[len(prefix):]):
            raise SnapshotError("Expected the exact GitHub merge-queue branch for this pull request")
        ref = queue_ref
    directory = Path(directory)
    if directory.is_symlink() or (directory.exists() and (not directory.is_dir() or any(directory.iterdir()))):
        raise SnapshotError("Review capture requires an empty, unlinked directory")
    directory.mkdir(exist_ok=True)
    directory = directory.resolve()

    _git(directory, "init", "--bare", "--quiet", "--template=", "--object-format=sha1")
    _git(
        directory, "fetch", "--quiet", "--depth=2", "--no-tags", "--no-recurse-submodules",
        "--no-auto-maintenance", _REMOTE_URL, ref,
        config=("http.followRedirects=false", "fetch.fsckObjects=true"),
    )
    fetched = _git(directory, "rev-parse", "--verify", "FETCH_HEAD^{commit}").strip()
    if fetched != snapshot.merge.encode("ascii"):
        raise SnapshotError("GitHub merge candidate changed during capture")
    tree = _merge_tree(directory, snapshot)
    if linear_head:
        parents = _parents(_commit_headers(directory, snapshot.head))
        if len(parents) != 1 or re.fullmatch(rb"[0-9a-f]{40}", parents[0]) is None:
            raise SnapshotError("Queue admission requires a single-parent pull-request head")
    diff = _git(
        directory, "diff", "--no-ext-diff", "--no-textconv",
        "--no-color", "--no-relative", "--no-renames", "--binary", "--full-index",
        "--src-prefix=a/", "--dst-prefix=b/", "--ignore-submodules=none",
        "--diff-algorithm=myers", "--no-indent-heuristic", snapshot.base, snapshot.merge, "--",
        limit=MAX_DIFF_BYTES, config=("core.quotePath=true",),
    )
    if not diff:
        raise SnapshotError("The GitHub test merge makes no changes relative to its base")
    return tree, diff


def capture_control_paths(directory, snapshot):
    """Read governance-sensitive additions, edits and deletions from the captured merge."""
    changes = _git(directory, "diff", "--name-only", "-z", "--no-renames",
                   snapshot.base, snapshot.merge, "--", *CONTROL_PATHS, limit=65536)
    return [path.decode("utf-8", errors="backslashreplace") for path in changes.rstrip(b"\x00").split(b"\x00") if path]
