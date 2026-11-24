"""Replay the pinned SPDX archive against the catalog and its trusted prior tree."""

import os
from pathlib import Path
import subprocess
import tarfile
from tempfile import TemporaryDirectory
from urllib.request import Request, build_opener
from xml.etree.ElementTree import ParseError

from .qualification import _blob_hash, _git, _git_blobs
from .reconcile import DATA_REPOSITORY, RELEASE, SOURCE_REPOSITORY, load_release, reconcile
from .records import DATA_COMMIT, HEX_256, DataError, NoRedirects, decode, encode, require

CHUNK_BYTES = 1024 * 1024


def archive_pin(source):
    commit = source["data_commit"]
    archive = source["archive"]
    require(DATA_COMMIT.fullmatch(commit) and HEX_256.fullmatch(archive["sha256"]),
            "invalid SPDX archive commit or digest")
    url = f"https://codeload.github.com/{DATA_REPOSITORY}/tar.gz/{commit}"
    size = archive["bytes"]
    require(archive["url"] == url and type(size) is int and size > 0, "invalid SPDX archive location or size")
    return url, size


def fetch_archive(source, destination):
    url, size = archive_pin(source)
    request = Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "software-commons-license-index"})
    with build_opener(NoRedirects()).open(request, timeout=60) as reply, destination.open("xb") as output:
        require(reply.status == 200, "SPDX archive download did not return a complete response")
        remaining = size
        while remaining:
            chunk = reply.read(min(remaining, CHUNK_BYTES))
            require(chunk, "SPDX archive download is shorter than the committed size")
            output.write(chunk)
            remaining -= len(chunk)
        require(not reply.read(1), "SPDX archive download exceeds the committed size")


def trusted_candidates(root, base):
    require(DATA_COMMIT.fullmatch(base), "use a full 40-character Git base commit")
    try:
        _git(root, "merge-base", "--is-ancestor", base, "HEAD")
    except DataError as error:
        raise DataError(f"SPDX replay requires a base commit in the checkout's history: {error}") from error
    previous = {}
    algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
    for name, oid in _git_blobs(root, base, "registry/candidates").items():
        path = root / name
        working = path.read_bytes() if path.is_file() and path.resolve() == path else b""
        content = working if working and _blob_hash(working, algorithm) == oid else _git(root, "cat-file", "blob", oid)
        row = decode(content)
        if row["origin"]["kind"] == "spdx":
            identifier = row["origin"]["identifier"]
            require(identifier.casefold() not in previous, f"duplicate trusted SPDX candidate: {identifier}")
            previous[identifier.casefold()] = row
    return previous


def compare_registry(catalog, origins, source, base):
    if base is None:
        require(all(row["origin"]["source"] == source["data_commit"] and "membership" not in row
                    for row in catalog.spdx.values()),
                "use --base to verify retained older SPDX origins or historical membership")
        previous = {}
    else:
        previous = trusted_candidates(catalog.root, base)
    updates, _ = reconcile(previous, origins, source)
    expected = {**previous, **{identifier.casefold(): row for identifier, row in updates.items()}}
    live_origins = {identifier.casefold(): origin for identifier, origin in origins.items()}
    missing = sorted(expected.keys() - catalog.spdx.keys())
    extra = sorted(catalog.spdx.keys() - expected.keys())
    require(not missing and not extra,
            f"SPDX replay inventory mismatch (missing: {', '.join(missing[:5])}; unexpected: {', '.join(extra[:5])})")
    for key, projected in sorted(expected.items()):
        actual = catalog.spdx[key]
        identifier = projected["origin"]["identifier"]
        if key in previous:
            require(actual["id"] == previous[key]["id"], f"SPDX replay candidate ID mismatch: {identifier}")
        require(encode(actual["origin"]) == encode(projected["origin"]), f"SPDX replay origin mismatch: {identifier}")
        if key in live_origins and actual["origin"]["source"] == source["data_commit"]:
            require(encode(actual["origin"]) == encode(live_origins[key]),
                    f"SPDX replay current origin differs from the archive: {identifier}")
        require(("membership" in actual) == ("membership" in projected)
                and encode(actual.get("membership")) == encode(projected.get("membership")),
                f"SPDX replay membership mismatch: {identifier}")
        history = projected["history"]
        require(encode(actual["history"][:len(history)]) == encode(history),
                f"SPDX replay history mismatch: {identifier}")
        additional = actual["history"][len(history):]
        require(all(isinstance(note, dict) and not {"origin", "membership"} & note.keys() for note in additional),
                f"SPDX replay found an unsupported origin or membership transition: {identifier}")


def archive_origins(source, archive):
    _, size = archive_pin(source)
    require(Path(archive).stat().st_size == size, "SPDX archive size differs from the committed pin")
    try:
        origins, observed = load_release(archive, source["release"], source["data_commit"],
                                         source["xml_commit"], source["archive"]["sha256"])
    except (ValueError, tarfile.TarError, ParseError) as error:
        raise DataError(f"could not replay pinned SPDX archive: {error}") from error
    require(encode(observed) == encode(source), "replayed SPDX source manifest differs from the committed pin")
    return origins


def replay(catalog, source, archive, base):
    compare_registry(catalog, archive_origins(source, archive), source, base)


def resolve_release_tag(repository, release, directory):
    """Confirm the publisher's exact tag and peel it to a commit without the REST API."""
    return resolve_upstream_ref(repository, f"refs/tags/v{release}", directory,
                                f"SPDX release tag v{release} in {repository}")


def resolve_upstream_ref(repository, ref, directory, description):
    url = f"https://github.com/{repository}.git"
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
                       GIT_NO_REPLACE_OBJECTS="1", GIT_GRAFT_FILE=os.devnull)
    command = ["git", "-C", str(directory), "-c", "http.followRedirects=false",
               "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]

    def git(*arguments):
        try:
            result = subprocess.run([*command, *arguments], stdin=subprocess.DEVNULL,
                                    capture_output=True, check=False, env=environment, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DataError(f"could not run Git to verify {description}: {error}") from error
        require(result.returncode == 0,
                f"Git {arguments[0]} could not verify {description} (exit {result.returncode})")
        return result.stdout

    git("init", "--quiet", "--template=")
    git("fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance",
        "--depth=1", "--filter=tree:0", "--", url, ref)
    commit = git("rev-parse", "--verify", "FETCH_HEAD^{commit}").decode("ascii").strip()
    require(DATA_COMMIT.fullmatch(commit), f"invalid commit for {description}")
    return commit


def replay_download(catalog, source, base, *, archives=None, historical=False):
    release = source["release"]
    require(RELEASE.fullmatch(release), "invalid SPDX release version")
    require(all(DATA_COMMIT.fullmatch(source[field]) for field in ("xml_commit", "data_commit")),
            "invalid SPDX upstream commit pin")
    if archives is None:
        archives = {}
    pin = encode(source)
    if pin not in archives or not historical:
        with TemporaryDirectory(prefix="license-index-spdx-") as directory:
            root = Path(directory)
            for repository, field, label in ((SOURCE_REPOSITORY, "xml_commit", "XML"),
                                              (DATA_REPOSITORY, "data_commit", "data")):
                expected = source[field]
                if historical:
                    # A managed tag can move after a historical capture. Verify the exact retained upstream object.
                    observed = resolve_upstream_ref(repository, expected, root, f"SPDX historical {label} commit")
                    require(observed == expected, f"SPDX historical {label} commit differs from the committed pin")
                else:
                    observed = resolve_release_tag(repository, release, root)
                    require(observed == expected, f"SPDX {label} release tag differs from the committed {label} pin")
            if pin not in archives:
                archive = root / "spdx.tar.gz"
                fetch_archive(source, archive)
                archives[pin] = archive_origins(source, archive)
    compare_registry(catalog, archives[pin], source, base)
