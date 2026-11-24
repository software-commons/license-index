"""Verify the scope and immediate predecessor of a coverage checkpoint."""

from hashlib import sha256
from pathlib import Path

from .qualification import _exact_file, _git, _git_blobs
from .records import DATA_COMMIT, HEX_256, decode, local_path, require


COVERAGE = "registry/coverage/current.json"
SNAPSHOTS = "registry/coverage/snapshots"
_SCOPE_FIELDS = ("included_ecosystems", "discovery_paths", "exclusions",
                 "inaccessible_areas", "reconciliation_choices")


def _validate_predecessor_history(root, name, commit, raw, origin):
    require(isinstance(origin, str) and DATA_COMMIT.fullmatch(origin) and origin != commit,
            "coverage predecessor must be a distinct full Git revision")
    _git(root, "merge-base", "--is-ancestor", commit, origin)
    pinned = _git_blobs(root, commit, COVERAGE, name)
    blob = pinned.get(name)
    require(blob is not None and pinned.get(COVERAGE) == blob
            and _git(root, "cat-file", "blob", blob) == raw,
            f"{name}: predecessor revision did not select the exact archived bytes")
    require(_git_blobs(root, origin, name).get(name) == blob,
            f"{name}: predecessor archive differs at the original coverage cutoff")

    revision = _git(root, "rev-list", "--parents", "-n", "1", origin).decode("ascii").split()
    require(len(revision) >= 2 and revision[0] == origin,
            "coverage checkpoint has no first-parent ledger")
    parent = _git_blobs(root, revision[1], COVERAGE, name)
    require(parent.get(COVERAGE) == blob and parent.get(name) == blob,
            f"{name}: predecessor is not the exact first-parent coverage ledger")


def validate_coverage_context(root, snapshot, *, origin=None):
    """Return the exact predecessor archive path, with Git ancestry proved when requested."""
    root = Path(root).resolve()
    scope = snapshot.get("research_scope")
    require(isinstance(scope, dict) and scope.keys() == set(_SCOPE_FIELDS),
            "coverage research scope must describe ecosystems, discovery, exclusions, access, and reconciliation")
    for field in _SCOPE_FIELDS:
        entries = scope[field]
        require(isinstance(entries, list) and entries
                and all(isinstance(item, str) and item.strip() for item in entries),
                f"coverage research scope {field} must contain nonblank entries")

    predecessor = snapshot.get("predecessor")
    require(isinstance(predecessor, dict) and predecessor.keys() == {"snapshot", "commit", "sha256"},
            "coverage requires an exact predecessor archive, Git revision, and SHA-256")
    name, commit, digest = (predecessor[field] for field in ("snapshot", "commit", "sha256"))
    require(isinstance(commit, str) and DATA_COMMIT.fullmatch(commit)
            and isinstance(digest, str) and HEX_256.fullmatch(digest),
            "coverage predecessor has an invalid Git revision or SHA-256")
    path = local_path(root, name)
    require(name.startswith(f"{SNAPSHOTS}/") and name != snapshot["snapshot"]
            and path.suffix == ".json" and path.relative_to(root).as_posix() == name,
            "coverage predecessor must name a different JSON archive under registry/coverage/snapshots")
    raw = _exact_file(path)
    require(sha256(raw).hexdigest() == digest, f"{name}: coverage predecessor SHA-256 mismatch")
    archived = decode(raw)
    require(isinstance(archived, dict) and archived.get("snapshot") == name,
            f"{name}: predecessor archive has an invalid self-reference")
    if origin is not None:
        _validate_predecessor_history(root, name, commit, raw, origin)
    return name
