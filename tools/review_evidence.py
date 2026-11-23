"""Capture the active SCES publication inputs as inert bytes from a reviewed Git tree."""

from base64 import b64decode, b64encode
from collections import defaultdict
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.request import ProxyHandler, Request, build_opener

from .qualification import POLICY_DIGEST, _blob_hash, _canonical
from .records import DataError, NoRedirects, decode, encode, require
from .review_snapshot import REPOSITORY, SnapshotError, _GIT_TIMEOUT, _REMOTE_URL, _git


_RECORD_KINDS = {"claim", "source", "dependency", "disposition", "conflict", "verification"}
_SUPPORT = {"support", "corroboration", "premise"}
_PHASES = ("research", "independent-review")
_SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_ARTIFACT_PATH = re.compile(r"sces/(?:[a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*")
_TREE_PATH = re.compile(r"sces/(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*")
_MAX_INVENTORY = 2 * 1024 * 1024
_MAX_RECORDS = 16 * 1024 * 1024
_MAX_EVIDENCE = 16 * 1024 * 1024
_MAX_BLOB = 4 * 1024 * 1024
_SELECTION = "sces/publication.json"
_ADOPTION = "sces/adoption.json"
_RAW_HOST = "https://raw.githubusercontent.com"
_RAW_TIMEOUT = 20
_READ_FROZEN_RECORDS = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from tools.review_evidence import _retrieve_frozen_records; "
    "_retrieve_frozen_records()"
)


def _digest(blob):
    return sha256(blob).hexdigest()


def _key(row, *kinds):
    kind, name, revision = (row[field] for field in ("kind", "id", "revision"))
    require(kind in (kinds or _RECORD_KINDS) and isinstance(name, str) and _SLUG.fullmatch(name)
            and type(revision) is int and 1 <= revision <= 2147483647, "invalid SCES record identity")
    return kind, name, revision


def _record_path(identity):
    kind, name, revision = identity
    return f"sces/records/{kind}/{name}--{revision}.json"


def _inventory(directory, commit, *prefixes):
    raw = _git(directory, "ls-tree", "-r", "-z", commit, "--", *prefixes, limit=_MAX_INVENTORY)
    require(not raw or raw.endswith(b"\0"), "incomplete SCES Git tree inventory")
    paths = {}
    folded_paths = set()
    for row in raw.split(b"\0")[:-1]:
        parts = re.fullmatch(rb"100644 blob ([0-9a-f]{40})\t([^\0]+)", row)
        require(parts is not None, "SCES review tree must contain regular, non-executable blobs")
        oid, raw_path = parts.groups()
        path = raw_path.decode("ascii")
        folded = path.casefold()
        require(_TREE_PATH.fullmatch(path) and folded not in folded_paths,
                "unsafe or duplicate SCES Git tree path")
        folded_paths.add(folded)
        paths[path] = oid.decode("ascii")
    return paths


def _forget_promisor_remotes(directory):
    # A direct URL plus --filter still auto-registers a promisor. Older Git ignores
    # GIT_NO_LAZY_FETCH, so remove that local configuration in the bare capture.
    keys = _git(directory, "config", "--local", "--null", "--name-only", "--list").decode("utf-8").split("\0")
    sections = sorted({key.rsplit(".", 1)[0] for key in keys
                       if key.startswith("remote.") and key.endswith((".promisor", ".partialclonefilter"))})
    for section in sections:
        _git(directory, "config", "--local", "--remove-section", section)
    if "extensions.partialclone" in keys:
        _git(directory, "config", "--local", "--unset-all", "extensions.partialclone")


def _frozen_inputs(directory, commit):
    try:
        object_type = _git(directory, "cat-file", "-t", commit).strip()
    except SnapshotError:
        _git(directory, "fetch", "--quiet", "--depth=1", "--filter=blob:none", "--no-tags",
             "--no-recurse-submodules", "--no-auto-maintenance", "--", _REMOTE_URL, commit,
             config=("http.followRedirects=false", "fetch.fsckObjects=true",
                     "protocol.allow=never", "protocol.https.allow=always"))
        _forget_promisor_remotes(directory)
        fetched = _git(directory, "rev-parse", "--verify", "FETCH_HEAD").strip()
        require(fetched == commit.encode("ascii"), "Git did not fetch the exact frozen SCES source commit")
        object_type = _git(directory, "cat-file", "-t", commit).strip()
    require(object_type == b"commit", "the frozen SCES source is not a commit object")
    # The pinned SCES validator separately checks source ancestry in CI.
    return _inventory(directory, commit, _ADOPTION, "sces/records", "sces/artifacts")


def _blobs(directory, paths, ordered, *, limit):
    if not ordered:
        return {}
    oids = [paths[path].encode("ascii") for path in ordered]
    raw = _git(directory, "cat-file", "--batch", input_data=b"\n".join(oids) + b"\n", limit=limit)
    cursor = 0
    result = {}
    for path, oid in zip(ordered, oids, strict=True):
        boundary = raw.find(b"\n", cursor)
        require(boundary >= cursor, "incomplete SCES Git blob header")
        header = re.fullmatch(rb"([0-9a-f]{40}) blob ([0-9]{1,10})", raw[cursor:boundary])
        require(header is not None and header[1] == oid, "unexpected SCES Git blob")
        size = int(header[2])
        end = boundary + 1 + size
        require(size <= _MAX_BLOB and raw[end:end + 1] == b"\n", "incomplete or oversized SCES Git blob")
        result[path] = raw[boundary + 1:end]
        cursor = end + 1
    require(cursor == len(raw), "unexpected extra SCES Git blobs")
    return result


def _missing_record_oids(directory, oids):
    if not oids:
        return set()
    ordered = sorted(oids)
    rows = _git(directory, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                input_data=("\n".join(ordered) + "\n").encode("ascii"), limit=60 * len(ordered)).splitlines()
    require(len(rows) == len(ordered), "incomplete local frozen SCES object inventory")
    missing = set()
    for oid, row in zip(ordered, rows, strict=True):
        expected = oid.encode("ascii") + b" "
        require(row in (expected + b"blob", expected + b"missing"), "invalid local frozen SCES object inventory")
        if row.endswith(b" missing"):
            missing.add(oid)
    return missing


def _retrieve_frozen_records():
    """Read only bounded, commit-qualified record paths from the fixed raw host."""
    request = decode(sys.stdin.buffer.read())
    repository, commit, paths, remaining = (request[key] for key in ("repository", "commit", "paths", "limit"))
    require(repository == REPOSITORY and re.fullmatch(r"[0-9a-f]{40}", commit)
            and type(remaining) is int and 0 < remaining <= _MAX_RECORDS, "unapproved frozen record retrieval")
    opener = build_opener(ProxyHandler({}), NoRedirects())
    outputs = {}
    for path in paths:
        require(path.startswith("sces/records/") and _TREE_PATH.fullmatch(path) and path not in outputs,
                "invalid frozen record retrieval path")
        cap = min(remaining, _MAX_BLOB)
        require(cap > 0, "frozen SCES registry exceeds the review capture limit")
        url = f"{_RAW_HOST}/{repository}/{commit}/{path}"
        query = Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "software-commons-review"},
                        method="GET")
        with opener.open(query, timeout=_RAW_TIMEOUT) as response:
            require(response.status == 200 and response.geturl() == url
                    and response.headers.get("Content-Encoding") in (None, "identity"),
                    "unexpected frozen SCES record response")
            raw = response.read(cap + 1)
        require(0 < len(raw) <= cap, "invalid or oversized frozen SCES record response")
        remaining -= len(raw)
        outputs[path] = b64encode(raw).decode("ascii")
    sys.stdout.buffer.write(encode(outputs))


def _fetch_frozen_records(repository, commit, paths, limit):
    require(0 < limit <= _MAX_RECORDS, "frozen SCES registry exceeds the review capture limit")
    package_root = Path(__file__).resolve().parents[1]
    request = encode({"repository": repository, "commit": commit, "paths": sorted(paths), "limit": limit})
    environment = {name: value for name, value in os.environ.items() if name.upper() in {"SYSTEMROOT", "WINDIR"}}
    try:
        fetched = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", _READ_FROZEN_RECORDS, str(package_root)],
                                 input=request, capture_output=True, timeout=_GIT_TIMEOUT, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DataError("bounded frozen SCES record retrieval could not complete") from error
    require(fetched.returncode == 0, "frozen SCES record retrieval failed")
    outputs = decode(fetched.stdout)
    require(isinstance(outputs, dict) and outputs.keys() == paths.keys(), "frozen SCES record retrieval is incomplete")
    blobs = {path: b64decode(value, validate=True) for path, value in outputs.items()}
    require(sum(map(len, blobs.values())) <= limit, "frozen SCES registry exceeds the review capture limit")
    for path, blob in blobs.items():
        require(0 < len(blob) <= _MAX_BLOB and _blob_hash(blob, "sha1") == paths[path],
                f"retrieved frozen SCES blob does not match its Git object: {path}")
    return blobs


def _record_blobs(directory, paths, cache, *, frozen_source=None):
    records = {path: oid for path, oid in paths.items() if path.startswith("sces/records/")}
    uncached = {oid: path for path, oid in records.items() if oid not in cache}
    missing = _missing_record_oids(directory, uncached) if frozen_source is not None else set()
    local = sorted(path for oid, path in uncached.items() if oid not in missing)
    for path, payload in _blobs(directory, paths, local, limit=_MAX_RECORDS).items():
        cache[records[path]] = payload
    if missing:
        remaining = _MAX_RECORDS - sum(len(cache[oid]) for oid in records.values() if oid in cache)
        # Fetch only inventoried missing records. The incoming data tree is never checked out.
        wanted = {uncached[oid]: oid for oid in missing}
        repository, commit = frozen_source
        for path, payload in _fetch_frozen_records(repository, commit, wanted, remaining).items():
            cache[records[path]] = payload
    blobs = {path: cache[oid] for path, oid in records.items()}
    require(sum(map(len, blobs.values())) <= _MAX_RECORDS, "SCES registry exceeds the review capture limit")
    return blobs


def _registry(blobs):
    records = {}
    edges = defaultdict(list)
    reviews = defaultdict(list)
    dispositions = {}
    conflicts = {}
    for path, blob in blobs.items():
        row = decode(blob)
        identity = _key(row)
        require(path == _record_path(identity) and identity not in records, "invalid SCES record path")
        records[identity] = row
        kind = identity[0]
        if kind == "dependency":
            edges[_key(row["claim"], "claim")].append(identity)
        if kind == "verification":
            require(row["phase"] in _PHASES, "invalid SCES verification phase")
            reviews[_key(row["claim"], "claim"), row["phase"]].append(identity)
        if kind in {"disposition", "conflict"}:
            latest = dispositions if kind == "disposition" else conflicts
            target = (_key(row["target"], "claim", "source") if kind == "disposition"
                      else (_key(row["claim"], "claim"), identity[1]))
            prior = latest.get(target)
            require(prior is None or prior[2] != identity[2], "ambiguous SCES record revision")
            if prior is None or prior[2] < identity[2]:
                latest[target] = identity
    conflicts_by_claim = defaultdict(list)
    for (claim, _), identity in conflicts.items():
        conflicts_by_claim[claim].append(identity)
    return records, edges, reviews, dispositions, conflicts_by_claim


def _active_reviews(selected, records, edges, reviews, dispositions):
    active = {}
    pending = list(selected)
    while pending:
        identity = pending.pop()
        if identity in active:
            continue
        disposition = records[dispositions[identity]]
        require(disposition["evidence"] == "supported" and disposition["verification"] == "independently-reviewed",
                "selected SCES claim or supporting premise is unqualified")
        current = []
        for phase, field in zip(_PHASES, ("research", "review"), strict=True):
            candidates = sorted(reviews[identity, phase], key=lambda key: records[key]["run"]["completed"])
            chosen = _key(disposition[field], "verification")
            require(candidates and candidates[-1] == chosen and records[chosen]["conclusion"] == "supported"
                    and (len(candidates) == 1
                         or records[candidates[-2]]["run"]["completed"] != records[chosen]["run"]["completed"]),
                    "selected SCES claim lacks current independent verification")
            current.append(chosen)
        active[identity] = current
        for dependency in edges[identity]:
            row = records[dependency]
            if row["relation"] in _SUPPORT:
                basis = _key(row["basis"], "claim", "source")
                if basis[0] == "claim":
                    pending.append(basis)
    return active


def _closure(selected, records, edges, active, dispositions, conflicts):
    used = set()
    artifacts = {}
    pending = list(selected)
    while pending:
        identity = pending.pop()
        if identity in used:
            continue
        used.add(identity)
        row = records[identity]
        kind = identity[0]
        if identity in dispositions and (kind != "claim" or identity in active):
            pending.append(dispositions[identity])
        if identity in active:
            pending.extend(edges[identity] + active[identity] + conflicts[identity])
        if kind == "dependency":
            pending.append(_key(row["basis"], "claim", "source"))
        if kind == "source":
            pending.extend(_key(source, "source") for source in row["upstream"])
        for descriptor in (row.get("artifact"), row.get("method"), row.get("run", {}).get("trace"),
                           row.get("reproduction", {}).get("artifact")):
            if descriptor is not None:
                path, checksum = descriptor["path"], descriptor["sha256"]
                require(isinstance(path, str) and path.startswith("sces/artifacts/") and _ARTIFACT_PATH.fullmatch(path)
                        and artifacts.setdefault(path, checksum) == checksum, "invalid SCES artifact reference")
        for field in ("replaces", "previous"):
            if field in row:
                pending.append(_key(row[field], kind))
    return used, artifacts


def _selected_registry(selected, blobs):
    records, edges, reviews, dispositions, conflicts = _registry(blobs)
    active = _active_reviews(selected, records, edges, reviews, dispositions)
    used, artifacts = _closure(selected, records, edges, active, dispositions, conflicts)
    return records, edges, active, used, artifacts


def _selected_evidence(directory, paths, repository):
    metadata = _blobs(directory, paths, [_ADOPTION, _SELECTION], limit=_MAX_EVIDENCE)
    adoption = decode(metadata[_ADOPTION])
    selection = decode(metadata[_SELECTION])
    slug = selection["release"]
    require(isinstance(slug, str) and _SLUG.fullmatch(slug), "invalid SCES release name")
    report_path = f"sces/releases/{slug}/qualification.json"
    claims_path = f"sces/releases/{slug}/claims.json"
    metadata.update(_blobs(directory, paths, [claims_path, report_path], limit=_MAX_EVIDENCE))
    report = decode(metadata[report_path])
    require(adoption["policy"] == report["policy"] == "SCES-1.0"
            and adoption["policy_sha256"] == report["policy_sha256"] == POLICY_DIGEST
            and adoption["repository"] == report["repository"] == repository and adoption["mode"] == "index"
            and report["dataset"] == selection["dataset"]
            and report["schema_version"] == selection["schema_version"]
            and report["synthetic"] is False and report["release"] == slug
            and report["source_commit"] == selection["source_commit"]
            and re.fullmatch(r"[0-9a-f]{40}", selection["source_commit"])
            and report["selection_sha256"] == _digest(metadata[_SELECTION])
            and report["artifacts"] == [{"path": claims_path, "sha256": _digest(metadata[claims_path])}],
            "SCES selection and qualification do not bind the exact publication")

    selected = [_key(ref, "claim") for ref in selection["claims"]]
    require(selected and len({identity[:2] for identity in selected}) == len(selected)
            and [_key(ref, "claim") for ref in report["claims"]] == sorted(selected),
            "SCES publication claim selection does not match the report")
    blob_cache = {}
    record_blobs = _record_blobs(directory, paths, blob_cache)
    records, edges, active, used, artifacts = _selected_registry(selected, record_blobs)
    expected_claims = [{"claim": records[identity],
                        "dependencies": [records[edge] for edge in sorted(edges[identity])]}
                       for identity in sorted(selected)]
    require(metadata[claims_path] == _canonical(expected_claims), "SCES claims payload omits or changes selected evidence")
    expected_reviews = []
    for identity in sorted(active):
        for key in active[identity]:
            row = records[key]
            expected_reviews.append({"record": dict(zip(("kind", "id", "revision"), key, strict=True)),
                                     "phase": row["phase"], "execution": row["run"]["execution"],
                                     "result": row["conclusion"], "record_sha256": _digest(record_blobs[_record_path(key)])})
    require(report["verifications"] == expected_reviews, "SCES report omits or changes selected verification records")

    evidence = {**{_record_path(key): record_blobs[_record_path(key)] for key in used},
                **_blobs(directory, paths, sorted(artifacts), limit=_MAX_EVIDENCE)}
    require(all(_digest(evidence[path]) == checksum for path, checksum in artifacts.items()),
            "SCES selected artifact digest mismatch")
    inputs = {path: _digest(blob) for path, blob in evidence.items()}
    inputs[_ADOPTION] = _digest(metadata[_ADOPTION])
    require(report["inputs_sha256"] == _digest(_canonical(inputs)), "SCES selected input digest mismatch")
    frozen = _frozen_inputs(directory, selection["source_commit"])
    # The same selected roots must reach the same records when reverse links come from the frozen tree.
    frozen_records = _record_blobs(directory, frozen, blob_cache,
                                   frozen_source=(REPOSITORY, selection["source_commit"]))
    *_, frozen_used, frozen_artifacts = _selected_registry(selected, frozen_records)
    require(used == frozen_used, "SCES selected record membership differs from the frozen source commit")
    require(artifacts == frozen_artifacts, "SCES selected artifact descriptors differ from the frozen source commit")
    for path in sorted(inputs):
        require(frozen.get(path) == paths[path], f"SCES selected input differs from its frozen source commit: {path}")

    predecessor = selection.get("previous_report")
    require(report.get("previous_report") == predecessor, "SCES previous report mismatch")
    if predecessor is not None:
        path = predecessor["path"]
        require(isinstance(path, str) and re.fullmatch(r"sces/releases/[a-z][a-z0-9-]*/qualification\.json", path)
                and path != report_path, "invalid SCES previous report path")
        metadata.update(_blobs(directory, paths, [path], limit=_MAX_EVIDENCE))
        require(_digest(metadata[path]) == predecessor["sha256"], "SCES previous report digest mismatch")
    staged = {**metadata, **evidence}
    require(sum(map(len, staged.values())) <= _MAX_EVIDENCE, "SCES selected evidence exceeds the review capture limit")
    return dict(sorted(staged.items()))


def capture_selected_evidence(directory, commit, repository):
    """Return exact selected bytes, or an empty mapping when there is no active publication."""
    try:
        selection = _git(directory, "ls-tree", "-z", commit, "--", _SELECTION)
        if not selection:
            return {}
        require(re.fullmatch(rb"100644 blob [0-9a-f]{40}\tsces/publication\.json\x00", selection),
                "SCES publication selection is not a regular, non-executable blob")
        require(repository == REPOSITORY, "SCES review repository is outside the allowlist")
        paths = _inventory(directory, commit, "sces")
        return _selected_evidence(directory, paths, repository)
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, DataError):
            raise
        raise DataError(f"could not capture the active SCES publication evidence: {error}") from error
