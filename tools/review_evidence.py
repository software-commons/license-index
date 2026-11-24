"""Capture the active SCES publication inputs as inert bytes from a reviewed Git tree."""

from base64 import b64decode, b64encode
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess
import sys
from time import monotonic
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
_MAX_EVIDENCE = 16 * 1024 * 1024
_MAX_BLOB = 4 * 1024 * 1024
_RECORD_SCAN_PAGE = 256
_FROZEN_BATCH_COUNT = 4
_MAX_FROZEN_BATCH = _FROZEN_BATCH_COUNT * _MAX_BLOB
_MAX_RECORD_BATCH = _FROZEN_BATCH_COUNT * (_MAX_BLOB + 64)
# These per-candidate traversal and transport limits are separate from the 16 MiB staged evidence limit.
_MAX_REGISTRY_BYTES = 256 * 1024 * 1024
_MAX_FROZEN_BYTES = 64 * 1024 * 1024
_MAX_FROZEN_REQUESTS = 256
_REGISTRY_SECONDS = 300
_SELECTION = "sces/publication.json"
_BASE_SELECTION_REVIEW_PATH = "base:sces/publication.json"
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


def _forget_promisor_remotes(directory, budget):
    # A direct URL plus --filter still auto-registers a promisor. Older Git ignores
    # GIT_NO_LAZY_FETCH, so remove that local configuration in the bare capture.
    budget.time_remaining()
    keys = _git(directory, "config", "--local", "--null", "--name-only", "--list").decode("utf-8").split("\0")
    sections = sorted({key.rsplit(".", 1)[0] for key in keys
                       if key.startswith("remote.") and key.endswith((".promisor", ".partialclonefilter"))})
    for section in sections:
        budget.time_remaining()
        _git(directory, "config", "--local", "--remove-section", section)
    if "extensions.partialclone" in keys:
        budget.time_remaining()
        _git(directory, "config", "--local", "--unset-all", "extensions.partialclone")


def _frozen_inputs(directory, commit, budget):
    budget.time_remaining()
    try:
        object_type = _git(directory, "cat-file", "-t", commit).strip()
    except SnapshotError:
        budget.time_remaining()
        _git(directory, "fetch", "--quiet", "--depth=1", "--filter=blob:none", "--no-tags",
             "--no-recurse-submodules", "--no-auto-maintenance", "--", _REMOTE_URL, commit,
             config=("http.followRedirects=false", "fetch.fsckObjects=true",
                     "protocol.allow=never", "protocol.https.allow=always"))
        _forget_promisor_remotes(directory, budget)
        budget.time_remaining()
        fetched = _git(directory, "rev-parse", "--verify", "FETCH_HEAD").strip()
        require(fetched == commit.encode("ascii"), "Git did not fetch the exact frozen SCES source commit")
        budget.time_remaining()
        object_type = _git(directory, "cat-file", "-t", commit).strip()
    require(object_type == b"commit", "the frozen SCES source is not a commit object")
    # The pinned SCES validator separately checks source ancestry in CI.
    budget.time_remaining()
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


def _record_sizes(directory, paths, ordered):
    oids = [paths[path].encode("ascii") for path in ordered]
    rows = _git(directory, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                input_data=b"\n".join(oids) + b"\n", limit=64 * len(ordered)).splitlines()
    require(len(rows) == len(ordered), "incomplete local SCES record inventory")
    sizes = {}
    for path, oid, row in zip(ordered, oids, rows, strict=True):
        if row == oid + b" missing":
            sizes[path] = None
            continue
        match = re.fullmatch(rb"([0-9a-f]{40}) blob ([0-9]{1,10})", row)
        require(match is not None and match[1] == oid and 0 < int(match[2]) <= _MAX_BLOB,
                f"invalid or oversized local SCES record: {path}")
        sizes[path] = int(match[2])
    return sizes


def _retrieve_frozen_records():
    """Read only bounded, commit-qualified record paths from the fixed raw host."""
    request = decode(sys.stdin.buffer.read())
    repository, commit, paths, remaining = (request[key] for key in ("repository", "commit", "paths", "limit"))
    require(repository == REPOSITORY and re.fullmatch(r"[0-9a-f]{40}", commit)
            and isinstance(paths, list) and 0 < len(paths) <= _FROZEN_BATCH_COUNT
            and type(remaining) is int and 0 < remaining <= _MAX_FROZEN_BATCH, "unapproved frozen record retrieval")
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


def _fetch_frozen_records(repository, commit, paths, limit, *, timeout=_GIT_TIMEOUT):
    require(0 < limit <= _MAX_FROZEN_BATCH, "frozen SCES registry exceeds the review capture limit")
    package_root = Path(__file__).resolve().parents[1]
    request = encode({"repository": repository, "commit": commit, "paths": sorted(paths), "limit": limit})
    environment = {name.upper(): value for name, value in os.environ.items() if name.upper() in {"SYSTEMROOT", "WINDIR"}}
    try:
        fetched = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", _READ_FROZEN_RECORDS, str(package_root)],
                                 input=request, capture_output=True, timeout=min(timeout, _GIT_TIMEOUT), check=False,
                                 env=environment)
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


class _RecordBudget:
    def __init__(self):
        self.remaining = _MAX_REGISTRY_BYTES
        self.frozen_bytes = _MAX_FROZEN_BYTES
        self.frozen_requests = _MAX_FROZEN_REQUESTS
        self.deadline = monotonic() + _REGISTRY_SECONDS

    def time_remaining(self):
        remaining = self.deadline - monotonic()
        require(remaining > 0, "SCES registry traversal exceeded its elapsed-time limit")
        return remaining

    def charge(self, size):
        self.time_remaining()
        require(size <= self.remaining, "SCES registry exceeds its cumulative processing byte limit")
        self.remaining -= size

    def frozen_limit(self, count):
        require(count <= self.frozen_requests, "SCES frozen registry exceeds its cumulative retrieval request limit")
        require(self.frozen_bytes > 0, "SCES frozen registry exceeds its cumulative retrieval byte limit")
        require(self.remaining > 0, "SCES registry exceeds its cumulative processing byte limit")
        self.frozen_requests -= count
        return min(count * _MAX_BLOB, self.frozen_bytes, self.remaining)

    def charge_frozen(self, size):
        require(size <= self.frozen_bytes, "SCES frozen registry exceeds its cumulative retrieval byte limit")
        self.frozen_bytes -= size
        self.charge(size)


def _record_blobs(directory, paths, ordered, budget, *, frozen_source=None):
    """Read bounded Git batches and separately bound missing raw publisher blobs."""
    for offset in range(0, len(ordered), _RECORD_SCAN_PAGE):
        budget.time_remaining()
        page = ordered[offset:offset + _RECORD_SCAN_PAGE]
        sizes = _record_sizes(directory, paths, page)
        local, missing, size = [], [], 0
        for path in page:
            if sizes[path] is None:
                missing.append(path)
                continue
            weight = sizes[path] + 64
            if size + weight > _MAX_RECORD_BATCH:
                budget.charge(size - 64 * len(local))
                yield from _blobs(directory, paths, local, limit=size).items()
                local, size = [], 0
            local.append(path)
            size += weight
        if local:
            budget.charge(size - 64 * len(local))
            yield from _blobs(directory, paths, local, limit=size).items()
        if missing:
            require(frozen_source is not None, "an exact candidate SCES record is missing")
            repository, commit = frozen_source
            for start in range(0, len(missing), _FROZEN_BATCH_COUNT):
                group = missing[start:start + _FROZEN_BATCH_COUNT]
                wanted = {path: paths[path] for path in group}
                # Fetch only inventoried frozen records. No upstream tree is checked out.
                limit = budget.frozen_limit(len(group))
                blobs = _fetch_frozen_records(repository, commit, wanted, limit, timeout=budget.time_remaining())
                budget.charge_frozen(sum(map(len, blobs.values())))
                yield from blobs.items()
        budget.time_remaining()


def _reverse_record(blob):
    row = decode(blob)
    identity = _key(row)
    reverse = None
    if identity[0] in ("dependency", "conflict"):
        reverse = _key(row["claim"], "claim")
    elif identity[0] == "verification":
        phase, completed = row["phase"], row["run"]["completed"]
        require(phase in _PHASES and isinstance(completed, str)
                and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", completed),
                "invalid SCES verification phase or completion timestamp")
        reverse = (_key(row["claim"], "claim"), phase), completed
    elif identity[0] == "disposition":
        reverse = _key(row["target"], "claim", "source")
    return identity, reverse


def _registry(directory, paths, reverse_cache, budget, *, frozen_source=None):
    registry = sorted(path for path in paths if path.startswith("sces/records/"))
    uncached = [path for path in registry if paths[path] not in reverse_cache]
    for path, blob in _record_blobs(directory, paths, uncached, budget, frozen_source=frozen_source):
        reverse_cache[paths[path]] = _reverse_record(blob)
    edges = defaultdict(list)
    reviews = {}
    dispositions, conflicts = {}, {}
    for path in registry:
        identity, reverse = reverse_cache[paths[path]]
        require(path == _record_path(identity), "invalid SCES record path")
        kind = identity[0]
        if kind == "dependency":
            edges[reverse].append(identity)
        if kind == "verification":
            key, completed = reverse
            prior = reviews.get(key)
            if prior is None or completed > prior[0]:
                reviews[key] = (completed, identity, True)
            elif completed == prior[0]:
                reviews[key] = (completed, identity, False)
        if kind in ("disposition", "conflict"):
            latest = dispositions if kind == "disposition" else conflicts
            target = reverse if kind == "disposition" else (reverse, identity[1])
            prior = latest.get(target)
            require(prior is None or prior[2] != identity[2], "ambiguous SCES record revision")
            if prior is None or prior[2] < identity[2]:
                latest[target] = identity
    conflicts_by_claim = defaultdict(list)
    for (claim, _), identity in conflicts.items():
        conflicts_by_claim[claim].append(identity)
    return edges, reviews, dispositions, conflicts_by_claim


class _SelectedRecords:
    def __init__(self, directory, paths, budget, *, limit, frozen_source=None, reuse=None):
        self.directory, self.paths = directory, paths
        self.budget = budget
        self.remaining, self.frozen_source = limit, frozen_source
        self.reuse = {} if reuse is None else reuse
        self.raw, self.rows = {}, {}

    def load(self, keys):
        missing = []
        for identity in sorted(set(keys) - self.rows.keys()):
            path = _record_path(identity)
            existing = self.reuse.get(self.paths[path])
            if existing is None:
                missing.append(path)
            else:
                self.budget.charge(len(existing))
                self._store(path, existing)
        for path, blob in _record_blobs(self.directory, self.paths, missing, self.budget, frozen_source=self.frozen_source):
            self._store(path, blob)

    def _store(self, path, blob):
        self.remaining -= len(blob)
        require(self.remaining >= 0, "SCES selected evidence exceeds the review capture limit")
        row = decode(blob)
        identity = _key(row)
        require(path == _record_path(identity), "invalid SCES record path")
        self.raw[path] = blob
        self.rows[identity] = row


def _check_review_pair(claim_digest, research, review, now):
    require(research["claim_sha256"] == review["claim_sha256"] == claim_digest,
            "SCES verification pair does not bind the exact claim revision bytes")
    first, second = research["run"], review["run"]
    executions = (first["execution"], second["execution"])
    require(all(isinstance(value, str) and value and value == value.strip() for value in executions)
            and executions[0] != executions[1], "selected SCES claim requires distinct nonempty research and review executions")
    research_start, research_end = (_timestamp(first[field], "verification") for field in ("started", "completed"))
    review_start, review_end = (_timestamp(second[field], "verification") for field in ("started", "completed"))
    require(research_start <= research_end <= now and review_start <= review_end <= now,
            "SCES verification interval starts after it completes or completes after the current UTC time")
    require(research_end <= review_start,
            "SCES independent review started before the latest research execution completed")
    first_trace, second_trace = first["trace"], second["trace"]
    require(first_trace["path"] != second_trace["path"] and first_trace["sha256"] != second_trace["sha256"],
            "SCES research and independent review require distinct trace paths and digests")
    require({row["capture"] for row in research["acquisitions"]}.isdisjoint(row["capture"] for row in review["acquisitions"]),
            "SCES research and independent review share an acquisition capture")


def _active_reviews(selected, captured, edges, reviews, dispositions, now):
    active = {}
    pending = set(selected)
    while pending:
        frontier = pending - active.keys()
        pending = set()
        captured.load(frontier | {dispositions[identity] for identity in frontier})
        needed = set()
        for identity in frontier:
            disposition = captured.rows[dispositions[identity]]
            require(disposition["evidence"] == "supported" and disposition["verification"] == "independently-reviewed",
                    "selected SCES claim or supporting premise is unqualified")
            current = []
            for phase, field in zip(_PHASES, ("research", "review"), strict=True):
                latest = reviews.get((identity, phase))
                chosen = _key(disposition[field], "verification")
                require(latest is not None and latest[1:] == (chosen, True),
                        "selected SCES claim lacks current independent verification")
                current.append(chosen)
            active[identity] = current
            needed.update(current)
            needed.update(edges[identity])
        captured.load(needed)
        for identity in frontier:
            research, review = (captured.rows[key] for key in active[identity])
            require(research["conclusion"] == review["conclusion"] == "supported",
                    "selected SCES claim lacks current independent verification")
            _check_review_pair(_digest(captured.raw[_record_path(identity)]), research, review, now)
            for dependency in edges[identity]:
                row = captured.rows[dependency]
                if row["relation"] in _SUPPORT:
                    basis = _key(row["basis"], "claim", "source")
                    if basis[0] == "claim":
                        pending.add(basis)
    return active


def _closure(selected, captured, edges, active, dispositions, conflicts):
    used = set()
    artifacts = {}
    pending = set(selected)
    while pending:
        frontier = pending - used
        captured.load(frontier)
        used.update(frontier)
        pending = set()
        for identity in frontier:
            row = captured.rows[identity]
            kind = identity[0]
            if identity in dispositions and (kind != "claim" or identity in active):
                pending.add(dispositions[identity])
            if identity in active:
                pending.update(edges[identity] + active[identity] + conflicts[identity])
            if kind == "dependency":
                pending.add(_key(row["basis"], "claim", "source"))
            if kind == "source":
                pending.update(_key(source, "source") for source in row["upstream"])
            for descriptor in (row.get("artifact"), row.get("method"), row.get("run", {}).get("trace"),
                               row.get("reproduction", {}).get("artifact")):
                if descriptor is not None:
                    path, checksum = descriptor["path"], descriptor["sha256"]
                    require(isinstance(path, str) and path.startswith("sces/artifacts/") and _ARTIFACT_PATH.fullmatch(path)
                            and artifacts.setdefault(path, checksum) == checksum, "invalid SCES artifact reference")
            for field in ("replaces", "previous"):
                if field in row:
                    pending.add(_key(row[field], kind))
    return used, artifacts


def _selected_registry(selected, captured, reverse_cache, now):
    edges, reviews, dispositions, conflicts = _registry(
        captured.directory, captured.paths, reverse_cache, captured.budget, frozen_source=captured.frozen_source,
    )
    active = _active_reviews(selected, captured, edges, reviews, dispositions, now)
    used, artifacts = _closure(selected, captured, edges, active, dispositions, conflicts)
    return edges, active, used, artifacts


def _selection_tree(directory, commit):
    raw = _git(directory, "ls-tree", "-z", commit, "--", _SELECTION)
    if not raw:
        return {}
    match = re.fullmatch(rb"100644 blob ([0-9a-f]{40})\tsces/publication\.json\x00", raw)
    require(match is not None, "SCES publication selection is not a regular, non-executable blob")
    return {_SELECTION: match[1].decode("ascii")}


def _qualification_identity(report, slug):
    require(report["release"] == slug and report["repository"] == REPOSITORY
            and report["policy"] == "SCES-1.0" and report["policy_sha256"] == POLICY_DIGEST
            and report["synthetic"] is False, "invalid protected SCES qualification report")


def _bind_base_qualification(report, selection, selection_bytes):
    require(report["dataset"] == selection["dataset"] and report["schema_version"] == selection["schema_version"]
            and report["source_commit"] == selection["source_commit"]
            and report["selection_sha256"] == _digest(selection_bytes),
            "SCES prior qualification does not bind the exact verified base selection and dataset")


def _timestamp(recorded, context):
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", recorded),
            f"invalid SCES {context} timestamp")
    return datetime.strptime(recorded, "%Y-%m-%dT%H:%M:%S%z")


def _assert_retained_history(directory, commit, base, selection_tree):
    prefixes = ("sces/releases", "sces/advisories")
    inherited = _inventory(directory, base, *prefixes)
    candidate = _inventory(directory, commit, *prefixes)
    require(all(candidate.get(path) == oid for path, oid in inherited.items()),
            "SCES candidate must preserve exact verified base release and withdrawal advisory blobs")
    require(all(_archived_report_path(path)[1] in inherited for path in inherited if path.startswith("sces/advisories/")),
            "SCES verified base withdrawal advisory lacks its archived qualification")
    new = candidate.keys() - inherited.keys()
    active = None
    if selection_tree:
        active = decode(_blobs(directory, selection_tree, [_SELECTION], limit=_MAX_EVIDENCE)[_SELECTION])["release"]
        require(isinstance(active, str) and _SLUG.fullmatch(active), "invalid SCES release name")
        require(f"sces/advisories/{active}.json" not in candidate,
                "SCES active publication is already withdrawn")
    allowed = {f"sces/releases/{active}/{name}" for name in ("claims.json", "qualification.json")} if active else set()
    require(all(path.startswith("sces/advisories/") or path in allowed for path in new),
            "SCES candidate introduces release files outside the active qualification")
    return inherited, candidate, sorted(path for path in new if path.startswith("sces/advisories/"))


def _archived_report_path(advisory_path):
    slug = advisory_path.removeprefix("sces/advisories/").removesuffix(".json")
    require(_SLUG.fullmatch(slug) and advisory_path == f"sces/advisories/{slug}.json",
            "invalid SCES withdrawal advisory path")
    return slug, f"sces/releases/{slug}/qualification.json"


def _claims_path(report_path):
    return report_path.removesuffix("qualification.json") + "claims.json"


def _check_archived_claims(report, report_path, blobs):
    path = _claims_path(report_path)
    require(path in blobs and report["artifacts"] == [{"path": path, "sha256": _digest(blobs[path])}],
            "SCES archived claims payload does not match the exact qualification artifact descriptor")


def _check_withdrawal(advisory, report_path, report_digest, report):
    require(advisory["report"] == {"path": report_path, "sha256": report_digest},
            "SCES withdrawal advisory does not bind the exact verified base qualification")
    require(_timestamp(advisory["recorded"], "withdrawal advisory") <= datetime.now(timezone.utc),
            "SCES withdrawal advisory timestamp is in the future")
    affected = [_key(reference, "claim") for reference in advisory["affected"]]
    require(affected and len(set(affected)) == len(affected)
            and set(affected) <= {_key(reference, "claim") for reference in report["claims"]}
            and isinstance(advisory["reason"], str) and advisory["reason"].strip(),
            "SCES withdrawal advisory lacks a reason or lists invalid affected claims")


def _new_withdrawals(directory, commit, selection_tree, base_selection_tree, inherited, candidate, new):
    base_bytes, base_selection = None, None
    if base_selection_tree and (new or not selection_tree):
        base_bytes = _blobs(directory, base_selection_tree, [_SELECTION], limit=_MAX_EVIDENCE)[_SELECTION]
        base_selection = decode(base_bytes)
        slug = base_selection["release"]
        require(isinstance(slug, str) and _SLUG.fullmatch(slug), "invalid SCES base release name")
        if not selection_tree:
            require(f"sces/advisories/{slug}.json" in new,
                    "SCES active publication removal requires a new withdrawal advisory for the verified base release")
    if not selection_tree:
        # Pinned SCES-1.0 tools/sces/validate.py, validate_publication (unadvised-withdrawal).
        require(all(f"sces/advisories/{path.split('/')[2]}.json" in candidate
                    for path in candidate if path.endswith("/qualification.json")),
                "SCES inactive publication retains a qualification without a withdrawal advisory")
    if not new:
        return {}
    reports = {}
    for advisory in new:
        slug, path = _archived_report_path(advisory)
        require(path in inherited and _claims_path(path) in inherited,
                "SCES new withdrawal advisory must identify an inherited qualified release")
        reports[advisory] = (slug, path)
    adoption_paths = _inventory(directory, commit, _ADOPTION)
    ordered = [_ADOPTION, *new, *(artifact for _, path in reports.values() for artifact in (path, _claims_path(path)))]
    staged = _blobs(directory, {**candidate, **adoption_paths}, ordered,
                    limit=_MAX_EVIDENCE - len(base_bytes or b""))
    adoption = decode(staged[_ADOPTION])
    require(adoption["policy"] == "SCES-1.0" and adoption["policy_sha256"] == POLICY_DIGEST
            and adoption["repository"] == REPOSITORY and adoption["mode"] == "index",
            "invalid protected SCES adoption for a withdrawal")
    for advisory, (slug, report_path) in reports.items():
        report_bytes = staged[report_path]
        report = decode(report_bytes)
        _qualification_identity(report, slug)
        _check_archived_claims(report, report_path, staged)
        _check_withdrawal(decode(staged[advisory]), report_path, _digest(report_bytes), report)
        if base_selection is not None and slug == base_selection["release"]:
            _bind_base_qualification(report, base_selection, base_bytes)
            staged[_BASE_SELECTION_REVIEW_PATH] = base_bytes
    return staged


def _read_withdrawn_archive(directory, inherited, report_path):
    match = re.fullmatch(r"sces/releases/([a-z][a-z0-9-]*)/qualification\.json", report_path)
    require(match is not None and _SLUG.fullmatch(match[1]), "invalid protected SCES qualification report path")
    slug = match[1]
    advisory = f"sces/advisories/{slug}.json"
    require(advisory in inherited, "SCES inactive base contains a qualification without its withdrawal advisory")
    # Bound each independently validated triplet, including Git's small per-blob header.
    blobs = _blobs(directory, inherited, [report_path, _claims_path(report_path), advisory],
                   limit=3 * (_MAX_BLOB + 64))
    report = decode(blobs[report_path])
    _qualification_identity(report, slug)
    require(isinstance(report["dataset"], str) and _SLUG.fullmatch(report["dataset"]),
            "invalid protected SCES qualification dataset")
    _check_archived_claims(report, report_path, blobs)
    report_digest = _digest(blobs[report_path])
    _check_withdrawal(decode(blobs[advisory]), report_path, report_digest, report)
    return blobs, report, report_digest


def _withdrawn_predecessor(directory, inherited, selection):
    """Follow exact qualification parent links; advisory timestamps do not order releases."""
    release_paths = {path for path in inherited if path.startswith("sces/releases/")}
    report_paths = sorted(path for path in release_paths if path.endswith("/qualification.json"))
    expected_paths = {artifact for path in report_paths for artifact in (path, _claims_path(path))}
    require(release_paths == expected_paths, "SCES inactive base contains an incomplete archived release bundle")
    requested = selection.get("previous_report")
    digests, predecessors, staged = {}, {}, {}
    for path in report_paths:
        blobs, report, report_digest = _read_withdrawn_archive(directory, inherited, path)
        if report["dataset"] != selection["dataset"]:
            continue
        digests[path] = report_digest
        if "previous_report" in report:
            previous = report["previous_report"]
            require(isinstance(previous, dict) and previous.keys() == {"path", "sha256"}
                    and previous["path"] in release_paths and re.fullmatch(r"[0-9a-f]{64}", previous["sha256"]),
                    "SCES withdrawn qualification lineage has a broken predecessor")
            predecessors[path] = (previous["path"], previous["sha256"])
        # The request only selects bytes to retain. The lineage below independently authorizes the tip.
        if isinstance(requested, dict) and requested.get("path") == path:
            staged = blobs
    if not digests:
        require("previous_report" not in selection,
                "SCES archived predecessor requires an unchanged withdrawal advisory for the dataset on the verified pull-request base")
        return {}
    parents = {}
    for path, (parent, parent_digest) in predecessors.items():
        require(digests.get(parent) == parent_digest,
                "SCES withdrawn qualification lineage has a broken predecessor")
        parents[path] = parent
    tips = digests.keys() - set(parents.values())
    require(len(tips) == 1, "SCES withdrawn qualification lineage has no unique successor tip")
    tip, = tips
    seen = set()
    cursor = tip
    while cursor is not None:
        require(cursor not in seen, "SCES withdrawn qualification lineage contains a cycle")
        seen.add(cursor)
        cursor = parents.get(cursor)
    require(seen == digests.keys(), "SCES withdrawn qualification lineage is disconnected or cyclic")
    expected = {"path": tip, "sha256": digests[tip]}
    require(requested == expected,
            "SCES reactivation must identify the verified dataset's latest withdrawn qualification report")
    require(tip != f"sces/releases/{selection['release']}/qualification.json", "invalid SCES previous report path")
    return staged


def _previous_report(directory, paths, base, base_selection_tree, inherited, selection, selection_bytes):
    if not base_selection_tree:
        return _withdrawn_predecessor(directory, inherited, selection)
    predecessor = selection.get("previous_report")
    base_bytes = _blobs(directory, base_selection_tree, [_SELECTION], limit=_MAX_EVIDENCE)[_SELECTION]
    base_selection = decode(base_bytes)
    base_slug = base_selection["release"]
    require(isinstance(base_slug, str) and _SLUG.fullmatch(base_slug), "invalid SCES base release name")
    require(selection["dataset"] == base_selection["dataset"],
            "SCES active publication successor must retain the verified base dataset")
    if selection["release"] == base_slug:
        require(selection_bytes == base_bytes,
                "SCES active publication selection differs from the verified pull-request base")
    else:
        expected = f"sces/releases/{base_slug}/qualification.json"
        require(isinstance(predecessor, dict) and predecessor.get("path") == expected,
                "SCES successor must identify the verified base release's qualification report")
    if "previous_report" not in selection:
        return {}
    path = predecessor["path"]
    match = re.fullmatch(r"sces/releases/([a-z][a-z0-9-]*)/qualification\.json", path)
    require(match is not None and _SLUG.fullmatch(match[1]) and match[1] != selection["release"],
            "invalid SCES previous report path")
    claims = _claims_path(path)
    require(all(artifact in paths and inherited.get(artifact) == paths[artifact] for artifact in (path, claims)),
            "SCES previous report path or blob differs from the verified pull-request base")
    history = _blobs(directory, paths, [path, claims], limit=_MAX_EVIDENCE)
    require(_digest(history[path]) == predecessor["sha256"], "SCES previous report digest mismatch")
    report = decode(history[path])
    _qualification_identity(report, match[1])
    _check_archived_claims(report, path, history)
    require(report["dataset"] == selection["dataset"], "SCES previous report names a different dataset")
    if selection["release"] != base_slug:
        _bind_base_qualification(report, base_selection, base_bytes)
    return history


def _selected_evidence(directory, paths, base, base_selection_tree, inherited):
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
            and adoption["repository"] == report["repository"] == REPOSITORY and adoption["mode"] == "index"
            and report["dataset"] == selection["dataset"]
            and report["schema_version"] == selection["schema_version"]
            and report["synthetic"] is False and report["release"] == slug
            and report["source_commit"] == selection["source_commit"]
            and re.fullmatch(r"[0-9a-f]{40}", selection["source_commit"])
            and report["selection_sha256"] == _digest(metadata[_SELECTION])
            and report["artifacts"] == [{"path": claims_path, "sha256": _digest(metadata[claims_path])}],
            "SCES selection and qualification do not bind the exact publication")
    require(("previous_report" in report) == ("previous_report" in selection)
            and report.get("previous_report") == selection.get("previous_report"), "SCES previous report mismatch")
    metadata.update(_previous_report(directory, paths, base, base_selection_tree, inherited, selection, metadata[_SELECTION]))

    selected = [_key(ref, "claim") for ref in selection["claims"]]
    require(selected and len({identity[:2] for identity in selected}) == len(selected)
            and [_key(ref, "claim") for ref in report["claims"]] == sorted(selected),
            "SCES publication claim selection does not match the report")
    reverse_cache = {}
    budget = _RecordBudget()
    now = datetime.now(timezone.utc)
    record_limit = _MAX_EVIDENCE - sum(map(len, metadata.values()))
    captured = _SelectedRecords(directory, paths, budget, limit=record_limit)
    edges, active, used, artifacts = _selected_registry(selected, captured, reverse_cache, now)
    records, record_blobs = captured.rows, captured.raw
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
                **_blobs(directory, paths, sorted(artifacts), limit=captured.remaining + 64 * len(artifacts))}
    require(all(_digest(evidence[path]) == checksum for path, checksum in artifacts.items()),
            "SCES selected artifact digest mismatch")
    inputs = {path: _digest(blob) for path, blob in evidence.items()}
    inputs[_ADOPTION] = _digest(metadata[_ADOPTION])
    require(report["inputs_sha256"] == _digest(_canonical(inputs)), "SCES selected input digest mismatch")
    frozen = _frozen_inputs(directory, selection["source_commit"], budget)
    # The same selected roots must reach the same records when reverse links come from the frozen tree.
    frozen_records = _SelectedRecords(
        directory, frozen, budget, limit=record_limit, frozen_source=(REPOSITORY, selection["source_commit"]),
        reuse={paths[path]: blob for path, blob in record_blobs.items()},
    )
    *_, frozen_used, frozen_artifacts = _selected_registry(selected, frozen_records, reverse_cache, now)
    budget.time_remaining()
    require(used == frozen_used, "SCES selected record membership differs from the frozen source commit")
    require(artifacts == frozen_artifacts, "SCES selected artifact descriptors differ from the frozen source commit")
    for path in sorted(inputs):
        require(frozen.get(path) == paths[path], f"SCES selected input differs from its frozen source commit: {path}")

    staged = {**metadata, **evidence}
    require(sum(map(len, staged.values())) <= _MAX_EVIDENCE, "SCES selected evidence exceeds the review capture limit")
    return dict(sorted(staged.items()))


def capture_selected_evidence(directory, commit, repository, *, base=None):
    """Return exact active-publication or withdrawal inputs for the verified Git transition."""
    try:
        selection_tree = _selection_tree(directory, commit)
        require(repository == REPOSITORY, "SCES review repository is outside the allowlist")
        require(isinstance(base, str) and re.fullmatch(r"[0-9a-f]{40}", base),
                "SCES publication requires the exact verified pull-request base")
        base_selection_tree = _selection_tree(directory, base)
        inherited, candidate, new = _assert_retained_history(directory, commit, base, selection_tree)
        staged = _new_withdrawals(directory, commit, selection_tree, base_selection_tree, inherited, candidate, new)
        if selection_tree:
            paths = _inventory(directory, commit, "sces")
            staged.update(_selected_evidence(directory, paths, base, base_selection_tree, inherited))
        require(sum(map(len, staged.values())) <= _MAX_EVIDENCE, "SCES selected evidence exceeds the review capture limit")
        return dict(sorted(staged.items()))
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, DataError):
            raise
        raise DataError(f"could not capture the SCES publication evidence: {error}") from error
