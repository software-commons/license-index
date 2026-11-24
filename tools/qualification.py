"""Validate SCIRS domain records before projecting a checked SCES release."""

from hashlib import new as new_hash, sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from time import time

from .records import DATA_COMMIT, OPAQUE_ID, DataError, decode, require


POLICY_COMMIT = "ab26f278422772f2d9e5d4dd016407d14372a710"
POLICY_DIGEST = "14da3f31f697ab828d4a4560f060dbe511861020db54bea7bc531e20ea0855ce"
REPOSITORY = "software-commons/license-index"
DATASET = "license-index"
SCHEMA_VERSION = "1.0.0"

_KEY = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_INDEX = re.compile(r"software-commons/[a-z0-9]+(?:-[a-z0-9]+)*-index")
_GIT_ORIGIN = re.compile(r"git\+https://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(/[A-Za-z0-9][A-Za-z0-9._-]*)+")
_CONTENT_REVISION = re.compile(r"sha256:[0-9a-f]{64}")
_SCOPE_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]*")
_KINDS = {"license", "exception", "related-instrument", "family"}
_STATES = {"active", "historical", "retired"}
_LINEAGE = {"edition-of", "member-of", "derived-from", "supersedes", "merged-from", "split-from"}
_RELATIONS = _LINEAGE | {"exception-for", "related-to"}


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _matches(pattern, value):
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _fields(value, fields):
    return isinstance(value, dict) and value.keys() == fields


def _scoped_fields(value, fields, scope_key="scope"):
    if not isinstance(value, dict) or value.keys() - {scope_key} != fields:
        return False
    scope = value.get(scope_key, {})
    return isinstance(scope, dict) and all(_matches(_KEY, key) and _matches(_SCOPE_VALUE, identifier)
                                          for key, identifier in scope.items())


def _revision_scope(field, dimension, revision):
    scope = field.get("scope", {})
    require(scope.get(dimension, revision) == revision, f"explicit scope conflicts with pinned {dimension}")
    return {**scope, dimension: revision}


def _immutable_crosswalk_revision(origin, revision):
    if origin == "spdx":
        return _matches(DATA_COMMIT, revision)
    if _matches(_CONTENT_REVISION, revision):
        return True
    return (_matches(_INDEX, origin) or _matches(_GIT_ORIGIN, origin)) and _matches(DATA_COMMIT, revision)


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n").encode("utf-8")


def _claim_value(value):
    return _canonical(value).decode("utf-8").removesuffix("\n")


def _claim_key(ref):
    require(
        _fields(ref, {"kind", "id", "revision"}) and ref["kind"] == "claim"
        and _matches(_KEY, ref["id"]) and type(ref["revision"]) is int
        and 1 <= ref["revision"] <= 2147483647,
        f"invalid exact SCES claim reference: {ref!r}",
    )
    return ref["id"], ref["revision"]


def _run(arguments, *, input_data=None):
    # The validator also invokes Git. Both callers must read the same real objects
    # and parent links under the repository path supplied by the index.
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_GRAFT_FILE=os.devnull)
    if os.name == "nt":
        # Git for Windows tests the full commit:path argument as a path before
        # dereferencing it. Allow long paths in both Git and the validator's Git.
        environment.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.longpaths", GIT_CONFIG_VALUE_0="true")
    try:
        result = subprocess.run(arguments, capture_output=True, check=False, env=environment,
                                input=input_data)
    except OSError as error:
        raise DataError(f"could not execute {arguments[0]}: {error}") from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        action = "Git" if arguments[0] == "git" else "SCES validator"
        raise DataError(f"{action} failed ({result.returncode}): {detail or 'no diagnostic output'}")
    return result.stdout


def _git(root, *args, input_data=None):
    return _run(["git", "--no-pager", "-C", str(root), *args], input_data=input_data)


def _git_blobs(root, commit, *sections):
    require(_matches(DATA_COMMIT, commit), "use a full 40-character Git commit")
    result = {}
    listing = _git(root, "ls-tree", "-r", "-z", commit, "--", *sections)
    for entry in listing.decode("utf-8").split("\0"):
        if not entry:
            continue
        metadata, name = entry.split("\t", 1)
        mode, kind, oid = metadata.split(" ")
        require(mode == "100644" and kind == "blob", f"{name}: expected a regular Git data file")
        result[name] = oid
    return result


def _blob_hash(content, algorithm):
    digest = new_hash(algorithm, usedforsecurity=False)
    digest.update(f"blob {len(content)}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest()


def _record_paths(section, records):
    return {f"registry/{section}/{identity[:2]}/{identity}.json": record
            for identity, record in records.items()}


def _exact_file(path):
    require(path.is_file() and path.resolve() == path, f"missing or linked file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise DataError(f"could not read {path}: {error}") from error


def _pinned_validator(policy):
    root = Path(policy).resolve()
    if (root / ".git").exists():
        require(_git(root, "rev-parse", "HEAD").decode().strip() == POLICY_COMMIT,
                "SCES checkout is outside the pinned policy commit")

    # Verify all pinned bytes before running supplied Python code, including for
    # a clean policy archive without Git metadata.
    manifest_path = root / "evidence/v1/policy.json"
    manifest = decode(_exact_file(manifest_path))
    files = manifest.get("files")
    require(
        manifest.get("policy") == "SCES-1.0" and manifest.get("revision_tag") == "sces-v1.0"
        and manifest.get("sha256") == POLICY_DIGEST and isinstance(files, dict)
        and sha256(_canonical(files)).hexdigest() == POLICY_DIGEST,
        "SCES policy manifest does not match the adopted bundle digest",
    )
    for relative, expected in files.items():
        require(sha256(_exact_file(root / relative)).hexdigest() == expected,
                f"SCES policy file failed the pinned digest: {relative}")
    return root / "tools/sces/validate.py"


_HISTORICAL_POLICY = """
from datetime import datetime, timezone
from pathlib import Path
import runpy
import sys

validator, root, repository, expected_policy, base, timestamp = sys.argv[1:]
policy = runpy.run_path(validator)
if policy["policy_bundle"]() != expected_policy:
    raise ValueError("SCES history policy differs from the adopted digest")
as_of = datetime.fromtimestamp(int(timestamp), timezone.utc)
registry = policy["Registry"](Path(root), expected_policy, as_of, repository=repository)
registry.validate_publication(base=base or None)
"""


def _validate_policy(catalog_root, policy, base, *, historical_timestamp=None):
    if base is not None:
        require(_matches(DATA_COMMIT, base), "use a full Git commit for the history base")
    validator = _pinned_validator(policy)
    if historical_timestamp is not None:
        require(type(historical_timestamp) is int and 0 <= historical_timestamp <= time(),
                "invalid or future SCES historical commit time")
        _run([sys.executable, "-I", "-B", "-c", _HISTORICAL_POLICY, str(validator), str(catalog_root),
              REPOSITORY, POLICY_DIGEST, base or "", str(historical_timestamp)])
        return
    arguments = [
        sys.executable, "-I", "-B", str(validator),
        "--repo", str(catalog_root), "--repository", REPOSITORY,
    ]
    if base is not None:
        arguments.extend(["--base", base])
    _run(arguments)


def _binding_specs(entity):
    identity = {key: entity[key] for key in ("kind", "name", "state")}
    yield entity["identity_claim"], "instrument-identity", _claim_value(identity), entity.get("identity_scope", {})
    for alias in entity["aliases"]:
        yield alias["claim"], "instrument-identity", alias["name"], alias.get("scope", {})
    for item in entity["crosswalks"]:
        value = {key: item[key] for key in ("origin", "revision", "key")}
        if item["origin"] == "spdx":
            scope = _revision_scope(item, "data-revision", item["revision"])
            yield item["claim"], "spdx-membership", _claim_value(value), scope
        else:
            scope = _revision_scope(item, "revision", item["revision"])
            yield item["claim"], "instrument-identity", _claim_value(value), scope
    for edge in entity["relations"]:
        target = edge["target"]
        value = edge["type"] + ":" + _claim_value(target)
        if "index" in target:
            scope = _revision_scope(edge, "target-revision", target["revision"])
            yield edge["claim"], "cross-index-relationship", value, scope
        else:
            predicate = "exception-relationship" if edge["type"] == "exception-for" else "historical-relationship"
            yield edge["claim"], predicate, value, edge.get("scope", {})


def _validate_target(target, owner, relation, entities):
    entity_id = owner["id"]
    if relation == "exception-for":
        require(owner["kind"] == "exception", f"{entity_id}: exception-for requires an exception and a base license")
    if _fields(target, {"id"}):
        target_id = target["id"]
        require(_matches(OPAQUE_ID, target_id) and target_id in entities and target_id != entity_id,
                f"{entity_id}: unresolved or self-referential local relationship")
        other = entities[target_id]
        if relation == "exception-for":
            require(other["kind"] == "license",
                    f"{entity_id}: exception-for requires an exception and a base license")
        if relation == "member-of":
            require(other["kind"] == "family", f"{entity_id}: member-of requires a family target")
        if relation in {"supersedes", "merged-from", "split-from"}:
            require(other["state"] in {"historical", "retired"},
                    f"{entity_id}: lineage requires a historical or retired predecessor")
        return target_id
    require(
        _fields(target, {"index", "id", "revision"})
        and _matches(_INDEX, target["index"]) and target["index"] != REPOSITORY and _text(target["id"])
        and (_matches(DATA_COMMIT, target["revision"]) or _matches(_CONTENT_REVISION, target["revision"])),
        f"{entity_id}: external relationship requires an owning index and immutable revision",
    )
    return None


def _validate_entities(entities):
    lineage = {}
    crosswalk_owners = {}
    for identity, entity in entities.items():
        require(
            _scoped_fields(
                entity, {"id", "kind", "name", "state", "identity_claim", "candidate_ids",
                         "aliases", "crosswalks", "relations"}, "identity_scope",
            )
            and identity == entity["id"] and _matches(OPAQUE_ID, identity)
            and _text(entity["kind"]) and entity["kind"] in _KINDS
            and _text(entity["state"]) and entity["state"] in _STATES and _text(entity["name"])
            and all(isinstance(entity[field], list) for field in ("aliases", "crosswalks", "relations")),
            f"{identity}: invalid canonical record",
        )
        candidate_ids = entity["candidate_ids"]
        require(isinstance(candidate_ids, list) and candidate_ids
                and all(_matches(OPAQUE_ID, candidate) for candidate in candidate_ids)
                and len(set(candidate_ids)) == len(candidate_ids),
                f"{identity}: canonical provenance requires unique discovery candidate IDs")
        _claim_key(entity["identity_claim"])
        labels = {entity["name"].casefold()}
        for alias in entity["aliases"]:
            require(_scoped_fields(alias, {"name", "claim"}) and _text(alias["name"]),
                    f"{identity}: invalid alias")
            label = alias["name"].casefold()
            require(label not in labels, f"{identity}: duplicate canonical label or alias")
            labels.add(label)
            _claim_key(alias["claim"])
        for item in entity["crosswalks"]:
            require(
                _scoped_fields(item, {"origin", "revision", "key", "claim"})
                and all(_text(item[name]) for name in ("origin", "key"))
                and _immutable_crosswalk_revision(item["origin"], item["revision"]),
                f"{identity}: external identity crosswalk requires an immutable revision appropriate to its origin",
            )
            locator = item["origin"], item["revision"], item["key"]
            if item["origin"] == "spdx":
                locator = locator[:2] + (item["key"].casefold(),)
            require(locator not in crosswalk_owners,
                    f"{identity}: crosswalk duplicates {crosswalk_owners.get(locator)}")
            crosswalk_owners[locator] = identity
            _claim_key(item["claim"])

    for identity, entity in entities.items():
        lineage[identity] = []
        edges = set()
        for edge in entity["relations"]:
            require(
                _scoped_fields(edge, {"type", "target", "claim"}) and _text(edge["type"]) and edge["type"] in _RELATIONS,
                f"{identity}: invalid relationship",
            )
            _claim_key(edge["claim"])
            target = _validate_target(edge["target"], entity, edge["type"], entities)
            key = edge["type"], _claim_value(edge["target"])
            require(key not in edges, f"{identity}: duplicate relationship")
            edges.add(key)
            if target is not None and edge["type"] in _LINEAGE:
                lineage[identity].append(target)

    done = set()
    for identity in lineage:
        if identity in done:
            continue
        ancestors = {identity}
        stack = [(identity, iter(lineage[identity]))]
        while stack:
            current, children = stack[-1]
            child = next(children, None)
            if child is None:
                done.add(current)
                ancestors.remove(current)
                stack.pop()
            elif child not in done:
                require(child not in ancestors, f"cyclic entity lineage involving {child}")
                ancestors.add(child)
                stack.append((child, iter(lineage[child])))


def _bind_payload(entities, payload):
    _validate_entities(entities)
    by_key = {}
    for row in payload:
        claim = row["claim"]
        key = claim["id"], claim["revision"]
        subject = claim["subject"]
        require(key not in by_key and subject.startswith("e-") and subject[2:] in entities,
                f"duplicate SCES claim or noncanonical claim subject: {key}")
        by_key[key] = row
    for identity, entity in entities.items():
        for ref, predicate, value, scope in _binding_specs(entity):
            key = _claim_key(ref)
            claim = by_key.get(key, {}).get("claim", {})
            require(
                claim.get("subject") == f"e-{identity}" and claim.get("predicate") == predicate
                and claim.get("value") == value
                and claim.get("polarity") == "affirmative"
                and claim.get("modality") == "descriptive" and claim.get("conditions") == []
                and claim.get("scope") == scope,
                f"{identity}: exact SCES claim does not bind the canonical field: {key}",
            )
    return [by_key[key] for key in sorted(by_key)]


def _discovery_origins(candidate):
    current = candidate["origin"]
    yield current
    for note in candidate["history"]:
        origin = note.get("origin") if isinstance(note, dict) else None
        if not isinstance(origin, dict) or origin.get("kind") != current["kind"]:
            continue
        identifier = origin.get("identifier")
        if current["kind"] == "spdx":
            if (_text(identifier) and identifier.casefold() == current["identifier"].casefold()
                    and origin.get("list_kind") == current.get("list_kind")):
                yield origin
        elif (identifier == current["identifier"]
              and ("revision" not in origin or "revision" not in current or origin["revision"] == current["revision"])):
            yield origin


def _matches_discovery_crosswalk(crosswalk, candidate_id, origin, list_kind):
    if crosswalk["origin"] == "spdx":
        release = crosswalk.get("scope", {}).get("upstream-release")
        return (
            list_kind is not None and _text(release)
            and origin.get("kind") == "spdx" and origin.get("identifier") == crosswalk["key"]
            and origin.get("source") == crosswalk["revision"] and origin.get("release") == release
            and origin.get("list_kind") == list_kind
        )

    if not (
        origin.get("kind") == "publisher" and origin.get("identifier") == crosswalk["key"]
        and origin.get("source") == crosswalk["origin"] and crosswalk["origin"].startswith("https://")
        and _matches(_CONTENT_REVISION, crosswalk["revision"])
    ):
        return False
    provenance = {"candidate_id": candidate_id, "origin": origin}
    digest = sha256(_canonical(provenance)).hexdigest()
    return crosswalk.get("scope", {}).get("discovery-origin") == f"sha256:{digest}"


def _validate_frozen_provenance(root, frozen, entities, retained_candidates):
    """Resolve canonical links against the source snapshot and retained discovery history."""
    candidate_blobs = _git_blobs(root, frozen, "registry/candidates")
    candidates = {}
    for identity, entity in entities.items():
        for candidate_id in entity["candidate_ids"]:
            if candidate_id not in candidates:
                path = f"registry/candidates/{candidate_id[:2]}/{candidate_id}.json"
                require(path in candidate_blobs,
                        f"{identity}: discovery candidate {candidate_id} is absent from the frozen SCES source")
                candidate = decode(_git(root, "cat-file", "blob", candidate_blobs[path]))
                require(isinstance(candidate, dict) and candidate.get("id") == candidate_id
                        and isinstance(candidate.get("origin"), dict) and isinstance(candidate.get("history"), list),
                        f"{path}: invalid frozen discovery record")
                origin = candidate["origin"]
                require(origin.get("kind") in {"spdx", "publisher"}
                        and all(_text(origin.get(field)) for field in ("identifier", "name", "source")),
                        f"{path}: missing frozen discovery origin")
                require(candidate_id in retained_candidates,
                        f"{identity}: canonical provenance requires retained discovery records")
                retained = list(_discovery_origins(retained_candidates[candidate_id]))
                shared = [origin for origin in _discovery_origins(candidate) if origin in retained]
                require(shared, f"{identity}: frozen discovery origin is absent from the retained ledger")
                candidates[candidate_id] = shared

        unmatched = set(entity["candidate_ids"])
        list_kind = {"license": "license", "related-instrument": "license", "exception": "exception"}.get(entity["kind"])
        for crosswalk in entity["crosswalks"]:
            matched = {
                candidate_id for candidate_id in entity["candidate_ids"]
                if any(_matches_discovery_crosswalk(crosswalk, candidate_id, origin, list_kind)
                       for origin in candidates[candidate_id])
            }
            if crosswalk["origin"] == "spdx":
                require(matched,
                        f"{identity}: SPDX crosswalk does not match a linked frozen discovery origin: {crosswalk['key']}")
                require(len(matched) == 1,
                        f"{identity}: ambiguous SPDX crosswalk matches multiple linked discovery candidates: "
                        f"{crosswalk['key']}")
            elif crosswalk["origin"].startswith("https://") or "discovery-origin" in crosswalk.get("scope", {}):
                require(len(matched) == 1,
                        f"{identity}: publisher crosswalk does not match one linked frozen discovery origin: "
                        f"{crosswalk['key']}")
            unmatched.difference_update(matched)
        require(not unmatched,
                f"{identity}: discovery candidate {', '.join(sorted(unmatched))} has no qualified crosswalk for its frozen origin")


def _report(root, name):
    require(_matches(_KEY, name), "invalid SCES release slug")
    report = decode(_exact_file(root / "sces/releases" / name / "qualification.json"))
    require(
        report.get("repository") == REPOSITORY and report.get("dataset") == DATASET
        and report.get("schema_version") == SCHEMA_VERSION and report.get("synthetic") is False,
        "foreign, synthetic, or incompatible SCES report",
    )
    return report


def _entity_blobs(root, entities):
    algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
    blobs = {}
    for name, record in _record_paths("entities", entities).items():
        content = _exact_file(root / name)
        require(decode(content) == record, f"{name}: canonical record changed during validation")
        blobs[name] = _blob_hash(content, algorithm)
    return blobs


def _check_withdrawn_entities(root, entities, base):
    """Allow retained files only after the pinned policy has validated the withdrawal."""
    advisories = sorted((root / "sces/advisories").glob("*.json"))
    require(advisories, "canonical identities require an active SCES qualification or a checked withdrawal")
    _validate_entities(entities)
    baseline = base or _git(root, "rev-parse", "--verify", "HEAD").decode().strip()
    current = _entity_blobs(root, entities)
    require(current == _git_blobs(root, baseline, "registry/entities"),
            "withdrawn canonical records must retain the exact trusted baseline bytes")
    for advisory in advisories:
        report = _report(root, advisory.stem)
        frozen = report["source_commit"]
        if current == _git_blobs(root, frozen, "registry/entities"):
            _git(root, "merge-base", "--is-ancestor", frozen, baseline)
            return
    raise DataError("withdrawn canonical records do not match an archived SCES release")


def qualified(catalog, policy: Path | None, *, base: str | None = None) -> tuple[dict | None, list]:
    """Return the active validated report and domain-bound claims, if present."""
    return _qualified(catalog, policy, base=base)


def _qualified_historical(catalog, policy: Path, *, base: str, commit: str) -> tuple[dict | None, list]:
    root = catalog.root.resolve()
    require(_git(root, "rev-parse", "--verify", "HEAD").decode("ascii").strip() == commit,
            "historical SCES checkout is outside the exact coverage commit")
    timestamp = _git(root, "show", "-s", "--format=%ct", commit).decode("ascii").strip()
    require(timestamp.isdecimal(), f"{commit}: invalid historical Git commit time")
    return _qualified(catalog, policy, base=base, historical_timestamp=int(timestamp))


def _qualified(catalog, policy, *, base=None, historical_timestamp=None):
    root = catalog.root.resolve()
    selection = root / "sces/publication.json"
    if policy is not None:
        if historical_timestamp is None:
            _validate_policy(root, policy, base)
        else:
            _validate_policy(root, policy, base, historical_timestamp=historical_timestamp)

    if not selection.exists() and not selection.is_symlink():
        if catalog.entities:
            require(policy is not None, "canonical identities require an active SCES qualification or a checked withdrawal")
            _check_withdrawn_entities(root, catalog.entities, base)
        return None, []
    require(policy is not None, "active SCES publication requires --policy with the pinned bundle")

    name = decode(_exact_file(selection))["release"]
    report = _report(root, name)
    require(catalog.entities, "a License Index release must include a canonical entity")
    expected = _git_blobs(root, report["source_commit"], "registry/entities")
    current = _entity_blobs(root, catalog.entities)
    require(expected.keys() == current.keys(), "canonical entity paths differ from the frozen SCES source")
    require(expected == current, "canonical record bytes differ from the frozen SCES source")
    payload = decode(_exact_file(root / "sces/releases" / name / "claims.json"))
    bound = _bind_payload(catalog.entities, payload)
    _validate_frozen_provenance(root, report["source_commit"], catalog.entities, catalog.candidates)
    return report, bound


def _check_candidate_history(root, previous, candidates, algorithm):
    for name, oid in previous.items():
        if _blob_hash(_exact_file(root / name), algorithm) == oid:
            continue
        old = decode(_git(root, "cat-file", "blob", oid))
        current = candidates[name]
        previous_origin, origin = old["origin"], current["origin"]
        history, inherited = current["history"], old["history"]
        if previous_origin["kind"] == origin["kind"] == "spdx":
            # Compare against the protected base independently of the archive replay predecessor.
            require(previous_origin["identifier"].casefold() == origin["identifier"].casefold(),
                    f"{name}: cannot reassign a permanent SPDX candidate")
            require(history[:len(inherited)] == inherited, f"{name}: SPDX candidate history must remain append-only")
            continue
        require(previous_origin["kind"] == origin["kind"]
                and previous_origin["identifier"] == origin["identifier"]
                and ("revision" not in previous_origin or previous_origin["revision"] == origin.get("revision")),
                f"{name}: cannot reassign a permanent publisher lead")
        require(history[:len(inherited)] == inherited, f"{name}: publisher lead history must remain append-only")
        if previous_origin != origin:
            require(any(isinstance(note, dict) and note.get("origin") == previous_origin
                        for note in history[len(inherited):]),
                    f"{name}: publisher lead origin enrichment must retain the previous origin in history")


def check_history(catalog, base: str) -> None:
    """Keep permanent paths and leads, earlier coverage snapshots and source manifests."""
    root = catalog.root.resolve()
    _validate_entities(catalog.entities)
    entities = _git_blobs(root, base, "registry/entities")
    require(entities.keys() <= _record_paths("entities", catalog.entities).keys(),
            "prior registry/entities records must remain at their permanent paths")
    previous_candidates = _git_blobs(root, base, "registry/candidates")
    candidates = _record_paths("candidates", catalog.candidates)
    require(previous_candidates.keys() <= candidates.keys(),
            "prior registry/candidates records must remain at their permanent paths")
    prior = _git_blobs(root, base, "registry/coverage/snapshots")
    if not prior and not previous_candidates:
        return
    algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
    _check_candidate_history(root, previous_candidates, candidates, algorithm)
    if prior:
        sources = _git_blobs(root, base, "research/sources")
        referenced = set()
        for name, oid in prior.items():
            content = _exact_file(root / name)
            require(_blob_hash(content, algorithm) == oid, f"{name}: prior coverage snapshot was modified")
            manifest = decode(content).get("source_manifest")
            require(isinstance(manifest, str) and manifest in sources,
                    f"{name}: prior coverage source manifest is absent from the trusted base")
            referenced.add(manifest)
        for name in sorted(referenced):
            content = _exact_file(root / name)
            require(_blob_hash(content, algorithm) == sources[name],
                    f"{name}: prior coverage source manifest was modified")
