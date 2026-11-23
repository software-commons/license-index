"""Validate SCIRS domain records before projecting a checked SCES release."""

from hashlib import new as new_hash, sha256
import json
from pathlib import Path
import re
import subprocess
import sys

from .records import DATA_COMMIT, OPAQUE_ID, DataError, decode, require


POLICY_COMMIT = "ab26f278422772f2d9e5d4dd016407d14372a710"
POLICY_DIGEST = "14da3f31f697ab828d4a4560f060dbe511861020db54bea7bc531e20ea0855ce"
REPOSITORY = "software-commons/license-index"
DATASET = "license-index"
SCHEMA_VERSION = "1.0.0"

_KEY = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_INDEX = re.compile(r"software-commons/[a-z0-9]+(?:-[a-z0-9]+)*-index")
_VERSION = re.compile(r"v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?")
_KINDS = {"license", "exception", "related-instrument", "family"}
_STATES = {"active", "historical", "retired"}
_LINEAGE = {"edition-of", "member-of", "derived-from", "supersedes", "merged-from", "split-from"}
_RELATIONS = _LINEAGE | {"exception-for", "related-to"}
_MUTABLE = {"any", "current", "head", "latest", "main", "master", "unknown", "unspecified"}


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _matches(pattern, value):
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _fields(value, fields):
    return isinstance(value, dict) and value.keys() == fields


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


def _run(arguments):
    try:
        result = subprocess.run(arguments, capture_output=True, check=False)
    except OSError as error:
        raise DataError(f"could not execute {arguments[0]}: {error}") from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        action = "Git" if arguments[0] == "git" else "SCES validator"
        raise DataError(f"{action} failed ({result.returncode}): {detail or 'no diagnostic output'}")
    return result.stdout


def _git(root, *args):
    return _run(["git", "--no-pager", "-C", str(root), *args])


def _git_blobs(root, commit, section):
    require(_matches(DATA_COMMIT, commit), "use a full 40-character Git commit")
    result = {}
    listing = _git(root, "ls-tree", "-r", "-z", commit, "--", section)
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


def _validate_policy(catalog_root, policy, base):
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

    arguments = [
        sys.executable, "-I", "-B", str(root / "tools/sces/validate.py"),
        "--repo", str(catalog_root), "--repository", REPOSITORY,
    ]
    if base is not None:
        require(_matches(DATA_COMMIT, base), "use a full Git commit for the history base")
        arguments.extend(["--base", base])
    _run(arguments)


def _binding_specs(entity):
    identity = {key: entity[key] for key in ("kind", "name", "state")}
    yield entity["identity_claim"], "instrument-identity", _claim_value(identity), {}
    for alias in entity["aliases"]:
        yield alias["claim"], "instrument-identity", alias["name"], {}
    for item in entity["crosswalks"]:
        value = {key: item[key] for key in ("origin", "revision", "key")}
        if item["origin"] == "spdx":
            yield item["claim"], "spdx-membership", _claim_value(value), {"data-revision": item["revision"]}
        else:
            yield item["claim"], "instrument-identity", _claim_value(value), {"revision": item["revision"]}
    for edge in entity["relations"]:
        target = edge["target"]
        value = edge["type"] + ":" + _claim_value(target)
        if "index" in target:
            yield edge["claim"], "cross-index-relationship", value, {"target-revision": target["revision"]}
        else:
            predicate = "exception-relationship" if edge["type"] == "exception-for" else "historical-relationship"
            yield edge["claim"], predicate, value, {}


def _validate_target(target, owner, relation, entities):
    entity_id = owner["id"]
    if _fields(target, {"id"}):
        target_id = target["id"]
        require(_matches(OPAQUE_ID, target_id) and target_id in entities and target_id != entity_id,
                f"{entity_id}: unresolved or self-referential local relationship")
        other = entities[target_id]
        if relation == "exception-for":
            require(owner["kind"] == "exception" and other["kind"] == "license",
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
        and (_matches(DATA_COMMIT, target["revision"]) or _matches(_VERSION, target["revision"])),
        f"{entity_id}: external relationship requires an owning index and immutable revision",
    )
    return None


def _validate_entities(entities):
    lineage = {}
    crosswalk_owners = {}
    for identity, entity in entities.items():
        require(
            _fields(entity, {"id", "kind", "name", "state", "identity_claim", "aliases", "crosswalks", "relations"})
            and identity == entity["id"] and _matches(OPAQUE_ID, identity)
            and _text(entity["kind"]) and entity["kind"] in _KINDS
            and _text(entity["state"]) and entity["state"] in _STATES and _text(entity["name"])
            and all(isinstance(entity[field], list) for field in ("aliases", "crosswalks", "relations")),
            f"{identity}: invalid canonical record",
        )
        _claim_key(entity["identity_claim"])
        labels = {entity["name"].casefold()}
        for alias in entity["aliases"]:
            require(_fields(alias, {"name", "claim"}) and _text(alias["name"]),
                    f"{identity}: invalid alias")
            label = alias["name"].casefold()
            require(label not in labels, f"{identity}: duplicate canonical label or alias")
            labels.add(label)
            _claim_key(alias["claim"])
        for item in entity["crosswalks"]:
            require(
                _fields(item, {"origin", "revision", "key", "claim"})
                and all(_text(item[name]) for name in ("origin", "revision", "key"))
                and item["revision"].casefold() not in _MUTABLE,
                f"{identity}: invalid or mutable external identity crosswalk",
            )
            locator = item["origin"], item["revision"], item["key"]
            if item["origin"] == "spdx":
                require(_matches(DATA_COMMIT, item["revision"]), f"{identity}: missing SPDX data commit")
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
                _fields(edge, {"type", "target", "claim"}) and _text(edge["type"]) and edge["type"] in _RELATIONS,
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
        for ref, predicate, value, required_scope in _binding_specs(entity):
            key = _claim_key(ref)
            claim = by_key.get(key, {}).get("claim", {})
            require(
                claim.get("subject") == f"e-{identity}" and claim.get("predicate") == predicate
                and claim.get("value") == value
                and claim.get("polarity") == "affirmative"
                and all(claim.get("scope", {}).get(name) == value for name, value in required_scope.items()),
                f"{identity}: exact SCES claim does not bind the canonical field: {key}",
            )
    return [by_key[key] for key in sorted(by_key)]


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
    root = catalog.root.resolve()
    selection = root / "sces/publication.json"
    if policy is not None:
        _validate_policy(root, policy, base)

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
    return report, _bind_payload(catalog.entities, payload)


def check_history(catalog, base: str) -> None:
    """Keep permanent paths and earlier coverage snapshots on a trusted base."""
    root = catalog.root.resolve()
    _validate_entities(catalog.entities)
    for section, records in (("entities", catalog.entities), ("candidates", catalog.candidates)):
        old = _git_blobs(root, base, f"registry/{section}")
        require(old.keys() <= _record_paths(section, records).keys(),
                f"prior registry/{section} records must remain at their permanent paths")
    prior = _git_blobs(root, base, "registry/coverage/snapshots")
    if prior:
        algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
        for name, oid in prior.items():
            content = _exact_file(root / name)
            require(_blob_hash(content, algorithm) == oid, f"{name}: prior coverage snapshot was modified")
