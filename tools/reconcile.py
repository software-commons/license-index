"""Read a pinned SPDX generated-data tarball and stage candidate changes."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
from shutil import copyfileobj
import sys
import tarfile
from tempfile import NamedTemporaryFile, TemporaryDirectory
from urllib.parse import quote, unquote
from urllib.request import Request, urlopen
from uuid import uuid4
from xml.etree import ElementTree


DATA_REPOSITORY = "spdx/license-list-data"
SOURCE_REPOSITORY = "spdx/license-list-XML"
DATA_LOCATORS = (f"https://raw.githubusercontent.com/{DATA_REPOSITORY}/",
                 f"https://github.com/{DATA_REPOSITORY}/blob/")
CATALOG_PATHS = ("json/", "text/", "template/", "license-list-XML/")
ARTIFACT_URI_PATH = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})+\Z")
KINDS = {
    "license": ("licenses", "licenseId", "details"),
    "exception": ("exceptions", "licenseExceptionId", "exceptions"),
}
SAFE_ID = re.compile(r"[A-Za-z0-9][-A-Za-z0-9.+]*\Z")
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CANDIDATE_ID = re.compile(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\Z")
HEADER_FIELDS = (
    "standardLicenseHeader",
    "standardLicenseHeaderTemplate",
    "standardLicenseHeaderHtml",
)
SPDX_XML = {"spdx": "http://www.spdx.org/license"}


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_json(raw):
    return json.loads(raw.decode("utf-8", errors="strict"))


def fingerprint(path, raw):
    return {"path": path, "sha256": sha256(raw).hexdigest(), "bytes": len(raw)}


def describe_text(path, raw):
    raw.decode("utf-8", errors="strict")
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n") - crlf
    cr = raw.count(b"\r") - crlf
    if cr or (crlf and lf):
        line_endings = "mixed"
    elif crlf:
        line_endings = "CRLF"
    elif lf:
        line_endings = "LF"
    else:
        line_endings = "none"
    return {**fingerprint(path, raw), "encoding": "UTF-8", "line_endings": line_endings}


class Archive:
    def __init__(self, tar, data_commit, cited_paths=()):
        prefix = f"license-list-data-{data_commit}/"
        self.files = {}
        self.cited_digests = {}
        for member in tar:
            if not member.name.startswith(prefix):
                if member.isfile():
                    raise ValueError("Archive files must be rooted at the pinned data commit")
                continue
            path = member.name[len(prefix):]
            cited = path in cited_paths
            if not member.isfile():
                if cited:
                    raise ValueError(f"Cited archive path is not a regular file: {path}")
                continue
            catalogued = path.startswith(CATALOG_PATHS)
            if not catalogued and not cited:
                continue
            if path in self.files or path in self.cited_digests:
                raise ValueError(f"Duplicate archive path: {path}")
            with tar.extractfile(member) as file:
                if catalogued:
                    self.files[path] = file.read()
                    if cited:
                        self.cited_digests[path] = sha256(self.files[path]).hexdigest()
                else:
                    self.cited_digests[path] = file_digest(file, "sha256").hexdigest()

    def read(self, path, *, required=True):
        raw = self.files.get(path)
        if raw is None and required:
            raise ValueError(f"Missing required archive file: {path}")
        return raw


def make_origin(archive, record, list_kind, version, data_commit):
    _, id_field, detail_folder = KINDS[list_kind]
    identifier = record[id_field]
    if not isinstance(identifier, str) or not SAFE_ID.fullmatch(identifier):
        raise ValueError(f"Invalid SPDX identifier: {identifier!r}")
    name = record["name"]
    deprecated = record["isDeprecatedLicenseId"]
    if not isinstance(name, str) or not name or type(deprecated) is not bool:
        raise ValueError(f"Malformed SPDX summary for {identifier}")

    detail_path = f"json/{detail_folder}/{identifier}.json"
    detail_raw = archive.read(detail_path)
    detail = read_json(detail_raw)
    if (detail.get(id_field), detail.get("name"), detail.get("isDeprecatedLicenseId")) != (
        identifier, name, deprecated
    ):
        raise ValueError(f"SPDX summary/detail identity mismatch for {identifier}")

    metadata = dict(record)
    for field in ("isFsfLibre", "deprecatedVersion"):
        if field in detail:
            if field in metadata and metadata[field] != detail[field]:
                raise ValueError(f"SPDX summary/detail disagreement for {identifier} {field}")
            metadata[field] = detail[field]

    artifacts = {"detail": describe_text(detail_path, detail_raw)}
    stems = (f"deprecated_{identifier}", identifier) if deprecated else (identifier,)
    for key, pattern in (
        ("text", "text/{}.txt"),
        ("template", "template/{}.template.txt"),
    ):
        for stem in stems:
            filename = pattern.format(stem)
            raw = archive.read(filename, required=False)
            if raw:
                artifacts[key] = describe_text(filename, raw)
                break

    origin = {
        "kind": "spdx",
        "source": data_commit,
        "release": version,
        "identifier": identifier,
        "list_kind": list_kind,
        "name": name,
        "deprecated": deprecated,
        "metadata": metadata,
        "artifacts": artifacts,
    }
    headers = [field for field in HEADER_FIELDS
               if isinstance(detail.get(field), str) and detail[field].strip()]
    if headers:
        origin["headers"] = {"artifact": "detail", "fields": headers}
    if deprecated:
        artifact, replacements = read_spdx_replacements(archive, identifier, list_kind)
        if artifact:
            origin["artifacts"]["replacement_source"] = artifact
        if replacements:
            origin["upstream_replacements"] = replacements
    return origin


def read_spdx_replacements(archive, identifier, list_kind):
    """Read relationships absent from the supported summary and detail JSON formats."""
    folder = "exceptions/" if list_kind == "exception" else ""
    path = f"license-list-XML/{folder}{identifier}.xml"
    raw = archive.read(path, required=False)
    if raw is None:
        return None, []
    root = ElementTree.fromstring(raw)
    entry = root.find(f"spdx:{list_kind}", SPDX_XML)
    if entry is None or entry.get("licenseId") != identifier:
        raise ValueError(f"SPDX replacement XML identity mismatch for {identifier}")
    replacements = []
    for element in entry.findall("spdx:obsoletedBys/spdx:obsoletedBy", SPDX_XML):
        replacement = {"target": element.text.strip()}
        if "expression" in element.attrib:
            replacement["for_expression"] = element.attrib["expression"]
        replacements.append(replacement)
    return describe_text(path, raw), replacements


def origin_summary(origins):
    counts = Counter((origin["list_kind"], origin["deprecated"]) for origin in origins.values())
    return {
        "licenses": counts["license", False] + counts["license", True],
        "exceptions": counts["exception", False] + counts["exception", True],
        "deprecated_licenses": counts["license", True],
        "deprecated_exceptions": counts["exception", True],
        "missing_text": sum("text" not in origin["artifacts"] for origin in origins.values()),
        "missing_template": sum("template" not in origin["artifacts"] for origin in origins.values()),
    }


def load_release(archive_path, version, data_commit, source_commit, expected_sha256=None):
    origins, manifest, _ = _load_release(archive_path, version, data_commit, source_commit, expected_sha256)
    return origins, manifest


def _load_release(archive_path, version, data_commit, source_commit, expected_sha256, *, cited_paths=()):
    if not RELEASE.fullmatch(version) or not all(
        COMMIT.fullmatch(commit) for commit in (data_commit, source_commit)
    ):
        raise ValueError("Expected an SPDX X.Y.Z release and two exact 40-character Git commits")
    if expected_sha256 is not None and not DIGEST.fullmatch(expected_sha256):
        raise ValueError("Expected a lowercase SHA-256 digest")

    archive_path = Path(archive_path)
    with archive_path.open("rb") as file:
        archive_digest = file_digest(file, "sha256").hexdigest()
        archive_size = os.fstat(file.fileno()).st_size
        if expected_sha256 is not None and archive_digest != expected_sha256:
            raise ValueError(f"Archive SHA-256 mismatch: {archive_digest}")

        file.seek(0)
        origins, manifests, release_dates = {}, {}, set()
        known_ids = set()
        with tarfile.open(fileobj=file, mode="r|*") as tar:
            archive = Archive(tar, data_commit, cited_paths)
            for kind, (key, id_field, _) in KINDS.items():
                manifest_path = f"json/{key}.json"
                raw = archive.read(manifest_path)
                manifest = read_json(raw)
                if manifest.get("licenseListVersion") != version:
                    raise ValueError(f"SPDX release version mismatch in {manifest_path}")
                release_date = manifest["releaseDate"]
                datetime.fromisoformat(release_date)
                release_dates.add(release_date)
                records = manifest[key]
                if not isinstance(records, list) or not records:
                    raise ValueError(f"Expected a nonempty SPDX population in {manifest_path}")
                manifests[key] = fingerprint(manifest_path, raw)
                for record in records:
                    origin = make_origin(archive, record, kind, version, data_commit)
                    normalized_id = record[id_field].casefold()
                    if normalized_id in known_ids:
                        raise ValueError(f"Duplicate SPDX identifier: {record[id_field]}")
                    known_ids.add(normalized_id)
                    origins[record[id_field]] = origin
    if len(release_dates) != 1:
        raise ValueError("SPDX manifests disagree on the release date")

    manifest = {
        "kind": "spdx",
        "release": version,
        "release_date": release_dates.pop(),
        "data_repository": f"https://github.com/{DATA_REPOSITORY}",
        "data_commit": data_commit,
        "source_repository": f"https://github.com/{SOURCE_REPOSITORY}",
        "xml_commit": source_commit,
        "archive": {
            "url": f"https://codeload.github.com/{DATA_REPOSITORY}/tar.gz/{data_commit}",
            "sha256": archive_digest,
            "bytes": archive_size,
        },
        "manifests": manifests,
        "population": origin_summary(origins),
    }
    return origins, manifest, archive.cited_digests


def read_candidates(repo):
    records, normalized_ids = {}, set()
    pattern = "registry/candidates/*/*.json"
    for path in sorted(repo.glob(pattern)):
        candidate = read_json(path.read_bytes())
        origin = candidate.get("origin", {})
        if origin.get("kind") != "spdx":
            continue
        candidate_id = candidate["id"]
        if (not CANDIDATE_ID.fullmatch(candidate_id) or path.stem != candidate_id
                or path.parent.name != candidate_id[:2]):
            raise ValueError(f"Invalid SPDX candidate path: {path}")
        identifier = origin["identifier"]
        if identifier.casefold() in normalized_ids:
            raise ValueError(f"Duplicate existing SPDX candidate: {identifier}")
        normalized_ids.add(identifier.casefold())
        records[identifier] = candidate
    return records


def comparable_origin(origin):
    # Source pins qualify an artifact, while matching bytes and metadata identify
    # an otherwise identical entry across releases.
    comparable = {key: value for key, value in origin.items() if key not in ("source", "release")}
    comparable["metadata"] = {
        key: value for key, value in origin["metadata"].items() if key != "referenceNumber"
    }
    return comparable


def reconcile(existing, origins, manifest):
    updates = {}
    events = {label: [] for label in ("added", "changed", "deprecated", "removed", "restored")}
    existing_by_key = {identifier.casefold(): candidate for identifier, candidate in existing.items()}
    incoming_keys = {identifier.casefold() for identifier in origins}
    for identifier, origin in sorted(origins.items()):
        prior = existing_by_key.get(identifier.casefold())
        if prior is None:
            candidate_id = uuid4().hex
            updates[identifier] = {
                "id": candidate_id,
                "disposition": "unresolved",
                "reason": "SPDX list entry awaiting Software Commons identity and source qualification.",
                "origin": origin,
                "history": [],
            }
            events["added"].append(identifier)
            if origin["deprecated"]:
                events["deprecated"].append(identifier)
            continue

        old = prior["origin"]
        changed = json_bytes(comparable_origin(old)) != json_bytes(comparable_origin(origin))
        removed = prior.get("membership", {}).get("status") == "removed"
        if not changed and not removed:
            continue

        updated = dict(prior)
        history = list(prior.get("history", []))
        if changed:
            history.append({"origin": old})
            updated["origin"] = origin
            events["changed"].append(identifier)
        if removed:
            history.append({"membership": prior["membership"]})
            history.append({"membership": {
                "status": "restored",
                "source": manifest["data_commit"],
                "release": manifest["release"],
            }})
            updated.pop("membership")
            events["restored"].append(identifier)
        if origin["deprecated"] and not old["deprecated"]:
            events["deprecated"].append(identifier)
        updated["history"] = history
        updates[identifier] = updated

    for identifier in sorted(existing):
        if identifier.casefold() in incoming_keys:
            continue
        prior = existing[identifier]
        if prior.get("membership", {}).get("status") == "removed":
            continue
        updates[identifier] = {
            **prior,
            "membership": {
                "status": "removed",
                "source": manifest["data_commit"],
                "release": manifest["release"],
            },
        }
        events["removed"].append(identifier)
    return updates, events


def changed_artifact_locators(previous, incoming):
    locators = set()
    before = previous.get("artifacts", {})
    after = incoming.get("artifacts", {})
    for name in before.keys() | after.keys():
        if before.get(name) == after.get(name):
            continue
        for origin, artifact in ((previous, before.get(name)), (incoming, after.get(name))):
            if artifact is None:
                continue
            revision = origin["source"]
            if not COMMIT.fullmatch(revision):
                raise ValueError("Expected an exact SPDX artifact origin commit")
            for path in {artifact["path"], quote(artifact["path"])}:
                locators.update(f"{base}{revision}/{path}" for base in DATA_LOCATORS)
    return locators


def record_key(value):
    if isinstance(value, dict):
        kind, identity, revision = (value.get(field) for field in ("kind", "id", "revision"))
        if isinstance(kind, str) and isinstance(identity, str) and type(revision) is int and revision > 0:
            return kind, identity, revision
    return None


def record_refs(value):
    if isinstance(value, dict):
        if value.keys() == {"kind", "id", "revision"} and (key := record_key(value)):
            yield key
        else:
            for item in value.values():
                yield from record_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from record_refs(item)


def generated_artifact(locator):
    if not isinstance(locator, str):
        return None
    for base in DATA_LOCATORS:
        if not locator.startswith(base):
            continue
        revision, _, path = locator[len(base):].partition("/")
        if not COMMIT.fullmatch(revision) or not ARTIFACT_URI_PATH.fullmatch(path):
            return None
        try:
            decoded = unquote(path, errors="strict")
        except UnicodeError:
            return None
        if (decoded.isprintable() and "\\" not in decoded and decoded.count("/") == path.count("/")
                and all(part not in ("", ".", "..") for part in decoded.split("/"))):
            return revision, decoded
    return None


def cited_artifacts(repo):
    records = repo / "sces/records"
    citations = {}
    for path in sorted((records / "source").glob("*.json")):
        source = read_json(path.read_bytes())
        identity = record_key(source)
        if identity is None or identity[0] != "source":
            continue
        locator = source.get("locator")
        artifact = generated_artifact(locator)
        if artifact is None:
            continue
        retained = source.get("artifact")
        retained_digest = retained.get("sha256") if isinstance(retained, dict) else None
        digests = {digest for digest in (source.get("captured_sha256"), retained_digest)
                   if isinstance(digest, str) and DIGEST.fullmatch(digest)}
        citations[identity] = (locator, *artifact, digests)

    missing = {identity for identity, (_, _, _, digests) in citations.items() if not digests}
    if missing:
        dependencies = {}
        for path in sorted((records / "dependency").glob("*.json")):
            dependency = read_json(path.read_bytes())
            if dependency.get("kind") == "dependency" and (identity := record_key(dependency)):
                dependencies[identity] = (record_key(dependency.get("claim")), record_key(dependency.get("basis")))
        for path in sorted((records / "verification").glob("*.json")):
            verification = read_json(path.read_bytes())
            claim = record_key(verification.get("claim"))
            if verification.get("kind") != "verification" or claim is None or claim[0] != "claim":
                continue
            for receipt in verification.get("acquisitions", []):
                identity = record_key(receipt.get("source"))
                if identity not in missing or dependencies.get(record_key(receipt.get("dependency"))) != (claim, identity):
                    continue
                locator, _, _, digests = citations[identity]
                digest = receipt.get("sha256")
                if receipt.get("locator") == locator and isinstance(digest, str) and DIGEST.fullmatch(digest):
                    digests.add(digest)
    return citations.values()


def artifact_dependencies(records, locators):
    by_key = {}
    dependents = defaultdict(list)
    matches = {}
    queue = deque()

    def mark(path, reason):
        if path not in matches:
            matches[path] = set()
            queue.append(path)
        matches[path].add(reason)

    for path, value in records.items():
        if not path.startswith("sces/records/") or (key := record_key(value)) is None:
            continue
        by_key[key] = path
        for reference in set(record_refs(value)):
            dependents[reference].append(path)
        locator = value.get("locator")
        if value["kind"] == "source" and isinstance(locator, str) and locator in locators:
            mark(path, locator)

    while queue:
        path = queue.popleft()
        value = records[path]
        kind, identity, revision = key = record_key(value)
        reason = f"{kind}:{identity}--{revision}"
        for dependent in dependents[key]:
            mark(dependent, reason)
        # Dependency records point to both the basis and the owning claim.
        # Follow the owner without pulling in every other basis of that claim.
        if kind == "dependency":
            claim = record_key(value.get("claim"))
            if claim and claim[0] == "claim" and claim in by_key:
                mark(by_key[claim], reason)
    return matches


def find_dependencies(repo, identifiers, candidate_ids, *, artifact_locators=()):
    tokens = set(identifiers) | set(candidate_ids)
    matches = []
    records = {}
    for pattern in ("registry/entities/**/*.json", "sces/records/**/*.json"):
        for path in sorted(repo.glob(pattern)):
            records[path.relative_to(repo).as_posix()] = read_json(path.read_bytes())
    pending = {path: (value, spdx_membership_key(value)) for path, value in records.items()}
    while tokens and pending:
        found = [(path, find_tokens(value, tokens) | ({key} & tokens))
                 for path, (value, key) in pending.items()]
        tokens = set()
        for path, direct in found:
            if not direct:
                continue
            matches.append({"path": path, "direct_matches": sorted(direct)})
            value, _ = pending.pop(path)
            identity = value.get("id") if isinstance(value, dict) else None
            if isinstance(identity, str):
                tokens.add(identity)
                if path.startswith("registry/entities/") and CANDIDATE_ID.fullmatch(identity):
                    tokens.add(f"e-{identity}")
    if artifact_locators:
        exact = artifact_dependencies(records, artifact_locators)
        for match in matches:
            if direct := exact.pop(match["path"], None):
                match["direct_matches"] = sorted(set(match["direct_matches"]) | direct)
        matches.extend({"path": path, "direct_matches": sorted(direct)} for path, direct in exact.items())
    return matches


def spdx_membership_key(record):
    if not isinstance(record, dict) or record.get("kind") != "claim" or record.get("predicate") != "spdx-membership":
        return None
    value = record.get("value")
    if not isinstance(value, str):
        return None
    try:
        binding = read_json(value.encode("utf-8"))
    except ValueError:
        return None
    if (isinstance(binding, dict) and binding.keys() == {"origin", "revision", "key"}
            and binding["origin"] == "spdx"
            and isinstance(binding["revision"], str) and COMMIT.fullmatch(binding["revision"])
            and isinstance(binding["key"], str) and SAFE_ID.fullmatch(binding["key"])
            and json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) == value):
        return binding["key"]
    return None


def find_tokens(value, tokens):
    if isinstance(value, str):
        return {value} & tokens
    if isinstance(value, dict):
        return set().union(set(value) & tokens, *(find_tokens(item, tokens) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(find_tokens(item, tokens) for item in value))
    return set()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(raw)
            file.close()
            if os.name == "nt":
                temporary.rename(path)
            else:
                path.hardlink_to(temporary)
        finally:
            temporary.unlink(missing_ok=True)


def candidate_path(candidate_id):
    return Path("registry", "candidates", candidate_id[:2], f"{candidate_id}.json")


def _existing_manifest(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Retained source manifest must be a regular file: {path.name}")
    return path.read_bytes() if path.is_file() else None


def prepare(repo, out, origins, manifest, *, initial=False, cited_locators=()):
    repo, out = Path(repo).resolve(), Path(out).resolve()
    existing = read_candidates(repo)
    if initial:
        if repo != out or any(candidate["origin"] != origins.get(identifier)
                              for identifier, candidate in existing.items()):
            raise ValueError("Initial import can only create or resume the same pinned population")
    elif (out.is_relative_to(repo) or out in repo.parents
          or (out.exists() and (not out.is_dir() or any(out.iterdir())))):
        raise ValueError("Use a separate empty output directory for prepared changes")

    updates, events = reconcile(existing, origins, manifest)
    affected = set().union(*events.values())
    prior_keys = {identifier.casefold(): identifier for identifier in existing}
    # Affected membership claims can still cite the exact prior key spelling.
    review_keys = affected | {prior_keys.get(identifier.casefold(), identifier) for identifier in affected}
    artifact_locators = set(cited_locators)
    for identifier in affected:
        prior = existing.get(prior_keys.get(identifier.casefold()), {})
        artifact_locators.update(changed_artifact_locators(prior.get("origin", {}), origins.get(identifier, {})))
    report = {
        "release": manifest["release"],
        "data_commit": manifest["data_commit"],
        "xml_commit": manifest["xml_commit"],
        "population": manifest["population"],
        "events": events,
        "dependency_review": find_dependencies(
            repo, review_keys, (updates[identifier]["id"] for identifier in affected),
            artifact_locators=artifact_locators,
        ),
        "candidate_changes": len(updates),
        "unchanged": len(origins) - sum(identifier in origins for identifier in updates),
    }
    pending_files = {}
    for identifier, candidate in sorted(updates.items()):
        pending_files[candidate_path(candidate["id"])] = json_bytes(candidate)
    manifest_path = Path("research", "sources", f"spdx-{manifest['release']}.json")
    manifest_bytes = json_bytes(manifest)
    base_manifest = _existing_manifest(repo / manifest_path)
    manifest_matches = base_manifest == manifest_bytes
    if not initial and base_manifest is not None and not manifest_matches:
        stem = manifest_path.stem
        revision = manifest["data_commit"]
        manifest_path = manifest_path.with_name(f"{stem}-{revision}.json")
        retained = _existing_manifest(repo / manifest_path)
        if retained is not None and retained != manifest_bytes:
            digest = sha256(manifest_bytes).hexdigest()
            manifest_path = manifest_path.with_name(f"{stem}-sha256-{digest}.json")
            retained = _existing_manifest(repo / manifest_path)
            if retained is not None and retained != manifest_bytes:
                raise ValueError(f"Digest-addressed source manifest contains different bytes: {manifest_path}")
    if not initial or not manifest_matches:
        pending_files[manifest_path] = manifest_bytes
    if not initial:
        pending_files[Path("reconciliation-report.json")] = json_bytes(report)
    for path in pending_files:
        if (out / path).exists():
            raise ValueError(f"Output already exists: {path}")
    for path, raw in pending_files.items():
        write_new(out / path, raw)
    return report


def prepare_archive(repo, out, archive_path, version, data_commit, source_commit, expected_sha256=None, *, initial=False):
    citations = () if initial else cited_artifacts(Path(repo).resolve())
    paths = {path for _, _, path, _ in citations}
    origins, manifest, observed = _load_release(
        archive_path, version, data_commit, source_commit, expected_sha256, cited_paths=paths,
    )
    # Conflicting prior digests require review. Without an exact prior digest,
    # a new source pin or an unavailable member also requires reinspection.
    locators = {locator for locator, revision, path, digests in citations
                if (digests and digests != {observed.get(path)})
                or (not digests and (revision != data_commit or path not in observed))}
    return prepare(repo, out, origins, manifest, initial=initial, cited_locators=locators)


def github_json(path):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "software-commons-license-index",
    }
    request = Request(f"https://api.github.com/{path}", headers=headers)
    with urlopen(request, timeout=30) as reply:
        return json.load(reply)


def resolve_tag(repository, tag):
    ref = github_json(f"repos/{repository}/git/ref/tags/{tag}")["object"]
    seen = set()
    while ref["type"] == "tag":
        pin = ref["sha"]
        if pin in seen or not COMMIT.fullmatch(pin):
            raise ValueError(f"Invalid annotated tag chain for {tag}")
        seen.add(pin)
        ref = github_json(f"repos/{repository}/git/tags/{pin}")["object"]
    if ref["type"] != "commit" or not COMMIT.fullmatch(ref["sha"]):
        raise ValueError(f"SPDX tag does not point to a commit: {tag}")
    return ref["sha"]


def discover():
    source_release = github_json(f"repos/{SOURCE_REPOSITORY}/releases/latest")
    tag = source_release["tag_name"]
    if not tag.startswith("v") or not RELEASE.fullmatch(tag[1:]):
        raise ValueError(f"Unexpected SPDX release tag: {tag}")
    github_json(f"repos/{DATA_REPOSITORY}/releases/tags/{tag}")
    source_commit = resolve_tag(SOURCE_REPOSITORY, tag)
    data_commit = resolve_tag(DATA_REPOSITORY, tag)
    return {
        "release": tag[1:],
        "xml_commit": source_commit,
        "data_commit": data_commit,
        "archive_url": f"https://codeload.github.com/{DATA_REPOSITORY}/tar.gz/{data_commit}",
    }


def acquire_archive(url, destination):
    request = Request(url, headers={"User-Agent": "software-commons-license-index"})
    with urlopen(request, timeout=60) as source, destination.open("xb") as file:
        copyfileobj(source, file, length=1024 * 1024)


def prepare_latest(repo, out, expected_sha256=None):
    upstream = discover()
    with TemporaryDirectory() as directory:
        archive = Path(directory) / "spdx.tar.gz"
        acquire_archive(upstream["archive_url"], archive)
        return prepare_archive(
            repo, out, archive, upstream["release"], upstream["data_commit"], upstream["xml_commit"], expected_sha256,
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("discover", help="resolve the current stable upstream release and commits")
    for name in ("initial", "prepare", "prepare-latest"):
        command = subcommands.add_parser(name)
        command.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
        if name != "prepare-latest":
            command.add_argument("--archive", type=Path, required=True)
            command.add_argument("--release", required=True)
            command.add_argument("--data-commit", required=True)
            command.add_argument("--source-commit", required=True)
        command.add_argument("--sha256", help="verify against this independently obtained archive digest")
        if name != "initial":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            report = discover()
        elif args.command == "prepare-latest":
            report = prepare_latest(args.repo, args.output, args.sha256)
        else:
            initial = args.command == "initial"
            report = prepare_archive(
                args.repo, args.repo if initial else args.output, args.archive,
                args.release, args.data_commit, args.source_commit, args.sha256, initial=initial,
            )
    except (KeyError, TypeError, ValueError, OSError, tarfile.TarError, ElementTree.ParseError) as error:
        parser.exit(1, f"SPDX reconciliation failed: {error}\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
