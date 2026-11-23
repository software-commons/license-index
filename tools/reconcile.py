"""Read a pinned SPDX generated-data tarball and stage candidate changes."""

from __future__ import annotations

import argparse
from collections import Counter
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
from urllib.request import Request, urlopen
from uuid import uuid4
from xml.etree import ElementTree


DATA_REPOSITORY = "spdx/license-list-data"
SOURCE_REPOSITORY = "spdx/license-list-XML"
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
    def __init__(self, tar, data_commit):
        prefix = f"license-list-data-{data_commit}/"
        self.files = {}
        for member in tar:
            if not member.isfile():
                continue
            if not member.name.startswith(prefix):
                raise ValueError("Archive files must be rooted at the pinned data commit")
            path = member.name[len(prefix):]
            if not path.startswith(("json/", "text/", "template/", "license-list-XML/")):
                continue
            if path in self.files:
                raise ValueError(f"Duplicate archive path: {path}")
            with tar.extractfile(member) as file:
                self.files[path] = file.read()

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
            archive = Archive(tar, data_commit)
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

    return origins, {
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


def find_dependencies(repo, identifiers, candidate_ids):
    tokens = set(identifiers) | set(candidate_ids)
    matches = []
    pending = {}
    for pattern in ("registry/entities/**/*.json", "sces/records/**/*.json"):
        for path in sorted(repo.glob(pattern)):
            value = read_json(path.read_bytes())
            pending[path.relative_to(repo).as_posix()] = (value, spdx_membership_key(value))
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


def prepare(repo, out, origins, manifest, *, initial=False):
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
    report = {
        "release": manifest["release"],
        "data_commit": manifest["data_commit"],
        "xml_commit": manifest["xml_commit"],
        "population": manifest["population"],
        "events": events,
        "dependency_review": find_dependencies(
            repo, affected, (updates[identifier]["id"] for identifier in affected)
        ),
        "candidate_changes": len(updates),
        "unchanged": len(origins) - sum(identifier in origins for identifier in updates),
    }
    pending_files = {}
    for identifier, candidate in sorted(updates.items()):
        pending_files[candidate_path(candidate["id"])] = json_bytes(candidate)
    manifest_path = Path("research", "sources", f"spdx-{manifest['release']}.json")
    manifest_bytes = json_bytes(manifest)
    current_manifest = repo / manifest_path
    manifest_exists = current_manifest.is_file()
    manifest_matches = manifest_exists and current_manifest.read_bytes() == manifest_bytes
    if not initial and manifest_exists and not manifest_matches:
        suffix = manifest["data_commit"]
        manifest_path = manifest_path.with_name(f"{manifest_path.stem}-{suffix}.json")
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
        origins, manifest = load_release(
            archive, upstream["release"], upstream["data_commit"], upstream["xml_commit"], expected_sha256
        )
    return prepare(repo, out, origins, manifest)


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
            origins, manifest = load_release(
                args.archive, args.release, args.data_commit, args.source_commit, args.sha256
            )
            initial = args.command == "initial"
            report = prepare(
                args.repo, args.repo if initial else args.output, origins, manifest, initial=initial
            )
    except (KeyError, TypeError, ValueError, OSError, tarfile.TarError, ElementTree.ParseError) as error:
        parser.exit(1, f"SPDX reconciliation failed: {error}\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
