"""Validate development inputs and build deterministic offline artifacts."""

from __future__ import annotations

from functools import cache, partial
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import re
from urllib.request import Request, build_opener
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from .li_install import LGPL_V3_IDS, LGPL_V3_SUPPLEMENT, write_license
from .qualification import _blob_hash, _exact_file, _git, _git_blobs, check_history, qualified
from .reconcile import RELEASE
from .records import (
    DATA_COMMIT, HEX_256, VERSION, Catalog, DataError, NoRedirects, checked_bytes, decode, encode, is_removed,
    local_path, read, require,
)

COVERAGE = "registry/coverage/current.json"
SNAPSHOTS = "registry/coverage/snapshots"
SOURCES = "research/sources"
SPDX_SOURCE = re.compile(rf"{SOURCES}/spdx-[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9a-f]{{40}})?\.json")
PACKAGED_TEXTS = "legal-texts/manifest.json"
PROFILES = "research/campaigns/profiles.json"
QUALIFICATION_SCOPE = "development-discovery"
DIMENSION_STATES = {"permission", "condition", "restriction", "documented", "unresolved",
                    "inapplicable", "explicit-absence"}
CC_REVISION = "91780e140892982eb3e0d530591ccbbca0d4690d"
CC_PUBLISHER_TREE = f"https://raw.githubusercontent.com/creativecommons/cc-legal-tools-data/{CC_REVISION}"
CC_RIGHTS = f"{CC_PUBLISHER_TREE}/README.md"
CC_RIGHTS_SHA256 = "76eac782e1d4ea9bdcd0b88686f315fe42076b70af238a44114e87f024fe096f"
CC_LEGAL_TEXTS = {
    "CC-BY-4.0": ("licenses/by/4.0/legalcode.txt", "9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411"),
    "CC0-1.0": ("publicdomain/zero/1.0/legalcode.txt", "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"),
}
CC_LEGACY_RIGHTS = {"https://creativecommons.org/policies/", "https://creativecommons.org/policies/#cc-licensing-statement"}
POLYFORM_RIGHTS = ("https://raw.githubusercontent.com/polyformproject/polyform-licenses/"
                   "a2316cfa35d3947fdc5af4bcc1f321662bfd79d8/LICENSE.md")
RIGHTS_DOCUMENTS = {CC_RIGHTS: "cc-rights-exact.md", POLYFORM_RIGHTS: "polyform-rights-exact.md"}
RIGHTS_BY_IDENTIFIER = {
    **dict.fromkeys(CC_LEGAL_TEXTS, CC_RIGHTS),
    **dict.fromkeys(("CC-BY-NC-4.0", "CC-BY-NC-ND-4.0", "CC-BY-NC-SA-4.0",
                     "CC-BY-ND-4.0", "CC-BY-SA-4.0"), CC_RIGHTS),
    **dict.fromkeys(("PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0"), POLYFORM_RIGHTS),
}
RIGHTS_MAX_BYTES = 64 * 1024
BUNDLE_SUPPORT = {
    "LICENSE", "README.md", "license-index", "license-index.cmd", COVERAGE,
    "docs/CLI.md", "docs/CODEX_GATE.md", "docs/GOVERNANCE_REVIEW.md", "docs/MAINTENANCE.md",
    "docs/PROFILE_QUALIFICATION.md", "docs/PUBLICATION.md", "docs/RESEARCH_STATUS.md", "docs/SCOPE.md",
    "research/sources/predecessor-assessment.md", "schemas/domain/registry-v1.schema.json",
    "tools/__init__.py", "tools/distribution.py", "tools/index.py", "tools/li_install.py",
    "tools/qualification.py", "tools/reconcile.py", "tools/records.py", "tools/review_plan.py",
    "tools/run_isolated.py", "tools/schema_check.py", "tools/spdx_replay.py",
}


def descriptor(value):
    require(isinstance(value["path"], str) and HEX_256.fullmatch(value["sha256"])
            and type(value["bytes"]) is int and value["bytes"] > 0, "invalid artifact descriptor")


def validate_source(catalog, source):
    require(DATA_COMMIT.fullmatch(source["data_commit"]) and DATA_COMMIT.fullmatch(source["xml_commit"]),
            "invalid SPDX source commit")
    for value in source["manifests"].values():
        descriptor(value)
    expected = source["population"]
    catalog_counts = catalog.coverage()["catalog"]
    for field in ("licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions"):
        require(expected[field] == catalog_counts[f"spdx_{field}"], f"SPDX population mismatch: {field}")
    for key in ("text", "template"):
        count = sum(key not in row["origin"]["artifacts"] for row in catalog.active_spdx)
        require(expected[f"missing_{key}"] == count, f"SPDX missing {key} count mismatch")
    active_pins = set()
    for row in catalog.active_spdx:
        origin = row["origin"]
        active_pins.add((origin["release"], origin["source"]))
        require("detail" in origin["artifacts"], f"missing SPDX detail: {origin['identifier']}")
        for value in origin["artifacts"].values():
            descriptor(value)
        metadata = origin["metadata"]
        field = "licenseId" if origin["list_kind"] == "license" else "licenseExceptionId"
        require((metadata[field], metadata["name"], metadata["isDeprecatedLicenseId"]) ==
                (origin["identifier"], origin["name"], origin["deprecated"]),
                f"SPDX identity drift: {origin['identifier']}")

    # The current manifest defines membership. Unchanged records keep their original artifact
    # source, which archive replay checks against the exact predecessor and current population.
    retained_paths = set()
    for release, commit in sorted(active_pins - {(source.get("release"), source["data_commit"])}):
        require(RELEASE.fullmatch(release) and DATA_COMMIT.fullmatch(commit), "invalid retained SPDX source pin")
        for suffix in ("", f"-{commit}"):
            name = f"{SOURCES}/spdx-{release}{suffix}.json"
            prior = catalog._optional(name)
            if (prior.get("release"), prior.get("data_commit")) == (release, commit):
                retained_paths.add(name)
                break
        else:
            raise DataError(f"unregistered retained SPDX source pin: {release} at {commit}")
    return retained_paths


def read_rights_document(url, *, root=None):
    require(url in RIGHTS_DOCUMENTS, "unapproved publisher rights locator")
    if root is not None:
        path = local_path(root, RIGHTS_DOCUMENTS[url])
        require(path.is_file() and path.resolve() == path, f"missing or linked rights document: {path}")
        with path.open("rb") as body:
            data = body.read(RIGHTS_MAX_BYTES + 1)
    else:
        request = Request(url, headers={"User-Agent": "software-commons-license-index"}, method="GET")
        with build_opener(NoRedirects()).open(request, timeout=20) as body:
            require(body.status == 200 and body.geturl() == url, "unexpected publisher rights response")
            data = body.read(RIGHTS_MAX_BYTES + 1)
    require(0 < len(data) <= RIGHTS_MAX_BYTES, "publisher rights document has invalid size")
    return data


def _validate_text_rights(identifier, package, rights_reader, *, archived):
    expected_url = RIGHTS_BY_IDENTIFIER.get(identifier)
    if expected_url is None and "rights_sha256" not in package:
        return
    url, digest = package["rights"], package.get("rights_sha256")
    if identifier in CC_LEGAL_TEXTS:
        publisher_path, text_digest = CC_LEGAL_TEXTS[identifier]
        require(package["sha256"] == text_digest, f"unexpected admitted publisher text digest for {identifier}")
        if archived and "rights_sha256" not in package:
            # Bind the exact legacy edition already in Git to the same publisher statement without rewriting it.
            require(url in CC_LEGACY_RIGHTS and package["source"] == f"https://creativecommons.org/{publisher_path}",
                    f"unverified archival publisher reference for {identifier}")
            url, digest = CC_RIGHTS, CC_RIGHTS_SHA256
        else:
            require(package["source"] == f"{CC_PUBLISHER_TREE}/docs/{publisher_path}" and package["revision"] == CC_REVISION,
                    f"unapproved publisher text locator for {identifier}")
            require(digest == CC_RIGHTS_SHA256, f"invalid rights digest for {identifier}")
    require(url in RIGHTS_DOCUMENTS and (expected_url is None or url == expected_url),
            f"unapproved publisher rights locator for {identifier}")
    require(isinstance(digest, str) and HEX_256.fullmatch(digest), f"invalid rights digest for {identifier}")
    if rights_reader is not None:
        require(sha256(rights_reader(url)).hexdigest() == digest, f"publisher rights SHA-256 mismatch for {identifier}")


def validate_texts(catalog, read_bytes=None, *, rights_reader=None, archived=False):
    for identifier, package in catalog.packaged.items():
        row = catalog.resolve(identifier)
        origin = row["origin"]
        require(origin["identifier"] == identifier and origin["kind"] == "spdx",
                f"ambiguous text binding: {identifier}")
        descriptor(package)
        path = local_path(catalog.root, package["path"])
        content = checked_bytes(path.read_bytes() if read_bytes is None else read_bytes(package["path"]), package)
        content.decode("utf-8")
        require(package["source"].startswith("https://") and package["rights"].startswith("https://"),
                f"missing publication provenance for {identifier}")
        _validate_text_rights(identifier, package, rights_reader, archived=archived)
        recipe = package.get("install")
        require(recipe in {None, "unchanged", LGPL_V3_SUPPLEMENT}, f"unexpected bundle treatment: {identifier}")
        if recipe:
            require(origin["list_kind"] == "license" and not origin["deprecated"]
                    and not is_removed(row) and package.get("application"),
                    f"invalid installation target: {identifier}")
            lgplv3 = identifier in LGPL_V3_IDS
            require((recipe == LGPL_V3_SUPPLEMENT) == lgplv3, f"incorrect GPLv3 companion requirement: {identifier}")
            if lgplv3:
                require(catalog.packaged.get("GPL-3.0-only", {}).get("install") == "unchanged",
                        "LGPLv3 installation requires the bundled unchanged GPLv3 text")


def validate_profiles(catalog):
    for identifier, profile in catalog.profiles.items():
        row = catalog.resolve(identifier)
        require(row["origin"]["kind"] == "spdx" and row["origin"]["identifier"] == identifier,
                f"missing exact profile subject for {identifier}")
        require(profile["summary"] and profile["dimensions"] and profile["scenarios"],
                f"incomplete provisional profile for {identifier}")
        for value in profile["dimensions"].values():
            require(value["state"] in DIMENSION_STATES, f"invalid research state for {identifier}")
            require(value["sources"] or value["state"] in {"unresolved", "inapplicable"},
                    f"asserted dimension lacks an evidence locator for {identifier}")
        for value in profile["scenarios"]:
            require(value["sources"], f"scenario lacks an evidence locator for {identifier}")
        for value in [*profile["dimensions"].values(), *profile["scenarios"]]:
            require(value["text"], f"empty finding for {identifier}")
            for citation in value["sources"]:
                require(citation["url"].startswith("https://") and citation["locator"],
                        f"invalid evidence locator for {identifier}")


def validate_discovery(catalog, *, base=None, spdx_archive=None, fetch_spdx_archive=False, rights_reader=None):
    current = _exact_file(catalog.root / COVERAGE)
    saved = decode(current)
    source = read(local_path(catalog.root, saved["source_manifest"]))
    retained_sources = validate_source(catalog, source)
    validate_texts(catalog, rights_reader=rights_reader)
    validate_profiles(catalog)
    require(encode(saved["assessment"]) == encode(catalog.coverage()),
            "discovery coverage snapshot differs from the live ledger")
    name = saved["snapshot"]
    snapshot = local_path(catalog.root, name)
    require(name.startswith(f"{SNAPSHOTS}/") and snapshot.suffix == ".json"
            and snapshot.relative_to(catalog.root).as_posix() == name,
            "current coverage must name a JSON archive under registry/coverage/snapshots")
    require(_exact_file(snapshot) == current,
            "current coverage differs from its immutable snapshot")
    if spdx_archive is not None or fetch_spdx_archive:
        from .spdx_replay import replay, replay_download
        if spdx_archive is not None:
            replay(catalog, source, spdx_archive, base)
        else:
            replay_download(catalog, source, base)
    return saved, retained_sources


class _HistoricalCatalog(Catalog):
    """Replay current discovery logic over immutable JSON from one Git tree."""

    def __init__(self, root, rows):
        self._rows = rows
        super().__init__(root)

    def _optional(self, relative):
        return self._rows.get(relative, {})

    def _sharded_rows(self, kind):
        prefix = f"registry/{kind}/"
        return ((name, row) for name, row in self._rows.items()
                if name.startswith(prefix) and name.endswith(".json"))


def _read_git_blobs(root, paths, cache):
    missing = sorted(set(paths.values()) - cache.keys())
    if missing:
        request = "".join(f"{oid}\n" for oid in missing).encode("ascii")
        with BytesIO(_git(root, "cat-file", "--batch", input_data=request)) as stream:
            for oid in missing:
                header = stream.readline().split()
                require(len(header) == 3 and header[:2] == [oid.encode("ascii"), b"blob"]
                        and header[2].isdigit(), f"missing or invalid historical Git blob: {oid}")
                payload = stream.read(int(header[2]))
                require(len(payload) == int(header[2]) and stream.read(1) == b"\n",
                        f"truncated historical Git blob: {oid}")
                cache[oid] = payload
            require(not stream.read(1), "unexpected data after historical Git blobs")
    return {path: cache[oid] for path, oid in paths.items()}


def _historical_spdx_base(root, base, commit, verified):
    ancestors = _git(root, "rev-list", "--topo-order", f"{commit}^@", f"^{base}").decode().splitlines()
    previous = next((ancestor for ancestor in ancestors if ancestor in verified), None)
    if previous is not None:
        return previous
    return _git(root, "merge-base", base, commit).decode().strip()


def validate_incoming_snapshots(root, base, *, rights_reader=None, replay_spdx=None):
    head = _git(root, "rev-parse", "--verify", "HEAD").decode().strip()
    prior = _git_blobs(root, base, SNAPSHOTS)
    _git(root, "merge-base", "--is-ancestor", base, head)
    tracked = _git_blobs(root, head, COVERAGE, SNAPSHOTS)
    current_oid = tracked.pop(COVERAGE, None)
    algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
    current = _exact_file(root / COVERAGE)
    require(_blob_hash(current, algorithm) == current_oid, "current coverage differs from the committed ledger")
    selected = decode(current)["snapshot"]
    require(tracked.get(selected) == current_oid, "current coverage does not name an exact committed archive")
    worktree = {path.relative_to(root).as_posix() for path in (root / SNAPSHOTS).rglob("*.json")}
    require(worktree == tracked.keys(), "coverage snapshots must be committed JSON files")
    pending = tracked.keys() - prior.keys()
    if not pending:
        return
    tracked_sources = _git_blobs(root, head, SOURCES)
    for name in sorted(pending):
        require(_blob_hash(_exact_file(root / name), algorithm) == tracked[name],
                f"{name}: incoming coverage differs from the committed snapshot")

    cache = {}
    commits = _git(root, "log", "--full-history", "--topo-order", "--format=%H", f"{base}..{head}",
                   "--", COVERAGE).decode().splitlines()
    snapshots = {}
    for commit in commits:
        blobs = _git_blobs(root, commit, COVERAGE, SNAPSHOTS)
        matches = sorted(name for name in pending if blobs.get(COVERAGE) == blobs.get(name) == tracked[name])
        for name in matches:
            snapshots[name] = commit
            pending.remove(name)
        if not pending:
            break
    require(not pending, f"coverage snapshots lack a matching historical current ledger: {', '.join(sorted(pending))}")

    verified = set()
    for name, commit in reversed(snapshots.items()):
        archived = decode(_read_git_blobs(root, {name: tracked[name]}, cache)[name])
        require(archived["snapshot"] == name, f"{name}: invalid snapshot self-reference")
        source = archived["source_manifest"]
        inputs = _git_blobs(root, commit, SOURCES, "registry/candidates", PACKAGED_TEXTS, PROFILES)
        require(isinstance(source, str) and source.startswith(f"{SOURCES}/") and source in inputs,
                f"{name}: source manifest missing from historical Git tree {commit}")
        require(tracked_sources.get(source) == inputs[source],
                f"{name}: historical source manifest was dropped or changed at the candidate tip")
        data = _read_git_blobs(root, {path: oid for path, oid in inputs.items()
                                     if path == source or SPDX_SOURCE.fullmatch(path)
                                     or not path.startswith(f"{SOURCES}/")}, cache)
        rows = {path: decode(payload) for path, payload in data.items()}
        historic = _HistoricalCatalog(root, rows)
        validate_source(historic, rows[source])
        text_paths = {package["path"] for package in historic.packaged.values()}
        texts = _git_blobs(root, commit, "legal-texts", "LICENSE")
        require(text_paths <= texts.keys(), f"{name}: publisher text missing from historical Git tree {commit}")
        historical_texts = _read_git_blobs(root, {path: texts[path] for path in text_paths}, cache)
        validate_texts(historic, historical_texts.__getitem__, rights_reader=rights_reader, archived=True)
        validate_profiles(historic)
        expected = historic.coverage()
        installation = expected["installation"]
        # The v1 discovery format originally omitted this field when there were no companions.
        if not installation["requires_verified_companion"] and (
                "requires_verified_companion" not in archived["assessment"]["installation"]):
            del installation["requires_verified_companion"]
        require(encode(archived["assessment"]) == encode(expected),
                f"{name}: coverage differs from historical registry inputs at {commit}")
        if replay_spdx is not None:
            predecessor = _historical_spdx_base(root, base, commit, verified)
            try:
                replay_spdx(historic, rows[source], predecessor)
            except DataError as error:
                raise DataError(f"{name}: {error}") from error
            verified.add(commit)
    return snapshots.get(selected)


def validate(catalog, base=None, policy=None, *, spdx_archive=None, fetch_spdx_archive=False, rights_reader=None):
    if rights_reader is not None:
        rights_reader = cache(rights_reader)
    saved, _ = validate_discovery(catalog, base=base, spdx_archive=spdx_archive, rights_reader=rights_reader)
    replay_history = None
    if spdx_archive is None and fetch_spdx_archive:
        from .spdx_replay import replay_download

        archives = {}
        replay_history = partial(replay_download, archives=archives, historical=True)
    result = qualified(catalog, policy, base=base)
    archived = None
    if base:
        check_history(catalog, base)
        archived = validate_incoming_snapshots(catalog.root, base, rights_reader=rights_reader,
                                               replay_spdx=replay_history)
    if replay_history is not None:
        source = read(local_path(catalog.root, saved["source_manifest"]))
        replay_download(catalog, source, archived or base, archives=archives)
    return result


def discovery_export(catalog):
    snapshot = read(catalog.root / COVERAGE)
    return {
        "dataset": "software-commons/license-index",
        "schema_version": "1.0.0",
        "software_version": VERSION,
        "status": QUALIFICATION_SCOPE,
        "coverage": snapshot,
        "source": read(local_path(catalog.root, snapshot["source_manifest"])),
        "candidates": [catalog.describe(row) for row in catalog.search(include_history=True)],
        "provisional_profiles": catalog.profiles,
    }


def archive_entry(archive, name, data):
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (0o100755 if name == "license-index" else 0o100644) << 16
    archive.writestr(info, data, compress_type=ZIP_STORED)


def _bundle_path(root, value, folder, suffixes):
    target = local_path(root, value)
    require(value.startswith(f"{folder}/") and target.suffix in suffixes
            and target.relative_to(root).as_posix() == value, f"invalid bundle path: {value}")
    return value


def bundle(catalog, output):
    coverage, retained_sources = validate_discovery(catalog)
    root = catalog.root
    files = BUNDLE_SUPPORT | {
        _bundle_path(root, coverage["source_manifest"], SOURCES, {".json"}),
        _bundle_path(root, coverage["snapshot"], SNAPSHOTS, {".json"}),
        *retained_sources,
        *(f"registry/candidates/{identity[:2]}/{identity}.json" for identity in catalog.candidates),
    }
    if catalog.packaged:
        files.add(PACKAGED_TEXTS)
        files.update(_bundle_path(root, row["path"], "legal-texts", {".txt", ".md"})
                     for row in catalog.packaged.values() if row["path"] != "LICENSE")
    if catalog.profiles:
        files.add(PROFILES)
    data = BytesIO()
    with ZipFile(data, "w") as archive:
        archive_entry(archive, "catalog.json", encode(discovery_export(catalog)))
        for name in sorted(files):
            archive_entry(archive, name, _exact_file(local_path(root, name)))
    write_license(Path(output), data.getvalue())
    return {"output": str(output), "software_version": VERSION, "status": QUALIFICATION_SCOPE}
