"""Validate development inputs and build deterministic offline artifacts."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from .li_install import write_license
from .qualification import check_history, qualified
from .records import DATA_COMMIT, HEX_256, VERSION, checked_bytes, encode, is_removed, local_path, read, require

COVERAGE = "registry/coverage/current.json"
QUALIFICATION_SCOPE = "development-discovery"
DIMENSION_STATES = {"permission", "condition", "restriction", "documented", "unresolved",
                    "inapplicable", "explicit-absence"}


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
    for row in catalog.active_spdx:
        origin = row["origin"]
        require("detail" in origin["artifacts"], f"missing SPDX detail: {origin['identifier']}")
        for value in origin["artifacts"].values():
            descriptor(value)
        metadata = origin["metadata"]
        field = "licenseId" if origin["list_kind"] == "license" else "licenseExceptionId"
        require((metadata[field], metadata["name"], metadata["isDeprecatedLicenseId"]) ==
                (origin["identifier"], origin["name"], origin["deprecated"]),
                f"SPDX identity drift: {origin['identifier']}")


def validate_texts(catalog):
    for identifier, package in catalog.packaged.items():
        row = catalog.resolve(identifier)
        origin = row["origin"]
        require(origin["identifier"] == identifier and origin["kind"] == "spdx",
                f"ambiguous text binding: {identifier}")
        descriptor(package)
        content = checked_bytes(local_path(catalog.root, package["path"]).read_bytes(), package)
        content.decode("utf-8")
        require(package["source"].startswith("https://") and package["rights"].startswith("https://"),
                f"missing publication provenance for {identifier}")
        if "rights_sha256" in package:
            require(HEX_256.fullmatch(package["rights_sha256"]), f"invalid rights digest for {identifier}")
        require(package.get("install") in {None, "unchanged"}, f"unexpected bundle treatment: {identifier}")
        if package.get("install"):
            require(origin["list_kind"] == "license" and not origin["deprecated"]
                    and not is_removed(row) and package.get("application"),
                    f"invalid installation target: {identifier}")


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


def validate_discovery(catalog):
    saved = read(catalog.root / COVERAGE)
    source = read(local_path(catalog.root, saved["source_manifest"]))
    validate_source(catalog, source)
    validate_texts(catalog)
    validate_profiles(catalog)
    require(saved["assessment"] == catalog.coverage(), "discovery coverage snapshot differs from the live ledger")
    snapshot = local_path(catalog.root, saved["snapshot"])
    require(snapshot.read_bytes() == (catalog.root / COVERAGE).read_bytes(),
            "current coverage differs from its immutable snapshot")


def validate(catalog, base=None, policy=None):
    validate_discovery(catalog)
    result = qualified(catalog, policy, base=base)
    if base:
        check_history(catalog, base)
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


def bundle(catalog, output):
    validate_discovery(catalog)
    files = {"LICENSE", "README.md", "license-index", "license-index.cmd", COVERAGE}
    for folder, pattern in (
        ("registry/candidates", "*.json"), ("registry/coverage/snapshots", "*.json"),
        ("research/sources", "*"), ("docs", "*.md"), ("tools", "*.py"),
        ("legal-texts", "*"), ("schemas/domain", "*.json"),
    ):
        files.update(path.relative_to(catalog.root).as_posix()
                     for path in (catalog.root / folder).rglob(pattern) if path.is_file())
    if catalog.profiles:
        files.add("research/campaigns/profiles.json")
    files.difference_update({"tools/review_commission.py", "tools/review_gate.py", "tools/review_snapshot.py",
                             "tools/stage_release.py"})
    data = BytesIO()
    with ZipFile(data, "w") as archive:
        archive_entry(archive, "catalog.json", encode(discovery_export(catalog)))
        for name in sorted(files):
            archive_entry(archive, name, local_path(catalog.root, name).read_bytes())
    write_license(Path(output), data.getvalue())
    return {"output": str(output), "software_version": VERSION, "status": QUALIFICATION_SCOPE}
