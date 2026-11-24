"""Stage exact SCES release bytes for separate owner authorization."""

from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import re
import sys
from zipfile import ZipFile

from .distribution import COVERAGE, archive_entry, validate
from .li_install import InstallError, write_license
from .qualification import POLICY_COMMIT, POLICY_DIGEST, _blob_hash, _canonical, _exact_file, _git, _git_blobs
from .records import Catalog, DATA_COMMIT, DataError, ROOT, decode, encode, local_path, require

CONTRACTS_PATH = "evidence/v1/contracts.schema.json"
CONTRACTS_SHA256 = "574956395247de677332da8e2cec19453bd34cf0497b40c31280b202cfd8630c"
CONTRACTS_ASSET = "sces-contracts.schema.json"
SELECTION_PATH = "sces/publication.json"
DATA_DIRECTORIES = ("sces", "registry", "research", "legal-texts")
REPORT_FIELDS = ("repository", "release", "dataset", "dataset_version", "schema_version", "source_commit",
                 "policy_sha256", "selection_sha256")
REQUEST_STATUS = "awaiting-separate-release-authorization"
CHECKSUMS = "SHA256SUMS"
RELEASE_ASSETS = {"claims.json", "qualification.json", CONTRACTS_ASSET, CHECKSUMS}
ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip", re.ASCII | re.IGNORECASE)
GITHUB_ASSET_LIMIT = 2 * 1024 ** 3


def valid_archive_name(name):
    return isinstance(name, str) and ARCHIVE_NAME.fullmatch(name) is not None


def valid_archive_size(size):
    return type(size) is int and 0 < size < GITHUB_ASSET_LIMIT


def checksum_listing(assets):
    return "".join(f"{sha256(content).hexdigest()}  {name}\n" for name, content in sorted(assets.items())
                   if name != CHECKSUMS).encode("ascii")


def committed_file(root, commit, path):
    require(path in _git_blobs(root, commit, path), f"release input is not a regular committed file: {path}")
    committed = _git(root, "show", f"{commit}:{path}")
    require(_exact_file(root / path) == committed, f"release input differs from the candidate commit: {path}")
    return committed


def verify_candidate_data(root, commit):
    """Reject local-only inputs, including ignored files consumed by a validator."""
    algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
    for section in DATA_DIRECTORIES:
        expected = _git_blobs(root, commit, section)
        directory = root / section
        require(directory.resolve() == directory, f"linked release input directory: {section}")
        paths = {item.relative_to(root).as_posix() for item in directory.rglob("*")
                 if item.is_symlink() or not item.is_dir()}
        require(paths == expected.keys(), f"{section} paths differ from the candidate commit")
        for path, digest in expected.items():
            require(_blob_hash(_exact_file(root / path), algorithm) == digest,
                    f"release input differs from the candidate commit: {path}")

    # Discovery descriptors may point to committed files outside the normal data directories.
    coverage = root / COVERAGE
    manifest = root / "legal-texts/manifest.json"
    references = []
    if coverage.is_file():
        index = decode(_exact_file(coverage))
        references.extend((index["source_manifest"], index["snapshot"]))
    if manifest.is_file():
        references.extend(descriptor["path"] for descriptor in decode(_exact_file(manifest)).values())
    for reference in references:
        path = local_path(root, reference).relative_to(root)
        if path.parts[0] not in DATA_DIRECTORIES:
            committed_file(root, commit, path.as_posix())


def policy_schema(policy):
    """Bind the staged schema to the same pinned manifest as the validator."""
    root = Path(policy).resolve()
    manifest = decode(_exact_file(root / "evidence/v1/policy.json"))
    files = manifest["files"]
    require(sha256(_canonical(files)).hexdigest() == POLICY_DIGEST, "SCES schema manifest is outside the policy pin")
    schema = _exact_file(root / CONTRACTS_PATH)
    require(sha256(schema).hexdigest() == files[CONTRACTS_PATH] == CONTRACTS_SHA256,
            "SCES schema bytes differ from the policy pin")
    return schema


def collect(catalog, policy, base):
    root = catalog.root.resolve()
    publication_commit = _git(root, "rev-parse", "--verify", "HEAD").decode().strip()
    require(DATA_COMMIT.fullmatch(publication_commit), "expected a full publication candidate commit")
    require(isinstance(base, str) and DATA_COMMIT.fullmatch(base) and base != publication_commit,
            "use a full trusted predecessor SHA distinct from the candidate commit")
    _git(root, "merge-base", "--is-ancestor", base, publication_commit)
    verify_candidate_data(root, publication_commit)
    report, claims = validate(catalog, base=base, policy=policy)
    require(report, "no active SCES-qualified release to stage")

    selection_bytes = committed_file(root, publication_commit, SELECTION_PATH)
    selection = decode(selection_bytes)
    stem = f"sces/releases/{report['release']}"
    report_bytes = committed_file(root, publication_commit, f"{stem}/qualification.json")
    claims_bytes = committed_file(root, publication_commit, f"{stem}/claims.json")
    require(decode(report_bytes) == report and decode(claims_bytes) == claims,
            "committed release artifacts differ from the checked release")
    require(selection["release"] == report["release"]
            and selection["source_commit"] == report["source_commit"]
            and sha256(selection_bytes).hexdigest() == report["selection_sha256"]
            and report["policy_sha256"] == POLICY_DIGEST
            and report["artifacts"] == [{"path": f"{stem}/claims.json", "sha256": sha256(claims_bytes).hexdigest()}],
            "release selection, payload, and qualification report do not match")
    require(_git(root, "rev-parse", "--verify", "HEAD").decode().strip() == publication_commit,
            "the candidate commit changed during release validation")
    verify_candidate_data(root, publication_commit)

    assets = {
        "claims.json": claims_bytes,
        "qualification.json": report_bytes,
        CONTRACTS_ASSET: policy_schema(policy),
    }
    assets[CHECKSUMS] = checksum_listing(assets)
    metadata = {key: report[key] for key in REPORT_FIELDS}
    metadata.update({
        "status": REQUEST_STATUS,
        "publication_candidate_commit": publication_commit,
        "history_base_commit": base,
        "policy_commit": POLICY_COMMIT,
        "assets": [{"path": name, "bytes": len(content), "sha256": sha256(content).hexdigest()}
                   for name, content in sorted(assets.items())],
    })
    return assets, metadata


def stage(catalog, policy, output, base):
    target = Path(output)
    require(valid_archive_name(target.name), "release staging requires a GitHub-safe ZIP filename")
    root = catalog.root.resolve()
    output_parent = target.parent.resolve()
    require(not any(output_parent.is_relative_to(root / section) for section in DATA_DIRECTORIES),
            "release archive must be staged outside the validated input directories")
    assets, metadata = collect(catalog, policy, base)
    archive = BytesIO()
    with ZipFile(archive, "w") as bundle:
        for name, content in sorted(assets.items()):
            archive_entry(bundle, name, content)
    content = archive.getvalue()
    require(valid_archive_size(len(content)), "release ZIP exceeds the GitHub attachment size limit")
    write_license(target, content)
    return {**metadata, "archive": {"name": target.name, "bytes": len(content), "sha256": sha256(content).hexdigest()}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new candidate ZIP path")
    parser.add_argument("--policy", required=True, type=Path, help="checkout or archive of the pinned SCES policy")
    parser.add_argument("--base", required=True, help="full SHA of a trusted prior commit")
    parser.add_argument("--root", default=ROOT, type=Path, help="License Index Git checkout")
    args = parser.parse_args(argv)
    try:
        result = stage(Catalog(args.root), args.policy, args.output, args.base)
    except (DataError, InstallError, OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"stage release: {error}\n")
    sys.stdout.buffer.write(encode(result))


if __name__ == "__main__":
    main()
