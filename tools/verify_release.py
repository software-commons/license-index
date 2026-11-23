"""Verify exact local or public release bytes against an independently retained request."""

from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import re
import sys
from zipfile import BadZipFile, ZIP_STORED, ZipFile

from .qualification import DATASET, POLICY_COMMIT, POLICY_DIGEST, REPOSITORY, SCHEMA_VERSION
from .records import DATA_COMMIT, HEX_256, DataError, decode, encode, require
from .release_download import fetch_public_archive
from .review_snapshot import GitHub
from .stage_release import (
    CHECKSUMS, RELEASE_ASSETS, REPORT_FIELDS, REQUEST_STATUS, checksum_listing, valid_archive_name, valid_archive_size,
)

REQUEST_FIELDS = {*REPORT_FIELDS, "archive", "assets", "status", "history_base_commit",
                  "publication_candidate_commit", "policy_commit"}
RELEASE_SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
GATES = {"A": "structural-pass", "B": "admissibility-pass", "C": "recorded-review-pass",
         "D": "recorded-scientific-controls-pass", "E": "artifact-integrity-pass"}


def match(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def descriptor(value, name_field):
    require(isinstance(value, dict) and value.keys() == {name_field, "bytes", "sha256"}
            and isinstance(value[name_field], str) and type(value["bytes"]) is int and value["bytes"] > 0
            and match(HEX_256, value["sha256"]), f"invalid release descriptor with field {name_field}")
    return value


def load_request(raw, expected_digest):
    require(match(HEX_256, expected_digest) and sha256(raw).hexdigest() == expected_digest,
            "staged request does not match the independently recorded SHA-256")
    request = decode(raw)
    require(isinstance(request, dict) and request.keys() == REQUEST_FIELDS
            and request["status"] == REQUEST_STATUS and request["repository"] == REPOSITORY
            and request["dataset"] == DATASET and request["schema_version"] == SCHEMA_VERSION
            and request["policy_commit"] == POLICY_COMMIT and request["policy_sha256"] == POLICY_DIGEST
            and match(RELEASE_SLUG, request["release"]) and match(HEX_256, request["selection_sha256"])
            and isinstance(request["dataset_version"], str) and request["dataset_version"].strip()
            and all(match(DATA_COMMIT, request[key]) for key in
                    ("publication_candidate_commit", "source_commit", "history_base_commit"))
            and request["history_base_commit"] != request["publication_candidate_commit"],
            "invalid staging request identity or policy pin")
    archive = descriptor(request["archive"], "name")
    require(valid_archive_name(archive["name"]), "staged archive must have a GitHub-safe ZIP filename")
    require(valid_archive_size(archive["bytes"]), "staged archive exceeds the GitHub attachment size limit")
    require(isinstance(request["assets"], list) and len(request["assets"]) == len(RELEASE_ASSETS),
            "unexpected staged release asset list")
    assets = {item["path"]: item for item in (descriptor(row, "path") for row in request["assets"])}
    require(assets.keys() == RELEASE_ASSETS, "staged asset names are missing, duplicated or unexpected")
    return request, assets


def checked_bytes(content, expected, label):
    require(len(content) == expected["bytes"] and sha256(content).hexdigest() == expected["sha256"],
            f"release size or SHA-256 mismatch: {label}")
    return content


def verify_report(request, assets):
    report = decode(assets["qualification.json"])
    require(isinstance(report, dict) and all(report.get(key) == request[key] for key in REPORT_FIELDS)
            and report.get("policy") == "SCES-1.0" and report.get("synthetic") is False
            and report.get("review_kind") == "separate-codex-executions"
            and report.get("outcome") == "structure-and-recorded-review-qualified"
            and report.get("gates") == GATES, "qualification report differs from the staged release or policy result")
    path = f"sces/releases/{request['release']}/claims.json"
    require(report.get("artifacts") == [{"path": path, "sha256": sha256(assets["claims.json"]).hexdigest()}],
            "qualification report does not bind the staged claim payload")
    claims = decode(assets["claims.json"])
    coverage = report.get("coverage")
    require(isinstance(claims, list) and claims and isinstance(coverage, dict)
            and type(coverage.get("selected")) is int and coverage["selected"] == len(claims),
            "qualification coverage does not match the staged claim payload")
    selected = [{key: row["claim"][key] for key in ("kind", "id", "revision")} for row in claims]
    require(report.get("claims") == selected, "qualification selection differs from the staged claim revisions")
    return report


def verify_archive(content, request, descriptors):
    archive = request["archive"]
    checked_bytes(content, archive, archive["name"])
    with ZipFile(BytesIO(content)) as bundle:
        entries = bundle.infolist()
        require(len(entries) == len(descriptors) and {item.filename for item in entries} == descriptors.keys(),
                "release ZIP members are missing, duplicated or unexpected")
        assets = {}
        for item in entries:
            name = item.filename
            expected = descriptors[name]
            require(not item.is_dir() and item.compress_type == ZIP_STORED and item.file_size == expected["bytes"],
                    f"unexpected ZIP representation or length: {name}")
            assets[name] = checked_bytes(bundle.read(item), expected, name)
    require(assets[CHECKSUMS] == checksum_listing(assets), "SHA256SUMS differs from the verified archive members")
    return verify_report(request, assets)


def verify(raw_request, request_digest, *, archive_path=None, tag=None, notes_digest=None):
    request, assets = load_request(raw_request, request_digest)
    require((archive_path is None) != (tag is None), "select either a local ZIP or a published tag")
    archive = request["archive"]
    public = None
    if archive_path is None:
        require(match(HEX_256, notes_digest), "supply the independently recorded release title and body SHA-256")
        content, public = fetch_public_archive(GitHub(), tag, request["publication_candidate_commit"],
                                               archive, notes_sha256=notes_digest)
    else:
        require(notes_digest is None and archive_path.is_file(), "supply a local regular ZIP file")
        require(archive_path.stat().st_size == archive["bytes"],
                f"release size or SHA-256 mismatch: {archive['name']}")
        with archive_path.open("rb") as saved:
            content = saved.read(archive["bytes"] + 1)
    report = verify_archive(content, request, assets)
    result = {
        "status": "public-release-integrity-verified" if public else "local-archive-integrity-verified",
        "repository": request["repository"],
        "release": request["release"],
        "dataset_version": request["dataset_version"],
        "publication_commit": request["publication_candidate_commit"],
        "source_commit": request["source_commit"],
        "request_sha256": request_digest,
        "archive": archive,
        "assets": request["assets"],
        "selected_claims": report["coverage"]["selected"],
    }
    if public:
        result["public_release"] = public
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="exact JSON emitted by stage_release")
    parser.add_argument("--request-sha256", required=True, help="SHA-256 of the request from the separate decision")
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--zip", type=Path, help="local candidate archive for an offline integrity check")
    targets.add_argument("--tag", help="versioned tag from the separate publication decision")
    parser.add_argument("--notes-sha256", help="approved SHA-256 of the JSON release name and body for --tag")
    args = parser.parse_args(argv)
    try:
        result = verify(args.request.read_bytes(), args.request_sha256, archive_path=args.zip, tag=args.tag,
                        notes_digest=args.notes_sha256)
    except (DataError, OSError, ValueError, TypeError, KeyError, BadZipFile, RuntimeError) as error:
        parser.exit(1, f"verify release: {error}\n")
    sys.stdout.buffer.write(encode(result))


if __name__ == "__main__":
    main()
