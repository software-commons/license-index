"""Verify exact local or public release bytes against an independently retained request."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import re
import sys
from zipfile import BadZipFile, ZIP_STORED, ZipFile

from .qualification import DATASET, POLICY_COMMIT, POLICY_DIGEST, REPOSITORY, SCHEMA_VERSION
from .records import DATA_COMMIT, HEX_256, DataError, decode, encode, require
from .release_download import _valid_tag, fetch_public_archive
from .review_snapshot import GitHub
from .stage_release import (
    CHECKSUMS, CONTRACTS_ASSET, CONTRACTS_SHA256, RELEASE_ASSETS, REPORT_FIELDS, REQUEST_STATUS,
    checksum_listing, valid_archive_name, valid_archive_size,
)

REQUEST_FIELDS = {*REPORT_FIELDS, "archive", "assets", "status", "history_base_commit",
                  "publication_candidate_commit", "policy_commit"}
AUTHORIZATION_FIELDS = {"version", "decision", "repository", "principal", "approved_at", "request_sha256",
                        "publication_commit", "tag", "notes", "data_license", "scope"}
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
    require(assets[CONTRACTS_ASSET]["sha256"] == CONTRACTS_SHA256, "staged SCES schema differs from the policy pin")
    return request, assets


def checked_bytes(content, expected, label):
    require(len(content) == expected["bytes"] and sha256(content).hexdigest() == expected["sha256"],
            f"release size or SHA-256 mismatch: {label}")
    return content


def load_authorization(raw, expected_digest):
    require(isinstance(raw, bytes) and match(HEX_256, expected_digest)
            and sha256(raw).hexdigest() == expected_digest,
            "authorization does not match the digest from the authenticated owner decision")
    decision = decode(raw)
    require(isinstance(decision, dict) and decision.keys() == AUTHORIZATION_FIELDS
            and type(decision["version"]) is int and decision["version"] == 1
            and decision["decision"] == "authorize-publication" and decision["repository"] == REPOSITORY
            and match(HEX_256, decision["request_sha256"]) and match(DATA_COMMIT, decision["publication_commit"])
            and _valid_tag(decision["tag"]), "invalid owner authorization record")
    for field in ("principal", "approved_at", "data_license", "scope"):
        require(isinstance(decision[field], str) and decision[field].strip(), f"missing authorization {field}")
    try:
        approved = datetime.fromisoformat(decision["approved_at"])
    except ValueError as error:
        raise DataError("invalid authorization timestamp") from error
    require(approved.utcoffset() == timedelta(0), "authorization timestamp must be in UTC")
    notes = decision["notes"]
    require(isinstance(notes, dict) and notes.keys() == {"name", "body"}
            and all(isinstance(value, str) and value.strip() for value in notes.values()),
            "authorization must include the exact release name and body")
    return decision


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


def verify(raw_request, request_digest=None, *, archive_path=None, tag=None, notes_digest=None,
           authorization=None, authorization_digest=None):
    decision = None
    if authorization is not None or authorization_digest is not None:
        decision = load_authorization(authorization, authorization_digest)
        require(request_digest is None or request_digest == decision["request_sha256"],
                "request digest differs from the owner authorization")
        require(tag is None and notes_digest is None, "the owner authorization supplies the tag and exact notes")
        request_digest = decision["request_sha256"]
        if archive_path is None:
            tag = decision["tag"]
            notes_digest = sha256(encode(decision["notes"])).hexdigest()
    request, assets = load_request(raw_request, request_digest)
    if decision is not None:
        require(decision["publication_commit"] == request["publication_candidate_commit"],
                "publication commit differs from the owner authorization")
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
    if decision is not None:
        result["authorization_record"] = {"sha256": authorization_digest, "principal": decision["principal"],
                                          "approved_at": decision["approved_at"], "tag": decision["tag"],
                                          "data_license": decision["data_license"], "scope": decision["scope"]}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="exact JSON emitted by stage_release")
    parser.add_argument("--request-sha256", help="independently recorded request SHA-256 for an integrity-only check")
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument("--zip", type=Path, help="local candidate archive for an offline integrity check")
    targets.add_argument("--tag", help="versioned tag from the separate publication decision")
    parser.add_argument("--notes-sha256", help="approved SHA-256 of the JSON release name and body for --tag")
    parser.add_argument("--authorization", type=Path, help="exact owner authorization record")
    parser.add_argument("--authorization-sha256", help="digest obtained from the authenticated owner decision")
    args = parser.parse_args(argv)
    if (args.authorization is None) != (args.authorization_sha256 is None):
        parser.error("supply --authorization and --authorization-sha256 together")
    if args.authorization is None and (args.request_sha256 is None or (args.zip is None and args.tag is None)):
        parser.error("supply --request-sha256 and either --zip or --tag for an integrity-only check")
    try:
        authorization = args.authorization.read_bytes() if args.authorization is not None else None
        result = verify(args.request.read_bytes(), args.request_sha256, archive_path=args.zip, tag=args.tag,
                        notes_digest=args.notes_sha256, authorization=authorization,
                        authorization_digest=args.authorization_sha256)
    except (DataError, OSError, ValueError, TypeError, KeyError, BadZipFile, RuntimeError) as error:
        parser.exit(1, f"verify release: {error}\n")
    sys.stdout.buffer.write(encode(result))


if __name__ == "__main__":
    main()
