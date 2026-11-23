"""Capture an explicit source response and check its exact bytes offline."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPException
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from .li_install import InstallError, write_license
from .qualification import _exact_file
from .records import ROOT, DataError, HEX_256, NoRedirects, decode, encode, require


MAX_BYTES = 64 * 1024 * 1024
OBSERVATION = "source-byte-observation"


def validate_url(url):
    require(not any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in url)
            and "?" not in url and "#" not in url,
            "source URL must omit whitespace, control characters, query strings, and fragments")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise DataError("invalid HTTPS source URL") from error
    require(parsed.scheme == "https" and parsed.hostname and (port is None or port > 0)
            and parsed.username is None and parsed.password is None,
            "source URL must be an explicit HTTPS URL without credentials")


def validate_digest(value):
    require(isinstance(value, str) and HEX_256.fullmatch(value), "expected a lowercase SHA-256 digest")


def validate_count(value):
    require(type(value) is int and value > 0, "expected a positive byte count")


def check_ranges(ranges, size):
    for start, end in ranges:
        require(type(start) is int and type(end) is int and 0 <= start < end <= size,
                "source range must be nonempty and within the bytes")


def download(url, limit):
    request = Request(url, headers={"Accept-Encoding": "identity",
                                    "User-Agent": "software-commons-license-index"})
    try:
        with build_opener(NoRedirects()).open(request, timeout=30) as response:
            require(response.status == 200 and response.geturl() == url
                    and response.headers.get("Content-Range") is None, "expected one complete source response")
            encodings = response.headers.get_all("Content-Encoding", [])
            require(not encodings or [value.strip().lower() for value in encodings] == ["identity"],
                    "source response has unsupported content encoding")
            lengths = response.headers.get_all("Content-Length", [])
            transfer = response.headers.get_all("Transfer-Encoding", [])
            require(not transfer or (not lengths and [value.strip().lower() for value in transfer] == ["chunked"]),
                    "source response has unsupported or conflicting transfer framing")
            require(len(lengths) <= 1 and all(re.fullmatch(r"[0-9]+", value.strip()) for value in lengths),
                    "source response has invalid Content-Length")
            declared = int(lengths[0]) if lengths else None
            require(declared is None or declared <= limit, "source response exceeds the byte limit")
            content = response.read(limit + 1)
            require(0 < len(content) <= limit, "source response is empty or exceeds the byte limit")
            require(declared is None or declared == len(content), "source response size differs from Content-Length")
            media_type = response.headers.get_content_type() if "Content-Type" in response.headers else None
    except HTTPError as error:
        error.close()
        raise DataError(f"source returned HTTP {error.code}") from error
    except (HTTPException, OSError) as error:
        raise DataError("could not retrieve a complete HTTPS source response") from error
    return content, media_type


def fingerprints(content, ranges):
    check_ranges(ranges, len(content))
    return {
        "bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "ranges": [{"start": start, "end": end, "sha256": sha256(content[start:end]).hexdigest()}
                   for start, end in ranges],
    }


def capture(url, destination, *, max_bytes=MAX_BYTES, expected_digest=None, expected_size=None, ranges=()):
    validate_url(url)
    destination = Path(destination)
    require(not destination.resolve().is_relative_to(ROOT),
            "capture destination must be in working storage outside the tool checkout")
    validate_count(max_bytes)
    if expected_size is not None:
        validate_count(expected_size)
        require(expected_size <= max_bytes, "expected size exceeds the byte limit")
    if expected_digest is not None:
        validate_digest(expected_digest)
    limit = expected_size if expected_size is not None else max_bytes
    ranges = tuple(ranges)
    check_ranges(ranges, limit)
    content, media_type = download(url, limit)
    retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    observed = fingerprints(content, ranges)
    require(expected_size is None or expected_size == observed["bytes"], "source byte count differs from the pin")
    require(expected_digest is None or expected_digest == observed["sha256"], "source SHA-256 differs from the pin")
    write_license(destination, content)
    return {
        "status": OBSERVATION,
        "version": 1,
        "url": url,
        "http_status": 200,
        "media_type": media_type,
        "retrieved_at": retrieved_at,
        "expected_bytes": expected_size,
        "expected_sha256": expected_digest,
        **observed,
    }


def verify(artifact, observation, expected_observation=None):
    raw = _exact_file(Path(os.path.abspath(observation)))
    observation_digest = sha256(raw).hexdigest()
    if expected_observation is not None:
        validate_digest(expected_observation)
        require(observation_digest == expected_observation, "observation SHA-256 differs from the independent pin")
    try:
        report = decode(raw)
    except (DataError, ValueError, RecursionError) as error:
        raise DataError("observation contains invalid JSON") from error
    require(isinstance(report, dict) and report.get("status") == OBSERVATION
            and type(report.get("version")) is int and report["version"] == 1, "unsupported source observation")
    validate_count(report["bytes"])
    validate_digest(report["sha256"])
    if report.get("expected_bytes") is not None:
        validate_count(report["expected_bytes"])
        require(report["expected_bytes"] == report["bytes"], "observation byte count conflicts with its pin")
    if report.get("expected_sha256") is not None:
        validate_digest(report["expected_sha256"])
        require(report["expected_sha256"] == report["sha256"], "observation SHA-256 conflicts with its pin")
    ranges = report["ranges"]
    require(isinstance(ranges, list) and all(isinstance(item, dict)
            and item.keys() == {"start", "end", "sha256"} for item in ranges), "invalid observation ranges")
    bounds = [(item["start"], item["end"]) for item in ranges]
    check_ranges(bounds, report["bytes"])
    content = _exact_file(Path(os.path.abspath(artifact)))
    require(len(content) == report["bytes"], "source bytes differ from the observation")
    observed = fingerprints(content, bounds)
    require(observed["sha256"] == report["sha256"], "source bytes differ from the observation")
    require(observed["ranges"] == ranges, "source range SHA-256 differs from the observation")
    return {"status": "source-bytes-match-observation", "observation_sha256": observation_digest,
            "observation_pin_checked": expected_observation is not None,
            "bytes": report["bytes"], "sha256": report["sha256"], "ranges": ranges}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("capture", help="retrieve exact bytes from one explicit HTTPS source")
    fetch.add_argument("url", help="final public HTTPS source URL")
    fetch.add_argument("artifact", type=Path, help="new file for the response body")
    fetch.add_argument("--max-bytes", type=int, default=MAX_BYTES, help="download byte limit (default: 64 MiB)")
    fetch.add_argument("--expect-bytes", type=int, help="independently pinned source length")
    fetch.add_argument("--expect-sha256", help="independently pinned source SHA-256")
    fetch.add_argument("--range", action="append", nargs=2, type=int, default=[],
                       metavar=("START", "END"), help="zero-based half-open citation range")
    check = commands.add_parser("verify", help="check an exact source artifact and observation offline")
    check.add_argument("artifact", type=Path, help="retained source bytes")
    check.add_argument("observation", type=Path, help="exact JSON output from capture")
    check.add_argument("--observation-sha256", help="independently retained observation SHA-256")
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            report = capture(args.url, args.artifact, max_bytes=args.max_bytes, expected_size=args.expect_bytes,
                             expected_digest=args.expect_sha256, ranges=args.range)
        else:
            report = verify(args.artifact, args.observation, args.observation_sha256)
    except (DataError, InstallError) as error:
        parser.exit(1, f"capture source: {error}\n")
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        parser.exit(1, "capture source: invalid input or unreadable source data\n")
    sys.stdout.buffer.write(encode(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
