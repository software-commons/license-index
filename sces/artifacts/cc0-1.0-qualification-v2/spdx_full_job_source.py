"""Acquire the entire fixed SPDX job response and derive a separate exact passage index."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import re
import shutil
import subprocess
import sys
from uuid import uuid4

here = Path(__file__).resolve().parent
trusted_pin = "7db4c2783e5c3bd0af5bf239c2d22380fd45ebd9"
endpoint = "repos/spdx/license-list-XML/actions/jobs/104892289184/logs"
locator = f"https://api.github.com/{endpoint}"
name = "spdx_release_job"
byte_count = 81691
body_digest = "1e9137b29385a9ce0deaa48c20ab9927916426819a69f0cfc6281d239340c282"
xml_commit = b"b1dbeb5c8bca21af860a90e187f71d60b84a7a40"


def acquire_job():
    gh = shutil.which("gh")
    if not gh:
        raise ValueError("GitHub CLI is required for the published job logs endpoint")
    response = subprocess.run(
        (gh, "api", "--hostname", "github.com", "--allow-escape-sequences", endpoint),
        capture_output=True, timeout=45, check=True,
    )
    body = response.stdout
    if len(body) != byte_count or sha256(body).hexdigest() != body_digest:
        raise ValueError("The complete authenticated workflow response differs from its pin")
    body.decode("utf-8")
    return body


def ordered_ranges(body):
    if len(body) != byte_count or sha256(body).hexdigest() != body_digest:
        raise ValueError("Passage derivation requires the exact complete source")
    rows = body.splitlines(keepends=True)
    selectors = (
        rb"\[command\]/usr/bin/git .* fetch .* \+" + xml_commit + rb":refs/tags/v3\.29\.0$",
        rb"\[command\]/usr/bin/git checkout --progress --force refs/tags/v3\.29\.0$",
        rb"\[command\]/usr/bin/git log -1 --format=%H$",
        rb"\[main 31ba1a5\] License list build 3\.29\.0 using license list publisher 3\.1\.4$",
        rb"3027e0c\.\.31ba1a5  main -> main$",
    )
    indices = []
    for pattern in selectors:
        index, = [i for i, row in enumerate(rows) if re.search(pattern, row.rstrip(b"\r\n"))]
        indices.append(index)
    checkout_result = indices[2] + 1
    if not rows[checkout_result].rstrip(b"\r\n").endswith(b" " + xml_commit):
        raise ValueError("The checkout log does not show the expected full XML revision")
    indices.insert(3, checkout_result)
    if indices != sorted(set(indices)):
        raise ValueError("Workflow source and publication lines are out of order")
    offsets = [0]
    for row in rows:
        offsets.append(offsets[-1] + len(row))
    return [(offsets[i], offsets[i + 1]) for i in indices]


def run_mcp(trusted, arguments):
    checked = subprocess.check_output(("git", "-C", str(trusted), "rev-parse", "HEAD"), text=True).strip()
    if checked != trusted_pin or subprocess.check_output(("git", "-C", str(trusted), "status", "--porcelain")):
        raise ValueError("Original fixed public source connector differs from its trusted revision")
    sys.path.insert(0, str(trusted))
    from tools import public_source_mcp as mcp

    standard_spec = mcp.source_spec
    standard_acquire = mcp.acquire

    def source_spec(row):
        if row.get("url") != locator:
            return standard_spec(row)
        expected = {"url":locator, "mode":"full-utf8", "expected_bytes":byte_count,
                    "expected_sha256":body_digest, "ranges":row.get("ranges")}
        if row != expected:
            raise ValueError("The original workflow source must use the fixed full-body proof")
        spans = tuple(tuple(span) for span in row["ranges"])
        mcp.check_ranges(spans, byte_count)
        return mcp.Source(locator, "full-utf8", byte_count, spans, byte_count, body_digest)

    def acquire(alias, source):
        if alias != name:
            return standard_acquire(alias, source)
        try:
            body = acquire_job()
        except (subprocess.SubprocessError, ValueError, OSError) as error:
            raise ValueError("The complete fixed job response could not be acquired") from error
        if tuple(ordered_ranges(body)) != source.ranges:
            raise ValueError("Published log passages differ from the exact full-body derivation")
        return {"source":alias, "url":locator, "http_status":200,
                "retrieved_at":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "acquisition_id":uuid4().hex, **mcp.fingerprints(body, source.ranges),
                "body_encoding":"utf-8", "source_text":body.decode("utf-8")}

    mcp.source_spec = source_spec
    mcp.acquire = acquire
    return mcp.main(arguments)


def main(arguments):
    if arguments == ["--capture"]:
        sys.stdout.buffer.write(acquire_job())
        return 0
    if len(arguments) < 2 or arguments[0] != "--trusted":
        raise SystemExit("Use --capture or supply the exact trusted transport checkout")
    return run_mcp(Path(arguments[1]).resolve(), arguments[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
