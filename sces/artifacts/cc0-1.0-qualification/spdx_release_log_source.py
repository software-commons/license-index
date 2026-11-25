"""Reacquire the fixed public SPDX release job and return only its three cited lines."""
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

here = Path(__file__).resolve().parent
trusted = here.parent / "trusted-qualification-connector"
gh = Path("C:/Program Files/GitHub CLI/gh.exe")
git_url = "https://github.com/spdx/license-list-XML/actions/runs/35125161397/job/104892289184"
alias = "spdx_release_job"
patterns = (
    rb"\[command\]/usr/bin/git .* fetch .* \+b1dbeb5c8bca21af860a90e187f71d60b84a7a40:refs/tags/v3\.29\.0$",
    rb"\[main 31ba1a5\] License list build 3\.29\.0 using license list publisher 3\.1\.4$",
    rb"3027e0c\.\.31ba1a5  main -> main$",
)


def capture():
    result = subprocess.run(
        (str(gh), "run", "view", "35125161397", "--repo", "spdx/license-list-XML",
         "--job", "104892289184", "--log"),
        capture_output=True, timeout=45, check=True,
    )
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("Public job exceeds the capture bound")
    lines = result.stdout.splitlines()
    selected = []
    for pattern in patterns:
        match, = [(number, line) for number, line in enumerate(lines) if re.search(pattern, line)]
        selected.append(match)
    if sorted(number for number, _ in selected) != [number for number, _ in selected]:
        raise ValueError("Build input and publication lines are out of order")
    return b"".join(line + b"\n" for _, line in selected)


def main():
    if sys.argv[1:] == ["--capture"]:
        sys.stdout.buffer.write(capture())
        return 0
    pin = "7db4c2783e5c3bd0af5bf239c2d22380fd45ebd9"
    if subprocess.check_output(("git", "-C", str(trusted), "rev-parse", "HEAD"), text=True).strip() != pin:
        raise ValueError("Fixed public source transport departed from its trusted revision")
    if subprocess.check_output(("git", "-C", str(trusted), "status", "--porcelain")):
        raise ValueError("Fixed public source transport is dirty")
    sys.path.insert(0, str(trusted))
    from tools import public_source_mcp as mcp

    standard = mcp.acquire

    def acquire(name, source):
        if name != alias:
            return standard(name, source)
        try:
            body = capture()
        except (subprocess.SubprocessError, ValueError, OSError) as error:
            raise ValueError("Fixed SPDX release job could not be acquired") from error
        observed = mcp.fingerprints(body, source.ranges)
        if (source.url != git_url or source.mode != "full-utf8" or observed["bytes"] != source.expected_bytes
                or observed["sha256"] != source.expected_sha256):
            raise ValueError("Public job excerpt differs from its fixed identity")
        return {"source":name,"url":source.url,"http_status":200,
                "retrieved_at":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "acquisition_id":uuid4().hex,**observed,"body_encoding":"utf-8","source_text":body.decode("utf-8")}

    mcp.acquire = acquire
    return mcp.main()


if __name__ == "__main__":
    sys.exit(main())
