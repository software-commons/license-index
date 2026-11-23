"""Reproduce the public MIT representation and narrow notice transformation locally."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
REPO = HERE.parent / "license-index"
ARCHIVE = HERE.parent / "spdx-3.29.0.tar.gz"
DATA = "31ba1a50e5397e00a304dbadc76531740e89ee48"
ROW = REPO / "registry/candidates/63/63d7de23bf5d4c13b52375f9428a82f0.json"
RENDERER_SHA = "00da9a90ea0b9f035d9cf2c08600efe8c0f0b97aa11dddf8a3ee09686938a39e"
INPUT_NOTICE = b"Copyright (c) <year> <copyright holders>"
FIXTURE_HOLDER = "Example Project"
FIXTURE_YEAR = "2026"


def digest(data):
    return sha256(data).hexdigest()


def cli(*args):
    return subprocess.run([sys.executable, "-B", "-m", "tools.index", *map(str, args)],
                          cwd=REPO, capture_output=True, timeout=45)


def member(archive, item):
    entry = archive.getmember(f"license-list-data-{DATA}/{item['path']}")
    assert entry.isfile() and entry.size == item["bytes"] <= 65536
    extracted = archive.extractfile(entry)
    assert extracted is not None
    with extracted:
        raw = extracted.read()
    assert len(raw) == item["bytes"] and digest(raw) == item["sha256"]
    return raw


def exact_inputs():
    origin = json.loads(ROW.read_bytes())["origin"]
    assert (origin["identifier"], origin["release"], origin["source"]) == ("MIT", "3.29.0", DATA)
    manifest = json.loads((REPO / "research/sources/spdx-3.29.0.json").read_bytes())["archive"]
    assert (ARCHIVE.stat().st_size, digest(ARCHIVE.read_bytes())) == (manifest["bytes"], manifest["sha256"])
    with tarfile.open(ARCHIVE, mode="r:gz") as pinned:
        raw = member(pinned, origin["artifacts"]["text"])
        detail = member(pinned, origin["artifacts"]["detail"])
    license_text = json.loads(detail)["licenseText"].encode()
    assert license_text == raw
    assert raw.count(INPUT_NOTICE) == 1 and len(raw) == 1078
    return raw, detail, manifest


def refusal(result, output):
    assert result.returncode != 0 and not output.exists()


def check_cli(raw, expected):
    with TemporaryDirectory(prefix="mit-render-", dir=HERE) as folder:
        artifact_root = Path(folder).resolve()
        input_file = artifact_root / "text/MIT.txt"
        input_file.parent.mkdir()
        input_file.write_bytes(raw)
        output = artifact_root / "license.txt"
        common = ["add", "MIT", "--artifact-root", artifact_root, "--output", output]
        parameters = ["--holder", FIXTURE_HOLDER, "--year", FIXTURE_YEAR]
        exact = cli("text", "MIT", "--artifact-root", artifact_root)
        assert exact.returncode == 0 and exact.stdout == raw
        preview = cli(*common, "--dry-run")
        assert preview.returncode == 0 and preview.stdout == raw and not output.exists()
        rendered = cli(*common, *parameters, "--dry-run")
        assert rendered.returncode == 0 and rendered.stdout == expected and not output.exists()
        refusal(cli(*common, "--holder", FIXTURE_HOLDER), output)
        refusal(cli(*common, "--holder", FIXTURE_HOLDER, "--year", "0000"), output)
        refusal(cli(*common, "--holder", "Example\nInjected", "--year", FIXTURE_YEAR), output)
        input_file.write_bytes(raw + b"\n")
        refusal(cli(*common, *parameters), output)
        input_file.write_bytes(raw)
        written = cli(*common, *parameters)
        assert written.returncode == 0 and output.read_bytes() == expected
        assert cli(*common, *parameters).returncode != 0 and output.read_bytes() == expected


def check_renderer(raw, expected):
    renderer = REPO / "tools/li_install.py"
    assert digest(renderer.read_bytes()) == RENDERER_SHA
    sys.path.insert(0, str(REPO))
    from tools.li_install import InstallError, render

    assert render(raw, "mit-notice", holder=FIXTURE_HOLDER, year=FIXTURE_YEAR) == expected
    for synthetic in (expected, raw + b"\n" + INPUT_NOTICE + b"\n"):
        try:
            render(synthetic, "mit-notice", holder=FIXTURE_HOLDER, year=FIXTURE_YEAR)
        except InstallError:
            continue
        raise AssertionError("Renderer accepted zero or duplicate notice placeholders")


def main():
    original, detail, manifest = exact_inputs()
    start = original.index(INPUT_NOTICE)
    end = start + len(INPUT_NOTICE)
    assert (start, end) == (13, 53) and original[end:end + 1] == b"\n"
    replacement = f"Copyright (c) {FIXTURE_YEAR} {FIXTURE_HOLDER}".encode()
    expected = original[:start] + replacement + original[end:]
    check_cli(original, expected)
    check_renderer(original, expected)
    measurement = {
        "spdx_data_commit": DATA, "archive_sha256": manifest["sha256"],
        "text_sha256": digest(original), "text_bytes": len(original),
        "detail_sha256": digest(detail), "detail_text_bytes_equal": True,
        "renderer_sha256": RENDERER_SHA, "notice_range": [start, end],
        "fixture_holder": FIXTURE_HOLDER, "fixture_year": FIXTURE_YEAR,
        "output_bytes": len(expected), "output_sha256": digest(expected),
        "cli_checks": ["byte-exact text", "unfilled preview", "filled preview", "partial pair refusal",
                       "invalid year refusal", "multiline holder refusal", "digest refusal", "exact write", "no clobber"],
        "render_checks": ["exact output", "zero placeholder refusal", "duplicate placeholder refusal"],
    }
    print(json.dumps(measurement, sort_keys=True))


if __name__ == "__main__":
    main()
