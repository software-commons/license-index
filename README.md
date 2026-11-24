# Software Commons License Index

Find software licenses and exceptions by identifier or name, retrieve exact pinned text, install selected license documents, and inspect the sources behind plain-language explanations.

The development catalog accounts for all 740 licenses and 86 exceptions listed in pinned SPDX 3.29.0. Canonical admissions and publication require SCES qualification. Current profiles and comparisons are provisional educational research.

## Install and use

Use Python 3.11 or newer. Clone the repository at the revision you want or unpack the offline ZIP. Invoke `license-index.cmd` on Windows or `./license-index` on Linux and macOS. Adding the extracted folder to PATH makes the launcher available from another project. If an archive extractor removes executable permissions on Unix, run `chmod +x license-index`. The same interface is available from the repository root via `python -m tools.index`.

```powershell
.\license-index.cmd search Apache
.\license-index.cmd show GPL-2.0+
.\license-index.cmd text Apache-2.0
.\license-index.cmd add Apache-2.0 --output "D:\Projects\Example\LICENSE" --dry-run
.\license-index.cmd add MIT --artifact-root "D:\Inputs\license-list-data-31ba1a50" --holder "Example Software Inc." --year 2026
.\license-index.cmd explain GPL-3.0-only
.\license-index.cmd compare MIT Apache-2.0
.\license-index.cmd expression "GPL-2.0-only WITH Classpath-exception-2.0"
.\license-index.cmd sources MIT --json
.\license-index.cmd coverage --json
```

MIT requires a verified pinned SPDX text input and explicit holder and year when writing. Supply the extracted archive directory with `--artifact-root`, or use `--fetch` to retrieve the exact pinned file. Bundled texts work offline. Select `--force` to replace an existing regular target intentionally. On Linux and macOS, a successful replacement preserves the previous file at the reported path.

See [CLI and offline data](docs/CLI.md), [scope and identity](docs/SCOPE.md), [maintenance](docs/MAINTENANCE.md), [source assessment](research/sources/predecessor-assessment.md), [research status](docs/RESEARCH_STATUS.md), and [publication controls](docs/PUBLICATION.md). The repository adopts [SCES-1.0](https://github.com/software-commons/.github/blob/ab26f278422772f2d9e5d4dd016407d14372a710/docs/standards/EVIDENCE_STANDARD.md) and [SCIRS-1.0](https://github.com/software-commons/.github/blob/f23ffb93c5ad8d6b96d8652186ba20befee3bca8/docs/standards/INDEX_REPOSITORY_STANDARD.md).
