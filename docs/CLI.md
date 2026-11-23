# CLI and offline data

Use the launcher from the project where you want to create a license file. Use `--output` with an explicit filename when invoking it from another directory. `text` writes source bytes to stdout. `add --dry-run` writes the preview to stdout. `--json` returns structured UTF-8 to stdout, including the representation, source and output checksums for text operations. CLI errors return exit code 1. Argument errors return 2. Successful calls return 0.

| Command | Result |
| --- | --- |
| `list`, `search QUERY` | List or search names and IDs. Use `--kind license`, `--kind exception`, `--kind other` or `--history` to focus lookup. |
| `show ID` | Machine-readable discovery record, upstream status, artifact locators and coverage information. |
| `text ID` | Exact pinned bytes from the publisher package, or from a checksum-verified SPDX artifact. |
| `add ID` | Write only the selected LICENSE file, using an explicitly supported installation recipe. |
| `explain ID` | Brief, detailed and scenario-level provisional research with sources, where available. |
| `compare ID ID ...` | Compare cited dimensions, including unresolved fields. |
| `sources ID` | Upstream location, byte fingerprints, archived discovery origins and explanation citations. |
| `coverage` | Report catalog, text, installation and research counts. Supply `--policy PATH` to include validated active publication counts. |
| `review-plan [ID ...]` | List provisional facets, source leads and draft fingerprints for [claim-by-claim review](PROFILE_QUALIFICATION.md). Add `--admission` to plan source and identity review for catalog candidates, including entries without a profile. |
| `expression EXPRESSION` | Parse SPDX 3.0.1 syntax and show unresolved document-local references. |
| `--version` | Print the software version. |

The text command prefers a bundled publisher file when available. Other SPDX-listed texts can be read from a local copy of the pinned upstream data via `--artifact-root PATH`. `--fetch` makes a single explicit request for the cataloged SPDX artifact and verifies its length and SHA-256 before emitting it. The catalog preserves identifiers for both active and deprecated entries. A deprecated identifier may have SPDX replacement advice in `show` and `sources`. Matching templates have their own artifact references. A generated text file may contain upstream matching markers, as observed for the I2P GPL Java exception, so use its representation label and provenance when deciding how to apply it.

`text PolyForm-Noncommercial-1.0.0` and `text PolyForm-Small-Business-1.0.0` return the publisher's exact source Markdown with its original line wrapping. The six Creative Commons 4.0 International texts use the publisher's English plain-text representation. Inspect `text --json` for the representation, source and digest.

The installation command supports exact copies of Apache-2.0, EPL-2.0, AGPL-3.0-only, GPL-2.0-only and GPL-3.0-only. Use the separate publisher guidance to declare the applicable terms and add any required notices or headers. EPL 2.0’s Secondary License option has the separate conditions in §3.2 and Exhibit A. The AGPL and GPL later-version identifiers also have offline text. The application notice states which version election applies.

MIT's recipe accepts a single-line Unicode holder and an explicit four-digit year. It replaces only the designated notice line in the hash-verified source. A preview without MIT fields shows that line with placeholders. The CLI rejects incomplete pairs and rejects copyright fields for unchanged-copy recipes.

Only a single current license identifier can select an install recipe. With a compound expression or a standalone exception, inspect the source and determine the applicable documents first. Expression output describes syntax and referenced identities. The meaning of `WITH` depends on the identified exception and the relevant base instrument.

The output parent directory must exist. Linked paths, device names, traversal components and nonregular targets are rejected. The existing target can be previewed without modifying it. Without `--force`, publication is atomic and no-clobber. On POSIX, this requires hard-link support in the selected directory. Windows checks for reparse points and validates the parent again before the final rename. Use a directory you control for license installation.

Profiles and comparisons distinguish permissions, conditions, restrictions, sourced descriptions and questions with unresolved treatment. Patent silence, a blank approval field, and a missing explanation carry no affirmative legal finding. The guides provide educational context. Professional legal advice may be needed for applicability to a project or jurisdiction.
