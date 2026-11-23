# Registry maintenance

The sharded candidate and entity files are authoritative registry inputs. `research/sources/` stores exact upstream revision and checksum manifests. `research/campaigns/` stores provisional review material. `registry/coverage/current.json` matches a retained snapshot byte-for-byte. Exact SCES sources, claims and dispositions belong in `sces/records/`. Add permitted source bytes under `sces/artifacts/` and use `legal-texts/` for documented redistributed developer copies.

## Reconcile an SPDX release

1. Run `python -m tools.reconcile discover` at release adoption time to resolve the current stable tag, data commit and source XML commit. Record the archive acquisition digest. Check a publisher checksum if available and explicitly identify any locally measured transport digest.
2. Run `python -m tools.reconcile prepare-latest --output NEW_DIRECTORY` to download and stage the resolved release. Add `--sha256` to verify an independently acquired archive digest. For an existing archive use `python -m tools.reconcile prepare --archive PATH --release X.Y.Z --data-commit FULL_SHA --source-commit FULL_SHA --sha256 ARCHIVE_SHA --output NEW_DIRECTORY`.
3. Inspect the staged plan, including changes to bytes, deprecation or removal, restored entries, source locations, and impacted evidence or entity references. Reopen controlling sources for affected claims and schedule SCES revalidation. Merge only the reviewed candidate deltas through the ordinary pull-request workflow.
4. Update the exact source manifest and new immutable coverage snapshot. Keep earlier snapshots and record histories. An unchanged SPDX entry retains its original bytes and opaque ID. Separate qualified review controls handle movement from discovered to canonical entities.

Run `python -m tools.index validate --policy PINNED_SCES_CHECKOUT --base FULL_TRUSTED_BASE`, `python -m tools.schema_check`, and `python -m unittest discover -s tests -v`. Schema validation and the pinned policy check use the organizational Python requirements. Normal CLI operations and the development bundle use the Python standard library.

## Export development data

`python -m tools.index export` returns a deterministic JSON discovery view. `python -m tools.index bundle NEW_ZIP_PATH` builds a deterministic, extractable distribution with launchers, the development catalog, packaged texts, and selected research data. ZIP paths, timestamps and modes are fixed, with stored entries to keep the output independent of compression implementations. Canonical input records are read-only during build.

The initial SPDX snapshot is reproducible from the archive at the pinned data commit and the committed UUID allocation files. Replay reconciliation against those allocations to reproduce the no-change state. Fresh first-time allocations are deliberately random and become stable once recorded.

## Preserve provenance

Add publisher and research origins with an exact edition, date or immutable source when available. Record the difference between text bytes and display representations. Use the SCES task brief and immutable source and verification records for new factual claims. Add upheld findings with their exact revision, scope and evidence. Provisional notes remain available for research and correction.
