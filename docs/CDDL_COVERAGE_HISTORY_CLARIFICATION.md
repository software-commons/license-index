# CDDL coverage snapshot and later MIT evidence

The retained `2026-11-25-cddl-native-comparison-method.json` snapshot records 150 claim revisions. Its introduction commit is `4697475acf0ba2465bd554b722977c9f4dc50aac`, whose tree contains 150 files under `sces/records/claim`. Its predecessor `22ad238b8530883566c8ced2433dbc5e2ea422e4` contains 148. The protected merge `d1ee009852e51b4783d047221a27ab91cac97a33` contains 150.

The later commit `633a9c268b35400ad61c57160ff2a1cac4b0b44c` contains 155 claim-revision files. Its difference from `d1ee009852e51b4783d047221a27ab91cac97a33` consists of five additions: `mit-osi-reference-spdx-3290-crosswalk--2.json`, `mit-spdx-3290-plaintext-detail-byte-equality--2.json`, `mit-spdx-3290-plaintext-detail-byte-equality--3.json`, `mit-spdx-3290-template-detail-byte-boundary--2.json`, and `mit-spdx-3290-template-detail-byte-boundary--3.json`. These are later evidence revisions and do not alter the earlier CDDL snapshot's recorded census.

The successor snapshot `2026-11-25-mit-tag-native-method-after-cddl.json`, introduced at `f5101ff0c2d1d0062ef06df204b2834b3f60c988`, names `633a9c268b35400ad61c57160ff2a1cac4b0b44c` as the predecessor commit containing the CDDL snapshot. The CDDL archive has Git blob ID `738efc240c9b09666072577c261f83507911b28c` at both its introduction and that later containing commit. At `633a9c2`, `registry/coverage/current.json` and the archived CDDL snapshot are that same blob. The successor's first parent selects the same bytes.

`tools/coverage_context.py` checks the predecessor commit's ancestry, that its current ledger and named archive select the same exact bytes, and that the successor's first-parent ledger retains them. The containing predecessor commit can therefore include later claim records while retaining an earlier snapshot. This explanation does not independently establish eligibility of the inherited claims.

To reproduce from a complete checkout, count each tree with `git ls-tree -r --name-only COMMIT -- sces/records/claim` and compare the added paths with:

```sh
git diff --name-status d1ee009852e51b4783d047221a27ab91cac97a33 633a9c268b35400ad61c57160ff2a1cac4b0b44c -- sces/records/claim
git rev-parse 4697475acf0ba2465bd554b722977c9f4dc50aac:registry/coverage/snapshots/2026-11-25-cddl-native-comparison-method.json 633a9c268b35400ad61c57160ff2a1cac4b0b44c:registry/coverage/snapshots/2026-11-25-cddl-native-comparison-method.json 633a9c268b35400ad61c57160ff2a1cac4b0b44c:registry/coverage/current.json f5101ff0c2d1d0062ef06df204b2834b3f60c988^:registry/coverage/current.json
```
