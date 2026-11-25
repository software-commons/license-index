# MIT SPDX release-tag correction

Protected review identified three selected MIT claims whose earlier executions inspected files pinned to SPDX data commit `31ba1a50e5397e00a304dbadc76531740e89ee48`. The claim records also named SPDX 3.29.0. That version attribution depended on the supplied release mapping rather than a directly inspected dependency.

Two fresh Codex executions acquired the exact annotated `v3.29.0` tag object, the named OSI record, and the original SPDX representations. The tag object identifies the exact data commit as its target. GitHub reports an unsigned tag. The same upstream project supplies the annotation and the generated data. [SPDX release](https://github.com/spdx/license-list-data/releases/tag/v3.29.0) · [Exact annotated tag object](https://api.github.com/repos/spdx/license-list-data/git/tags/76c9a79bb7d2bf851143b76b3935a4d7cbaa644b) · [OSI reference](https://opensource.org/license/mit)

An initial reacquisition detected an OSI CMS update. The current record has a new modification timestamp and promotional figure. Its title, link, SPDX label, and rendered license paragraphs match the older capture. The revised crosswalk uses the current documentary evidence. The earlier archived identity and terms retain their original scope.

| Successor claim | Verified scope |
| --- | --- |
| OSI MIT reference and SPDX correspondence | The tag binds the version to the inspected commit. The SPDX detail at that commit identifies MIT and cites the OSI reference. The published OSI record labels its form MIT. The separate X.Org source and any project's actual license grant remain outside the claim. |
| Generated plain-text representation | The 1,078-byte SPDX text matches the UTF-8 encoding of the decoded `licenseText` field. Both executions repeated the comparison without normalization. |
| Matching-template representation | The 1,958-byte matching template matches the UTF-8 encoding of the decoded `standardLicenseTemplate` field and differs from the plain text. Matching behavior, installation rights and rights in other representations remain outside the claim. |

The [fixed source manifest](../../sces/artifacts/mit-spdx-tag-supersession/public-source-manifest.json) pins all original acquisitions. The [research receipts](../../sces/artifacts/mit-spdx-tag-supersession/research-receipts.jsonl) and [independent review receipts](../../sces/artifacts/mit-spdx-tag-supersession/independent-review-receipts.jsonl) bind the exact source observations to each claim revision. The [independent byte comparison](../../sces/artifacts/mit-spdx-tag-supersession/independent-review-reproduction.json) records the native result and the compared source captures.

The Git registry retains the original selection's evidence and [qualification report](../../sces/releases/mit-reference-0-1-0/qualification.json). The [advisory](../../sces/advisories/mit-reference-0-1-0.json) records the three superseded revisions. The [successor qualification](../../sces/releases/mit-reference-0-1-1/qualification.json) selects their successors and the five unaffected MIT claims. The exact owner decision for any dataset publication remains separate.

## Native comparison method

Both MIT representation crosswalks use revision 3. The earlier revision paired a JavaScript operation with the Python implementation in its reproduction metadata. The separately run research and independent review now bind the exact JavaScript file, the native comparison result, and the full source acquisition for each input. The superseded claim records and the earlier prepared artifacts remain available in Git history. The selected MIT release remains pending exact protected review and separate release authorization. [Actual method](../../sces/artifacts/mit-spdx-native-method/executed-comparison.js)
