# Apache 2.0 redistribution conditions

Separate Codex executions reopened the exact English January 2004 legal text and inspected the redistribution preamble, sections 4(a)–(c), and the adjacent context. The claims apply to distributions under section 4. [Official Apache 2.0 text](https://www.apache.org/licenses/LICENSE-2.0)

| Provision | Supported scope |
| --- | --- |
| §4(a) | Give other recipients a copy of the license when distributing the Work or Derivative Works under section 4, including unmodified Object form. Delivery method and filename remain outside the claim. [License copy](../../sces/records/claim/apache-20-section-4a-license-copy--1.json) |
| §4(b) | Files changed by the distributor and included in distributed derivative Source carry prominent notices of those changes. Treatment of Object-only delivery and the form of a particular notice need separate assessment. [Changed Source files](../../sces/records/claim/apache-20-section-4b-source-change-notices--1.json) |
| §4(c) | In distributed derivative Source, retain upstream Source copyright, patent, trademark, and attribution notices that still pertain to any part. [Source notice retention](../../sces/records/claim/apache-20-section-4c-source-notice-retention--1.json) |

**Hypothetical Source archive.** Assume a distributor modifies a retained file and removes a separate upstream component. Identify the changed file and each upstream notice that still pertains to the distributed Source. A notice specific to removed material requires checking whether it also pertains to any retained part. The separate §4(d) condition concerns readable attribution from any upstream NOTICE file where its trigger applies. [NOTICE revision 2](../../sces/records/claim/apache-20-section-4d-notice-attributions--2.json)

The annual review interval follows the controlling English edition’s existing review date because these claims use its fixed byte ranges. A publisher correction, change in representation, or change in scope triggers earlier review. [Source manifest](../../sces/artifacts/apache-20-redistribution/public-source-manifest.json) · [Research receipt](../../sces/artifacts/apache-20-redistribution/research-receipts.jsonl) · [Independent review receipt](../../sces/artifacts/apache-20-redistribution/independent-review-receipts.jsonl)

The registry audit lists every tested revision and digest. Recompute it from the recorded audited commit using `python -B -m tools.audit_claims --repo . --policy PATH_TO_PINNED_POLICY --base 8a92e545c37f34f34c2b369539750c6147c619fb`. [Exact registry audit](../../sces/artifacts/apache-20-redistribution/registry-eligibility-audit.json)
