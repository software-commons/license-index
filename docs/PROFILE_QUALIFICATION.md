# Qualify a license profile

Run `license-index review-plan` to enumerate the provisional profiles or pass SPDX identifiers to narrow the output. The plan lists facets and source leads with stable SHA-256 fingerprints of the profile and each draft facet. The fingerprints identify research inputs. A verification receipt must bind the bytes of the eventual SCES claim record.

## Plan candidate admission

Run `license-index review-plan --admission` to account for every discovery candidate, including publisher leads and records retained only for history. Pass exact identifiers or opaque candidate IDs to generate a focused set, for example `license-index review-plan --admission LLVM-exception GPL-2.0-with-classpath-exception`.

Each packet gives the candidate path and `record_json_sha256`, a fingerprint of the tool's stable JSON serialization. The envelope identifies the current SPDX census and its list and archive digests. A packet's `origin_membership_list` can differ from the current census list when reconciliation carried an unchanged record forward. Use the current list for present membership and compare former listing and current absence for historical-only records. Match the pinned artifact digests before using the content. SPDX list records, generated texts, matching templates and replacement XML document upstream representations. Treat SPDX's `seeAlso` links as source leads. Open the controlling primary instrument and relevant publisher guidance separately. Reopen publisher leads and record the edition and bytes or a supported preservation limit.

Use the packet's planning labels to separate instrument identity, authority, text representation and permitted reuse. Choose the applicable predicate from the adoption policy when drafting each claim. For exceptions, establish the applicable base editions and scope. For deprecated identifiers, preserve the upstream replacement expression and check the actual grant before drawing conclusions about equivalence or migration. Each recorded disposition describes the discovery candidate. Canonical admission and qualified selection require separate SCES evidence and review.

## Draft and verify one claim

1. Use the pinned [SCES task brief](https://github.com/software-commons/.github/blob/ab26f278422772f2d9e5d4dd016407d14372a710/templates/SCES_RESEARCH_TASK.md) for an individual material assertion. State its instrument, edition, actor, activity, and triggering facts. Choose a predicate from `sces/adoption.json`. Claims about normative terms should identify the text of the applicable clause and any relevant definitions, exceptions or successor editions.
2. Open the publisher's legal text and any relevant separate guidance. Bind an immutable location and exact source revision. Preserve source bytes and byte ranges where permitted. If recording a locator-only source, document the reproduction route and preservation limit. SPDX supplies its own list identity and classification observations. A generated SPDX text label alone supplies no interpretation, publisher authority, or installation authorization.
3. Create the exact source, claim and dependency revisions locally. Treat unresolved rows and summaries as leads. Split scenarios into factual conditions and illustrative assumptions. A disclaimer, silence, a documented absence and observed absence have different evidence requirements. For an installation rule, record the exact input representation, rights to use it and the allowed transformation separately.
4. Run claim-bound research and a fresh independent Codex review. Keep the first run's rationale out of the reviewer's initial context. Limit any approved transfer to the claim, digest, source locators and narrow scope. Require the second run to reopen each source and challenge applicability and contrary evidence. Use actual tool event IDs, execution identities, acquisition times and digest-bound trace excerpts. For targeted review, identify the adverse case in advance. An Apache patent review can challenge unrelated litigation and the distinction between copyright and patent grants. An MIT notice review can challenge whether a particular substantial portion is in scope.
5. Preserve separate assessments, actual outcomes and material limitations using the pinned [protocol](https://github.com/software-commons/.github/blob/ab26f278422772f2d9e5d4dd016407d14372a710/docs/protocols/CODEX_RESEARCH_PROTOCOL.md). Retain failed acquisition or contradictory evidence. Update the exact claim's disposition only once the controlling evidence and independent findings support that change.
6. Validate the records and review their underlying traces before selection. For output that summarizes several claims, check sentence-to-claim mappings, factual labels, examples and limitations. Freeze eligible source records and follow the [protected release procedure](PUBLICATION.md).

Maintain separate counts for catalog entries, provisional profiles, independently reviewed assertions, canonical identities and selected claims. A single verified assertion can remain useful while the rest of its profile awaits review. The initial pilot concerns SPDX membership and supplies no legal interpretation or accepted instrument identity.

## Retain and recheck exact source bytes

After choosing a public, authorized source, use its final HTTPS URL without credentials, a query, or a fragment. Give the capture command a new file in local working storage outside the tool checkout. It checks the HTTP response and any supplied pins before atomically writing the body. It reports the observed SHA-256, length, media type, capture time and optional citation fingerprints. It requests identity encoding and refuses redirects and existing destinations. Save stdout to a new observation file using byte-preserving redirection.

```text
python -B -m tools.capture_source capture FINAL_HTTPS_URL NEW_ARTIFACT --expect-sha256 SOURCE_DIGEST --expect-bytes SOURCE_SIZE --range START END > OBSERVATION.json
python -B -m tools.capture_source verify NEW_ARTIFACT OBSERVATION.json --observation-sha256 OBSERVATION_DIGEST
```

Ranges count raw bytes from zero and exclude the end offset. Repeat `--range` to hash multiple passages. The offline verifier recomputes the whole-file and range fingerprints. Supply the observation SHA-256 from separate trusted custody to pin the exact observation. If the first capture has no independent source pin, leave the corresponding `--expect` options out and record the result as a measurement.

Keep the captured bytes and observation where the research and independent review can inspect them with authorized access. Follow the pinned protocol for each execution’s acquisition events, authority assessment, citation locators, applicable modality and review records.

## Audit exact draft revisions locally

Use a trusted License Index tool checkout, a trusted pinned policy checkout, and a Python environment with the policy's `tools/sces/requirements.txt` installed. Run `python -B -m tools.audit_claims --repo PRIVATE_DRAFT_CHECKOUT --policy PINNED_SCES_CHECKOUT --base TRUSTED_PREDECESSOR_SHA`. The draft's adoption file must match the tool checkout. Supply a trusted Git ancestor as `--base`, or omit it for a draft with no trusted predecessor. The audit compares the pinned policy bytes before loading the validator. It verifies the registry and reports each exact claim revision and digest, the recorded review phases and disposition, and the first SCES eligibility check that blocks it. An invalid registry aborts the audit. Preserve the output privately because it names draft claims and includes their digests.

The audit uses the policy's recorded eligibility checks without making a release selection or changing evidence. It provides a way to catch missing or stale review records before selection. Source inspection, authentic execution verification, domain admission, release validation, and the separate owner decision remain part of the protected workflow.

## Compare retained Codex source receipts

Retain each original `codex exec --json` stream and its corresponding session JSONL at acquisition time. Record who retained each file and its SHA-256. Supply the two original files for each phase, including both the research run and the independent review.

```text
python -B -m tools.audit_receipts --repo PRIVATE_DRAFT_CHECKOUT --policy PINNED_SCES_CHECKOUT --base TRUSTED_PREDECESSOR_SHA --execution RESEARCH_EVENTS RESEARCH_SESSION --execution REVIEW_EVENTS REVIEW_SESSION
```

The local audit matches eligible claim pairs in the pinned registry to the supplied event IDs, exact URLs, timestamps and tool responses. It checks the claim digests and conclusions in the final assessments. It also supports source-byte acquisitions from the fixed public source connector. For those acquisitions, it compares the completed tool response in both logs, decodes the retained bytes, and recomputes the full-file and citation-range digests. Rendered web opens support controlled inspection. Source-byte receipts require actual bytes. The command reports log digests and counts without printing transcripts. Compare the digests with the independently retained capture record and inspect the underlying responses, tool configuration and findings. Keep original logs and audit output in controlled custody.

## Reacquire fixed public sources inside Codex

Prepare a UTF-8 JSON manifest in operator-controlled storage. Check each final HTTPS origin and the reuse rights for sending the source to the two executions. Select exact public URLs without credentials, queries, or fragments. The only tool argument is a name from this manifest. Each call starts a new HTTPS retrieval without an environment proxy or redirect.

```json
{
  "version": 1,
  "sources": {
    "publisher": {
      "url": "https://raw.githubusercontent.com/gcc-mirror/gcc/04696df09633baf97cdbbdd6e9929b9d472161d3/COPYING.RUNTIME",
      "expected_bytes": 3324,
      "expected_sha256": "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74",
      "ranges": [[59, 247]]
    }
  }
}
```

For each fresh read-only Codex execution, configure the stdio server `fixed_public_source` with the trusted Python executable, the reviewed License Index checkout as its working directory, and arguments `-B -m tools.public_source_mcp /absolute/sources.json --manifest-sha256 MANIFEST_DIGEST`. Pin the checkout commit, Python and Codex CLI versions, and manifest digest in the operator's custody record. Set no credential environment variables. Start the server separately for each execution. The historical [GCC connector snapshot](../sces/artifacts/gcc-runtime-exception-31/public-source-connector-v1.py) preserves the earlier implementation used in those original logs.

Use `full` delivery for byte receipts. It returns the original UTF-8 body, its reversible Base64 encoding and the measured file and range digests. The default cap is 64 KiB. Supply `max_bytes` to lower the limit. A named `excerpts` entry compares specified passages from a response of up to 1 MiB and limits total excerpt text to 16 KiB. Use it for comparison controls. The full-byte audit requires the original response body. In Codex, return each full tool response intact and budget enough tool output so both native logs retain it. If the response is truncated, record the acquisition failure and preserve its limits. Preserve the original execution logs, including the results of adverse cases, and export the safe SCES receipt fields.
