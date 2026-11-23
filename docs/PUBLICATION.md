# Publication control

Canonical publication uses the exact selected SCES artifacts and an authorized release decision on a protected source revision. Every additional consumer format needs a reviewed claim-to-output mapping. The index includes no workflow with repository write permissions to publish releases.

## Candidate release

1. Freeze a source commit containing the exact registry entities, source revisions, claims, dependency links, acquisition evidence, and verification records used in the release.
2. Verify the two distinct Codex executions and directly inspect their source acquisition records. Resolve blocking adversarial findings before selection.
3. Write the publication selection and run the pinned SCES builder and validator. Validate the domain registry against the same source commit and reproduce consumer output using the offline CLI.
4. Open a governed release pull request. Require SCES and registry validation and the applicable code-owner review or the commissioned Codex gate. Preserve the frozen source commit in the integrated Git history. If the release PR introduces that commit, use an ancestry-preserving merge.
5. Stage from the integrated publication commit on the protected default branch. Verify protection for the intended versioned release tag and obtain the separate owner decision before publishing the exact checked assets.

The repository keeps evidence and domain gate configuration, review requirements, and publication records on protected paths. Administrator changes to the controls remain governance decisions and require a recorded rationale.

[The repository ruleset](https://github.com/software-commons/license-index/rules/27875276) targets the default branch. It requires a pull request, the GitHub Actions checks **Evidence / SCES validation** and **Registry validation**, and review of CODEOWNERS paths. It blocks non-fast-forward updates and deletion and has no bypass actor. The domain check requires passing platform jobs on Windows, Ubuntu and macOS. Changes to evidence controls and sources require an authorized reviewer who can review the author’s pull request.

The current ruleset requires one eligible approving review. The [Codex review governance decision](GOVERNANCE_REVIEW.md) records the conditions for replacing GitHub approval with an authenticated independent review check. [Profile qualification](PROFILE_QUALIFICATION.md) defines claim-by-claim verification for the provisional research.

The local qualified export assembles the exact SCES claims and the entity records from the frozen source commit. The validator compares the name, kind and state against the identity claim and verifies the exact claim, predicate, and applicable revision for each alias, external identity and relationship. Any public consumer artifact must be mapped and approved in its release decision, including its exact SHA-256. The development JSON and ZIP carry their discovery status and are excluded from canonical publication.

Use `license-index coverage --policy PATH` to check the pinned policy and any active release. It reports zero selected claims if the registry has no active release. `license-index export --qualified --policy PATH` requires an active, validated release. The default discovery view and offline ZIP use the discovery snapshot and can be built without the policy checkout.

## Stage the exact release candidate

From a trusted checkout of the checked publication commit, run `python -B -m tools.stage_release /path/to/new-candidate.zip --policy /path/to/pinned-policy --base TRUSTED_PREDECESSOR_SHA`. Substitute paths appropriate to the operating system. Staging and the pinned validator read the recorded Git objects and parent links with local replacements and grafts disabled. The command requires the evidence and registry data used in validation to match the commit. It stages only the exact SCES payload and qualification report, the pinned SCES schema and their checksums. Discovery records, extra entity projections, raw source captures and verification traces stay outside the ZIP.

Preserve the exact UTF-8 output as `REQUEST.json` using byte-preserving redirection, such as native command redirection in PowerShell 7.4 or later. It binds the publication candidate commit, trusted history base, frozen source commit, dataset and policy versions, exact asset hashes and the archive digest. It carries no approval. A second build from the same inputs and the pinned policy produces identical ZIP bytes without fetching sources. Compare the hash and use the pinned `sces-contracts.schema.json` definitions for the payload claim, dependency and qualification structures.

Use a ZIP filename that starts with an ASCII letter or digit and contains only ASCII letters, digits, periods, underscores and hyphens before the ZIP suffix. GitHub can rename uploaded assets with other characters. Release assets must be under 2 GiB. [GitHub asset naming](https://docs.github.com/en/rest/releases/assets#upload-a-release-asset), [GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).

Use the request generated from the final integrated commit for authorization. If a previously staged candidate integrates to a different commit, restage at the integrated commit and compare the payload and report digests. The frozen source commit identifies the earlier evidence snapshot. SCES validates that it remains in the integrated commit’s ancestry.

## Authorize and verify publication

Retain the owner’s separate decision with the approving principal, exact staging request SHA-256, integrated commit, versioned tag, release title and body, data license and scope. Verify the protected default branch and release tag controls using the owner’s view, including any bypass actors. The branch ruleset alone does not establish release tag protection. Attach the exact staged ZIP as the dataset attachment, using its filename as its displayed label or leaving the label blank. The machine-readable qualification report is inside that ZIP and at the same SCES path in the tagged source. GitHub also supplies source archives for the tag.

Verify the staged bytes locally before attaching them. After publication, verify the public asset and tag without credentials.

```text
python -B -m tools.verify_release REQUEST.json --request-sha256 REQUEST_DIGEST --zip CANDIDATE.zip
python -B -m tools.verify_release REQUEST.json --request-sha256 REQUEST_DIGEST --tag APPROVED_TAG --notes-sha256 NOTES_DIGEST
```

For `NOTES_DIGEST`, hash the bytes from `tools.records.encode({"name": approved_title, "body": approved_body})`. Use the exact GitHub title and body, including whitespace. The verifier matches the published title and body and resolves the public tag to the integrated commit in the request. It checks the downloaded ZIP, each asset digest, the checksum file, and the report’s claim list and policy result. It verifies those bindings against the supplied digests. Preserve the authenticated owner decision and protection observations separately.

Research-only notes and candidate catalogs carry provisional status. Empty registries and incomplete qualification provide no release. Follow SCES advisory and supersession procedures if an existing release loses active status.

## Withdraw a release

Add the required SCES advisory and remove the active selection in the same protected change when there is no qualified successor. Retain the archived report, payload, evidence, and canonical entity files at their exact trusted baseline bytes. The pinned policy validates the withdrawal and the domain validator checks that the retained entity bytes match an archived release. The CLI reports zero selected claims and refuses qualified export until a new checked selection becomes active. Use the previous report when preparing a successor and correct the affected downstream publication surfaces.

## Licensing

Apache-2.0 governs the index's original tooling and documentation. Record the provenance and applicable terms of upstream material before retaining or redistributing it. State the data license and scope in each versioned release.
