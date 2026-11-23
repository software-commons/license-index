# Publication control

Canonical publication uses the exact selected SCES artifacts and an authorized release decision on a protected source revision. Every additional consumer format needs a reviewed claim-to-output mapping. The index includes no workflow with repository write permissions to publish releases.

## Candidate release

1. Freeze a source commit containing the exact registry entities, source revisions, claims, dependency links, acquisition evidence, and verification records used in the release.
2. Verify the two distinct Codex executions and directly inspect their source acquisition records. Resolve blocking adversarial findings before selection.
3. Write the publication selection and run the pinned SCES builder and validator. Validate the domain registry against the same source commit and reproduce consumer output using the offline CLI.
4. Open a governed release pull request. Require SCES and registry validation and the applicable code-owner review. Record who authorized publication and which exact report, commit, and asset digests are approved.
5. A release operator may publish the exact checked artifacts under a versioned release identifier after merge. A tag alone does not establish qualification.

The repository keeps evidence and domain gate configuration, review requirements, and publication records on protected paths. Administrator changes to the controls remain governance decisions and require a recorded rationale.

[The repository ruleset](https://github.com/software-commons/license-index/rules/27875276) targets the default branch. It requires a pull request, the GitHub Actions checks **Evidence / SCES validation** and **Registry validation**, and review of CODEOWNERS paths. It blocks non-fast-forward updates and deletion and has no bypass actor. The domain check requires passing platform jobs on Windows, Ubuntu and macOS. Changes to evidence controls and sources require an authorized reviewer who can review the author’s pull request.

The current ruleset requires one eligible approving review. The [Codex review governance decision](GOVERNANCE_REVIEW.md) records the conditions for replacing GitHub approval with an authenticated independent review check. [Profile qualification](PROFILE_QUALIFICATION.md) defines claim-by-claim verification for the provisional research.

The local qualified export assembles the exact SCES claims and the entity records from the frozen source commit. The validator compares the name, kind and state against the identity claim and verifies the exact claim, predicate, and applicable revision for each alias, external identity and relationship. Any public consumer artifact must be mapped and approved in its release decision, including its exact SHA-256. The development JSON and ZIP carry their discovery status and are excluded from canonical publication.

Use `license-index coverage --policy PATH` to check the pinned policy and any active release. It reports zero selected claims if the registry has no active release. `license-index export --qualified --policy PATH` requires an active, validated release. The default discovery view and offline ZIP use the discovery snapshot and can be built without the policy checkout.

## Stage the exact release candidate

From the checked publication candidate commit, run `python -B -m tools.stage_release /path/to/new-candidate.zip --policy /path/to/pinned-policy --base TRUSTED_PREDECESSOR_SHA`. Substitute paths appropriate to the operating system. The command verifies the active release against the pinned policy and requires the evidence and registry data used in validation to match the commit. It stages only the exact SCES payload and qualification report, the pinned SCES schema and their checksums. Discovery records, extra entity projections, raw source captures and verification traces stay outside the ZIP.

Preserve the JSON result with the authorization request. It binds the publication candidate commit, trusted history base, frozen source commit, dataset and policy versions, exact asset hashes and the archive digest. It carries no approval. A second build from the same inputs and the pinned policy produces identical ZIP bytes without fetching sources. Compare the hash and use the pinned `sces-contracts.schema.json` definitions for the payload claim, dependency and qualification structures.

Before publishing, verify the integrated publication commit and intended protected release ref. Record the separate owner's authorization for the exact assets, data license and scope. Verify the bytes again when attaching them and after public download.

Research-only notes and candidate catalogs carry provisional status. Empty registries and incomplete qualification provide no release. Follow SCES advisory and supersession procedures if an existing release loses active status.

## Withdraw a release

Add the required SCES advisory and remove the active selection in the same protected change when there is no qualified successor. Retain the archived report, payload, evidence, and canonical entity files at their exact trusted baseline bytes. The pinned policy validates the withdrawal and the domain validator checks that the retained entity bytes match an archived release. The CLI reports zero selected claims and refuses qualified export until a new checked selection becomes active. Use the previous report when preparing a successor and correct the affected downstream publication surfaces.

## Licensing

Apache-2.0 governs the index's original tooling and documentation. Record the provenance and applicable terms of upstream material before retaining or redistributing it. State the data license and scope in each versioned release.
