# Publication control

Canonical publication uses the exact selected SCES artifacts and an authorized release decision on a protected source revision. Every additional consumer format needs a reviewed claim-to-output mapping. The index includes no workflow with repository write permissions to publish releases.

## Candidate release

1. Freeze a source commit containing the exact registry entities, source revisions, claims, dependency links, acquisition evidence, and verification records used in the release.
2. Verify the two distinct Codex executions and directly inspect their source acquisition records. Resolve blocking adversarial findings before selection.
3. Write the publication selection and run the pinned SCES builder and validator. Record an immutable coverage snapshot using the checked selection counts and the exact prior assessment reference. Validate the registry and reproduce the consumer output.
4. Open a governed release pull request. Require SCES and registry validation and the applicable code-owner review or the commissioned Codex gate. Preserve the frozen source commit in the integrated Git history. If the release PR introduces that commit, use an ancestry-preserving merge.
5. Stage from the integrated publication commit on the protected default branch. Verify protection for the intended versioned release tag and obtain the separate owner decision before publishing the exact checked assets.

The repository keeps evidence and domain gate configuration, review requirements, and publication records on protected paths. Administrator changes to the controls remain governance decisions and require a recorded rationale.

[The repository ruleset](https://github.com/software-commons/license-index/rules/27875276) targets the default branch. It requires a pull request, the GitHub Actions checks **Evidence / SCES validation** and **Registry validation**, and review of CODEOWNERS paths. It blocks non-fast-forward updates and deletion and has no bypass actor. The domain check requires passing platform jobs on Windows, Ubuntu and macOS. Changes to evidence controls and sources require an authorized reviewer who can review the author’s pull request.

The current ruleset requires one eligible approving review. The [Codex review governance decision](GOVERNANCE_REVIEW.md) records the conditions for replacing GitHub approval with an authenticated independent review check. [Profile qualification](PROFILE_QUALIFICATION.md) defines claim-by-claim verification for the provisional research.

The local qualified export assembles the exact SCES claims and the entity records from the frozen source commit. The validator compares the name, kind and state against the identity claim and verifies the exact claim, predicate, and applicable revision for each alias, external identity and relationship. Any public consumer artifact must be mapped and approved in its release decision, including its exact SHA-256. The development JSON and ZIP carry their discovery status and are excluded from canonical publication.

Use `license-index coverage --policy PATH` to check the pinned policy and any active release. It reports zero selected claims if the registry has no active release. `license-index export --qualified --policy PATH` requires an active, validated release. A checkout with active publication also requires the pinned policy for discovery export and offline ZIP creation. The extracted ZIP reports the archived selection counts as unverified snapshot observations alongside its own discovery coverage.

## Stage the exact release candidate

From a trusted checkout of the checked publication commit, run `python -I -B tools/run_isolated.py stage_release /path/to/new-candidate.zip --policy /path/to/pinned-policy --base TRUSTED_PREDECESSOR_SHA`. Substitute paths appropriate to the operating system. Keep the archive and the captured staging request outside the checkout's `sces`, `registry`, `research`, and `legal-texts` directories. Staging and the pinned validator read the recorded Git objects and parent links with local replacements and grafts disabled. The command requires the evidence and registry data used in validation to match the commit. It stages only the exact SCES payload and qualification report, the pinned SCES schema and their checksums. Discovery records, extra entity projections, raw source captures and verification traces stay outside the ZIP.

Registry CI exercises staging against the trusted predecessor. With an active selection it builds both distributions twice, compares the exact bytes, verifies the staged archive and pinned schema digest, and validates the extracted development ZIP offline. Without a selection it checks that qualified staging refuses to produce an archive. The workflow writes its test artifacts to a temporary directory. Production staging and owner authorization follow integration on the protected branch.

Preserve the exact UTF-8 output as `REQUEST.json` using byte-preserving redirection, such as native command redirection in PowerShell 7.4 or later. It binds the publication candidate commit, trusted history base, frozen source commit, dataset and policy versions, exact asset hashes and the archive digest. It carries no approval. A second build from the same inputs and the pinned policy produces identical ZIP bytes without fetching sources. Compare the hash and use the pinned `sces-contracts.schema.json` definitions for the payload claim, dependency and qualification structures.

Use a ZIP filename that starts with an ASCII letter or digit and contains only ASCII letters, digits, periods, underscores and hyphens before the ZIP suffix. GitHub can rename uploaded assets with other characters. Release assets must be under 2 GiB. [GitHub asset naming](https://docs.github.com/en/rest/releases/assets#upload-a-release-asset), [GitHub release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).

Use the request generated from the final integrated commit for authorization. If a previously staged candidate integrates to a different commit, restage at the integrated commit and compare the payload and report digests. The frozen source commit identifies the earlier evidence snapshot. SCES validates that it remains in the integrated commit’s ancestry.

## Authorize and verify publication

Verify the protected default branch and versioned release tag controls using the owner’s view, including any bypass actors. Retain the authenticated decision and protection observations with the exact authorization record. Store the authorization separately from the release archive and the commit it approves. Ask the owner to communicate the exact authorization file’s SHA-256 through the authenticated decision channel so an operator can verify the binding independently.

Record those approved values in the following UTF-8 JSON format as `AUTHORIZATION.json`. Use a UTC timestamp such as `YYYY-MM-DDTHH:MM:SSZ` for `approved_at`.

```json
{
  "version": 1,
  "decision": "authorize-publication",
  "repository": "software-commons/license-index",
  "principal": "AUTHENTICATED_OWNER_IDENTIFIER",
  "approved_at": "APPROVAL_TIMESTAMP_IN_UTC",
  "request_sha256": "APPROVED_REQUEST_SHA256",
  "publication_commit": "INTEGRATED_COMMIT_SHA",
  "tag": "APPROVED_VERSIONED_TAG",
  "notes": {"name": "APPROVED_RELEASE_TITLE", "body": "APPROVED_RELEASE_BODY"},
  "data_license": "APPROVED_DATA_LICENSE",
  "scope": "APPROVED_DATASET_SCOPE_AND_LIMITATIONS"
}
```

The verifier checks the supplied decision digest and its bindings to the exact request, integrated commit, release tag and notes. Authenticating the principal and confirming the body communicates the approved scope and license require the retained owner decision. Attach the exact staged ZIP as the dataset attachment, using its filename as its displayed label or leaving the label blank. The machine-readable qualification report is inside that ZIP and at the same SCES path in the tagged source. GitHub also supplies source archives for the tag.

Verify the staged bytes locally before attaching them. After publication, verify the public asset and tag without credentials.

```text
python -I -B tools/run_isolated.py verify_release REQUEST.json --authorization AUTHORIZATION.json --authorization-sha256 AUTHORIZATION_DIGEST --zip CANDIDATE.zip
python -I -B tools/run_isolated.py verify_release REQUEST.json --authorization AUTHORIZATION.json --authorization-sha256 AUTHORIZATION_DIGEST
```

Preserve the exact GitHub title and body, including whitespace, in `notes`. The verifier matches the published notes, resolves the public tag to the integrated commit, checks the downloaded ZIP and each asset digest, and compares the report’s claim list and policy result. For an integrity-only check, use `--request-sha256 REQUEST_DIGEST` with `--zip CANDIDATE.zip`, or with `--tag TAG --notes-sha256 NOTES_DIGEST`. Calculate the notes digest from `tools.records.encode({"name": title, "body": body})`.

Research-only notes and candidate catalogs carry provisional status. Empty registries and incomplete qualification provide no release. Follow SCES advisory and supersession procedures if an existing release loses active status.

## Withdraw a release

Add the required SCES advisory and remove the active selection in the same protected change when there is no qualified successor. Retain the archived report, payload, evidence, and canonical entity files at their exact trusted baseline bytes. The pinned policy validates the withdrawal and the domain validator checks that the retained entity bytes match an archived release. The CLI reports zero selected claims and refuses qualified export until a new checked selection becomes active. Use the previous report when preparing a successor and correct the affected downstream publication surfaces.

## Licensing

Apache-2.0 governs the index's original tooling and documentation. Record the provenance and applicable terms of upstream material before retaining or redistributing it. State the data license and scope in each versioned release.
