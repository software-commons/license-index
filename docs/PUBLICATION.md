# Publication control

Canonical publication uses the exact selected SCES artifacts and an authorized release decision on a protected source revision. Every additional consumer format needs a reviewed claim-to-output mapping. The index includes no workflow with repository write permissions to publish releases.

## Candidate release

1. Freeze a source commit containing the exact registry entities, source revisions, claims, dependency links, acquisition evidence, and verification records used in the release.
2. Verify the two distinct Codex executions and directly inspect their source acquisition records. Resolve blocking adversarial findings before selection.
3. Write the publication selection and run the pinned SCES builder and validator. Validate the domain registry against the same source commit and reproduce consumer output using the offline CLI.
4. Open a governed release pull request. Require SCES and registry validation and the applicable code-owner review. Record who authorized publication and which exact report, commit, and asset digests are approved.
5. A release operator may publish the exact checked artifacts under a versioned release identifier after merge. A tag alone does not establish qualification.

The repository keeps evidence and domain gate configuration, review requirements, and publication records on protected paths. Administrator changes to the controls remain governance decisions and require a recorded rationale.

Research-only notes and candidate catalogs carry provisional status. Empty registries and incomplete qualification provide no release. Follow SCES advisory and supersession procedures if an existing release loses active status.

## Licensing

Apache-2.0 governs the index's original tooling and documentation. Record the provenance and applicable terms of upstream material before retaining or redistributing it. State the data license and scope in each versioned release.
