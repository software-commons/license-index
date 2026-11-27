# Codex review governance decision

**Status: The authenticated Codex review gate is active on the default branch.**

The Software Commons owner authorized a Codex-only review process conditional on a compliant enforced replacement. The owner excluded adding collaborators or creating a second GitHub account. Software Commons will retain mandatory pull requests, the pinned SCES check, the registry check and its three-platform test jobs. Default-branch deletion, force-push and unauthorized bypass stay prohibited. Publication requires a separate exact-artifact authorization.

## Enforced replacement

Use an organization-controlled required workflow or a dedicated, authenticated GitHub App whose issuer posts the designated verification check. Its verifier and credentials must be outside the target pull request's trust boundary. A shared App may serve owner-authorized Index repositories with separate repository-scoped tokens. The License Index issuer must verify its token has access only to this repository. The App would have no bypass access or merge authority and be the expected source of the new ruleset check. Give it the GitHub check and commit-status permissions required for that role, with no repository code or administration write access. Its issuer must verify the repository, pull request, exact head and base commits, review execution, retained audit evidence and disposition. A changed head or target requires a fresh determination. Code in the pull request must have no access to the issuer's key or to a way to generate the same check.

The reviewer inspects changes to evidence policy, Actions callers, validation code, acceptance and source mappings, publication controls and security boundaries. Record the immutable diff, the actual separate Codex execution and material findings. Verify any SCES research and independent review separately where required. A failed check, stale record or missing trace blocks issuance. The reviewer records a judgment on the exact reviewed change. Scientific approval and release authorization require their own decisions.

Verify the authenticated source of the successful check and exercise missing, stale, and wrong-source cases before replacing the current review rule. Exercise both a changed head and an unchanged head after a change to the base SHA or target branch. Bind the check to a GitHub merge-group commit or enforce and test an equivalent base-bound mechanism that rejects the stale result. A check name supplied by GitHub Actions alone cannot distinguish a review job under pull-request control from the intended trusted gate. Review the repository and ruleset after the change and verify that branch protection rejects each unapproved revision.

## Current deployment

On November 24, 2026, the owner-authorized cutover followed a successful isolated License Index trial. Production ruleset `27875276` requires the organization-controlled **Software Commons / Codex technical review** check from App `5893334` and a singleton, ancestry-preserving merge queue. The protected issuer binds the admission decision to the exact pull-request head, base, and test merge. A separate Codex execution reviews the live merge-group commit after the required CI checks pass. The issuer retains both decisions and their execution evidence outside the pull request. [Commissioning PR](https://github.com/software-commons/license-index/pull/2) · [Issuer procedure](CODEX_GATE.md)

Production requires pull requests and both source-pinned Actions checks, **Evidence / SCES validation** and **Registry validation**. The registry check requires all three platform tests. The ruleset blocks deletion and force-pushes and has no bypass actors. Before the cutover, it required one eligible approving review and Code Owner review. The commissioned ruleset requires zero GitHub approving reviews and has Code Owner review disabled. The isolated issuer requires exact-merge authority for changes to protected controls, including evidence policies, validation workflows, and publication code. [License Index ruleset](https://github.com/software-commons/license-index/rules/27875276)

## Release authorization

An authorized operator checks the evidence custody, exact source commit, selected claim revisions, mapped outputs, scope, and artifact digests. Record the approving principal and decision separately from the technical check. Bind that decision to the protected release change and verify the exact published bytes. Follow [publication control](PUBLICATION.md) and [profile qualification](PROFILE_QUALIFICATION.md).

### Pending solid-history corrective proposal

The [v2 history artifact](../research/review/history-v2/README.md) addresses a measured archive-capacity blocker without changing the configured archive or raw-object limits. It is review material, not an activated rule, approval or release authorization. The existing protected process remains in force until independent review, isolated commissioning and a verified runtime cutover.
