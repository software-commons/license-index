# Standing authorization for the License Index integration campaign

The deployed v56 issuer accepts the earlier signed fixed-list commissioning grant and exact signed PR records. The campaign needs fresh candidate bindings for successive protected reviews. The companion authorization patch adds a repository-scoped grant through the same signed owner verification. It preserves the existing fixed-list and exact grant paths.

The grant covers Software Commons License Index repository `1468281504`, production ruleset `27875276`, base `main`, and the admission and final merge-group review phases. The issuer continues to authenticate the active organization owner and GitHub's signature, verify the grant's Git and SHA-256 pins, and require protected active state and a fresh record for the exact candidate. Each record binds the repository, PR, base, head, candidate SHA, phase, diff, protected paths and applicable SCES evidence. Independent review, required CI and the protected merge queue remain in force. Public dataset release requires separate exact-artifact authorization.

## One authenticated bootstrap

The campaign grant is `docs/license-index-integration-authorization.json` on `refs/heads/codex-owner/license-index-campaign` in `software-commons/language-index`, the existing standing-grant repository. The owner signs one commit containing that file and a replacement `docs/standing-commissioning-authorization.json` on the same authorization branch. The replacement uses the legacy schema to authorize both exact review phases of License Index PR #29 under the deployed issuer. The legacy schema requires a nonempty Language Index list, so the replacement lists only Language Index PR #3, which is already merged. There is no new review to perform for that row. The owner records these decisions on the authorization branch.

Use the existing v56 issuer with the signed compatibility file until this correction itself passes required CI, independent admission and merge-group reviews, and the protected queue. Recheck that the signed bootstrap commit is the live authorization branch tip before each invocation. Preserve the signed commit and its exact file digest in the protected records. Use the campaign file only with the independently reviewed, commissioned successor issuer.

## Staging and revocation

Verify the raw v56 preimage hashes in both manifests before normalizing their named scratch inputs to LF. Apply the history patch and the companion `v56-license-campaign-authorization.patch` from the runtime root with `git -c core.autocrlf=false apply`. Verify each manifest's resulting file hashes. The patches change disjoint runtime files. Keep the currently deployed runtime and configuration in their existing locations until cutover.

For the campaign grant, the issuer requires the signed commit to remain the live authorization branch tip. Deletion, a different tip or an API error blocks authorization. If the owner revokes authorization or the campaign completes, record that decision in protected issuer state and retire its grant. Preserve the signed and revoked evidence. Never recreate active state from an old snapshot after revocation or completion. Remove the temporary authorization branch after its audit evidence is preserved.

The isolated trial must verify both review phases with different exact candidates under the same signature. Exercise stale candidate bindings, wrong repository, invalid signatures, non-owners, moved or unavailable authorization refs, inactive protected state and the separate publication boundary. Verify these authorization checks alongside the required history format and protected-queue trials before activation.
