# GCC Runtime Library Exception 3.1 document-copy research

This is a provisional SCES research packet for the verbatim copy permission in `COPYING.RUNTIME` at the GCC 14.2.0 release commit. The discovery cutoff is 2026-11-23. The existing SPDX discovery candidate is `6b5e21da7f4942fc9ff2698e807fb3c6`. The prospective claim subject reserves a separate identity. Canonical admission, a crosswalk, the application of the exception to software, and release selection require their own decisions.

| Field | Scope |
| --- | --- |
| Task | Assess whether the opening notice permits copying and distributing verbatim copies of this exact exception document. |
| Index and policy | `software-commons/license-index`, SCES-1.0 at `ab26f278422772f2d9e5d4dd016407d14372a710`, policy bundle SHA-256 `14da3f31f697ab828d4a4560f060dbe511861020db54bea7bc531e20ea0855ce`. |
| Claim | `gcc-14-2-runtime-exception-31-document-redistribution`, revision 1. The `text-redistribution` predicate scopes the normative permission to edition, release plaintext and SHA-256 provenance. |
| Acquisition | Reopen the release's commit-pinned raw file, record the actual tool event, retain exact bytes and verify the full-file and byte-range digests. The copyright notice and permission span is zero-based `[59, 247)`. |
| Targeted challenge | Compare a verbatim copy with an altered copy, a distinct SPDX representation and distribution of runtime software. Check whether the authority is the Free Software Foundation and whether the notice covers the exact release file. |
| Independent review | Use a later fresh Codex execution with only this public packet, the exact candidate digest and original source locators. Retain separate acquisition and assessment records. Give it no research rationale before source inspection. |
| Revalidation | Reopen the controlling source on a publisher correction or withdrawal, a changed representation, or a revised proposition. Eligibility requires two supported assessments and adjudication of any blocking findings. |

The retained exact publisher plaintext and the public SPDX generated text use different bytes. Their scope as representations should be examined independently of the separate question of whether one lawfully may publish either one. The release's copyright and verbatim-copy notice supply the proposed controlling basis. [Pinned GCC source](https://github.com/gcc-mirror/gcc/blob/04696df09633baf97cdbbdd6e9929b9d472161d3/COPYING.RUNTIME#L1-L14), [pinned SPDX generated text](https://github.com/spdx/license-list-data/blob/31ba1a50e5397e00a304dbadc76531740e89ee48/text/GCC-exception-3.1.txt).

## Documentary identity

Revision 1 of `gcc-14-2-runtime-exception-31-instrument-identity` examines the versioned libstdc++ manual's identification of the exception, its edition and date, and the reference to `COPYING.RUNTIME`. Its descriptive evidence comes from the publisher's manual. Challenge the candidate against confusion with the compiler's release number, the GPLv3 base text and the manual's separate documentation license. This claim uses the same prospective subject as the document-copy claim. [GCC 14.2.0 manual](https://gcc.gnu.org/onlinedocs/gcc-14.2.0/libstdc%2B%2B/manual/manual/license.html#manual.intro.status.license.gpl).

## Document-copy acquisition finding

The first completed Codex research attempt located `COPYING.RUNTIME` in the tree at the annotated GCC 14.2.0 release commit. The Windows tool policy denied its command before it could acquire the raw publisher file. The execution reported insufficient evidence. Preserve its original logs in local custody. This finding leaves the document-copy claim provisional until both phases complete a direct byte inspection. [GCC release tag and tree](https://gnu.googlesource.com/gcc/%2B/refs/tags/releases/gcc-14.2.0).
