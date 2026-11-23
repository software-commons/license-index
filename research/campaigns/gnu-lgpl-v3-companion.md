# GNU LGPL version 3 companion documents

Status **Provisional claim revisions**. Discovery cutoff 2026-11-23. The campaign uses SCES-1.0 at `ab26f278422772f2d9e5d4dd016407d14372a710` and policy SHA-256 `14da3f31f697ab828d4a4560f060dbe511861020db54bea7bc531e20ea0855ce`.

The supporting source is the Free Software Foundation's GNU LGPL version 3 Plain Text. Its 7,652 bytes have SHA-256 `e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118`. The evidence record preserves the source unchanged. Reacquire it directly in both fresh verification executions. [Publisher plaintext](https://ftp.gnu.org/pub/gnu/Licenses/lgpl-3.0.txt) · [Bundled text manifest](../../legal-texts/manifest.json).

| Candidate | Evidence and adverse controls |
| --- | --- |
| [Edition identity](../../sces/records/claim/gnu-lgpl-v3-instrument-identity--1.json) | Inspect the title and version date. Compare the GPLv3 title and the earlier LGPL 2.1 title. Distinguish the June 2007 document from the terms chosen for a particular program. [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) · [GNU LGPLv2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html). |
| [Verbatim document copy](../../sces/records/claim/gnu-lgpl-v3-verbatim-copy--1.json) | Verify the opening document copyright notice. Challenge the scope with a changed copy and distinguish the document's notice from terms for software covered by the LGPL. [Publisher plaintext](https://ftp.gnu.org/pub/gnu/Licenses/lgpl-3.0.txt). |
| [Copies accompanying a Combined Work](../../sces/records/claim/gnu-lgpl-v3-combined-work-license-copies--1.json) | Verify §4(b) against the opening of §4, the Combined Work definition in §0, the shared-library mechanism in §4(d)(1), and the edition-election terms in §6. Check the difference between supplying the documents for §4 and the GNU guide's suggested filenames. [Publisher text](https://www.gnu.org/licenses/lgpl-3.0-standalone.html) · [GNU application guide](https://www.gnu.org/licenses/gpl-howto.html#license-files). |

The CLI uses two explicit file writes. It checks that the supplied companion matches the pinned GPLv3 plaintext before it writes the supplemental LGPL document. Each recipe writes one target and uses the existing atomic writer. The CLI evidence concerns exact copying, companion validation and output protection. Assessment of a distribution's license terms or compliance remains separate. [CLI and offline data](../../docs/CLI.md#cli-and-offline-data).
