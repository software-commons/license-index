# Scope and identities

Software Commons License Index owns records for software licensing instruments, including governing terms for code, relevant documentation and data, exceptions, public-domain dedications, and related notices. It includes historical editions and publicly documented source-available and proprietary terms when suitably sourced. Project-specific compliance, blanket compatibility verdicts, dependency security, and custom contract drafting are outside the scope.

| Record | Admission criterion |
| --- | --- |
| License | A grant or licence with an identifiable text and edition, supported by a controlling source. |
| License exception | An additional permission or documented modification to a base license, with the affected editions supported separately. |
| Related legal instrument | A distinct dedication, mark, notice, or conditional term with a documented connection to software licensing. |
| License family | A documented lineage that helps resolve several instruments. Member-level claims have their own evidence. |

Discovery uses `registry/candidates/<shard>/<id>.json`. Accepted entities use `registry/entities/<shard>/<id>.json`. Both allocate independent UUIDv4 values represented as 32 lowercase hexadecimal characters, sharded by the first two characters. A discovery ID stays attached to its original lead. An accepted entity needs a new opaque ID and an exact independently supported identity claim. Record the permanent discovery IDs in the entity's `candidate_ids` and retain those candidate records. SPDX crosswalks must match the exact identifier, list kind, data commit, and release in a linked candidate's origin or retained origin history at the frozen SCES source commit. Names, editions, classifications, SPDX identifiers, aliases, and relationships never determine a file path.

A retained publisher lead keeps its origin kind, exact identifier, and any already recorded revision. Enrich a lead by appending the previous origin to its history and recording the more precise source or description. Allocate a separate discovery ID for a different lead.

Accept or merge identities only with qualified evidence for the instrument boundary, authority, edition, and applicable external identifiers. Clarify whether a deprecated SPDX identifier denotes a distinct text, an expression, or an identifier reassignment. Preserve earlier identifiers and decisions. A candidate lookup returns the upstream assertion and identifies its status. Factual canonical attributes require exact SCES claim revisions.

SPDX governs membership and identifiers in its own list. License publishers govern their instruments and can issue guidance. OSI and FSF own their respective approval and classification decisions. A source reference from SPDX is a discovery lead. Membership, source availability, approval, redistribution rights, and installation eligibility require separate assessments.

The index owns its data model and crosswalk decisions. Link external Software Commons index records by repository, identifier, and immutable revision if needed. Alias and incoming-relationship views are derived from records at lookup time.
