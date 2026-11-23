"""Audit exact SCES claim revisions locally before publication selection."""

import argparse
from pathlib import Path
import sys

from .qualification import POLICY_COMMIT, POLICY_DIGEST, REPOSITORY, _exact_file, _pinned_validator, _run
from .records import DATA_COMMIT, ROOT, DataError, decode, encode, require


# Keep the pinned validator and its imports in the same isolated interpreter
# configuration used by the publication validator. The draft checkout is data.
PROBE = """
from datetime import datetime, timezone
from pathlib import Path
import runpy
import sys

validator, repository, name, policy_digest, base = sys.argv[1:]
policy = runpy.run_path(validator)
if policy["policy_bundle"]() != policy_digest:
    raise ValueError("SCES bundle differs from the adopted digest")
now = datetime.now(timezone.utc)
registry = policy["Registry"](Path(repository), policy_digest, now, repository=name)
registry.validate_publication(base=base or None)
rows = []
for identity in sorted(ref for ref in registry.records if ref[0] == "claim"):
    blocker = None
    try:
        registry.check_eligibility(identity, now)
    except policy["Invalid"] as error:
        blocker = str(error).split(":", 1)[0]
    disposition = registry.dispositions.get(identity, {})
    rows.append({
        "claim": dict(zip(("kind", "id", "revision"), identity)),
        "record_sha256": registry.record_digest(identity),
        "recorded_evidence": disposition.get("evidence"),
        "recorded_verification": disposition.get("verification"),
        "recorded_phases": [phase for phase in ("research", "independent-review")
                            if registry.verifications.get((identity, phase))],
        "eligible": blocker is None,
        "first_blocking_check": blocker,
    })
sys.stdout.buffer.write(policy["canonical"]({"assessed_at": now.isoformat(), "claims": rows}))
"""


def audit_claims(repository, policy, base=None):
    root = Path(repository).resolve()
    adoption = Path("sces/adoption.json")
    require(_exact_file(root / adoption) == _exact_file(ROOT / adoption),
            "the draft adoption file differs from the License Index tool checkout")
    require(base is None or DATA_COMMIT.fullmatch(base), "use a full Git commit for the history base")
    validator = _pinned_validator(policy)
    audited = decode(_run([sys.executable, "-I", "-B", "-c", PROBE, str(validator), str(root),
                           REPOSITORY, POLICY_DIGEST, base or ""]))
    eligible = sum(row["eligible"] for row in audited["claims"])
    return {"status": "local-claim-eligibility-audit", "repository": REPOSITORY,
            "policy_commit": POLICY_COMMIT, "policy_sha256": POLICY_DIGEST, "history_base": base,
            "eligible": eligible, "ineligible": len(audited["claims"]) - eligible, **audited}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path, help="private draft checkout to audit")
    parser.add_argument("--policy", required=True, type=Path, help="checkout at the pinned SCES policy")
    parser.add_argument("--base", help="full SHA of the trusted history base")
    args = parser.parse_args(argv)
    try:
        report = audit_claims(args.repo, args.policy, args.base)
    except (DataError, KeyError, OSError, ValueError) as error:
        parser.exit(1, f"claim audit: {error}\n")
    sys.stdout.buffer.write(encode(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
