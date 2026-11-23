"""Bind live GitHub approval rules to the authorized commissioning phase."""

from dataclasses import dataclass

from .records import require


PHASES = ("trial", "additive", "final")
PRODUCTION = {
    "software-commons/language-index": (27874363, 0),
    "software-commons/license-index": (27875276, 1),
}


@dataclass(frozen=True)
class ApprovalRule:
    ruleset_id: int
    code_owner_review: bool
    approving_review_count: int


@dataclass(frozen=True)
class CommissioningPolicy:
    phase: str
    approval: ApprovalRule

    def matches(self, observed):
        return (isinstance(observed, ApprovalRule)
                and (self.phase == "trial" or self.approval.ruleset_id == observed.ruleset_id)
                and self.approval.code_owner_review is observed.code_owner_review
                and self.approval.approving_review_count == observed.approving_review_count)


def commissioning_policy(repository, base_ref, phase, authorized_cutover_ruleset=None):
    require(repository in PRODUCTION and phase in PHASES, "select an explicit commissioning phase")
    ruleset_id, additive_count = PRODUCTION[repository]
    if phase == "trial":
        require(base_ref == "codex-gate-trial" and authorized_cutover_ruleset is None,
                "trial commissioning requires the pinned trial branch without cutover authorization")
        return CommissioningPolicy(phase, ApprovalRule(0, repository == "software-commons/language-index", 0))
    require(base_ref == "main", "production commissioning requires the pinned main branch")
    if phase == "additive":
        require(authorized_cutover_ruleset is None, "additive commissioning cannot carry cutover authorization")
        return CommissioningPolicy(phase, ApprovalRule(ruleset_id, True, additive_count))
    require(type(authorized_cutover_ruleset) is int and authorized_cutover_ruleset == ruleset_id,
            "final commissioning requires protected owner authorization for the exact production ruleset")
    return CommissioningPolicy(phase, ApprovalRule(ruleset_id, False, 0))


def observed_approval(rules):
    """Read the one commissioned effective PR rule without coercing missing fields."""
    approvals = [rule for rule in rules if rule.get("type") == "pull_request"]
    if len(approvals) != 1:
        return None
    rule, = approvals
    approval = rule.get("parameters")
    if not isinstance(approval, dict):
        return None
    source = rule.get("ruleset_id")
    owners = approval.get("require_code_owner_review")
    count = approval.get("required_approving_review_count")
    if type(source) is not int or source <= 0 or type(owners) is not bool or type(count) is not int or count < 0:
        return None
    return ApprovalRule(source, owners, count)
