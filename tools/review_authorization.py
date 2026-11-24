"""Bind a protected integration authorization to an independently signed owner grant."""

from base64 import b64decode
from binascii import Error as Base64Error
from datetime import date, datetime, timezone
from hashlib import sha1, sha256
import re

from .records import DataError, decode, require


GRANT_REPOSITORY = "software-commons/language-index"
GRANT_PATH = "docs/standing-commissioning-authorization.json"
GRANT_KIND = "standing-commissioning-owner-authorization"
GRANT_SCOPE = "commissioning-and-existing-integration"
REPOSITORY_RULESETS = {
    "software-commons/language-index": 27874363,
    "software-commons/license-index": 27875276,
}
GRANT_ACTIONS = [
    "commission", "review-protected-controls", "review-revised-candidates", "activate-verified-governance",
    "merge-through-protected-queue", "clean-verified-integrated-branches",
]
STATE_FIELDS = {
    "version", "status", "repository", "commit", "path", "sha256", "owner_id", "owner_login",
    "signer_id", "signer_login",
}
CANDIDATE_FIELDS = (
    "repository", "repository_id", "number", "base_ref", "phase", "head", "base", "merge", "diff_sha256",
)
_MAX_AUTHORIZATION_BYTES = 32 * 1024
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _positive_integer(value):
    return type(value) is int and value > 0


def _versioned(row, keys):
    return isinstance(row, dict) and row.keys() == keys and type(row["version"]) is int and row["version"] == 1


def _protected_json(path, check_protected):
    check_protected(path.parent, directory=True)
    check_protected(path, directory=False)
    with path.open("rb") as file:
        raw = file.read(_MAX_AUTHORIZATION_BYTES + 1)
    require(0 < len(raw) <= _MAX_AUTHORIZATION_BYTES, "invalid protected owner authorization file size")
    return decode(raw), sha256(raw).hexdigest()


def _actor(row, identifier, login):
    return (isinstance(row, dict) and row.get("type") == "User"
            and type(row.get("id")) is int and row["id"] == identifier and row.get("login") == login)


def _verified_grant(github, state):
    owner = github._get_json("/user")
    membership = github._get_json("/user/memberships/orgs/software-commons")
    require(_actor(owner, state["owner_id"], state["owner_login"])
            and isinstance(membership, dict) and membership.get("role") == "admin"
            and membership.get("state") == "active"
            and (membership.get("organization") or {}).get("login") == "software-commons",
            "the authenticated GitHub actor is not the configured active Software Commons owner")

    repo = f"/repos/{GRANT_REPOSITORY}"
    commit = state["commit"]
    observed = github._get_json(f"{repo}/commits/{commit}")
    require(isinstance(observed, dict) and observed.get("sha") == commit
            and _actor(observed.get("author"), state["owner_id"], state["owner_login"])
            and _actor(observed.get("committer"), state["signer_id"], state["signer_login"]),
            "the exact owner grant commit lacks the expected GitHub owner and web-flow actors")
    verification = (observed.get("commit") or {}).get("verification") or {}
    require(verification.get("verified") is True and verification.get("reason") == "valid"
            and all(isinstance(verification.get(field), str) and verification[field].strip()
                    for field in ("payload", "signature", "verified_at")),
            "GitHub did not verify the signature on the exact owner grant commit")

    response = github._get_json(f"{repo}/contents/{GRANT_PATH}?ref={commit}")
    require(isinstance(response, dict) and response.get("path") == GRANT_PATH and response.get("type") == "file"
            and response.get("encoding") == "base64" and isinstance(response.get("content"), str)
            and _matches(_GIT_SHA, response.get("sha")) and _positive_integer(response.get("size"))
            and response["size"] <= _MAX_AUTHORIZATION_BYTES,
            "GitHub did not return the exact owner grant as a bounded regular file")
    try:
        raw = b64decode(response["content"].replace("\r", "").replace("\n", ""), validate=True)
    except (ValueError, Base64Error) as error:
        raise DataError("GitHub returned malformed owner grant bytes") from error
    require(len(raw) == response["size"] and sha256(raw).hexdigest() == state["sha256"]
            and sha1(f"blob {len(raw)}\0".encode("ascii") + raw, usedforsecurity=False).hexdigest() == response["sha"],
            "owner grant file differs from the protected Git and SHA-256 pins")
    return decode(raw)


def _grant_applies(grant, repository, number):
    expected = {
        "kind": GRANT_KIND, "scope": GRANT_SCOPE, "repositories": list(REPOSITORY_RULESETS),
        "rulesets": list(REPOSITORY_RULESETS.values()), "expiry": "completion-or-owner-revocation",
        "actions": GRANT_ACTIONS, "publication_authorization": "required-separately",
    }
    require(isinstance(grant, dict) and grant.keys() == {*expected, "issued_on", "integration_prs"}
            and all(grant[key] == value for key, value in expected.items())
            and repository in REPOSITORY_RULESETS,
            "the signed owner grant does not cover this protected integration scope")
    integration = grant["integration_prs"]
    require(isinstance(integration, dict) and integration.keys() == REPOSITORY_RULESETS.keys()
            and all(isinstance(numbers, list) and numbers and all(map(_positive_integer, numbers))
                    and numbers == sorted(set(numbers)) for numbers in integration.values())
            and _positive_integer(number) and number in integration[repository],
            "the exact pull request is outside the signed owner integration scope")
    issued = grant["issued_on"]
    require(_matches(re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}"), issued)
            and date.fromisoformat(issued) <= datetime.now(timezone.utc).date(),
            "the signed owner grant is not yet effective")


def candidate_identity(binding):
    """Render the identity an owner-controlled record must bind after exact capture."""
    return {**{key: binding[key] for key in CANDIDATE_FIELDS},
            "sces_evidence_sha256": binding.get("sces_evidence_sha256"),
            "protected_paths": sorted(set(binding["protected_paths"]))}


def validate_control_authorization(github, binding, record_path, state_path, check_protected):
    """Check the exact candidate, protected live state, and GitHub's signed grant."""
    require(record_path is not None and state_path is not None,
            "protected main control changes require authenticated owner authorization evidence")
    candidate = candidate_identity(binding)
    record, record_digest = _protected_json(record_path, check_protected)
    claim = record.get("candidate") if isinstance(record, dict) else None
    require(_versioned(record, {"version", "candidate", "grant_commit", "grant_sha256"})
            and isinstance(claim, dict) and _positive_integer(claim.get("number"))
            and _positive_integer(claim.get("repository_id")) and claim == candidate
            and candidate["base_ref"] == "main" and candidate["phase"] in {"queue-admission", "queue-merge"}
            and candidate["protected_paths"],
            "protected owner authorization does not bind the exact review candidate")

    state, state_digest = _protected_json(state_path, check_protected)
    require(_versioned(state, STATE_FIELDS) and state["status"] == "active"
            and state["repository"] == GRANT_REPOSITORY and state["path"] == GRANT_PATH
            and _matches(_GIT_SHA, state["commit"]) and state["commit"] == record["grant_commit"]
            and _matches(_SHA256, state["sha256"]) and state["sha256"] == record["grant_sha256"]
            and _positive_integer(state["owner_id"]) and _matches(_LOGIN, state["owner_login"])
            and _positive_integer(state["signer_id"]) and state["signer_login"] == "web-flow",
            "the protected standing owner grant is absent, inactive, or mismatched")
    _grant_applies(_verified_grant(github, state), candidate["repository"], candidate["number"])
    return {"grant_commit": state["commit"], "grant_sha256": state["sha256"],
            "record_sha256": record_digest, "state_sha256": state_digest}
