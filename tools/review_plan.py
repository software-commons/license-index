"""Enumerate provisional review tasks without authoring SCES records."""

from hashlib import sha256

from .records import encode, require


def _facet(kind, name, value):
    follow_up = "resolve-scope" if value.get("state") in {"unresolved", "inapplicable"} else "draft-scoped-claims"
    return {
        "kind": kind,
        "facet": name,
        "draft_sha256": sha256(encode(value)).hexdigest(),
        "next_step": follow_up,
        "source_leads": value["sources"],
    }


def build_plan(catalog, identifiers):
    requested = {catalog.resolve(item)["origin"]["identifier"] for item in identifiers}
    selected = sorted(requested or catalog.profiles.keys(), key=str.casefold)
    profiles = []
    for identifier in selected:
        profile = catalog.profiles.get(identifier)
        require(profile, f"no provisional profile to review for {identifier}")
        facets = [_facet("dimension", name, value) for name, value in sorted(profile["dimensions"].items())]
        facets.extend(_facet("scenario", value["situation"], value) for value in profile["scenarios"])
        profiles.append({"identifier": identifier, "profile_sha256": sha256(encode(profile)).hexdigest(),
                         "facets": facets})
    return {"status": "provisional-review-plan", "profiles": profiles}
