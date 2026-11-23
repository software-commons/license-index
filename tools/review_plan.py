"""Enumerate discovery and provisional review tasks without authoring SCES records."""

from collections import Counter
from hashlib import sha256

from .distribution import COVERAGE
from .records import SPDX_DATA_RAW, decode, encode, is_removed, local_path, read, require


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


def admission_packet(catalog, row):
    origin = row["origin"]
    candidate_id = row["id"]
    identifier = origin["identifier"]
    removed = is_removed(row)
    profile = catalog.profile(row)
    work = {
        "instrument-identity": "Establish the instrument boundary, exact edition and any applicable variant.",
        "publication-authority": "Establish who had authority to publish the identified instrument and edition.",
        "text-revision": "Compare exact source bytes and distinguish the instrument from derived representations.",
        "text-redistribution": "Establish permission and conditions for redistributing the identified representation.",
    }
    packet = {
        "candidate_id": candidate_id,
        "identifier": identifier,
        "name": origin["name"],
        "record_path": f"registry/candidates/{candidate_id[:2]}/{candidate_id}.json",
        "record_json_sha256": sha256(encode(row)).hexdigest(),
        "disposition": row["disposition"],
        "recorded_reason": row["reason"],
        "explanation_status": "provisional" if profile else "unresearched",
        "profile_sha256": sha256(encode(profile)).hexdigest() if profile else None,
        "work": work,
    }
    if row["history"] or removed:
        packet["history"] = row["history"]
        work["historical-relationship"] = "Compare earlier origins and substantiate any claimed relationship separately."
    if origin["kind"] == "spdx":
        kind = origin["list_kind"]
        commit = origin["source"]
        packet.update({
            "kind": kind,
            "population": "historical-only" if removed else "listed",
            "upstream": {
                "release": origin["release"],
                "data_commit": commit,
                "deprecated": origin["deprecated"],
                "membership": row.get("membership"),
                "reference": origin["metadata"].get("reference"),
                "origin_membership_list": f"{SPDX_DATA_RAW}/{commit}/json/{kind}s.json",
                "upstream_see_also": origin["metadata"].get("seeAlso", []),
                "artifacts": {name: {**artifact, "url": f"{SPDX_DATA_RAW}/{commit}/{artifact['path']}"}
                              for name, artifact in origin["artifacts"].items()},
                "replacement_guidance": origin.get("upstream_replacements", []),
            },
            "publisher_package": catalog.packaged.get(identifier),
        })
        if removed:
            work["spdx-membership"] = (
                "Check the origin list for former membership and the current census list for absence. Review the removal record."
            )
        else:
            work["spdx-membership"] = (
                "Check the matching current census list. Inspect the per-identifier detail and its separate origin list."
            )
        if kind == "exception":
            work["exception-relationship"] = "Establish affected base editions, scope and triggering facts from primary text."
        if origin["deprecated"]:
            work["identifier-deprecation"] = (
                "Verify upstream deprecation and each exact replacement expression. "
                "Establish any instrument relationship separately."
            )
    else:
        packet.update({
            "kind": "publisher",
            "population": "publisher-lead",
            "publisher": origin,
        })
        work["scope-disposition"] = "Review the recorded disposition and collect evidence for any proposed change."
    return packet


def build_admission_plan(catalog, identifiers):
    rows = catalog.search(include_history=True)
    if identifiers:
        chosen = {catalog.resolve(identifier)["id"] for identifier in identifiers}
        rows = [row for row in rows if row["id"] in chosen]
    packets = [admission_packet(catalog, row) for row in rows]
    coverage = read(catalog.root / COVERAGE)
    manifest_path = coverage["source_manifest"]
    manifest_bytes = local_path(catalog.root, manifest_path).read_bytes()
    manifest = decode(manifest_bytes)
    commit = manifest["data_commit"]
    return {
        "status": "discovery-admission-plan",
        "current_census": {
            "manifest_path": manifest_path,
            "manifest_sha256": sha256(manifest_bytes).hexdigest(),
            "cutoff": coverage["cutoff"],
            "release": manifest["release"],
            "data_commit": commit,
            "archive": manifest["archive"],
            "membership_lists": {name: {**item, "url": f"{SPDX_DATA_RAW}/{commit}/{item['path']}"}
                                 for name, item in manifest["manifests"].items()},
        },
        "selected": len(packets),
        "by_kind": dict(Counter(packet["kind"] for packet in packets)),
        "by_population": dict(Counter(packet["population"] for packet in packets)),
        "by_disposition": dict(Counter(packet["disposition"] for packet in packets)),
        "listed_deprecated": sum(packet["population"] == "listed" and packet["upstream"]["deprecated"]
                                 for packet in packets),
        "candidates": packets,
    }
