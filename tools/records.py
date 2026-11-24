"""Read record files and derive catalog, text and coverage views."""

from __future__ import annotations

from collections import Counter
from functools import cached_property
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, build_opener

from .li_install import LGPL_V3_SUPPLEMENT

ROOT = Path(__file__).resolve().parent.parent
OPAQUE_ID = re.compile(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}")
HEX_256 = re.compile(r"[0-9a-f]{64}")
DATA_COMMIT = re.compile(r"[0-9a-f]{40}")
SPDX_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*\+?")
SPDX_DATA_RAW = "https://raw.githubusercontent.com/spdx/license-list-data"
VERSION = "0.1.0.dev0"
COVERAGE_VERSION = "4.0.0"
COVERAGE_VERSION_V3 = "3.0.0"
COVERAGE_VERSION_V2 = "2.0.0"
LEGACY_COVERAGE_VERSION = "1.0.0"
COVERAGE_VERSIONS = (LEGACY_COVERAGE_VERSION, COVERAGE_VERSION_V2, COVERAGE_VERSION_V3, COVERAGE_VERSION)
DIMENSION_STATES = {"permission", "condition", "restriction", "documented", "unresolved",
                    "inapplicable", "explicit-absence"}
_SCES_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_SCES_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SCES_COVERAGE_KINDS = ("claim", "disposition", "source", "verification")


class DataError(ValueError):
    """A catalog, input, or artifact failed validation."""


def require(condition, message):
    if not condition:
        raise DataError(message)


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def decode(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_fields)


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def read(path):
    try:
        return decode(path.read_bytes())
    except (OSError, ValueError) as error:
        raise DataError(f"{path}: {error}") from error


def local_path(root, relative):
    require(isinstance(relative, str) and "\\" not in relative, "invalid artifact path")
    path = PurePosixPath(relative)
    require(path.parts and not path.is_absolute() and ".." not in path.parts and ":" not in relative,
            f"unsafe artifact path: {relative}")
    target = root.joinpath(*path.parts)
    require(target.resolve().is_relative_to(root.resolve()), f"artifact escapes its storage root: {relative}")
    return target


def checked_bytes(data, descriptor):
    size = descriptor["bytes"]
    require(len(data) == size and sha256(data).hexdigest() == descriptor["sha256"],
            f"artifact size or SHA-256 mismatch: {descriptor['path']}")
    return data


def _sces_reference(value):
    if not isinstance(value, dict):
        return None
    kind, identifier, revision = (value.get(field) for field in ("kind", "id", "revision"))
    if (kind in _SCES_COVERAGE_KINDS and isinstance(identifier, str) and _SCES_ID.fullmatch(identifier)
            and type(revision) is int and 1 <= revision <= 2147483647):
        return kind, identifier, revision
    return None


def _supported_independent_review(target, disposition, claim_bytes, verifications, latest_verifications):
    if disposition.get("evidence") != "supported" or disposition.get("verification") != "independently-reviewed":
        return False
    claim_digest = sha256(claim_bytes).hexdigest()
    pair = []
    for field, phase in (("research", "research"), ("review", "independent-review")):
        ref = _sces_reference(disposition.get(field))
        current = latest_verifications.get((target, phase))
        if current is None or ref is None or ref != current[1]:
            return False
        review, _ = verifications[ref]
        run = review.get("run")
        execution = run.get("execution") if isinstance(run, dict) else None
        if (review.get("phase") != phase or _sces_reference(review.get("claim")) != target
                or review.get("claim_sha256") != claim_digest or review.get("conclusion") != "supported"
                or not isinstance(execution, str) or not execution.strip()):
            return False
        pair.append(review)
    research, review = pair
    first, second = research["run"], review["run"]
    try:
        first_trace, second_trace = first["trace"], second["trace"]
        first_acquisitions, second_acquisitions = research["acquisitions"], review["acquisitions"]
        if not isinstance(first_acquisitions, list) or not isinstance(second_acquisitions, list):
            return False
        first_captures = {item["capture"] for item in first_acquisitions}
        second_captures = {item["capture"] for item in second_acquisitions}
        # A recorded review pair must satisfy SCES review independence even with no selection.
        return (
            first["execution"] != second["execution"]
            and HEX_256.fullmatch(first_trace["sha256"]) is not None
            and HEX_256.fullmatch(second_trace["sha256"]) is not None
            and first_trace["sha256"] != second_trace["sha256"]
            and all(isinstance(trace["path"], str) and trace["path"].strip()
                    for trace in (first_trace, second_trace))
            and first_trace["path"] != second_trace["path"]
            and _SCES_TIMESTAMP.fullmatch(second["started"]) is not None
            and first["completed"] <= second["started"]
            and all(isinstance(capture, str) and capture.strip() for capture in first_captures | second_captures)
            and first_captures.isdisjoint(second_captures)
        )
    except (KeyError, TypeError):
        return False


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class Catalog:
    def __init__(self, root=ROOT):
        self.root = Path(root).resolve()
        self.candidates = self._read_sharded("candidates")
        self.spdx = {}
        self.non_spdx = []
        for candidate in self.candidates.values():
            origin = candidate["origin"]
            if origin["kind"] != "spdx":
                self.non_spdx.append(candidate)
                continue
            identifier = origin["identifier"]
            require(SPDX_ID.fullmatch(identifier), f"invalid SPDX identifier: {identifier}")
            require(DATA_COMMIT.fullmatch(origin["source"]), f"missing SPDX revision: {identifier}")
            require(origin["list_kind"] in {"license", "exception"}, f"invalid SPDX kind: {identifier}")
            require(type(origin["deprecated"]) is bool, f"invalid SPDX deprecation flag: {identifier}")
            key = identifier.casefold()
            require(key not in self.spdx, f"duplicate SPDX identifier: {identifier}")
            self.spdx[key] = candidate
        self.packaged = self._optional("legal-texts/manifest.json")
        self.profiles = self._optional("research/campaigns/profiles.json")

    @cached_property
    def entities(self):
        records = self._read_sharded("entities")
        require(not self.candidates.keys() & records.keys(), "candidate and entity IDs overlap")
        return records

    def _optional(self, relative):
        path = self.root / relative
        return read(path) if path.exists() else {}

    def _sharded_rows(self, kind):
        for path in sorted((self.root / "registry" / kind).rglob("*.json")):
            yield path.relative_to(self.root).as_posix(), read(path)

    def _read_sharded(self, kind):
        rows = {}
        for path, row in self._sharded_rows(kind):
            identifier = row.get("id", "")
            require(OPAQUE_ID.fullmatch(identifier), f"invalid permanent ID: {path}")
            require(path == f"registry/{kind}/{identifier[:2]}/{identifier}.json",
                    f"incorrect shard or filename: {path}")
            require(identifier not in rows, f"duplicate permanent ID: {identifier}")
            if kind == "candidates":
                disposition, reason = row.get("disposition"), row.get("reason")
                require(isinstance(disposition, str) and disposition.strip()
                        and isinstance(reason, str) and reason.strip(),
                        f"{path}: candidate disposition requires a recorded reason")
            rows[identifier] = row
        return rows

    @property
    def active_spdx(self):
        return [row for row in self.spdx.values() if not is_removed(row)]

    def exact(self, value):
        key = value.casefold()
        if key in self.candidates:
            return self.candidates[key]
        matches = [row for row in self.non_spdx if row["origin"]["identifier"].casefold() == key]
        if key in self.spdx:
            matches.append(self.spdx[key])
        require(len(matches) <= 1, f"ambiguous candidate identifier: {value}. Use the candidate UUID.")
        return matches[0] if matches else None

    def resolve(self, value):
        match = self.exact(value)
        require(match is not None, f"unknown catalog identifier: {value}")
        return match

    def search(self, token="", *, include_history=False, kind=None):
        target = token.casefold()
        rows = (self.candidates.values() if include_history
                else [*self.active_spdx, *self.non_spdx])
        found = []
        for row in rows:
            origin = row["origin"]
            if kind and origin.get("list_kind", "other") != kind:
                continue
            names = [row["id"], origin["identifier"], origin["name"], origin.get("spdx_identifier", "")]
            names.extend(old.get("identifier", "") for old in row.get("history", []))
            if any(target in name.casefold() for name in names):
                found.append(row)
        return sorted(found, key=lambda row: (row["origin"]["identifier"].casefold(), row["id"]))

    def profile(self, row):
        origin = row["origin"]
        return self.profiles.get(origin["identifier"]) if origin["kind"] == "spdx" else None

    def describe(self, row):
        origin = row["origin"]
        identifier = origin["identifier"]
        return {
            "record": row,
            "catalog_status": "discovery",
            "text_package": self.packaged.get(identifier) if origin["kind"] == "spdx" else None,
            "explanation_status": "provisional" if self.profile(row) else "unresearched",
            "legal_interpretation_qualification": "unqualified",
        }

    def text(self, row, *, artifact_root=None, fetch=False, for_installation=False):
        origin = row["origin"]
        identifier = origin["identifier"]
        require(origin["kind"] == "spdx", f"only a source locator is recorded for {identifier}")
        package = self.packaged.get(identifier)
        if package:
            from .distribution import validate_publisher_package

            validate_publisher_package(identifier, package)
            return checked_bytes(local_path(self.root, package["path"]).read_bytes(), package), package
        descriptor = origin["artifacts"].get("text")
        require(descriptor, f"no SPDX text artifact is recorded for {identifier}")
        text_path = descriptor["path"]
        require(re.fullmatch(r"text/(?:deprecated_)?[A-Za-z0-9][A-Za-z0-9.+-]*\.txt", text_path),
                f"invalid source text path: {text_path}")
        upstream = f"{SPDX_DATA_RAW}/{origin['source']}/{text_path}"
        material = {**descriptor, "source": upstream, "representation": "SPDX generated plain text"}
        if for_installation:
            require(identifier == "MIT", f"installation is unsupported for {identifier}")
            material["install"] = "mit-notice"
        if artifact_root is not None:
            local = local_path(Path(artifact_root), text_path)
            require(local.is_file(), f"pinned source text is missing: {local}")
            return checked_bytes(local.read_bytes(), descriptor), material
        require(fetch, f"{identifier} text is not bundled; use --artifact-root or explicit --fetch")
        try:
            with build_opener(NoRedirects()).open(upstream, timeout=20) as response:
                content = response.read(descriptor["bytes"] + 1)
        except URLError as error:
            raise DataError(f"could not retrieve the pinned SPDX text: {error.reason}") from error
        return checked_bytes(content, descriptor), material

    def _sces_rows(self, kind):
        directory = self.root / "sces" / "records" / kind
        for path in sorted(directory.glob("*.json")):
            require(path.is_file() and path.resolve() == path, f"missing or linked SCES coverage record: {path}")
            yield path.relative_to(self.root).as_posix(), path.read_bytes()

    def _sces_records(self, kind):
        records = {}
        for path, raw in self._sces_rows(kind):
            row = decode(raw)
            reference = _sces_reference(row)
            require(reference is not None and reference[0] == kind
                    and path == f"sces/records/{kind}/{reference[1]}--{reference[2]}.json"
                    and reference not in records, f"{path}: invalid SCES coverage record identity")
            records[reference] = row, raw
        return records

    def _recorded_qualification(self):
        claims = self._sces_records("claim")
        dispositions = self._sces_records("disposition")
        verifications = self._sces_records("verification")
        latest_verifications = {}
        for reference, (row, _) in verifications.items():
            target = _sces_reference(row.get("claim"))
            phase = row.get("phase")
            run = row.get("run")
            completed = run.get("completed") if isinstance(run, dict) else None
            require(target in claims and phase in ("research", "independent-review")
                    and isinstance(completed, str) and _SCES_TIMESTAMP.fullmatch(completed),
                    f"{row['id']}: invalid SCES coverage verification completion")
            slot = target, phase
            previous = latest_verifications.get(slot)
            if previous is None or completed > previous[0]:
                latest_verifications[slot] = completed, reference
            elif completed == previous[0]:
                # SCES does not select a review when multiple executions tie at the latest completion.
                latest_verifications[slot] = completed, None
        latest = {}
        for row, _ in dispositions.values():
            target = _sces_reference(row.get("target"))
            require(target is not None and target[0] in {"claim", "source"},
                    f"{row['id']}: invalid SCES coverage disposition target")
            if target[0] == "source":
                continue
            require(target in claims, f"{row['id']}: SCES coverage disposition targets a missing claim")
            previous = latest.get(target)
            require(previous is None or previous["id"] == row["id"],
                    f"{row['id']}: ambiguous SCES coverage disposition")
            if previous is None or row["revision"] > previous["revision"]:
                latest[target] = row
        # Report the retained evidence state. SCES eligibility still requires the pinned validator.
        return {
            "recorded_claim_revisions": len(claims),
            "recorded_independently_reviewed_claims": sum(
                _supported_independent_review(target, disposition, claims[target][1], verifications, latest_verifications)
                for target, disposition in latest.items()
            ),
            "recorded_invalidated_claim_revisions": sum(
                disposition.get("verification") == "invalidated" for disposition in latest.values()
            ),
        }

    def _research_depth(self):
        dimensions = {identifier: profile["dimensions"] for identifier, profile in self.profiles.items()}
        states = Counter(value["state"] for profile in dimensions.values() for value in profile.values())
        require(states.keys() <= DIMENSION_STATES, "invalid research dimension state")
        return {
            "dimensions": sum(states.values()),
            "dimension_states": dict(states),
            "dimension_assessments_sha256": sha256(encode(dimensions)).hexdigest(),
            "scenarios": sum(len(profile["scenarios"]) for profile in self.profiles.values()),
        }

    def coverage(self, qualified_claims=(), *, schema_version=COVERAGE_VERSION):
        require(schema_version in COVERAGE_VERSIONS,
                f"unknown coverage assessment schema version: {schema_version!r}")
        active = self.active_spdx
        installable = {row["origin"]["identifier"] for row in active if is_installation_target(row)}
        mit_text = self.spdx["mit"]["origin"]["artifacts"].get("text") if "MIT" in installable else None
        assessment = {
            "scope": "SPDX discovery and publisher leads",
            "catalog": {
                "spdx_licenses": sum(row["origin"]["list_kind"] == "license" for row in active),
                "spdx_exceptions": sum(row["origin"]["list_kind"] == "exception" for row in active),
                "spdx_deprecated_licenses": sum(row["origin"]["list_kind"] == "license"
                                                and row["origin"]["deprecated"] for row in active),
                "spdx_deprecated_exceptions": sum(row["origin"]["list_kind"] == "exception"
                                                  and row["origin"]["deprecated"] for row in active),
                "spdx_historical_only": len(self.spdx) - len(active),
                "spdx_deprecated_with_replacement_guidance": sum(
                    bool(row["origin"].get("upstream_replacements")) for row in active),
                "beyond_spdx_leads": len(self.non_spdx),
                "beyond_spdx_dispositions": dict(Counter(row["disposition"] for row in self.non_spdx)),
                "accepted_entities": len(self.entities) if qualified_claims else 0,
            },
            "authentic_text": {
                "spdx_text_references": sum(bool(row["origin"]["artifacts"].get("text")) for row in active),
                "spdx_matching_template_references": sum(bool(row["origin"]["artifacts"].get("template"))
                                                         for row in active),
                "spdx_header_references": sum(bool(row["origin"].get("headers")) for row in active),
                "bundled_publisher_text_identities": len(self.packaged),
                "bundled_publisher_text_files": len({item["path"] for item in self.packaged.values()}),
            },
            "installation": {
                "offline": sorted(key for key, package in self.packaged.items()
                                  if key in installable and package.get("install") == "unchanged"),
                "requires_verified_companion": sorted(key for key, package in self.packaged.items()
                                                      if key in installable and package.get("install") == LGPL_V3_SUPPLEMENT),
                "requires_verified_spdx_input": ["MIT"] if mit_text and not self.packaged.get("MIT") else [],
            },
            "research": {
                "provisional_explanations": len(self.profiles),
                "spdx_without_provisional_explanation": sum(self.profile(row) is None for row in active),
            },
            "qualification": {"status": "qualified-selection" if qualified_claims else "development"},
        }
        qualification = assessment["qualification"]
        if schema_version == LEGACY_COVERAGE_VERSION:
            qualification["independently_verified_claims"] = len(qualified_claims)
        else:
            assessment["catalog"]["candidate_dispositions"] = dict(
                Counter(row["disposition"] for row in self.candidates.values())
            )
            qualification.update(self._recorded_qualification(), selected_claims=len(qualified_claims))
        if schema_version in (COVERAGE_VERSION_V3, COVERAGE_VERSION):
            assessment["research"].update(self._research_depth())
        return assessment


def is_removed(row):
    return row.get("membership", {}).get("status") == "removed"


def is_installation_target(row):
    origin = row["origin"]
    return (origin["kind"] == "spdx" and origin.get("list_kind") == "license"
            and origin.get("deprecated") is False and not is_removed(row))
