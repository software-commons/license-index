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

    def _read_sharded(self, kind):
        rows = {}
        for path in sorted((self.root / "registry" / kind).rglob("*.json")):
            row = read(path)
            identifier = row.get("id", "")
            require(OPAQUE_ID.fullmatch(identifier), f"invalid permanent ID: {path}")
            require(path.parent.name == identifier[:2] and path.stem == identifier
                    and path.parent.parent == self.root / "registry" / kind,
                    f"incorrect shard or filename: {path}")
            require(identifier not in rows, f"duplicate permanent ID: {identifier}")
            rows[identifier] = row
        return rows

    @property
    def active_spdx(self):
        return [row for row in self.spdx.values() if not is_removed(row)]

    def exact(self, value):
        key = value.casefold()
        if key in self.candidates:
            return self.candidates[key]
        if key in self.spdx:
            return self.spdx[key]
        matches = [row for row in self.non_spdx if row["origin"]["identifier"].casefold() == key]
        require(len(matches) <= 1, f"ambiguous candidate identifier: {value}")
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

    def coverage(self, qualified_claims=()):
        active = self.active_spdx
        return {
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
                "offline": sorted(key for key, package in self.packaged.items() if package.get("install") == "unchanged"),
                "requires_verified_companion": sorted(key for key, package in self.packaged.items()
                                                      if package.get("install") == LGPL_V3_SUPPLEMENT),
                "requires_verified_spdx_input": ["MIT"] if "mit" in self.spdx else [],
            },
            "research": {
                "provisional_explanations": len(self.profiles),
                "spdx_without_provisional_explanation": sum(self.profile(row) is None for row in active),
            },
            "qualification": {
                "independently_verified_claims": len(qualified_claims),
                "status": "qualified-selection" if qualified_claims else "development",
            },
        }


def is_removed(row):
    return row.get("membership", {}).get("status") == "removed"
