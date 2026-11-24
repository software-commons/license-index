"""Validate development inputs and build deterministic offline artifacts."""

from __future__ import annotations

from functools import cache, partial
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from urllib.request import Request, build_opener
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from .coverage_context import COVERAGE, SNAPSHOTS, validate_coverage_context
from .li_install import LGPL_V3_IDS, LGPL_V3_SUPPLEMENT, write_license
from .qualification import _blob_hash, _exact_file, _git, _git_blobs, _qualified_historical, check_history, qualified
from .reconcile import RELEASE
from .records import (
    COVERAGE_VERSION, COVERAGE_VERSIONS, DATA_COMMIT, DIMENSION_STATES, HEX_256, LEGACY_COVERAGE_VERSION,
    VERSION, Catalog, DataError,
    NoRedirects, checked_bytes, decode, encode, is_removed, local_path, read, require,
)

DATA_DIRECTORIES = ("sces", "registry", "research", "legal-texts")
DISCOVERY_EXPORT = "catalog.json"
SCES_PUBLICATION = "sces/publication.json"
COVERAGE_SCES_SECTIONS = ("sces/records/claim", "sces/records/disposition", "sces/records/verification")
RECORDED_EVIDENCE_COUNTS = ("recorded_claim_revisions", "recorded_independently_reviewed_claims",
                            "recorded_invalidated_claim_revisions")
SOURCES = "research/sources"
SPDX_SOURCE = re.compile(rf"{SOURCES}/spdx-[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9a-f]{{40}})?\.json")
PACKAGED_TEXTS = "legal-texts/manifest.json"
PROFILES = "research/campaigns/profiles.json"
QUALIFICATION_SCOPE = "development-discovery"
CC_REVISION = "91780e140892982eb3e0d530591ccbbca0d4690d"
CC_PUBLISHER_TREE = f"https://raw.githubusercontent.com/creativecommons/cc-legal-tools-data/{CC_REVISION}"
CC_RIGHTS = f"{CC_PUBLISHER_TREE}/README.md"
CC_RIGHTS_SHA256 = "76eac782e1d4ea9bdcd0b88686f315fe42076b70af238a44114e87f024fe096f"
CC_LEGAL_TEXTS = {
    "CC-BY-4.0": ("licenses/by/4.0/legalcode.txt", "9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411"),
    "CC-BY-NC-4.0": ("licenses/by-nc/4.0/legalcode.txt",
                     "41003d4a74749c0220e33dd415042164b5a1093ed401f36277234f772d22d3d0"),
    "CC-BY-NC-ND-4.0": ("licenses/by-nc-nd/4.0/legalcode.txt",
                        "38762e3777f4ec00a6f769062a7c3f704fb78ce08303ecff88558da4c49cf9ea"),
    "CC-BY-NC-SA-4.0": ("licenses/by-nc-sa/4.0/legalcode.txt",
                        "e66c269d4819aaab34b49ef5220c4ddab6756f21bb5180761a4eb8561f2b7bbd"),
    "CC-BY-ND-4.0": ("licenses/by-nd/4.0/legalcode.txt",
                     "9cc97638cf0185884ac800144b6246c7772f94ff2cc70686afa9574aaea4fa2b"),
    "CC-BY-SA-4.0": ("licenses/by-sa/4.0/legalcode.txt",
                     "28a9529c7d0bb4dc51f4bf5c116a3d16ef247a052f7591466768ddf563fd1cf5"),
    "CC0-1.0": ("publicdomain/zero/1.0/legalcode.txt", "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"),
}
CC_LEGACY_EDITIONS = {"CC-BY-4.0", "CC0-1.0"}
CC_LEGACY_RIGHTS = {"https://creativecommons.org/policies/", "https://creativecommons.org/policies/#cc-licensing-statement"}
POLYFORM_REVISION = "a2316cfa35d3947fdc5af4bcc1f321662bfd79d8"
POLYFORM_PUBLISHER_TREE = f"https://raw.githubusercontent.com/polyformproject/polyform-licenses/{POLYFORM_REVISION}"
POLYFORM_RIGHTS = f"{POLYFORM_PUBLISHER_TREE}/LICENSE.md"
POLYFORM_RIGHTS_SHA256 = "d04a8527e90a7f7fe36083fa1fd25db16b0e43c2244f4f6880f7a2c5d18c631e"
POLYFORM_LEGAL_TEXTS = {
    "PolyForm-Noncommercial-1.0.0": "c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5",
    "PolyForm-Small-Business-1.0.0": "03eea824bff13316b767424b3e8f49538b46e52d897aecc87d6344343364aa56",
}
GNU_LICENSE_FTP = "https://ftp.gnu.org/pub/gnu/Licenses"
GNU_LICENSE_WEB = "https://www.gnu.org/licenses"
GNU_LEGAL_TEXTS = {
    "AGPL-3.0": (f"{GNU_LICENSE_FTP}/agpl-3.0.txt",
                 "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"),
    "GFDL-1.1": (f"{GNU_LICENSE_FTP}/fdl-1.1.txt",
                 "1040f0fffcf5a73398512aaa3f7cf89b7e4bb8feb13c661ad71184e015c7fcb6"),
    "GFDL-1.2": (f"{GNU_LICENSE_FTP}/fdl-1.2.txt",
                 "2652c22ba086f92e55ae4a9f9c890ad4766ffd7814a73d318e22a597edf857a4"),
    "GFDL-1.3": (f"{GNU_LICENSE_FTP}/fdl-1.3.txt",
                 "110535522396708cea37c72a802c5e7e81391139f5f7985631c93ef242b206a4"),
    "GPL-1.0": (f"{GNU_LICENSE_FTP}/gpl-1.0.txt",
                "49c007bafb5ad6dd9f9d4dae4d3ac0461975498150c05d684c551f0914ab486c"),
    "GPL-2.0": (f"{GNU_LICENSE_WEB}/gpl-2.0.txt",
                "edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6"),
    "GPL-3.0": (f"{GNU_LICENSE_WEB}/gpl-3.0.txt",
                "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"),
    "LGPL-2.0": (f"{GNU_LICENSE_FTP}/lgpl-2.0.txt",
                 "cc535c21133c895b56b374c8a1dc1eb948d99003ed2b47372069456b62f42b24"),
    "LGPL-2.1": (f"{GNU_LICENSE_FTP}/lgpl-2.1.txt",
                 "20e50fe7aae3e56378ebf0417d9de904f55a0e61e4df315333e632a4d3555d95"),
    "LGPL-3.0": (f"{GNU_LICENSE_FTP}/lgpl-3.0.txt",
                 "e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118"),
}
GNU_VERSION_SUFFIXES = ("only", "or-later")
GFDL_SUFFIXES = (*GNU_VERSION_SUFFIXES, "invariants-only", "invariants-or-later",
                 "no-invariants-only", "no-invariants-or-later")
APACHE_REVISION = "01b1be9fbc5cd93b6794f5653a58b9b863807f84"
GCC_REVISION = "04696df09633baf97cdbbdd6e9929b9d472161d3"
PLAINTEXT_PUBLISHER_TEXTS = {
    **{f"{edition}-{variant}": pins for edition, pins in GNU_LEGAL_TEXTS.items()
       for variant in (GFDL_SUFFIXES if edition.startswith("GFDL-") else GNU_VERSION_SUFFIXES)},
    "Apache-2.0": (
        f"https://raw.githubusercontent.com/apache/www-site/{APACHE_REVISION}/content/licenses/LICENSE-2.0.txt",
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    ),
    "EPL-1.0": ("https://www.eclipse.org/org/documents/epl-1.0/EPL-1.0.txt",
                "04132df1d27e9f0062df1503f88af2cc4ce4e7c75d0fe6eea5eda636bb2920bb"),
    "EPL-2.0": ("https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.txt",
                "0becf16567beb77fa252b7664631dd177c8f9a1889e48995b45379c7130e5303"),
    "GCC-exception-3.1": (f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/COPYING.RUNTIME",
                          "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74"),
}
PLAINTEXT_REVISIONS = {"Apache-2.0": APACHE_REVISION, "GCC-exception-3.1": GCC_REVISION}
PLAINTEXT_RIGHTS_REFERENCES = {
    **{f"GPL-2.0-{variant}": f"{GNU_LICENSE_WEB}/old-licenses/gpl-2.0.en.html" for variant in GNU_VERSION_SUFFIXES},
    **{f"GPL-3.0-{variant}": f"{GNU_LICENSE_WEB}/gpl-3.0.en.html" for variant in GNU_VERSION_SUFFIXES},
    "Apache-2.0": "https://www.apache.org/foundation/license-faq.html#mod-license",
    "GCC-exception-3.1": f"https://github.com/gcc-mirror/gcc/blob/{GCC_REVISION}/COPYING.RUNTIME#L5-L8",
}
PUBLISHER_TEXT_REPRESENTATIONS = {
    **dict.fromkeys(POLYFORM_LEGAL_TEXTS, "publisher source Markdown"),
    **dict.fromkeys(LGPL_V3_IDS, "publisher plain text supplement"),
    "GCC-exception-3.1": "publisher release plain text",
}
# A version election can differ even where the publisher text bytes are shared.
GNU_APPLICATION_SHA256 = {
    "AGPL-3.0-only": "a622710b2c6f5e32a06c847aa1981ce2f4672a45a68301a60f3f3e0a5a0f8d13",
    "AGPL-3.0-or-later": "4eaadf3ce2656c6de585d4437241c395458b6d11cc2d630ec005f9a0eff6608b",
    "GFDL-1.1-invariants-only": "c5f25585e0c390c25d7be9355a1af52e387931ebce4579433b0007ad1d688d26",
    "GFDL-1.1-invariants-or-later": "e583bfd5a076cde0a2fba53d1609091ef1b116d4f77275cf052deb6b85711cae",
    "GFDL-1.1-no-invariants-only": "84a25013dd51d1e789159a0edf36c31e92089fa244873f09ae7a872e3f6dff7b",
    "GFDL-1.1-no-invariants-or-later": "60c3f3b5e475cf5b9e57864f1daa147fdc52274262638c69db0a495c11b91f33",
    "GFDL-1.1-only": "8287bf8c0063186242aec20a10a188577b13f240b54d48ca019b4ba36b3685c9",
    "GFDL-1.1-or-later": "cbe3c88f2f05a1594f4e79c6e94560a5b072fd895933c927e05b229edbc2dee0",
    "GFDL-1.2-invariants-only": "afc5f2e77d338b626368ebd077f13ad8ae49d41769fa8d7a89bb7a6724f46845",
    "GFDL-1.2-invariants-or-later": "ed51e1dd92ab41283a2f226d11f6f7cb75da739bc3430021a3dffa89652099ff",
    "GFDL-1.2-no-invariants-only": "414cd2510d0c4b75381c3a7ea7841e38135c694deef8b3d738d2a246fbcd725d",
    "GFDL-1.2-no-invariants-or-later": "381cc88c6865af36938a87d25382cec61607bbe2e82c88380f562747929ed17b",
    "GFDL-1.2-only": "dd9a92eb59253ea66726a6bf75d1305deb919f00e4c21b879a7ea750ed8d7164",
    "GFDL-1.2-or-later": "d475790910b5dcb3f747681ea103757d3615fc4cd2f73efca0d2903426a6a858",
    "GFDL-1.3-invariants-only": "eb0a864cabb2f1f5d9d7b7b1fd33043ac8d5497aa27980933bd5779a33fd27e0",
    "GFDL-1.3-invariants-or-later": "86a30dbc676d60cc259ac449f18b3cc563e51dc2571c0f71deb7131259f79415",
    "GFDL-1.3-no-invariants-only": "f6e208e0e8044b0ce9e085425f949e3a9c0faa44ba13453e5a0467cea6147211",
    "GFDL-1.3-no-invariants-or-later": "7313fa74b7735039822208d6a8f90221beee952dca4c02e10f5be8c1c6e4e8c7",
    "GFDL-1.3-only": "0098cbc559b7b10c754192c920ee9f9d8148181909957a85d056925f7ef650f4",
    "GFDL-1.3-or-later": "45fb1b69f06c1b9f24f502fd6e6e5f1a4af73ca638d6b339946d2baa052adf95",
    "GPL-1.0-only": "ed06bc5a06a287c8f56e93ee0b7df9f6cb71230dcb90b7472c46c44aaf859226",
    "GPL-1.0-or-later": "a263a0945a785e42ffcbad87de5b9c71645c56e4b438048aae91f97acb060b98",
    "GPL-2.0-only": "70cbf5dff312b2af4df9b6cf34781f8b4c3f1df78ec9f2c6856d620b445aa123",
    "GPL-2.0-or-later": "2c9928d8cc3ce2389117af24b36f9bfe05fde9b5ddf04fa1cce001a61bd5c06e",
    "GPL-3.0-only": "8d245f516775644079119547037710d3e1040f94c811da7042e50d7c76909365",
    "GPL-3.0-or-later": "7fe192215109d413bb64380bf7dc395efd0790f56824b329842837450bccb0b9",
    "LGPL-2.0-only": "ba64a5773a2e98b15a3190cfa7dd899c853bc5b3c20bd9da6c13097bfc329d32",
    "LGPL-2.0-or-later": "f83982f228b9ca8eff8d761bfdf6300b2070725773caa2d2308e77825a76e919",
    "LGPL-2.1-only": "83c5f1154492188ffb9589a79e19123fd96421007f66da6773fb7b5b2d34607b",
    "LGPL-2.1-or-later": "f739bc888130dc2efc97315f1e501d6522ce928dbabbf04116eb536ae14a909f",
    "LGPL-3.0-only": "e498bd07d6a206d8708866d3a77cc654216e5f84f07f3badfd0422295f956bd2",
    "LGPL-3.0-or-later": "a8640e3a5d65c3d0862d19c2e4081f0aa6bec5aba0d3e401b0cef74b0ef3aeba",
}
GNU_ARCHIVED_APPLICATION_SHA256 = {
    "GPL-2.0-only": "629b5a82fa04c93a955aa8c2a38aabc29d45ca882c6031152d39da38deefb51d",
    "GPL-3.0-only": "629b5a82fa04c93a955aa8c2a38aabc29d45ca882c6031152d39da38deefb51d",
}
RIGHTS_DOCUMENTS = {CC_RIGHTS: "cc-rights-exact.md", POLYFORM_RIGHTS: "polyform-rights-exact.md"}
RIGHTS_BY_IDENTIFIER = {
    **dict.fromkeys(CC_LEGAL_TEXTS, CC_RIGHTS),
    **dict.fromkeys(POLYFORM_LEGAL_TEXTS, POLYFORM_RIGHTS),
}
RIGHTS_MAX_BYTES = 64 * 1024
BUNDLE_SUPPORT = {
    "LICENSE", "README.md", "license-index", "license-index.cmd", COVERAGE,
    "docs/CLI.md", "docs/CODEX_GATE.md", "docs/GOVERNANCE_REVIEW.md", "docs/MAINTENANCE.md",
    "docs/PROFILE_QUALIFICATION.md", "docs/PUBLICATION.md", "docs/RESEARCH_STATUS.md", "docs/SCOPE.md",
    "research/sources/predecessor-assessment.md", "schemas/domain/registry-v1.schema.json",
    "tools/__init__.py", "tools/coverage_context.py", "tools/distribution.py", "tools/index.py", "tools/li_install.py",
    "tools/qualification.py", "tools/reconcile.py", "tools/records.py", "tools/review_plan.py",
    "tools/run_isolated.py", "tools/schema_check.py", "tools/spdx_replay.py",
}


def descriptor(value):
    require(isinstance(value["path"], str) and HEX_256.fullmatch(value["sha256"])
            and type(value["bytes"]) is int and value["bytes"] > 0, "invalid artifact descriptor")


def validate_source(catalog, source):
    require(DATA_COMMIT.fullmatch(source["data_commit"]) and DATA_COMMIT.fullmatch(source["xml_commit"]),
            "invalid SPDX source commit")
    for value in source["manifests"].values():
        descriptor(value)
    expected = source["population"]
    catalog_counts = catalog.coverage(schema_version=LEGACY_COVERAGE_VERSION)["catalog"]
    for field in ("licenses", "exceptions", "deprecated_licenses", "deprecated_exceptions"):
        require(expected[field] == catalog_counts[f"spdx_{field}"], f"SPDX population mismatch: {field}")
    for key in ("text", "template"):
        count = sum(key not in row["origin"]["artifacts"] for row in catalog.active_spdx)
        require(expected[f"missing_{key}"] == count, f"SPDX missing {key} count mismatch")
    for row in catalog.active_spdx:
        origin = row["origin"]
        require("detail" in origin["artifacts"], f"missing SPDX detail: {origin['identifier']}")
        for value in origin["artifacts"].values():
            descriptor(value)
        metadata = origin["metadata"]
        field = "licenseId" if origin["list_kind"] == "license" else "licenseExceptionId"
        require((metadata[field], metadata["name"], metadata["isDeprecatedLicenseId"]) ==
                (origin["identifier"], origin["name"], origin["deprecated"]),
                f"SPDX identity drift: {origin['identifier']}")

    # Exported discovery records retain artifact origins even after an identifier is removed
    # or its origin moves to history. These pins do not affect the current population.
    origin_pins = set()
    for row in catalog.candidates.values():
        origins = [row["origin"]]
        origins.extend(note.get("origin") for note in row.get("history", ()))
        for origin in origins:
            if isinstance(origin, dict) and origin.get("kind") == "spdx":
                origin_pins.add((origin["release"], origin["source"]))
    retained_paths = set()
    for release, commit in sorted(origin_pins - {(source.get("release"), source["data_commit"])}):
        require(RELEASE.fullmatch(release) and DATA_COMMIT.fullmatch(commit), "invalid retained SPDX source pin")
        for suffix in ("", f"-{commit}"):
            name = f"{SOURCES}/spdx-{release}{suffix}.json"
            prior = catalog._optional(name)
            if (prior.get("release"), prior.get("data_commit")) == (release, commit):
                retained_paths.add(name)
                break
        else:
            raise DataError(f"unregistered retained SPDX source pin: {release} at {commit}")
    return retained_paths


def read_rights_document(url, *, root=None):
    require(url in RIGHTS_DOCUMENTS, "unapproved publisher rights locator")
    if root is not None:
        path = local_path(root, RIGHTS_DOCUMENTS[url])
        require(path.is_file() and path.resolve() == path, f"missing or linked rights document: {path}")
        with path.open("rb") as body:
            data = body.read(RIGHTS_MAX_BYTES + 1)
    else:
        request = Request(url, headers={"User-Agent": "software-commons-license-index"}, method="GET")
        with build_opener(NoRedirects()).open(request, timeout=20) as body:
            require(body.status == 200 and body.geturl() == url, "unexpected publisher rights response")
            data = body.read(RIGHTS_MAX_BYTES + 1)
    require(0 < len(data) <= RIGHTS_MAX_BYTES, "publisher rights document has invalid size")
    return data


def validate_publisher_package(identifier, package, *, archived=False):
    """Check the exact edition and provenance, returning a rights-document pin when retained."""
    expected_url = RIGHTS_BY_IDENTIFIER.get(identifier)
    require(identifier in PLAINTEXT_PUBLISHER_TEXTS or expected_url is not None,
            f"no admitted publisher text binding for {identifier}")
    representation = PUBLISHER_TEXT_REPRESENTATIONS.get(identifier, "publisher plain text")
    require(package.get("representation") == representation,
            f"unexpected admitted publisher text representation for {identifier}")
    url, digest = package.get("rights"), package.get("rights_sha256")
    if identifier in PLAINTEXT_PUBLISHER_TEXTS:
        source, text_digest = PLAINTEXT_PUBLISHER_TEXTS[identifier]
        revision = PLAINTEXT_REVISIONS.get(identifier, "edition plus SHA-256")
        require(package.get("sha256") == text_digest,
                f"unexpected admitted publisher text digest for {identifier}")
        require(package.get("source") == source and package.get("revision") == revision,
                f"unapproved publisher text locator for {identifier}")
        require(url == PLAINTEXT_RIGHTS_REFERENCES.get(identifier, source),
                f"unapproved publisher rights locator for {identifier}")
        require(digest is None, f"invalid rights digest for {identifier}")
        if identifier in GNU_APPLICATION_SHA256 and package.get("install"):
            application = package.get("application")
            require(isinstance(application, str), f"missing publisher application guidance for {identifier}")
            measured = sha256(application.encode("utf-8")).hexdigest()
            require(measured == GNU_APPLICATION_SHA256[identifier]
                    or (archived and measured == GNU_ARCHIVED_APPLICATION_SHA256.get(identifier)),
                    f"unexpected publisher application guidance for {identifier}")
        return None

    if identifier in CC_LEGAL_TEXTS:
        publisher_path, text_digest = CC_LEGAL_TEXTS[identifier]
        require(package["sha256"] == text_digest, f"unexpected admitted publisher text digest for {identifier}")
        if archived and identifier in CC_LEGACY_EDITIONS and "rights_sha256" not in package:
            # Bind the exact legacy edition already in Git to the same publisher statement without rewriting it.
            require(url in CC_LEGACY_RIGHTS and package["source"] == f"https://creativecommons.org/{publisher_path}",
                    f"unverified archival publisher reference for {identifier}")
            url, digest = CC_RIGHTS, CC_RIGHTS_SHA256
        else:
            require(package["source"] == f"{CC_PUBLISHER_TREE}/docs/{publisher_path}" and package["revision"] == CC_REVISION,
                    f"unapproved publisher text locator for {identifier}")
            require(digest == CC_RIGHTS_SHA256, f"invalid rights digest for {identifier}")
    elif identifier in POLYFORM_LEGAL_TEXTS:
        require(package["sha256"] == POLYFORM_LEGAL_TEXTS[identifier],
                f"unexpected admitted publisher text digest for {identifier}")
        require(package["source"] == f"{POLYFORM_PUBLISHER_TREE}/{identifier}.md"
                and package.get("revision") == POLYFORM_REVISION,
                f"unapproved publisher text locator for {identifier}")
        require(digest == POLYFORM_RIGHTS_SHA256, f"invalid rights digest for {identifier}")
    require(url == expected_url, f"unapproved publisher rights locator for {identifier}")
    require(isinstance(digest, str) and HEX_256.fullmatch(digest), f"invalid rights digest for {identifier}")
    return url, digest


def _validate_text_rights(identifier, package, rights_reader, *, archived):
    proof = validate_publisher_package(identifier, package, archived=archived)
    if proof is not None and rights_reader is not None:
        url, digest = proof
        require(sha256(rights_reader(url)).hexdigest() == digest, f"publisher rights SHA-256 mismatch for {identifier}")


def validate_texts(catalog, read_bytes=None, *, rights_reader=None, archived=False):
    for identifier, package in catalog.packaged.items():
        row = catalog.resolve(identifier)
        origin = row["origin"]
        require(origin["identifier"] == identifier and origin["kind"] == "spdx",
                f"ambiguous text binding: {identifier}")
        descriptor(package)
        path = local_path(catalog.root, package["path"])
        content = checked_bytes(path.read_bytes() if read_bytes is None else read_bytes(package["path"]), package)
        content.decode("utf-8")
        require(package["source"].startswith("https://") and package["rights"].startswith("https://"),
                f"missing publication provenance for {identifier}")
        _validate_text_rights(identifier, package, rights_reader, archived=archived)
        recipe = package.get("install")
        require(recipe in {None, "unchanged", LGPL_V3_SUPPLEMENT}, f"unexpected bundle treatment: {identifier}")
        if recipe:
            require(origin["list_kind"] == "license" and not origin["deprecated"]
                    and not is_removed(row) and package.get("application"),
                    f"invalid installation target: {identifier}")
            lgplv3 = identifier in LGPL_V3_IDS
            require((recipe == LGPL_V3_SUPPLEMENT) == lgplv3, f"incorrect GPLv3 companion requirement: {identifier}")
            if lgplv3:
                require(catalog.packaged.get("GPL-3.0-only", {}).get("install") == "unchanged",
                        "LGPLv3 installation requires the bundled unchanged GPLv3 text")


def validate_profiles(catalog):
    for identifier, profile in catalog.profiles.items():
        row = catalog.resolve(identifier)
        require(row["origin"]["kind"] == "spdx" and row["origin"]["identifier"] == identifier,
                f"missing exact profile subject for {identifier}")
        require(profile["summary"] and profile["dimensions"] and profile["scenarios"],
                f"incomplete provisional profile for {identifier}")
        for value in profile["dimensions"].values():
            require(value["state"] in DIMENSION_STATES, f"invalid research state for {identifier}")
            require(value["sources"] or value["state"] in {"unresolved", "inapplicable"},
                    f"asserted dimension lacks an evidence locator for {identifier}")
        for value in profile["scenarios"]:
            require(value["sources"], f"scenario lacks an evidence locator for {identifier}")
        for value in [*profile["dimensions"].values(), *profile["scenarios"]]:
            require(value["text"], f"empty finding for {identifier}")
            for citation in value["sources"]:
                require(citation["url"].startswith("https://") and citation["locator"],
                        f"invalid evidence locator for {identifier}")


def _current_snapshot(catalog):
    current = _exact_file(catalog.root / COVERAGE)
    saved = decode(current)
    require(saved.get("schema_version") == COVERAGE_VERSION,
            f"current coverage must use schema {COVERAGE_VERSION}")
    name = saved["snapshot"]
    snapshot = local_path(catalog.root, name)
    require(name.startswith(f"{SNAPSHOTS}/") and snapshot.suffix == ".json"
            and snapshot.relative_to(catalog.root).as_posix() == name,
            "current coverage must name a JSON archive under registry/coverage/snapshots")
    require(_exact_file(snapshot) == current,
            "current coverage differs from its immutable snapshot")
    if saved["schema_version"] == "4.0.0":
        validate_coverage_context(catalog.root, saved)
    return saved


def _is_evidence_omitting_bundle(catalog, base, policy):
    root = catalog.root
    return (base is None and policy is None and (root / DISCOVERY_EXPORT).is_file()
            and not any((root / name).exists() or (root / name).is_symlink()
                        for name in (".git", ".github", "sces/adoption.json", "sces/records",
                                     SCES_PUBLICATION, "sces/releases", "registry/entities")))


def _has_active_selection(catalog):
    path = catalog.root / SCES_PUBLICATION
    return path.exists() or path.is_symlink()


def _apply_bundle_evidence(catalog, assessment, snapshot):
    require(_exact_file(catalog.root / DISCOVERY_EXPORT) == encode(discovery_export(catalog)),
            "offline catalog export differs from the complete discovery data and coverage snapshot digest")
    recorded = snapshot["assessment"]["qualification"]
    counts = {key: recorded.get(key) for key in RECORDED_EVIDENCE_COUNTS}
    require(all(type(value) is int and value >= 0 for value in counts.values())
            and counts["recorded_independently_reviewed_claims"] + counts["recorded_invalidated_claim_revisions"]
            <= counts["recorded_claim_revisions"], "invalid recorded evidence counts in offline coverage")
    assessment["qualification"].update(counts)


def _bundle_recorded_selection(snapshot):
    assessment = snapshot["assessment"]
    qualification = assessment["qualification"]
    accepted = assessment["catalog"].get("accepted_entities")
    selected = qualification.get("selected_claims")
    status = qualification.get("status")
    require(type(accepted) is int and type(selected) is int
            and (status == "development" and accepted == selected == 0
                 or status == "qualified-selection" and 0 < accepted <= selected <= qualification["recorded_claim_revisions"]),
            "invalid recorded selection counts in offline coverage")
    return {"accepted_entities": accepted, "selected_claims": selected, "status": status}


def coverage_assessment(catalog, qualified_claims=(), *, base=None, policy=None):
    """Report recorded evidence separately from policy-validated active selection."""
    require(policy is not None or not _has_active_selection(catalog),
            "active SCES publication requires --policy with the pinned bundle")
    assessment = catalog.coverage(qualified_claims)
    if not qualified_claims and _is_evidence_omitting_bundle(catalog, base, policy):
        saved = _current_snapshot(catalog)
        _apply_bundle_evidence(catalog, assessment, saved)
        assessment["qualification"].update(
            recorded_evidence_basis="distribution-snapshot",
            selection_basis="unverified-distribution-snapshot",
            recorded_selection=_bundle_recorded_selection(saved),
        )
    return assessment


def validate_discovery(catalog, *, base=None, policy=None, spdx_archive=None, fetch_spdx_archive=False,
                       rights_reader=None):
    claims = qualified(catalog, policy, base=base)[1] if _has_active_selection(catalog) else ()
    return _validate_discovery(catalog, claims, base=base, policy=policy, spdx_archive=spdx_archive,
                               fetch_spdx_archive=fetch_spdx_archive, rights_reader=rights_reader)


def _validate_discovery(catalog, checked_claims, *, base=None, policy=None, spdx_archive=None,
                        fetch_spdx_archive=False, rights_reader=None):
    saved = _current_snapshot(catalog)
    source = read(local_path(catalog.root, saved["source_manifest"]))
    retained_sources = validate_source(catalog, source)
    validate_texts(catalog, rights_reader=rights_reader)
    validate_profiles(catalog)
    expected = catalog.coverage(checked_claims, schema_version=saved["schema_version"])
    if _is_evidence_omitting_bundle(catalog, base, policy):
        _apply_bundle_evidence(catalog, expected, saved)
        recorded = _bundle_recorded_selection(saved)
        expected["catalog"]["accepted_entities"] = recorded["accepted_entities"]
        expected["qualification"].update(selected_claims=recorded["selected_claims"], status=recorded["status"])
    require(encode(saved["assessment"]) == encode(expected),
            "discovery coverage snapshot differs from the live ledger")
    if spdx_archive is not None or fetch_spdx_archive:
        from .spdx_replay import replay, replay_download
        if spdx_archive is not None:
            replay(catalog, source, spdx_archive, base)
        else:
            replay_download(catalog, source, base)
    return saved, retained_sources


class _HistoricalCatalog(Catalog):
    """Replay current discovery logic over immutable JSON from one Git tree."""

    def __init__(self, root, rows, sces_rows):
        self._rows = rows
        self._historical_sces = sces_rows
        super().__init__(root)

    def _optional(self, relative):
        return self._rows.get(relative, {})

    def _sharded_rows(self, kind):
        prefix = f"registry/{kind}/"
        return ((name, row) for name, row in self._rows.items()
                if name.startswith(prefix) and name.endswith(".json"))

    def _sces_rows(self, kind):
        prefix = f"sces/records/{kind}/"
        return ((name, raw) for name, raw in self._historical_sces.items()
                if name.startswith(prefix) and name.endswith(".json") and "/" not in name[len(prefix):])


def _read_git_blobs(root, paths, cache):
    missing = sorted(set(paths.values()) - cache.keys())
    if missing:
        request = "".join(f"{oid}\n" for oid in missing).encode("ascii")
        with BytesIO(_git(root, "cat-file", "--batch", input_data=request)) as stream:
            for oid in missing:
                header = stream.readline().split()
                require(len(header) == 3 and header[:2] == [oid.encode("ascii"), b"blob"]
                        and header[2].isdigit(), f"missing or invalid historical Git blob: {oid}")
                payload = stream.read(int(header[2]))
                require(len(payload) == int(header[2]) and stream.read(1) == b"\n",
                        f"truncated historical Git blob: {oid}")
                cache[oid] = payload
            require(not stream.read(1), "unexpected data after historical Git blobs")
    return {path: cache[oid] for path, oid in paths.items()}


def _historical_spdx_base(root, base, commit, verified):
    ancestors = _git(root, "rev-list", "--topo-order", f"{commit}^@", f"^{base}").decode().splitlines()
    previous = next((ancestor for ancestor in ancestors if ancestor in verified), None)
    if previous is not None:
        return previous
    return _git(root, "merge-base", base, commit).decode().strip()


# The foundation's first snapshot was a draft until the header count was corrected.
_FOUNDATION_DRAFT_COMMITS = {
    "0401697e3e641a6611380d213c1ac67be6422d7c",
    "fc28454a9c689ca9583ce1c6d02ce5b4a4e15673",
}
_FOUNDATION_SNAPSHOT = f"{SNAPSHOTS}/2026-11-22-spdx-3.29.0.json"
_FOUNDATION_DRAFT_BLOB = "894aa11bc1193640994d8a840b0bed42fd635367"
_FOUNDATION_RECORDED_BLOB = "f4de218b0cdaf2c98e57da63cfc2b5302171f303"
# The first scope-aware checkpoint fixes the end of the legacy coverage formats.
_COVERAGE_V4_ADOPTION = "b9d2a140337d441730ece18a1c65aa8e213d661b"


def _incoming_snapshot_origins(root, base, head, tracked, prior):
    revisions = _git(root, "rev-list", "--topo-order", "--reverse", "--parents",
                     f"{base}..{head}").decode().splitlines()
    coverage_by_commit = {}
    prior_by_commit = {base: prior}
    origins = {}
    for revision in revisions:
        commit, *parents = revision.split()
        blobs = _git_blobs(root, commit, COVERAGE, SNAPSHOTS)
        if prior:
            current_prior = {name: blobs[name] for name in prior.keys() & blobs.keys()}
            prior_by_commit[commit] = current_prior
            if current_prior != prior:
                for parent in parents:
                    if parent not in prior_by_commit:
                        prior_by_commit[parent] = _git_blobs(root, parent, SNAPSHOTS)
                for name, oid in prior.items():
                    current = current_prior.get(name)
                    if current == oid:
                        continue
                    parent_blobs = {prior_by_commit[parent].get(name) for parent in parents} or {None}
                    # A side branch can retain its older parent state before inheriting the trusted bytes.
                    require(oid not in parent_blobs and current in parent_blobs,
                            f"{name}: prior coverage snapshot was modified or removed in incoming history at {commit}")
        present = blobs.keys() - prior.keys() - {COVERAGE}
        if (commit in _FOUNDATION_DRAFT_COMMITS
                and blobs.get(_FOUNDATION_SNAPSHOT) == _FOUNDATION_DRAFT_BLOB
                and tracked.get(_FOUNDATION_SNAPSHOT) == _FOUNDATION_RECORDED_BLOB):
            present.discard(_FOUNDATION_SNAPSHOT)
        inherited = set().union(*(coverage_by_commit.get(parent, ()) for parent in parents))
        removed = inherited - present
        require(not removed, f"{commit}: incoming coverage snapshots were removed: {', '.join(sorted(removed))}")
        for name in sorted(present):
            require(name in tracked, f"{name}: incoming coverage snapshot is missing at the candidate tip")
            require(blobs[name] == tracked[name], f"{name}: incoming snapshot bytes changed in history at {commit}")
        for name in sorted(present - inherited):
            require(name not in origins, f"{name}: incoming coverage snapshot has multiple original commits")
            require(blobs.get(COVERAGE) == tracked[name],
                    f"{name}: incoming snapshot was not the exact current ledger when recorded at {commit}")
            origins[name] = commit
        coverage_by_commit[commit] = present
    missing = tracked.keys() - prior.keys() - origins.keys()
    require(not missing, f"coverage snapshots lack an original recorded cutoff: {', '.join(sorted(missing))}")
    return origins


def _checked_historical_claims(root, base, commit, policy, cache):
    require(policy is not None, "historical SCES selection requires --policy with the pinned bundle")
    predecessor = _git(root, "merge-base", base, commit).decode("ascii").strip()
    algorithm = _git(root, "rev-parse", "--show-object-format").decode("ascii").strip()
    object_store = Path(_git(root, "rev-parse", "--path-format=absolute", "--git-path", "objects")
                        .decode("utf-8").strip()).resolve(strict=True)
    alternate = object_store.as_posix()
    require(object_store.is_dir() and "\n" not in alternate and "\r" not in alternate,
            "invalid historical Git object store")
    inventory = _git_blobs(root, commit, "sces", "registry/candidates", "registry/entities")
    blobs = _read_git_blobs(root, inventory, cache)

    # The pinned validator sees a private, data-only checkout with the exact original HEAD.
    with TemporaryDirectory(prefix="license-index-history-") as directory:
        view = Path(directory).resolve()
        _git(view, "init", "--quiet", "--template=", f"--object-format={algorithm}")
        info = view / ".git/objects/info"
        (info / "alternates").write_bytes(f"{alternate}\n".encode("utf-8"))
        (view / ".git/HEAD").write_bytes(f"{commit}\n".encode("ascii"))
        for name, raw in blobs.items():
            path = local_path(view, name)
            require(path.relative_to(view).as_posix() == name and _blob_hash(raw, algorithm) == inventory[name],
                    f"{commit}: invalid historical SCES data blob: {name}")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
        report, claims = _qualified_historical(Catalog(view), policy, base=predecessor, commit=commit)
        require(report and claims, f"{commit}: historical SCES selection was not qualified")
        return claims


def validate_incoming_snapshots(root, base, *, rights_reader=None, replay_spdx=None, policy=None):
    head = _git(root, "rev-parse", "--verify", "HEAD").decode().strip()
    prior = _git_blobs(root, base, SNAPSHOTS)
    _git(root, "merge-base", "--is-ancestor", base, head)
    legacy_origins = None
    if COVERAGE_VERSION == "4.0.0":
        _git(root, "merge-base", "--is-ancestor", _COVERAGE_V4_ADOPTION, head)
        legacy_origins = set(_git(root, "rev-list", _COVERAGE_V4_ADOPTION).decode("ascii").splitlines())
    tracked = _git_blobs(root, head, COVERAGE, SNAPSHOTS)
    current_oid = tracked.pop(COVERAGE, None)
    algorithm = _git(root, "rev-parse", "--show-object-format").decode().strip()
    current = _exact_file(root / COVERAGE)
    require(_blob_hash(current, algorithm) == current_oid, "current coverage differs from the committed ledger")
    selected = decode(current)["snapshot"]
    require(tracked.get(selected) == current_oid, "current coverage does not name an exact committed archive")
    worktree = {path.relative_to(root).as_posix() for path in (root / SNAPSHOTS).rglob("*.json")}
    require(worktree == tracked.keys(), "coverage snapshots must be committed JSON files")
    snapshots = _incoming_snapshot_origins(root, base, head, tracked, prior)
    if not snapshots:
        return
    tracked_sources = _git_blobs(root, head, SOURCES)
    for name in snapshots:
        require(_blob_hash(_exact_file(root / name), algorithm) == tracked[name],
                f"{name}: incoming coverage differs from the committed snapshot")

    cache = {}
    verified = set()
    for name, commit in snapshots.items():
        archived = decode(_read_git_blobs(root, {name: tracked[name]}, cache)[name])
        require(archived["snapshot"] == name, f"{name}: invalid snapshot self-reference")
        version = archived.get("schema_version")
        require(version in COVERAGE_VERSIONS, f"{name}: unsupported coverage schema")
        if version == "4.0.0":
            validate_coverage_context(root, archived, origin=commit)
        elif legacy_origins is not None:
            require(commit in legacy_origins, f"{name}: legacy coverage snapshot was recorded after v4 adoption")
        source = archived["source_manifest"]
        inputs = _git_blobs(root, commit, SOURCES, "registry/candidates", "registry/entities", PACKAGED_TEXTS,
                            PROFILES, SCES_PUBLICATION)
        require(isinstance(source, str) and source.startswith(f"{SOURCES}/") and source in inputs,
                f"{name}: source manifest missing from historical Git tree {commit}")
        require(tracked_sources.get(source) == inputs[source],
                f"{name}: historical source manifest was dropped or changed at the candidate tip")
        data = _read_git_blobs(root, {path: oid for path, oid in inputs.items()
                                     if path != SCES_PUBLICATION and (path == source or SPDX_SOURCE.fullmatch(path)
                                         or not path.startswith(f"{SOURCES}/"))}, cache)
        rows = {path: decode(payload) for path, payload in data.items()}
        sces_rows = {}
        if version != LEGACY_COVERAGE_VERSION:
            evidence = _git_blobs(root, commit, *COVERAGE_SCES_SECTIONS)
            sces_rows = _read_git_blobs(root, evidence, cache)
        historic = _HistoricalCatalog(root, rows, sces_rows)
        validate_source(historic, rows[source])
        text_paths = {package["path"] for package in historic.packaged.values()}
        texts = _git_blobs(root, commit, "legal-texts", "LICENSE")
        require(text_paths <= texts.keys(), f"{name}: publisher text missing from historical Git tree {commit}")
        historical_texts = _read_git_blobs(root, {path: texts[path] for path in text_paths}, cache)
        validate_texts(historic, historical_texts.__getitem__, rights_reader=rights_reader, archived=True)
        validate_profiles(historic)
        claims = _checked_historical_claims(root, base, commit, policy, cache) if SCES_PUBLICATION in inputs else ()
        expected = historic.coverage(claims, schema_version=version)
        installation = expected["installation"]
        # The v1 discovery format originally omitted this field when there were no companions.
        if (version == LEGACY_COVERAGE_VERSION and not installation["requires_verified_companion"]
                and "requires_verified_companion" not in archived["assessment"]["installation"]):
            del installation["requires_verified_companion"]
        require(encode(archived["assessment"]) == encode(expected),
                f"{name}: coverage differs from historical registry inputs at {commit}")
        if replay_spdx is not None:
            predecessor = _historical_spdx_base(root, base, commit, verified)
            try:
                confirmed = replay_spdx(historic, rows[source], predecessor)
            except DataError as error:
                raise DataError(f"{name}: {error}") from error
            if confirmed is not False:
                verified.add(commit)
    if verified:
        # HEAD may itself contain the selected archive. Replaying HEAD must use an earlier verified tree.
        return _historical_spdx_base(root, base, head, verified)


def validate(catalog, base=None, policy=None, *, spdx_archive=None, fetch_spdx_archive=False, rights_reader=None):
    if rights_reader is not None:
        rights_reader = cache(rights_reader)
    result = qualified(catalog, policy, base=base)
    saved, _ = _validate_discovery(catalog, result[1], base=base, policy=policy, rights_reader=rights_reader)
    replay_history = None
    if spdx_archive is not None or fetch_spdx_archive:
        source = read(local_path(catalog.root, saved["source_manifest"]))
    if spdx_archive is not None:
        from .spdx_replay import archive_origins, compare_registry

        origins = archive_origins(source, spdx_archive)
        pin = encode(source)

        def replay_history(historic, historic_source, predecessor):
            if encode(historic_source) != pin:
                return False
            compare_registry(historic, origins, historic_source, predecessor)
            return True
    elif fetch_spdx_archive:
        from .spdx_replay import replay_download

        archives = {}
        replay_history = partial(replay_download, archives=archives, historical=True)
    predecessor = base
    if base:
        check_history(catalog, base)
        verified_predecessor = validate_incoming_snapshots(catalog.root, base, rights_reader=rights_reader,
                                                           replay_spdx=replay_history, policy=policy)
        predecessor = verified_predecessor or base
    if spdx_archive is not None:
        compare_registry(catalog, origins, source, predecessor)
    elif fetch_spdx_archive:
        replay_download(catalog, source, predecessor, archives=archives)
    return result


def discovery_export(catalog):
    coverage_bytes = _exact_file(catalog.root / COVERAGE)
    snapshot = decode(coverage_bytes)
    return {
        "dataset": "software-commons/license-index",
        "schema_version": "1.0.0",
        "software_version": VERSION,
        "status": QUALIFICATION_SCOPE,
        "coverage": snapshot,
        "coverage_snapshot_sha256": sha256(coverage_bytes).hexdigest(),
        "source": read(local_path(catalog.root, snapshot["source_manifest"])),
        "candidates": [catalog.describe(row) for row in catalog.search(include_history=True)],
        "provisional_profiles": catalog.profiles,
    }


def qualified_export(catalog, report, claims):
    """Build the consumer view from the catalog and its validated active selection."""
    require(report, "no active SCES-qualified release")
    return {"release": report, "entities": list(catalog.entities.values()), "claims": claims}


def qualified_lookup(entities, identifier):
    """Find one selected entity and derive its incoming local relationships."""
    entity = next((row for row in entities if row["id"] == identifier), None)
    if entity is None:
        label = identifier.casefold()
        matches = [
            row for row in entities
            if row["name"].casefold() == label or any(alias["name"].casefold() == label for alias in row["aliases"])
        ]
        require(matches, f"unknown qualified entity identifier: {identifier!r}")
        require(len(matches) == 1, f"ambiguous qualified entity identifier: {identifier!r}")
        entity = matches[0]

    target = {"id": entity["id"]}
    incoming = [
        {"source": owner["id"], **relation}
        for owner in entities for relation in owner["relations"] if relation["target"] == target
    ]
    return {"entity": entity, "incoming_relations": incoming}


def archive_entry(archive, name, data):
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (0o100755 if name == "license-index" else 0o100644) << 16
    archive.writestr(info, data, compress_type=ZIP_STORED)


def _bundle_path(root, value, folder, suffixes):
    target = local_path(root, value)
    require(value.startswith(f"{folder}/") and target.suffix in suffixes
            and target.relative_to(root).as_posix() == value, f"invalid bundle path: {value}")
    return value


def validate_build_destination(root, output):
    parent = Path(output).parent.resolve()
    root = root.resolve()
    require(not any(parent.is_relative_to(root / section) for section in DATA_DIRECTORIES),
            "build output must be outside the validated input directories")


def bundle(catalog, output, *, policy=None):
    validate_build_destination(catalog.root, output)
    coverage, retained_sources = validate_discovery(catalog, policy=policy)
    root = catalog.root
    files = BUNDLE_SUPPORT | {
        _bundle_path(root, coverage["source_manifest"], SOURCES, {".json"}),
        _bundle_path(root, coverage["snapshot"], SNAPSHOTS, {".json"}),
        *retained_sources,
        *(f"registry/candidates/{identity[:2]}/{identity}.json" for identity in catalog.candidates),
    }
    if coverage["schema_version"] == "4.0.0":
        files.add(coverage["predecessor"]["snapshot"])
    if catalog.packaged:
        files.add(PACKAGED_TEXTS)
        files.update(_bundle_path(root, row["path"], "legal-texts", {".txt", ".md"})
                     for row in catalog.packaged.values() if row["path"] != "LICENSE")
    if catalog.profiles:
        files.add(PROFILES)
    data = BytesIO()
    with ZipFile(data, "w") as archive:
        archive_entry(archive, DISCOVERY_EXPORT, encode(discovery_export(catalog)))
        for name in sorted(files):
            archive_entry(archive, name, _exact_file(local_path(root, name)))
    write_license(Path(output), data.getvalue())
    return {"output": str(output), "software_version": VERSION, "status": QUALIFICATION_SCOPE}
