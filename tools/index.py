"""Explore the Software Commons license discovery catalog."""

from __future__ import annotations

import argparse
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
import sys

from .li_install import (
    LGPL_V3_IDS, LGPL_V3_SUPPLEMENT, InstallError, parse_expression, render, verify_gplv3_companion, write_license,
)
from .records import Catalog, DataError, ROOT, VERSION, encode, is_installation_target, require


def parser():
    cli = argparse.ArgumentParser(prog="license-index", description=__doc__)
    cli.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    cli.add_argument("--json", action="store_true", help="return structured JSON")
    cli.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    commands = cli.add_subparsers(dest="command", required=True)
    descriptions = {
        "list": "list upstream and publisher records",
        "search": "search identifiers and names",
        "show": "inspect one discovered or qualified record",
        "text": "retrieve verified text bytes",
        "add": "preview or install a supported LICENSE file",
        "explain": "read a scoped provisional explanation",
        "compare": "compare documented dimensions and uncertainties",
        "sources": "inspect exact source locators and provisional evidence",
        "coverage": "show population, text, research and qualification counts",
        "expression": "parse an SPDX 3.0.1 expression",
        "validate": "validate repository data and history",
        "export": "write an offline JSON discovery view or qualified payload to stdout",
        "bundle": "write a deterministic offline ZIP",
        "review-plan": "plan evidence review for provisional facets or catalog admission",
    }
    for command, help_text in descriptions.items():
        sub = commands.add_parser(command, help=help_text, description=help_text)
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        if command in {"list", "search"}:
            sub.add_argument("--kind", choices=["license", "exception", "other"])
            sub.add_argument("--history", action="store_true", help="include identifiers removed from the active list")
        if command == "search":
            sub.add_argument("query")
        if command in {"show", "sources", "explain", "text", "add"}:
            sub.add_argument("identifier")
        if command in {"text", "add"}:
            sub.add_argument("--artifact-root", type=Path, help="verified input from an extracted SPDX data archive")
            sub.add_argument("--fetch", action="store_true", help="retrieve the exact SPDX text over HTTPS")
        if command == "add":
            sub.add_argument("--holder")
            sub.add_argument("--year")
            sub.add_argument("--output", type=Path, default=Path("LICENSE"), help="target filename")
            sub.add_argument("--gplv3-text", type=Path,
                             help="existing exact GNU GPLv3 text required for an LGPLv3 supplement")
            sub.add_argument("--dry-run", action="store_true")
            sub.add_argument("--force", action="store_true", help="explicitly replace an existing regular file")
        if command == "compare":
            sub.add_argument("identifiers", nargs="+")
        if command == "expression":
            sub.add_argument("expression")
        if command in {"validate", "export", "coverage", "show"}:
            sub.add_argument("--policy", type=Path, help="checkout at the pinned SCES commit")
        if command == "validate":
            sub.add_argument("--base", help="full SHA of a trusted prior commit")
            archive = sub.add_mutually_exclusive_group()
            archive.add_argument("--spdx-archive", type=Path, help="replay the pinned SPDX archive from a local file")
            archive.add_argument("--fetch-spdx-archive", action="store_true",
                                 help="retrieve and replay the pinned SPDX archive")
            rights = sub.add_mutually_exclusive_group()
            rights.add_argument("--rights-root", type=Path, help="verify publisher rights bytes from a local directory")
            rights.add_argument("--fetch-rights", action="store_true", help="verify pinned publisher rights over HTTPS")
        if command in {"export", "show"}:
            sub.add_argument("--qualified", action="store_true", help="require a current SCES-qualified selection")
        if command == "bundle":
            sub.add_argument("output", type=Path)
        if command == "review-plan":
            sub.add_argument("identifiers", nargs="*", metavar="ID", help="omit to plan the entire selected population")
            sub.add_argument("--admission", action="store_true", help="plan canonical admission from discovery records")
    return cli


def expression(catalog, value):
    active = [row["origin"] for row in catalog.active_spdx]
    licenses = {row["identifier"] for row in active if row["list_kind"] == "license"}
    exceptions = {row["identifier"] for row in active if row["list_kind"] == "exception"}
    return parse_expression(value, licenses, exceptions)


def install_target(catalog, value):
    exact = catalog.exact(value)
    if exact is None:
        result = expression(catalog, value)
        identifier = result["single_license_id"]
        require(identifier, "expression requires review of its licenses, exceptions and document-local references")
        exact = catalog.resolve(identifier)
    origin = exact["origin"]
    require(origin.get("list_kind") == "license", "choose a supported standalone license for installation")
    require(is_installation_target(exact), "installation requires a current, nondeprecated identifier")
    return exact


def text_or_add(catalog, args):
    installing = args.command == "add"
    row = install_target(catalog, args.identifier) if installing else catalog.resolve(args.identifier)
    identifier = row["origin"]["identifier"]
    companion = getattr(args, "gplv3_text", None)
    supplement = installing and identifier in LGPL_V3_IDS
    if supplement:
        require(companion is not None, "Include both publisher texts. Use --gplv3-text to verify an existing GPLv3 copy.")
    else:
        require(companion is None, "--gplv3-text applies only to LGPL-3.0-only and LGPL-3.0-or-later")
    text, source = catalog.text(row, artifact_root=args.artifact_root, fetch=args.fetch,
                                for_installation=installing)
    result = {"identifier": identifier, "source": source, "text_sha256": sha256(text).hexdigest()}
    if not installing:
        result["text"] = text.decode("utf-8")
        return result, text
    application = source.get("application")
    guidance = f". {application}" if application else ""
    recipe = source.get("install")
    require(recipe, f"installation is unsupported for {identifier}{guidance}")
    require((recipe == LGPL_V3_SUPPLEMENT) == supplement, f"incorrect GPLv3 companion requirement: {identifier}")
    mode = "unchanged" if supplement else recipe
    installed = render(text, mode, holder=args.holder, year=args.year, preview=args.dry_run)
    before_publish = None
    if supplement:
        base, descriptor = catalog.text(catalog.resolve("GPL-3.0-only"))

        def before_publish(stat_output):
            verify_gplv3_companion(args.output, companion, base, stat_output=stat_output)

        result["gplv3_text"] = {"path": str(companion), "sha256": descriptor["sha256"]}
    write_license(args.output, installed, force=args.force, dry_run=args.dry_run, before_publish=before_publish)
    result.update({
        "output": str(args.output),
        "dry_run": args.dry_run,
        "written": not args.dry_run,
        "output_sha256": sha256(installed).hexdigest(),
        "application": application or "Use the selected notice only for material you can license.",
    })
    if args.dry_run:
        result["text"] = installed.decode("utf-8")
        return result, installed
    return result, f"Wrote {args.output}\n{result['application']}"


def comparison(catalog, identifiers):
    rows = [catalog.resolve(identifier) for identifier in identifiers]
    require(len(rows) >= 2 and len({row["id"] for row in rows}) == len(rows),
            "compare requires at least two distinct catalog entries")
    dimensions = {"copyright_grant", "patent_grant", "trademark", "notices", "modification",
                  "source_availability", "reciprocity", "warranty", "termination", "exceptions"}
    profile_dimensions = []
    for row in rows:
        profile = catalog.profile(row)
        recorded = {} if profile is None else profile["dimensions"]
        dimensions.update(recorded)
        profile_dimensions.append(recorded)
    unknown = {"state": "unresolved", "text": "No assessment recorded for this dimension.", "sources": []}
    records = [
        {"identifier": row["origin"]["identifier"],
         "dimensions": {key: recorded.get(key, unknown) for key in sorted(dimensions)}}
        for row, recorded in zip(rows, profile_dimensions)
    ]
    return {"status": "provisional", "records": records}


def execute(catalog, args):
    command = args.command
    if command in {"list", "search"}:
        rows = catalog.search(getattr(args, "query", ""), include_history=args.history, kind=args.kind)
        return [catalog.describe(row) for row in rows], "\n".join(
            f"{row['origin']['identifier']}  {row['origin']['name']}" for row in rows)
    if command == "coverage":
        from .distribution import coverage_assessment, validate
        claims = validate(catalog, policy=args.policy)[1] if args.policy else ()
        return coverage_assessment(catalog, claims, policy=args.policy), None
    if command == "expression":
        return expression(catalog, args.expression), None
    if command in {"text", "add"}:
        return text_or_add(catalog, args)
    if command == "compare":
        result = comparison(catalog, args.identifiers)
        sections = ["Provisional comparison"]
        for item in result["records"]:
            bullets = [item["identifier"]]
            for key, value in item["dimensions"].items():
                bullets.append(f"  {key.replace('_', ' ')} [{value['state']}]  {value['text']}")
                bullets.extend(f"    {source['locator']} · {source['url']}" for source in value["sources"])
            sections.append("\n".join(bullets))
        return result, "\n\n".join(sections)
    if command == "review-plan":
        from .review_plan import build_admission_plan, build_plan
        if args.admission:
            return build_admission_plan(catalog, args.identifiers), None
        return build_plan(catalog, args.identifiers), None
    if command in {"show", "export"} and args.qualified:
        from .distribution import qualified_export, qualified_lookup, validate
        require(command != "show" or args.policy is not None, "show --qualified requires --policy with the pinned SCES checkout")
        report, claims = validate(catalog, policy=args.policy)
        selection = qualified_export(catalog, report, claims)
        if command == "show":
            return qualified_lookup(selection["entities"], args.identifier), None
        return selection, None
    if command in {"validate", "export", "bundle"}:
        from .distribution import (
            bundle, coverage_assessment, discovery_export, read_rights_document, validate, validate_discovery,
        )
        if command == "bundle":
            return bundle(catalog, args.output), None
        if command == "export":
            if args.policy is None:
                validate_discovery(catalog)
            else:
                validate(catalog, policy=args.policy)
            return discovery_export(catalog), None
        if command == "validate":
            rights_reader = None
            if args.rights_root is not None or args.fetch_rights:
                rights_dir = args.rights_root.resolve() if args.rights_root is not None else None
                rights_reader = partial(read_rights_document, root=rights_dir)
            report, claims = validate(catalog, args.base, args.policy, spdx_archive=args.spdx_archive,
                                      fetch_spdx_archive=args.fetch_spdx_archive, rights_reader=rights_reader)
            rights_status = "verified" if rights_reader is not None else "references-only"
            spdx_status = "upstream" if args.fetch_spdx_archive else ("local-current" if args.spdx_archive else "references-only")
            message = f"Valid registry (SPDX replay: {spdx_status}, pinned publisher rights digests: {rights_status})"
            coverage = coverage_assessment(catalog, claims, base=args.base, policy=args.policy)
            return {"valid": True, "qualification": report, "coverage": coverage,
                    "spdx_replay": spdx_status, "pinned_publisher_rights_digests": rights_status}, message
    if command == "show":
        require(args.policy is None, "show --policy requires --qualified")
    row = catalog.resolve(args.identifier)
    item = catalog.describe(row)
    profile = catalog.profile(row)
    if command == "show":
        return item, None
    if command == "sources":
        citations = [] if profile is None else list({
            (citation["url"], citation["locator"]): citation
            for part in [*profile["dimensions"].values(), *profile["scenarios"]]
            for citation in part["sources"]
        }.values())
        return {"status": "provisional", "origin": row["origin"], "history": row["history"],
                "membership": row.get("membership"),
                "text_package": item["text_package"], "research_citations": citations}, None
    result = {"identifier": row["origin"]["identifier"], "status": item["explanation_status"],
              "profile": profile}
    if profile is None:
        return result, f"No explanation recorded for {result['identifier']}."
    sections = [f"{result['identifier']}  ·  Provisional educational research", profile["summary"]]
    for dimension, entry in profile["dimensions"].items():
        sections.append(f"{dimension.replace('_', ' ')} [{entry['state']}]\n{entry['text']}\n" +
                        "\n".join(f"{source['locator']} · {source['url']}" for source in entry["sources"]))
    for scenario in profile["scenarios"]:
        sections.append(f"{scenario['situation']}\n{scenario['text']}\n" +
                        "\n".join(f"{source['locator']} · {source['url']}" for source in scenario["sources"]))
    return result, "\n\n".join(sections)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result, human = execute(Catalog(args.root), args)
        if args.json or human is None:
            sys.stdout.buffer.write(encode(result))
        elif isinstance(human, bytes):
            sys.stdout.buffer.write(human)
        elif human:
            sys.stdout.buffer.write((human + "\n").encode("utf-8"))
        return 0
    except (DataError, InstallError, OSError, UnicodeError, KeyError, TypeError, json.JSONDecodeError) as error:
        if args.json:
            sys.stderr.buffer.write(encode({"error": str(error)}))
        else:
            sys.stderr.buffer.write((f"license-index: {error}\n").encode("utf-8"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
