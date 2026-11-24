"""Validate repository records and consumer output against the versioned JSON Schema."""

from argparse import ArgumentParser
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, RefResolver

from .distribution import COVERAGE, SNAPSHOTS, discovery_export, qualified_export, qualified_lookup
from .qualification import qualified
from .records import Catalog, DataError, ROOT, decode, local_path, read


class _LocalResolver(RefResolver):
    def resolve_remote(self, uri):
        raise DataError(f"schema reference is not in the local policy bundle: {uri}")


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, help="pinned SCES policy checkout for active qualification")
    parser.add_argument("--base", help="full trusted Git SHA for the SCES history check")
    args = parser.parse_args(argv)

    schema = read(ROOT / "schemas/domain/registry-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    catalog = Catalog(ROOT)
    snapshots = [read(ROOT / COVERAGE), *(read(path) for path in sorted((ROOT / SNAPSHOTS).rglob("*.json")))]
    groups = {
        "candidate": catalog.candidates.values(),
        "entity": catalog.entities.values(),
        "coverage": snapshots,
        "source": (read(local_path(ROOT, name)) for name in sorted({row["source_manifest"] for row in snapshots})),
        "export": (discovery_export(catalog),),
    }
    local_schemas = {}
    selection = ROOT / "sces/publication.json"
    if selection.exists() or selection.is_symlink():
        if args.policy is None:
            parser.error("an active publication requires --policy with the pinned SCES bundle")
        # The standard-library CLI can project qualified data without loading the schema checker.
        from .stage_release import policy_schema

        report, claims = qualified(catalog, args.policy, base=args.base)
        contracts = decode(policy_schema(args.policy))
        local_schemas[contracts["$id"]] = contracts
        exported = qualified_export(catalog, report, claims)
        entities = exported["entities"]
        groups["qualified_export"] = (exported,)
        lookup_id = next((relation["target"]["id"] for entity in entities for relation in entity["relations"]
                          if "index" not in relation["target"]), entities[0]["id"])
        groups["qualified_lookup"] = (qualified_lookup(entities, lookup_id),)

    for name, rows in groups.items():
        entry_schema = {**schema, "$ref": f"#/$defs/{name}"}
        validator = Draft202012Validator(
            entry_schema,
            resolver=_LocalResolver.from_schema(entry_schema, store=local_schemas),
            format_checker=FormatChecker(),
        )
        for row in rows:
            validator.validate(row)


if __name__ == "__main__":
    main()
