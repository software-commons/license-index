"""Validate repository domain records against the versioned JSON Schema."""

from jsonschema import Draft202012Validator, FormatChecker

from .distribution import COVERAGE, SNAPSHOTS, discovery_export
from .records import Catalog, ROOT, local_path, read


def main():
    schema = read(ROOT / "schemas/domain/registry-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    catalog = Catalog()
    snapshots = [read(ROOT / COVERAGE), *(read(path) for path in sorted((ROOT / SNAPSHOTS).rglob("*.json")))]
    groups = {
        "candidate": catalog.candidates.values(),
        "entity": catalog.entities.values(),
        "coverage": snapshots,
        "source": (read(local_path(ROOT, name)) for name in sorted({row["source_manifest"] for row in snapshots})),
        "export": (discovery_export(catalog),),
    }
    for name, rows in groups.items():
        validator = Draft202012Validator(
            {**schema, "$ref": f"#/$defs/{name}"}, format_checker=FormatChecker(),
        )
        for row in rows:
            validator.validate(row)


if __name__ == "__main__":
    main()
