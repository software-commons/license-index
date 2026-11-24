"""Measure the exact MPL plaintext representations without normalization."""

import argparse
from hashlib import sha256
import json
from pathlib import Path


def compare(publisher: bytes, bedrock: bytes, spdx_standard: bytes, spdx_exhibit_b: bytes) -> dict:
    values = {
        "publisher": publisher,
        "bedrock": bedrock,
        "spdx_standard": spdx_standard,
        "spdx_exhibit_b": spdx_exhibit_b,
    }
    # The first unequal byte may follow a common prefix equal to the shorter input.
    offset = next((index for index, pair in enumerate(zip(publisher, spdx_standard)) if pair[0] != pair[1]),
                  min(len(publisher), len(spdx_standard)))
    insertion = spdx_standard[offset:offset + 1]
    single_insertion = (
        len(spdx_standard) == len(publisher) + 1
        and spdx_standard == publisher[:offset] + insertion + publisher[offset:]
    )
    return {
        "ascii": all(raw.isascii() for raw in values.values()),
        "sources": {name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()} for name, raw in values.items()},
        "publisher_equals_bedrock": publisher == bedrock,
        "spdx_plaintexts_equal": spdx_standard == spdx_exhibit_b,
        "spdx_equals_publisher": spdx_standard == publisher,
        "spdx_inserted_byte": insertion.hex() if single_insertion else None,
        "spdx_inserted_byte_offset": offset if single_insertion else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("publisher", "bedrock", "spdx_standard", "spdx_exhibit_b"):
        parser.add_argument(name, type=Path)
    paths = vars(parser.parse_args())
    print(json.dumps(compare(**{name: path.read_bytes() for name, path in paths.items()}), sort_keys=True))


if __name__ == "__main__":
    main()
