"""Compare exact SPDX MIT plaintext and matching-template representations."""

from hashlib import sha256
import json


def compare(plain, detail, matcher):
    values = {"plain": plain, "detail": detail, "matcher": matcher}
    if not all(raw.isascii() for raw in values.values()):
        raise ValueError("Expected the exact ASCII subset of UTF-8 for these pinned representations")
    data = json.loads(detail)
    if data["licenseId"] != "MIT":
        raise ValueError("Unexpected SPDX detail identity")
    return {
        "sources": {key: {"bytes": len(value), "sha256": sha256(value).hexdigest()}
                    for key, value in values.items()},
        "plain_equals_detail_field": plain == data["licenseText"].encode("utf-8"),
        "matcher_equals_detail_field": matcher == data["standardLicenseTemplate"].encode("utf-8"),
        "matcher_differs_from_plain": matcher != plain,
    }
