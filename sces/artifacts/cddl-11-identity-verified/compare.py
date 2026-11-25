"""Compare the pinned Oracle and SPDX text representations for one CDDL edition."""

import re

_QUOTES = str.maketrans("“”‘’", '""\x27\x27')
_NOTICE = "NOTICE PURSUANT TO SECTION 9"
_SEPARATOR = "-" * 72


def words(value):
    return re.findall(r"[^ \t\r\n]+", value.translate(_QUOTES))


def compare(publisher, spdx):
    publisher = publisher.decode("utf-8")
    spdx = spdx.decode("utf-8")
    original, generated = words(publisher), words(spdx)
    without_separator = [token for token in original if token != _SEPARATOR]
    core = without_separator
    if _NOTICE in publisher:
        core = words(publisher.split(_NOTICE, 1)[0])
        core = [token for token in core if token != _SEPARATOR]
    edited = words(spdx.replace("License Grants", "License Conditions", 1))
    assert edited != generated
    return {
        "byte_identical": publisher == spdx,
        "normalized_with_notice": without_separator == generated,
        "normalized_agreement_only": core == generated,
        "publisher_notice": _NOTICE in publisher,
        "spdx_notice": _NOTICE in spdx,
        "separator_count": original.count(_SEPARATOR),
        "altered_clause_equal": without_separator == edited,
    }