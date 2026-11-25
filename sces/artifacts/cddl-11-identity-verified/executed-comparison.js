const original = (label) => [1, 2].map(index => {
    const part = load("cddl-" + label + "_part_" + index);
    if (!part || part.excerpts.length !== 1) throw new Error("Missing original source part");
    return part.excerpts[0].text;
}).join("");
const publisher = original("publisher");
const spdx = original("spdx");
const notice = "NOTICE PURSUANT TO SECTION 9";
const separator = "-".repeat(72);
const words = source => source.replace(/[“”]/g, '"').replace(/[‘’]/g, "'").match(/[^ \t\r\n]+/g);
const starts = words(publisher);
const generated = words(spdx);
const withoutSeparator = words(publisher).filter(token => token !== separator);
const core = words(publisher.split(notice)[0]).filter(token => token !== separator);
const changed = words(spdx.replace("License Grants", "License Conditions"));
const equal = (first, second) => first.length === second.length && first.every((token, i) => token === second[i]);
if (equal(changed, generated)) throw new Error("Changed clause not found");
text("CDDL-OBSERVATION " + JSON.stringify({
    byte_identical: publisher === spdx,
    normalized_with_notice: equal(withoutSeparator, generated),
    normalized_agreement_only: equal(core, generated),
    publisher_notice: publisher.includes(notice),
    spdx_notice: spdx.includes(notice),
    separator_count: starts.filter(token => token === separator).length,
    altered_clause_equal: equal(withoutSeparator, changed),
}));