const names = ["plain", "detail", "matcher"];
const observations = Object.fromEntries(names.map(name => [name, load("sces-byte-" + name)]));
if (names.some(name => !observations[name] || observations[name].body_encoding !== "utf-8")) throw new Error("Missing complete SPDX source");
if (names.some(name => {
  const source = observations[name];
  return source.bytes !== source.source_text.length || !/^[\x00-\x7f]*$/.test(source.source_text);
})) throw new Error("Unexpected byte encoding or incomplete comparison inputs");
const detail = JSON.parse(observations.detail.source_text);
if (detail.licenseId !== "MIT") throw new Error("Unexpected SPDX detail identity");
const result = {
  sources: Object.fromEntries(names.map(name => [name, {bytes: observations[name].bytes, sha256: observations[name].sha256}])),
  plain_equals_detail_field: observations.plain.source_text === detail.licenseText,
  matcher_equals_detail_field: observations.matcher.source_text === detail.standardLicenseTemplate,
  matcher_differs_from_plain: observations.matcher.source_text !== observations.plain.source_text,
};
text("SCES-MIT-REP-OBSERVATION " + JSON.stringify(result));
