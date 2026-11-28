const results = {};
for (const [alias, id] of [["bsd-darwin","BSD-2-Clause-Darwin"],["bsd-flex","BSD-3-Clause-flex"],["bsd-openwebui","BSD-3-Clause-OpenWebUI"]]) {
  const input = load(alias), detail = load("spdx-" + alias);
  for (const item of [input, detail]) if (item.body_encoding !== "utf-8" || item.bytes !== item.source_text.length || !/^[\x00-\x7f]*$/.test(item.source_text)) throw new Error("Expected complete ASCII in UTF-8");
  const record = JSON.parse(detail.source_text);
  if (record.licenseId !== id) throw new Error("Unexpected SPDX detail identifier");
  const line = input.source_text.indexOf("\n");
  const compared = alias === "bsd-darwin" ? input.source_text.slice(line + 1) : alias === "bsd-openwebui" ? input.source_text + "\n" : input.source_text;
  results[id] = (alias !== "bsd-darwin" || (line >= 0 && input.source_text.startsWith("$File:") && input.source_text.slice(0,line).endsWith(" $"))) && compared === record.licenseText;
}
text("BSD-EXACT-BYTE-RESULT " + JSON.stringify(results));
