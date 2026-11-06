import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const source = "https://nizlo.com/guides/nizlo-rmm-security-indicators";
const expectedValues = [
  "Nizlo.Agent.exe",
  "Nizlo.Agent.Updater.exe",
  "Nizlo.RemoteBridge.exe",
  "C:\\Program Files\\Nizlo\\Agent\\",
  "C:\\ProgramData\\Nizlo\\Agent\\",
  "Nizlo RMM Agent",
  "HKLM\\Software\\Nizlo\\Agent",
  "HKLM\\Software\\Classes\\nizlo",
  "HKLM\\Software\\Classes\\nizlo-remote",
  "nizlo:",
  "nizlo-remote:",
  "app.nizlo.com:443",
  "/Library/PrivilegedHelperTools/com.nizlo.agent/Nizlo.Agent.Mac",
  "/Applications/NizloRemote.app/Contents/MacOS/NizloRemote",
  "com.nizlo.NizloRemote_service",
  "com.nizlo.NizloRemote_server",
];
const expectedPlatforms = [
  ...Array(12).fill("Windows"),
  ...Array(4).fill("macOS"),
];

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        field += character;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === ",") {
      row.push(field);
      field = "";
    } else if (character === "\n") {
      row.push(field.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

const [jsonText, csvText, schemaText, page, docsJson, docsCsv, docsSchema, sitemap, llms] =
  await Promise.all([
    readFile("indicators.json", "utf8"),
    readFile("indicators.csv", "utf8"),
    readFile("indicators.schema.json", "utf8"),
    readFile("docs/index.html", "utf8"),
    readFile("docs/indicators.json", "utf8"),
    readFile("docs/indicators.csv", "utf8"),
    readFile("docs/indicators.schema.json", "utf8"),
    readFile("docs/sitemap.xml", "utf8"),
    readFile("docs/llms.txt", "utf8"),
  ]);

const data = JSON.parse(jsonText);
const schema = JSON.parse(schemaText);
assert.equal(data.schema_version, "1.1");
assert.equal(data.dataset_version, "1.1.0");
assert.equal(data.platform, "Windows and macOS");
assert.equal(data.source, source);
assert.equal(data.expected_network_behavior.destination, "app.nizlo.com");
assert.equal(data.expected_network_behavior.port, 443);
assert.equal(data.expected_network_behavior.inbound_port_required, false);
assert.equal(data.artifacts.length, expectedValues.length);
assert.deepEqual(data.artifacts.map(({ value }) => value), expectedValues);
assert.equal(new Set(data.artifacts.map(({ type, value }) => `${type}\u0000${value}`)).size, data.artifacts.length);
for (const artifact of data.artifacts) {
  assert.equal(artifact.source, source);
  assert.match(artifact.last_reviewed, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(artifact.context.length >= 10);
}
assert.equal(schema.$id, "https://izikipizi.github.io/nizlo-security-indicators/indicators.schema.json");

const rows = parseCsv(csvText);
assert.deepEqual(rows[0], ["type", "value", "platform", "context", "source", "last_reviewed"]);
assert.equal(rows.length - 1, data.artifacts.length);
assert.deepEqual(rows.slice(1).map((row) => row[1]), expectedValues);
assert.deepEqual(rows.slice(1).map((row) => row[2]), expectedPlatforms);
for (const [index, row] of rows.slice(1).entries()) {
  assert.equal(row.length, 6);
  assert.equal(row[4], source);
  assert.equal(row[5], data.artifacts[index].last_reviewed);
}

assert.deepEqual(JSON.parse(docsJson), data);
assert.equal(docsCsv, csvText);
assert.deepEqual(JSON.parse(docsSchema), schema);
for (const required of [
  source,
  "indicators.json",
  "indicators.csv",
  "Relationship disclosure",
  "Presence alone is not evidence of compromise",
]) {
  assert.ok(page.includes(required), `docs/index.html is missing ${required}`);
}
assert.ok(sitemap.includes("https://izikipizi.github.io/nizlo-security-indicators/"));
for (const required of [
  "# Nizlo Security Indicators",
  source,
  "indicators.json",
  "indicators.csv",
  "Presence alone is not evidence of compromise",
]) {
  assert.ok(llms.includes(required), `docs/llms.txt is missing ${required}`);
}

console.log(`Validated ${data.artifacts.length} Nizlo indicators across JSON, CSV, schema, and GitHub Pages.`);
