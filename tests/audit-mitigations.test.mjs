import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { nodeForgeFixture, patchPolicy as forgePolicy, projectRoot } from "./helpers/node-forge-fixture.mjs";

const bracesPolicy = JSON.parse(readFileSync(join(projectRoot, "security/braces-patch.json"), "utf8"));
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

function report(vulnerabilities) {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  for (const finding of Object.values(vulnerabilities)) { counts[finding.severity]++; counts.total++; }
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: counts } };
}

function bracesFindings() {
  return Object.fromEntries(Object.entries(bracesPolicy.auditNodes).map(([name, nodes]) => [name, {
    name, severity: "high", nodes: [...nodes], via: name === "braces" ? [{
      url: bracesPolicy.advisory, name, dependency: name, severity: "high", range: "<=3.0.3",
    }] : [...bracesPolicy.auditEdges[name]],
  }]));
}

function runAudit(findings, change = () => {}, after = () => {}) {
  const fixture = nodeForgeFixture();
  try {
    change(fixture);
    const payload = report(findings);
    writeFileSync(join(fixture.root, "fixture.json"), JSON.stringify(payload));
    const stub = join(fixture.root, "fake-npm.cjs");
    writeFileSync(stub, `
const assert = require("node:assert/strict");
const fs = require("node:fs");
assert.deepEqual(process.argv.slice(2), ["audit", "--omit=dev", "--json"]);
const payload = fs.readFileSync(process.env.STOKDAS_AUDIT_FIXTURE, "utf8");
process.stdout.write(payload);
process.exit(JSON.parse(payload).metadata.vulnerabilities.total ? 1 : 0);
`);
    if (process.platform === "win32") {
      writeFileSync(join(fixture.root, "npm.cmd"), `@"${process.execPath}" "${stub}" %*\r\n`);
    } else {
      writeFileSync(join(fixture.root, "npm"), `#!${process.execPath}\nrequire(${JSON.stringify(stub)});\n`, { mode: 0o755 });
    }
    const result = spawnSync(process.execPath, [join(fixture.root, "scripts/verify-npm-audit.mjs")], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${fixture.root}${delimiter}${process.env.PATH}`, STOKDAS_AUDIT_FIXTURE: join(fixture.root, "fixture.json") },
    });
    after(fixture, result);
    return result;
  } finally { fixture.cleanup(); }
}

test("Geçerli braces zinciri doğrulanmış yamalarla yayın denetimini geçer", () => {
  const result = runAudit(bracesFindings());
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Production dependency audit passed with verified, bounded mitigations/);
});

test("Birleşik braces ve node-forge azaltımları yalnız doğrulanmış zincirleri kapsar", () => {
  const findings = bracesFindings();
  findings["node-forge"] = { name: "node-forge", severity: "high", nodes: forgePolicy.installPaths, via: [{
    url: forgePolicy.advisory, name: "node-forge", dependency: "node-forge", severity: "high", range: "<=1.4.0",
  }] };
  findings["@expo/code-signing-certificates"] = { name: "@expo/code-signing-certificates", severity: "high", nodes: forgePolicy.auditNodes["@expo/code-signing-certificates"], via: ["node-forge"] };
  findings["@expo/cli"].via.push("node-forge", "@expo/code-signing-certificates");
  const result = runAudit(findings);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Production dependency audit passed with verified, bounded mitigations/);
});

for (const [label, mutate] of [
  ["yeni danışman", (findings) => { findings.braces.via.push({ url: "https://github.com/advisories/GHSA-new-advisory", name: "braces", dependency: "braces", severity: "high", range: "<=3.0.3" }); }],
  ["başka paket kaynağı", (findings) => { findings.braces.via[0].dependency = "different-package"; }],
  ["değişen etkilenen sürüm aralığı", (findings) => { findings.braces.via[0].range = "<=3.0.4"; }],
  ["değişen rapor önem derecesi", (findings) => { findings.braces.severity = "moderate"; }],
  ["kritik önem", (findings) => { findings.braces.severity = "critical"; }],
  ["ek dolaylı kurulum", (findings) => { findings.micromatch.nodes.push("node_modules/other/node_modules/micromatch"); }],
  ["yeni tüketici kenarı", (findings) => { findings.expo.via.push("micromatch"); }],
  ["bilinmeyen kendine döngü", (findings) => { findings.expo.via.push("expo"); }],
  ["kanıtsız Metro döngüsü", (findings) => { delete findings["metro-file-map"]; }],
]) {
  test(`Braces azaltımı değişmiş raporu kapsamaz: ${label}`, () => {
    const findings = bracesFindings();
    mutate(findings);
    const result = runAudit(findings);
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /Production dependency audit failed:/);
  });
}

test("Bilinmeyen döngü doğrulanmış braces yaprağına erişse bile kabul edilmez", () => {
  const findings = bracesFindings();
  findings.micromatch.via.push("metro-file-map");
  const result = runAudit(findings);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /uncovered braces consumer chain|cyclic advisory provenance/);
});

test("Geçerli audit raporu değiştirilmiş braces tarball kaynağını gizleyemez", () => {
  const result = runAudit(bracesFindings(), ({ root }) => {
    const path = join(root, "package-lock.json");
    const lock = readJson(path);
    lock.packages[bracesPolicy.installPaths[0]].resolved = "https://example.invalid/fork.tgz";
    writeFileSync(path, JSON.stringify(lock));
  });
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /braces mitigation was not verified/);
});

test("Temiz audit raporu bile değiştirilmiş braces baytlarını gizleyemez veya onaramaz", () => {
  let changed;
  const result = runAudit({}, ({ root }) => {
    const path = join(root, bracesPolicy.installPaths[0], "index.js");
    changed = `${readFileSync(path, "utf8")}\n// unexpected change\n`;
    writeFileSync(path, changed);
  }, ({ root }) => {
    assert.equal(readFileSync(join(root, bracesPolicy.installPaths[0], "index.js"), "utf8"), changed);
  });
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /braces mitigation was not verified/);
});

test("Süresi dolan braces kararı diğer azaltımlar geçerli olsa da audit kapısını kapatır", () => {
  const result = runAudit(bracesFindings(), ({ root }) => {
    const path = join(root, "security/braces-patch.json");
    writeFileSync(path, JSON.stringify({ ...bracesPolicy, expiresOn: "2000-01-01" }));
  });
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /braces mitigation was not verified:.*expired/);
});

test("Braces kanıtı mevcut Metro istisnasının başka danışman kabul etmesini sağlamaz", () => {
  const findings = bracesFindings();
  findings["image-size"] = { name: "image-size", severity: "high", via: [{ url: bracesPolicy.advisory, name: "braces", dependency: "braces", severity: "high", range: "<=3.0.3" }] };
  const result = runAudit(findings);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /image-size: unexpected advisory/);
});
