import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { nodeForgeFixture, patchPolicy, restoreOriginal } from "./helpers/node-forge-fixture.mjs";

const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const packageJson = JSON.parse(source("package.json"));
const allowlist = JSON.parse(source("security/npm-audit-allowlist.json"));

function report(vulnerabilities = {}) {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  for (const value of Object.values(vulnerabilities)) {
    counts[value.severity]++;
    counts.total++;
  }
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: counts } };
}

function runAudit(payload, status = 0, change = () => {}) {
  const fixture = nodeForgeFixture();
  const { root } = fixture;
  try {
    change(fixture);
    writeFileSync(join(root, "fixture.json"), JSON.stringify({ payload, status }));
    const stub = join(root, "fake-npm.cjs");
    writeFileSync(stub, `
const assert = require("node:assert/strict");
const fs = require("node:fs");
assert.deepEqual(process.argv.slice(2), ["audit", "--omit=dev", "--json"]);
const fixture = JSON.parse(fs.readFileSync(process.env.STOKDAS_AUDIT_FIXTURE, "utf8"));
process.stdout.write(typeof fixture.payload === "string" ? fixture.payload : JSON.stringify(fixture.payload));
process.exit(fixture.status);
`);
    if (process.platform === "win32") {
      writeFileSync(join(root, "npm.cmd"), `@"${process.execPath}" "${stub}" %*\r\n`);
    } else {
      writeFileSync(join(root, "npm"), `#!${process.execPath}\nrequire(${JSON.stringify(stub)});\n`, { mode: 0o755 });
    }
    return spawnSync(process.execPath, [join(root, "scripts", "verify-npm-audit.mjs")], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${root}${delimiter}${process.env.PATH}`,
        STOKDAS_AUDIT_FIXTURE: join(root, "fixture.json"),
      },
    });
  } finally {
    fixture.cleanup();
  }
}

test("Temiz bağımlılık raporu açık node-forge kapsam boşluğunu kapatamaz", () => {
  const result = runAudit(report());
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /node-forge release assurance is blocked/);
});

for (const [label, payload, status] of [
  ["boş nesne", {}, 0],
  ["null", null, 0],
  ["bozuk JSON", "not-json", 0],
  ["desteklenmeyen sürüm", { ...report(), auditReportVersion: 3 }, 0],
  ["eksik kayıt listesi", { ...report(), vulnerabilities: undefined }, 0],
  ["dizi kayıt listesi", { ...report(), vulnerabilities: [] }, 0],
  ["eksik sayaçlar", { ...report(), metadata: {} }, 0],
  ["yanlış toplam", { ...report(), metadata: { vulnerabilities: { ...report().metadata.vulnerabilities, total: 1 } } }, 0],
  ["gizlenen yüksek bulgu", { ...report(), metadata: { vulnerabilities: { ...report().metadata.vulnerabilities, high: 1 } } }, 0],
  ["tutarsız çıkış kodu", report(), 1],
  ["sağlayıcı hatası", { error: { summary: "registry unavailable" } }, 1],
  ["beklenmeyen çıkış kodu", report(), 2],
]) {
  test(`Geçersiz audit yanıtı yayını kapatır: ${label}`, () => {
    const result = runAudit(payload, status);
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /Production dependency audit failed:/);
  });
}

const forge = {
  name: "node-forge",
  severity: "high",
  via: [{ url: patchPolicy.advisory, name: "node-forge", dependency: "node-forge", severity: "high", range: "<=1.4.0" }],
  nodes: patchPolicy.installPaths,
};

test("Yamasız node-forge imza doğrulama açığı yayın izni alamaz", () => {
  const result = runAudit(report({ "node-forge": forge }), 1, ({ packageRoot }) => restoreOriginal(packageRoot));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /node-forge mitigation was not verified/);
});

test("Mevcut node-forge yaması ve bilinen Expo zinciri yayın güvencesi vermez", () => {
  const payload = report({
    "node-forge": forge,
    "@expo/code-signing-certificates": { name: "@expo/code-signing-certificates", severity: "high", via: ["node-forge"], nodes: patchPolicy.auditNodes["@expo/code-signing-certificates"] },
    "@expo/cli": { name: "@expo/cli", severity: "high", via: ["node-forge", "@expo/code-signing-certificates"], nodes: patchPolicy.auditNodes["@expo/cli"] },
    expo: { name: "expo", severity: "high", via: ["@expo/cli"], nodes: patchPolicy.auditNodes.expo },
  });
  const result = runAudit(payload, 1);
  assert.equal(result.status, 1, result.stdout);
  assert.match(result.stderr, /node-forge release assurance is blocked/);
  assert.match(result.stderr, /60 parser cases do not establish complete mitigation/);
});

for (const [label, changed] of [
  ["yeni danışman", { ...forge, via: [...forge.via, { url: "https://github.com/advisories/GHSA-new-advisory" }] }],
  ["yanlış danışman kaynağı", { ...forge, via: [{ ...forge.via[0], dependency: "different-package" }] }],
  ["kapsanmayan kurulum", { ...forge, nodes: [...forge.nodes, "node_modules/other/node_modules/node-forge"] }],
  ["kritik bulgu", { ...forge, severity: "critical" }],
]) {
  test(`Doğrulanmış yama değiştirilmiş bulguyu kapsamaz: ${label}`, () => {
    assert.equal(runAudit(report({ "node-forge": changed }), 1).status, 1);
  });
}

test("Metro istisnası node-forge'un farklı tüketicisini kapsamaz", () => {
  const result = runAudit(report({ "node-forge": forge, metro: { name: "metro", severity: "high", via: ["node-forge"] } }), 1);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /uncovered node-forge consumer chain/);
});

test("İndirekt bulgu eksik veya döngülü danışman zinciriyle geçemez", () => {
  for (const via of [["node-forge"], ["expo"]]) {
    const result = runAudit(report({ expo: { name: "expo", severity: "high", via } }), 1);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /missing or cyclic advisory provenance/);
  }
});

test("Temiz audit yanıtı bile uygulanmamış yamayı gizleyemez", () => {
  const result = runAudit(report(), 0, ({ packageRoot }) => restoreOriginal(packageRoot));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unapplied patch/);
});

test("Süresi dolan node-forge kararı audit kapısını kapatır", () => {
  const result = runAudit(report({ "node-forge": forge }), 1, ({ root }) => {
    writeFileSync(join(root, "security/node-forge-patch.json"), JSON.stringify({ ...patchPolicy, expiresOn: "2000-01-01" }));
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /review expired/);
});

test("Bulgu içeren rapor başarılı çıkış koduyla gizlenemez", () => {
  const result = runAudit(report({ "node-forge": forge }), 0);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /exit status/);
});

test("Bilinmeyen önem derecesi temiz rapor sayılmaz", () => {
  const payload = report({ "node-forge": forge });
  payload.vulnerabilities["node-forge"].severity = "unknown";
  const result = runAudit(payload, 1);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /invalid vulnerability record/);
});

test("Önceden belgelenen Metro istisnası yeni danışmanları kapsamaz", () => {
  const imageSize = { name: "image-size", severity: "high", via: [{ url: allowlist.allowedAdvisories[0] }] };
  const bounded = runAudit(report({ "image-size": imageSize }), 1);
  assert.equal(bounded.status, 1);
  assert.match(bounded.stderr, /node-forge release assurance is blocked/);
  const changed = { ...imageSize, via: [{ url: forge.via[0].url }] };
  assert.equal(runAudit(report({ "image-size": changed }), 1).status, 1);
});

test("Kritik bulgu mevcut geçici istisnadan yararlanamaz", () => {
  const imageSize = { name: "image-size", severity: "critical", via: [{ url: allowlist.allowedAdvisories[0] }] };
  const result = runAudit(report({ "image-size": imageSize }), 1);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /critical vulnerabilities cannot use/);
});

const releaseCommands = [
  "npm run audit:production",
  "npm run typecheck",
  "npm run typecheck:edge",
  "npm run typecheck:strict",
  "npm test",
  "npx expo install --check",
  "npm run export:android",
];

test("Doğrudan EAS üretim derlemesi ve uzak kurulum da yayın ön kontrolünü kullanır", () => {
  assert.equal(packageJson.scripts["eas-build-post-install"], "npm run verify:release");
  assert.equal(packageJson.scripts["build:play"], "npm run verify:release && eas build --platform android --profile production");
});

function runRelease(failure) {
  const root = mkdtempSync(join(tmpdir(), "stokdas-release-"));
  const calls = join(root, "calls.txt");
  try {
    for (const command of ["npm", "npx"]) {
      writeFileSync(join(root, command), `#!${process.execPath}\n
const fs = require("node:fs");
const call = ${JSON.stringify(command)} + " " + process.argv.slice(2).join(" ");
fs.appendFileSync(process.env.STOKDAS_RELEASE_CALLS, call + "\\n");
process.exit(call === process.env.STOKDAS_RELEASE_FAILURE ? 23 : 0);
`, { mode: 0o755 });
    }
    const result = spawnSync(packageJson.scripts["verify:release"], {
      shell: true,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${root}${delimiter}${process.env.PATH}`,
        STOKDAS_RELEASE_CALLS: calls,
        STOKDAS_RELEASE_FAILURE: failure ?? "",
      },
    });
    return { ...result, calls: readFileSync(calls, "utf8").trim().split("\n") };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("Yayın ön kontrolü güvenlik, tip, test, Expo ve Android dışa aktarımını çalıştırır", { skip: process.platform === "win32" }, () => {
  const result = runRelease();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls, releaseCommands);
});

for (const [index, command] of releaseCommands.entries()) {
  test(`Başarısız yayın kontrolünden sonra devam edilmez: ${command}`, { skip: process.platform === "win32" }, () => {
    const result = runRelease(command);
    assert.equal(result.status, 23);
    assert.deepEqual(result.calls, releaseCommands.slice(0, index + 1));
  });
}

for (const [file, releaseJob] of [
  ["eas-android-production.yml", "build"],
  ["eas-google-play-submit.yml", "submit"],
]) {
  test(`${file} başarılı güvenlik ön kontrolü olmadan yayın işini açmaz`, () => {
    const workflow = source(`.github/workflows/${file}`);
    const [validate, release] = workflow.split(`\n  ${releaseJob}:\n`);
    assert.match(validate, /\n  validate:\n/);
    assert.match(validate, /- name: Verify release security, tests and Android bundle\n        run: npm run verify:release/);
    assert.doesNotMatch(validate, /continue-on-error:|always\(\)|if:.*verify:release/);
    assert.match(release, /\n    needs: validate\n/);
    assert.doesNotMatch(release.split("\n    steps:")[0], /always\(\)|!cancelled\(\)/);
    assert.match(workflow, /persist-credentials: false/);
    assert.match(workflow, /\npermissions:\n  contents: read\n/);
  });
}
