import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyNodeForgePatch } from "../scripts/node-forge-patch.mjs";
import { encodingGapNames, signatureProbeCaseCount, signatureProbeResults } from "../scripts/node-forge-probes.mjs";
import { nodeForgeFixture, patchPolicy, projectRoot, restoreOriginal } from "./helpers/node-forge-fixture.mjs";

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
function withFixture(fn, options) {
  const fixture = nodeForgeFixture(options);
  try { return fn(fixture); } finally { fixture.cleanup(); }
}
function editJson(root, file, change) {
  const path = join(root, file);
  const value = readJson(path);
  change(value);
  writeFileSync(path, JSON.stringify(value));
}
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

test("Yamasız paket kaynak ve iki tarayıcı girişinde açığı tekrar gösterir", () => withFixture(({ packageRoot }) => {
  const results = signatureProbeResults(packageRoot);
  assert.equal(results.length, signatureProbeCaseCount);
  for (const result of results) {
    const vulnerable = [...encodingGapNames, "extra nested OCTET STRING", "unexpected nested parameter", "duplicate nested NULL"].includes(result.name);
    assert.equal(result.accepted, vulnerable ? true : result.expected, JSON.stringify(result));
  }
}, { original: true }));

test("Temiz kaynak yaması uygulanır, gerçek imzalar doğrulanır ve ikinci uygulama değişiklik yapmaz", () => withFixture(({ root, packageRoot }) => {
  assert.throws(() => verifyNodeForgePatch({ root }), /unapplied patch/);
  const first = verifyNodeForgePatch({ root, apply: true });
  assert.equal(first.cases, signatureProbeCaseCount);
  assert.equal(first.fileCount, 59);
  const before = Object.keys(patchPolicy.replacements).map((file) => hash(join(packageRoot, file)));
  assert.equal(verifyNodeForgePatch({ root, apply: true }).cases, signatureProbeCaseCount);
  assert.deepEqual(Object.keys(patchPolicy.replacements).map((file) => hash(join(packageRoot, file))), before);
}, { original: true }));

// If a future reviewed manifest matches bytes that accidentally omit either
// check, the behavior probes must still close the release gate.
for (const file of Object.keys(patchPolicy.replacements)) {
  for (const check of ["NULL", "DER length"]) {
    test(`Davranış kontrolü hash güncellense de eksik ${check} denetimini yakalar: ${file}`, () => withFixture(({ root, packageRoot }) => {
      const path = join(packageRoot, file);
      const source = readFileSync(path, "utf8");
      const removed = file === "lib/rsa.js" ?
        (check === "NULL" ? "            (('parameters' in capture) && capture.parameters !== '') ||\n" : " ||\n            asn1.toDer(obj).getBytes() !== d.substr(0,\n              options._parseAllDigestBytes ? d.length : asn1.toDer(obj).length())") :
        (check === "NULL" ? '||("parameters"in o&&""!==o.parameters)' : `||s.toDer(${file === "dist/forge.min.js" ? "n" : "a"}).getBytes()!==t.substr(0,i._parseAllDigestBytes?t.length:s.toDer(${file === "dist/forge.min.js" ? "n" : "a"}).length())`);
      assert.equal(source.split(removed).length, 2);
      writeFileSync(path, source.replace(removed, ""));
      editJson(root, "security/node-forge-patch.json", (policy) => { policy.files[file].patched = hash(path); });
      const scenario = check === "NULL" ? "NULL with one content octet" : "DigestInfo long-form short length";
      assert.throws(() => verifyNodeForgePatch({ root }), (error) => error.message.includes("node-forge signature check failed") && error.message.includes(scenario));
    }));
  }
}

for (const file of Object.keys(patchPolicy.replacements)) {
  test(`Tek bir yamalı girişin geri alınması kontrolü kapatır: ${file}`, () => withFixture(({ root, packageRoot }) => {
    restoreOriginal(packageRoot, [file]);
    const result = spawnSync(process.execPath, [join(root, "scripts/node-forge-patch.mjs"), "--check"], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /unapplied patch/);
    assert.equal(hash(join(packageRoot, file)), patchPolicy.files[file].original);
  }));
}

for (const file of ["lib/rsa.js", "lib/asn1.js", "lib/index.js"]) {
  test(`Değiştirilmiş paket dosyası otomatik onarılmaz: ${file}`, () => withFixture(({ root, packageRoot }) => {
    const path = join(packageRoot, file);
    writeFileSync(path, `${readFileSync(path, "utf8")}\n// unexpected change\n`);
    const before = hash(path);
    assert.throws(() => verifyNodeForgePatch({ root, apply: true }), /integrity mismatch/);
    assert.equal(hash(path), before);
  }));
}

test("Eklenen veya silinen paket dosyası reddedilir", () => {
  withFixture(({ root, packageRoot }) => {
    writeFileSync(join(packageRoot, "lib/unexpected.js"), "module.exports = {};\n");
    assert.throws(() => verifyNodeForgePatch({ root }), /inventory changed/);
  });
  withFixture(({ root, packageRoot }) => {
    rmSync(join(packageRoot, "lib/asn1.js"));
    assert.throws(() => verifyNodeForgePatch({ root }), /inventory changed/);
  });
});

test("Paket içindeki sembolik bağlantı reddedilir", { skip: process.platform === "win32" }, () => withFixture(({ root, packageRoot }) => {
  const target = join(packageRoot, "lib/rsa.js");
  cpSync(target, join(root, "external.js"));
  rmSync(target);
  symlinkSync(join(root, "external.js"), target);
  assert.throws(() => verifyNodeForgePatch({ root }), /symlink or non-regular file/);
}));

for (const [label, change] of [
  ["tarball özeti", (lock) => { lock.packages[patchPolicy.installPaths[0]].integrity = "sha512-changed"; }],
  ["paket kaynağı", (lock) => { lock.packages[patchPolicy.installPaths[0]].resolved = "https://example.invalid/fork.tgz"; }],
  ["paket sürümü", (lock) => { lock.packages[patchPolicy.installPaths[0]].version = "1.4.1"; }],
  ["ek kurulum", (lock) => { lock.packages["node_modules/extra/node_modules/node-forge"] = lock.packages[patchPolicy.installPaths[0]]; }],
  ["yeni tüketici", (lock) => { lock.packages["node_modules/extra"] = { version: "1.0.0", dependencies: { "node-forge": "1.4.0" } }; }],
]) {
  test(`Lockfile kapsamı değiştiğinde yeniden inceleme gerekir: ${label}`, () => withFixture(({ root }) => {
    editJson(root, "package-lock.json", change);
    assert.throws(() => verifyNodeForgePatch({ root }), /changed|unexpected/);
  }));
}

test("Kilitte görünmeyen, tüketicinin gerçekten çözdüğü node-forge kopyası reddedilir", () => withFixture(({ root, packageRoot }) => {
  const parent = join(root, "node_modules/@expo/code-signing-certificates/node_modules");
  mkdirSync(parent, { recursive: true });
  cpSync(packageRoot, join(parent, "node-forge"), { recursive: true });
  assert.throws(() => verifyNodeForgePatch({ root }), /uncovered node-forge resolved/);
}));

test("Süresi dolan yama kurulumu ve yayını durdurur", () => withFixture(({ root }) => {
  const now = Date.parse(`${patchPolicy.expiresOn}T23:59:59.999Z`) + 1;
  for (const apply of [false, true]) assert.throws(() => verifyNodeForgePatch({ root, apply, now }), /review expired/);
}));

test("Kurulum hook'u kaldırılarak veya sürüm aralığıyla yama atlanamaz", () => {
  for (const change of [
    (pkg) => { delete pkg.scripts.postinstall; },
    (pkg) => { pkg.overrides["node-forge"] = "^1.4.0"; },
  ]) withFixture(({ root }) => {
    editJson(root, "package.json", change);
    assert.throws(() => verifyNodeForgePatch({ root }), /mandatory|exact override/);
  });
});

test("Expo gerçek sertifika, CSR ve SHA-256 imza akışıyla uyumluluğunu korur", () => {
  verifyNodeForgePatch();
  const require = createRequire(join(projectRoot, "package.json"));
  const api = require("@expo/code-signing-certificates");
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyPair = api.convertKeyPairPEMToKeyPair({
    privateKeyPEM: pair.privateKey.export({ type: "pkcs1", format: "pem" }),
    publicKeyPEM: pair.publicKey.export({ type: "spki", format: "pem" }),
  });
  const certificate = api.generateSelfSignedCodeSigningCertificate({
    keyPair, commonName: "Stokdas local security regression",
    validityNotBefore: new Date(Date.now() - 60_000), validityNotAfter: new Date(Date.now() + 60_000),
  });
  const parsed = api.convertCertificatePEMToCertificate(api.convertCertificateToCertificatePEM(certificate));
  api.validateSelfSignedCertificate(parsed, keyPair);
  const csr = api.convertCSRPEMToCSR(api.convertCSRToCSRPEM(api.generateCSR(keyPair, "Stokdas local regression")));
  assert.equal(csr.verify(), true);
  const message = Buffer.from("Stokdas Expo code signing compatibility");
  const signature = Buffer.from(api.signBufferRSASHA256AndVerify(keyPair.privateKey, parsed, message), "base64");
  assert.equal(verify("sha256", message, pair.publicKey, signature), true);
  assert.equal(verify("sha256", Buffer.from("changed"), pair.publicKey, signature), false);
});
