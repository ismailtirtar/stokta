import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyBracesPatch } from "../scripts/braces-patch.mjs";
import { bracesFixture, patchPolicy, restoreOriginal } from "./helpers/braces-fixture.mjs";

function withFixture(fn, options) {
  const fixture = bracesFixture(options);
  try { return fn(fixture); } finally { fixture.cleanup(); }
}
function editJson(root, file, change) {
  const path = join(root, file);
  const value = JSON.parse(readFileSync(path, "utf8"));
  change(value);
  writeFileSync(path, JSON.stringify(value));
}
const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

test("Unpatched expansion overflows the default Node stack below the character limit", () => withFixture(({ packageRoot }) => {
  const source = "const b=require(process.argv[1]);b.expand('{'.repeat(4400)+'a'+'}'.repeat(4400));";
  const result = spawnSync(process.execPath, ["--input-type=commonjs", "-e", source, packageRoot], { encoding: "utf8", timeout: 8000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /RangeError: Maximum call stack size exceeded/);
}, { original: true }));

test("Unpatched compile and expand reproduce recursion overflow with a 256 KiB stack", () => withFixture(({ packageRoot }) => {
  for (const api of ["compile", "expand"]) {
    const source = `const b=require(process.argv[1]);b.${api}('{'.repeat(4400)+'a'+'}'.repeat(4400));`;
    const result = spawnSync(process.execPath, ["--stack_size=256", "--input-type=commonjs", "-e", source, packageRoot], { encoding: "utf8", timeout: 8000 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /RangeError: Maximum call stack size exceeded/);
  }
}, { original: true }));

test("Clean patch applies and passes 206 actual parser, walker and consumer probes", () => withFixture(({ root, packageRoot }) => {
  assert.throws(() => verifyBracesPatch({ root }), /unapplied patch/);
  const first = verifyBracesPatch({ root, apply: true });
  assert.equal(first.cases, 206);
  assert.equal(first.fileCount, 10);
  const before = Object.keys(patchPolicy.replacements).map((file) => hash(join(packageRoot, file)));
  assert.equal(verifyBracesPatch({ root, apply: true }).cases, 206);
  assert.deepEqual(Object.keys(patchPolicy.replacements).map((file) => hash(join(packageRoot, file))), before);
}, { original: true }));

for (const file of Object.keys(patchPolicy.replacements)) {
  test(`Check never heals a missing patch: ${file}`, () => withFixture(({ root, packageRoot }) => {
    restoreOriginal(packageRoot, [file]);
    const before = hash(join(packageRoot, file));
    const result = spawnSync(process.execPath, [join(root, "scripts/braces-patch.mjs"), "--check"], { encoding: "utf8", timeout: 8000 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /unapplied patch/);
    assert.equal(hash(join(packageRoot, file)), before);
  }));
}

test("All files validate before any pending patch is written", () => withFixture(({ root, packageRoot }) => {
  restoreOriginal(packageRoot);
  const path = join(packageRoot, "README.md");
  writeFileSync(path, `${readFileSync(path, "utf8")}\n// unexpected\n`);
  assert.throws(() => verifyBracesPatch({ root, apply: true }), /integrity mismatch/);
  for (const file of Object.keys(patchPolicy.replacements)) assert.equal(hash(join(packageRoot, file)), patchPolicy.files[file].original);
}));

test("Added and removed package files fail closed", () => {
  withFixture(({ root, packageRoot }) => {
    writeFileSync(join(packageRoot, "lib/extra.js"), "module.exports={};\n");
    assert.throws(() => verifyBracesPatch({ root }), /inventory changed/);
  });
  withFixture(({ root, packageRoot }) => {
    rmSync(join(packageRoot, "lib/utils.js"));
    assert.throws(() => verifyBracesPatch({ root }), /inventory changed/);
  });
});

test("Package file symlinks fail closed", { skip: process.platform === "win32" }, () => withFixture(({ root, packageRoot }) => {
  const target = join(packageRoot, "lib/parse.js");
  cpSync(target, join(root, "external.js"));
  rmSync(target);
  symlinkSync(join(root, "external.js"), target);
  assert.throws(() => verifyBracesPatch({ root }), /symlink or non-regular file/);
}));

for (const [label, change] of [
  ["tarball integrity", (lock) => { lock.packages[patchPolicy.installPaths[0]].integrity = "sha512-changed"; }],
  ["registry source", (lock) => { lock.packages[patchPolicy.installPaths[0]].resolved = "https://example.invalid/fork.tgz"; }],
  ["version", (lock) => { lock.packages[patchPolicy.installPaths[0]].version = "3.0.4"; }],
  ["additional install", (lock) => { lock.packages["node_modules/extra/node_modules/braces"] = lock.packages[patchPolicy.installPaths[0]]; }],
  ["new consumer", (lock) => { lock.packages["node_modules/extra"] = { version: "1.0.0", dependencies: { braces: "3.0.3" } }; }],
  ["consumer dependency graph", (lock) => { lock.packages["node_modules/micromatch"].version = "4.0.9"; }],
  ["Expo graph tarball", (lock) => { lock.packages["node_modules/expo"].integrity = "sha512-changed"; }],
]) {
  test(`Lock graph changes require review: ${label}`, () => withFixture(({ root }) => {
    editJson(root, "package-lock.json", change);
    assert.throws(() => verifyBracesPatch({ root }), /changed|unexpected/);
  }));
}

test("An installed copy absent from the lockfile is rejected", () => withFixture(({ root, packageRoot }) => {
  const hidden = join(root, "node_modules/unrelated/node_modules/braces");
  mkdirSync(hidden, { recursive: true });
  cpSync(packageRoot, hidden, { recursive: true });
  assert.throws(() => verifyBracesPatch({ root }), /unexpected or missing installed braces copy/);
}));

test("A symlinked unrelated package cannot hide a nested braces copy", { skip: process.platform === "win32" }, () => withFixture(({ root, packageRoot }) => {
  const external = join(root, "external-package/node_modules/braces");
  mkdirSync(external, { recursive: true });
  cpSync(packageRoot, external, { recursive: true });
  symlinkSync(join(root, "external-package"), join(root, "node_modules/unrelated"));
  assert.throws(() => verifyBracesPatch({ root }), /may not be symlinked/);
}));

test("A shadow micromatch resolved by Metro is rejected", () => withFixture(({ root }) => {
  const shadow = join(root, "node_modules/metro-file-map/node_modules/micromatch");
  mkdirSync(shadow, { recursive: true });
  cpSync(join(root, "node_modules/micromatch"), shadow, { recursive: true });
  assert.throws(() => verifyBracesPatch({ root }), /uncovered micromatch resolved/);
}));

test("A changed installed Metro consumer is rejected", () => withFixture(({ root }) => {
  editJson(root, "node_modules/metro-file-map/package.json", (pkg) => { pkg.version = "0.83.4"; });
  assert.throws(() => verifyBracesPatch({ root }), /micromatch consumer version changed/);
}));

test("Expiry fails both installation and release check", () => withFixture(({ root }) => {
  const now = Date.parse(`${patchPolicy.expiresOn}T23:59:59.999Z`) + 1;
  for (const apply of [false, true]) assert.throws(() => verifyBracesPatch({ root, apply, now }), /review expired/);
}));

test("Exact override and mandatory installation hook cannot be removed", () => {
  for (const change of [
    (pkg) => { delete pkg.scripts.postinstall; },
    (pkg) => { pkg.overrides.braces = "^3.0.3"; },
  ]) withFixture(({ root }) => {
    editJson(root, "package.json", change);
    assert.throws(() => verifyBracesPatch({ root }), /mandatory|exact override/);
  });
});
