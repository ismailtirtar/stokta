import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { signatureProbeResults } from "./node-forge-probes.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function inventory(root, prefix = "") {
  assert(lstatSync(root).isDirectory(), `node-forge directory is missing or symlinked: ${root}`);
  const files = [];
  for (const name of readdirSync(root).sort()) {
    const path = join(root, name);
    const relative = `${prefix}${name}`;
    const stat = lstatSync(path);
    if (stat.isDirectory()) files.push(...inventory(path, `${relative}/`));
    else {
      assert(stat.isFile(), `node-forge has a symlink or non-regular file: ${relative}`);
      files.push(relative);
    }
  }
  return files.sort();
}

// apply=true is only used by postinstall. The release check never repairs a
// missing/altered patch: even npm ci --ignore-scripts must fail closed.
export function verifyNodeForgePatch({ root = projectRoot, apply = false, now = Date.now() } = {}) {
  root = resolve(root);
  const policy = json(join(root, "security/node-forge-patch.json"));
  assert.equal(policy.version, "1.4.0", "node-forge patch needs review for a new version");
  assert.equal(policy.advisory, "https://github.com/advisories/GHSA-86w9-cpqp-85rv");
  assert.match(policy.expiresOn, /^\d{4}-\d{2}-\d{2}$/);
  const expiry = Date.parse(`${policy.expiresOn}T23:59:59.999Z`);
  assert(Number.isFinite(expiry) && new Date(expiry).toISOString().startsWith(policy.expiresOn), "invalid patch expiry");
  assert(Number.isFinite(now) && now <= expiry, `node-forge patch review expired on ${policy.expiresOn}`);
  const pkg = json(join(root, "package.json"));
  const lock = json(join(root, "package-lock.json"));
  assert.equal(pkg.overrides?.["node-forge"], policy.version, "node-forge must have an exact override");
  assert.equal(pkg.scripts?.postinstall, "node scripts/node-forge-patch.mjs", "node-forge postinstall is mandatory");
  assert.equal(lock.lockfileVersion, 3, "unsupported package-lock format");
  const locked = Object.entries(lock.packages);
  const paths = locked.filter(([path]) => /(^|\/)node_modules\/node-forge$/.test(path)).map(([path]) => path).sort();
  assert.deepEqual(paths, policy.installPaths, "unexpected or missing node-forge installation in lockfile");
  const consumers = Object.fromEntries(locked.filter(([, value]) => value.dependencies?.["node-forge"]).map(([path, value]) => [path, value.version]));
  assert.deepEqual(consumers, policy.consumers, "node-forge consumer graph changed; review required");
  assert.deepEqual(Object.keys(policy.replacements).sort(), ["dist/forge.all.min.js", "dist/forge.min.js", "lib/rsa.js"]);

  const pending = [];
  for (const path of paths) {
    const entry = lock.packages[path];
    assert.equal(entry.version, policy.version, "node-forge lock version changed");
    assert.equal(entry.resolved, policy.resolved, "node-forge registry source changed");
    assert.equal(entry.integrity, policy.integrity, "node-forge tarball integrity changed");
    const packageRoot = join(root, path);
    assert.equal(realpathSync(packageRoot), packageRoot, "node-forge installation may not resolve through a symlink");
    assert.deepEqual(inventory(packageRoot), Object.keys(policy.files).sort(), "node-forge file inventory changed");
    for (const [file, hashes] of Object.entries(policy.files)) {
      const target = join(packageRoot, file);
      const bytes = readFileSync(target);
      const hash = sha256(bytes);
      if (hash === (hashes.patched ?? hashes.original)) continue;
      assert(apply && hashes.patched && hash === hashes.original, `node-forge integrity mismatch or unapplied patch: ${path}/${file}`);
      const replacement = policy.replacements[file];
      const source = bytes.toString("utf8");
      assert(replacement && source.split(replacement.before).length === 2, `node-forge patch context changed: ${file}`);
      const patched = source.replace(replacement.before, replacement.after);
      assert.equal(sha256(patched), hashes.patched, `node-forge patched hash mismatch: ${file}`);
      pending.push({ target, patched });
    }
  }

  for (const [path, version] of Object.entries(policy.consumers)) {
    const parent = join(root, path, "package.json");
    assert.equal(json(parent).version, version, `node-forge consumer version changed: ${path}`);
    const require = createRequire(parent);
    const resolvedPackage = require.resolve("node-forge/package.json");
    assert(paths.some((path) => resolvedPackage === join(root, path, "package.json")), `uncovered node-forge resolved by ${path}`);
    assert.equal(require.resolve("node-forge"), join(dirname(resolvedPackage), "lib/index.js"), `unexpected node-forge entrypoint for ${path}`);
  }

  // Validate every input before writing any file. Then require a fresh full
  // verification, including cryptographic behavior, of the installed bytes.
  if (pending.length > 0) {
    for (const { target, patched } of pending) writeFileSync(target, patched);
    return verifyNodeForgePatch({ root, now });
  }
  let cases = 0;
  for (const path of paths) {
    const results = signatureProbeResults(join(root, path));
    assert.equal(results.length, 60, "node-forge signature probes are incomplete");
    for (const result of results) {
      assert.equal(result.accepted, result.expected, `node-forge signature check failed: ${result.entrypoint}, e=${result.exponent}, ${result.name}`);
    }
    cases += results.length;
  }
  return { ...policy, cases, fileCount: Object.keys(policy.files).length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === "--check"), "usage: node scripts/node-forge-patch.mjs [--check]");
    const proof = verifyNodeForgePatch({ apply: process.argv[2] !== "--check" });
    console.log(`node-forge ${proof.version}: patch verified; ${proof.fileCount} file hashes, ${proof.cases} RSA parser cases, source + 2 browser builds; review expires ${proof.expiresOn}.`);
  } catch (error) {
    console.error(`node-forge patch verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
