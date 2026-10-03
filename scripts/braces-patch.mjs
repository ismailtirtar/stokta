import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { depthProbeResults } from "./braces-probes.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function inventory(root, prefix = "") {
  assert(lstatSync(root).isDirectory(), `braces directory is missing or symlinked: ${root}`);
  const files = [];
  for (const name of readdirSync(root).sort()) {
    const path = join(root, name);
    const relative = `${prefix}${name}`;
    const stat = lstatSync(path);
    if (stat.isDirectory()) files.push(...inventory(path, `${relative}/`));
    else {
      assert(stat.isFile(), `braces has a symlink or non-regular file: ${relative}`);
      files.push(relative);
    }
  }
  return files.sort();
}

// Scan actual npm package locations as well as the lockfile and consumer
// resolution. A hidden nested installation must not escape the patch.
function installations(root) {
  const found = [];
  const visit = (modules) => {
    if (!existsSync(modules)) return;
    assert(lstatSync(modules).isDirectory(), `node_modules may not be symlinked: ${modules}`);
    const packages = [];
    for (const name of readdirSync(modules)) {
      if (name.startsWith(".")) continue;
      const path = join(modules, name);
      assert(lstatSync(path).isDirectory(), `npm package or scope may not be symlinked: ${path}`);
      if (name.startsWith("@")) {
        for (const child of readdirSync(path)) packages.push(join(path, child));
      } else packages.push(path);
    }
    for (const path of packages) {
      assert(lstatSync(path).isDirectory(), `npm package may not be symlinked: ${path}`);
      if (path.endsWith("/braces")) found.push(path);
      visit(join(path, "node_modules"));
    }
  };
  visit(join(root, "node_modules"));
  return found.sort();
}

// apply is reserved for postinstall. Check and audit never repair bytes.
export function verifyBracesPatch({ root = projectRoot, apply = false, now = Date.now() } = {}) {
  root = resolve(root);
  const policy = json(join(root, "security/braces-patch.json"));
  assert.equal(policy.version, "3.0.3", "braces patch needs review for a new version");
  assert.equal(policy.advisory, "https://github.com/advisories/GHSA-vfj7-8cjw-p6xm");
  assert.equal(policy.maxDepth, 100, "braces depth ceiling requires review");
  assert.match(policy.expiresOn, /^\d{4}-\d{2}-\d{2}$/);
  const expiry = Date.parse(`${policy.expiresOn}T23:59:59.999Z`);
  assert(Number.isFinite(expiry) && new Date(expiry).toISOString().startsWith(policy.expiresOn), "invalid patch expiry");
  assert(Number.isFinite(now) && now <= expiry, `braces patch review expired on ${policy.expiresOn}`);
  const pkg = json(join(root, "package.json"));
  const lock = json(join(root, "package-lock.json"));
  assert.equal(pkg.overrides?.braces, policy.version, "braces must have an exact override");
  assert.equal(pkg.scripts?.postinstall, "node scripts/node-forge-patch.mjs && node scripts/braces-patch.mjs", "braces postinstall is mandatory");
  assert.equal(lock.lockfileVersion, 3, "unsupported package-lock format");
  const locked = Object.entries(lock.packages);
  const paths = locked.filter(([path]) => /(^|\/)node_modules\/braces$/.test(path)).map(([path]) => path).sort();
  assert.deepEqual(paths, policy.installPaths, "unexpected or missing braces installation in lockfile");
  assert.deepEqual(installations(root), paths.map((path) => join(root, path)).sort(), "unexpected or missing installed braces copy");
  const consumers = Object.fromEntries(locked.filter(([, value]) => value.dependencies?.braces).map(([path, value]) => [path, value.version]));
  assert.deepEqual(consumers, policy.consumers, "braces consumer graph changed; review required");
  const micromatchConsumers = Object.fromEntries(locked.filter(([, value]) => value.dependencies?.micromatch).map(([path, value]) => [path, value.version]));
  assert.deepEqual(micromatchConsumers, policy.micromatchConsumers, "micromatch consumer graph changed; review required");
  assert.deepEqual(Object.keys(policy.replacements).sort(), ["lib/compile.js", "lib/constants.js", "lib/expand.js", "lib/parse.js", "lib/stringify.js"]);
  for (const [path, metadata] of Object.entries({ ...policy.auditPackages, ...policy.probeDependencies })) {
    const entry = lock.packages[path];
    assert(entry, `braces dependency missing from lockfile: ${path}`);
    for (const key of ["version", "resolved", "integrity"]) assert.equal(entry[key], metadata[key], `braces dependency ${key} changed: ${path}`);
  }

  const pending = [];
  for (const path of paths) {
    const entry = lock.packages[path];
    assert.equal(entry.version, policy.version, "braces lock version changed");
    assert.equal(entry.resolved, policy.resolved, "braces registry source changed");
    assert.equal(entry.integrity, policy.integrity, "braces tarball integrity changed");
    const packageRoot = join(root, path);
    assert.equal(realpathSync(packageRoot), packageRoot, "braces installation may not resolve through a symlink");
    assert.deepEqual(inventory(packageRoot), Object.keys(policy.files).sort(), "braces file inventory changed");
    for (const [file, hashes] of Object.entries(policy.files)) {
      const target = join(packageRoot, file);
      const bytes = readFileSync(target);
      const hash = sha256(bytes);
      if (hash === (hashes.patched ?? hashes.original)) continue;
      assert(apply && hashes.patched && hash === hashes.original, `braces integrity mismatch or unapplied patch: ${path}/${file}`);
      const replacement = policy.replacements[file];
      const source = bytes.toString("utf8");
      assert(replacement && source === replacement.before, `braces patch context changed: ${file}`);
      assert.equal(sha256(replacement.after), hashes.patched, `braces patched hash mismatch: ${file}`);
      pending.push({ target, patched: replacement.after });
    }
  }

  for (const [path, version] of Object.entries(policy.consumers)) {
    const parent = join(root, path, "package.json");
    assert.equal(json(parent).version, version, `braces consumer version changed: ${path}`);
    assert.equal(realpathSync(dirname(parent)), dirname(parent), `braces consumer may not be symlinked: ${path}`);
    const require = createRequire(parent);
    const resolvedPackage = require.resolve("braces/package.json");
    assert(paths.some((path) => resolvedPackage === join(root, path, "package.json")), `uncovered braces resolved by ${path}`);
    assert.equal(require.resolve("braces"), join(dirname(resolvedPackage), "index.js"), `unexpected braces entrypoint for ${path}`);
  }
  for (const [path, metadata] of Object.entries(policy.probeDependencies)) {
    assert.equal(json(join(root, path, "package.json")).version, metadata.version, `installed braces dependency version changed: ${path}`);
  }
  for (const [path, version] of Object.entries(policy.micromatchConsumers)) {
    const parent = join(root, path, "package.json");
    assert.equal(json(parent).version, version, `micromatch consumer version changed: ${path}`);
    assert.equal(realpathSync(dirname(parent)), dirname(parent), `micromatch consumer may not be symlinked: ${path}`);
    const require = createRequire(parent);
    assert.equal(require.resolve("micromatch/package.json"), join(root, "node_modules/micromatch/package.json"), `uncovered micromatch resolved by ${path}`);
    assert.equal(require.resolve("micromatch"), join(root, "node_modules/micromatch/index.js"), `unexpected micromatch entrypoint for ${path}`);
  }
  // Validate every target before changing any file, then require fresh runtime
  // probes in an isolated process so a cached pre-patch module cannot pass.
  if (pending.length > 0) {
    for (const { target, patched } of pending) writeFileSync(target, patched);
    return verifyBracesPatch({ root, now });
  }
  let cases = 0;
  for (const path of paths) {
    const results = depthProbeResults(join(root, path), { consumers: Object.keys(policy.consumers).map((path) => join(root, path)) });
    assert.equal(results.length, 206, "braces depth probes are incomplete");
    for (const result of results) assert(result.passed, `braces depth probe failed: ${result.name}: ${result.detail}`);
    cases += results.length;
  }
  return { ...policy, cases, fileCount: Object.keys(policy.files).length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === "--check"), "usage: node scripts/braces-patch.mjs [--check]");
    const proof = verifyBracesPatch({ apply: process.argv[2] !== "--check" });
    console.log(`braces ${proof.version}: depth patch verified; ${proof.fileCount} file hashes, ${proof.cases} runtime cases, public + direct library + micromatch APIs; review expires ${proof.expiresOn}.`);
  } catch (error) {
    console.error(`braces patch verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
