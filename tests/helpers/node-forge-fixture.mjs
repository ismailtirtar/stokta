import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const projectRoot = fileURLToPath(new URL("../../", import.meta.url));
export const patchPolicy = JSON.parse(readFileSync(join(projectRoot, "security/node-forge-patch.json"), "utf8"));

export function restoreOriginal(packageRoot, files = Object.keys(patchPolicy.replacements)) {
  for (const file of files) {
    const path = join(packageRoot, file);
    const replacement = patchPolicy.replacements[file];
    const source = readFileSync(path, "utf8");
    writeFileSync(path, source.replace(replacement.after, replacement.before));
  }
}

export function nodeForgeFixture({ original = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "stokdas-forge-"));
  for (const file of [
    "package.json", "package-lock.json", "security/node-forge-patch.json", "security/braces-patch.json", "security/npm-audit-allowlist.json",
    "scripts/node-forge-release-assurance.mjs", "scripts/node-forge-patch.mjs", "scripts/node-forge-probes.mjs", "scripts/braces-patch.mjs", "scripts/braces-probes.mjs", "scripts/verify-npm-audit.mjs",
    ...Object.keys(patchPolicy.consumers).map((path) => `${path}/package.json`),
    ...["@jest/transform", "jest-haste-map", "jest-message-util", "metro-file-map"].map((name) => `node_modules/${name}/package.json`),
  ]) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    cpSync(join(projectRoot, file), join(root, file));
  }
  const packageRoot = join(root, "node_modules/node-forge");
  cpSync(join(projectRoot, "node_modules/node-forge"), packageRoot, { recursive: true });
  for (const name of ["braces", "micromatch", "picomatch", "fill-range", "to-regex-range", "is-number"]) {
    cpSync(join(projectRoot, "node_modules", name), join(root, "node_modules", name), { recursive: true });
  }
  if (original) restoreOriginal(packageRoot);
  return { root, packageRoot, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
