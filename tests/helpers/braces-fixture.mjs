import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const projectRoot = fileURLToPath(new URL("../../", import.meta.url));
export const patchPolicy = JSON.parse(readFileSync(join(projectRoot, "security/braces-patch.json"), "utf8"));

export function restoreOriginal(packageRoot, files = Object.keys(patchPolicy.replacements)) {
  for (const file of files) {
    const path = join(packageRoot, file);
    const { before, after } = patchPolicy.replacements[file];
    const source = readFileSync(path, "utf8");
    assert(source === before || source === after, `unexpected fixture source: ${file}`);
    writeFileSync(path, before);
  }
}

export function bracesFixture({ original = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "stokdas-braces-"));
  for (const file of [
    "package.json", "package-lock.json", "security/braces-patch.json",
    "scripts/braces-patch.mjs", "scripts/braces-probes.mjs",
    ...Object.keys(patchPolicy.micromatchConsumers).map((path) => `${path}/package.json`),
  ]) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    cpSync(join(projectRoot, file), join(root, file));
  }
  for (const path of [...patchPolicy.installPaths, ...Object.keys(patchPolicy.probeDependencies)]) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    cpSync(join(projectRoot, path), join(root, path), { recursive: true });
  }
  const packageRoot = join(root, patchPolicy.installPaths[0]);
  if (original) restoreOriginal(packageRoot);
  return { root, packageRoot, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
