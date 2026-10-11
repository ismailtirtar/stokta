import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertNodeForgeReleaseAssurance } from "../scripts/node-forge-release-assurance.mjs";

// Policy-only checks: no dependency installation, keys, signatures or parser inputs.
test("Unresolved encoding coverage cannot grant release assurance", () => {
  assert.throws(assertNodeForgeReleaseAssurance, /node-forge release assurance is blocked:.*60 parser cases/);
});

test("Release hold explains the independent diagnostic command", () => {
  assert.throws(assertNodeForgeReleaseAssurance, /Raw npm audit --omit=dev --json remains available/);
});

test("Both audit success paths require the release assurance guard", () => {
  const source = readFileSync(new URL("../scripts/verify-npm-audit.mjs", import.meta.url), "utf8");
  assert.match(source, /function pass\(message\) \{\s+try \{\s+assertNodeForgeReleaseAssurance\(\);/);
  assert.equal((source.match(/pass\("Production dependency audit passed/g) ?? []).length, 2);
  assert.doesNotMatch(source, /console\.log\("Production dependency audit passed/);
});
