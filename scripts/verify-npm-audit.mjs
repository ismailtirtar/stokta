import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { verifyNodeForgePatch } from "./node-forge-patch.mjs";
import { verifyBracesPatch } from "./braces-patch.mjs";

const allowlist = JSON.parse(
  readFileSync(new URL("../security/npm-audit-allowlist.json", import.meta.url), "utf8"),
);

function fail(message, details = []) {
  console.error(`Production dependency audit failed: ${message}`);
  for (const detail of details) console.error(`- ${detail}`);
  process.exit(1);
}

if (!/^\d{4}-\d{2}-\d{2}$/.test(allowlist.expiresOn ?? "")) {
  fail("allowlist expiry is missing or invalid");
}
const expiry = Date.parse(`${allowlist.expiresOn}T23:59:59.999Z`);
if (!Number.isFinite(expiry) || Date.now() > expiry) {
  fail(`temporary allowlist expired on ${allowlist.expiresOn}`);
}

const allowedPackages = new Set(allowlist.allowedPackages ?? []);
const allowedAdvisories = new Set(allowlist.allowedAdvisories ?? []);
if (allowedPackages.size === 0 || allowedAdvisories.size === 0) {
  fail("allowlist must name both packages and advisory URLs");
}

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const audit = spawnSync(npmCommand, ["audit", "--omit=dev", "--json"], {
  encoding: "utf8",
  maxBuffer: 20 * 1024 * 1024,
});
if (audit.error) fail(`npm audit could not start: ${audit.error.message}`);
if (![0, 1].includes(audit.status ?? -1)) {
  fail(`npm audit exited unexpectedly with status ${audit.status ?? "unknown"}`);
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch {
  fail("npm audit did not return valid JSON", [audit.stderr.trim()].filter(Boolean));
}
if (report?.error) {
  fail("npm audit returned an error", [report.error.summary, report.error.detail].filter(Boolean));
}

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const severities = ["info", "low", "moderate", "high", "critical"];
const counts = report?.metadata?.vulnerabilities;
if (report?.auditReportVersion !== 2 || !isRecord(report.vulnerabilities) || !isRecord(counts)) {
  fail("npm audit report is incomplete or has an unsupported format");
}
const vulnerabilities = Object.entries(report.vulnerabilities);
for (const [name, value] of vulnerabilities) {
  if (!isRecord(value) || value.name !== name || !severities.includes(value.severity) ||
    !Array.isArray(value.via) || value.via.length === 0) {
    fail(`invalid vulnerability record for ${name}`);
  }
}
for (const severity of severities) {
  const observed = vulnerabilities.filter(([, value]) => value.severity === severity).length;
  if (!Number.isSafeInteger(counts[severity]) || counts[severity] < 0 || counts[severity] !== observed) {
    fail(`npm audit ${severity} count does not match vulnerability records`);
  }
}
if (counts.total !== vulnerabilities.length ||
  (audit.status === 0) !== (counts.total === 0)) {
  fail("npm audit totals or exit status do not match vulnerability records");
}

const severe = vulnerabilities
  .filter(([, value]) => value && ["high", "critical"].includes(value.severity));
if (severe.some(([, value]) => value.severity === "critical")) {
  fail("critical vulnerabilities cannot use the temporary allowlist");
}
let forgeProof;
try {
  forgeProof = verifyNodeForgePatch();
} catch (error) {
  fail(`node-forge mitigation was not verified: ${error.message}`);
}
let bracesProof;
try {
  bracesProof = verifyBracesPatch();
} catch (error) {
  fail(`braces mitigation was not verified: ${error.message}`);
}
if (severe.length === 0) {
  console.log("Production dependency audit passed with no high or critical findings.");
  process.exit(0);
}

const unexpected = [];
const observedAdvisories = new Set();
const evidenceCache = new Map();
const forgeEdges = {
  "@expo/code-signing-certificates": ["node-forge"],
  "@expo/cli": ["node-forge", "@expo/code-signing-certificates"],
  expo: ["@expo/cli"],
};
// npm's indirect records may contain the actual Metro dependency cycle. First
// validate every reachable record; then propagate only bounded advisory evidence
// until a fixed point. A cycle cannot create its own evidence.
const graph = new Map();
const pending = severe.map(([name]) => name);
while (pending.length > 0) {
  const name = pending.pop();
  if (graph.has(name)) continue;
  const vulnerability = report.vulnerabilities[name];
  if (!vulnerability) {
    unexpected.push(`${name}: missing or cyclic advisory provenance`);
    continue;
  }
  const evidence = new Set();
  const children = [];
  for (const entry of vulnerability.via) {
    if (typeof entry === "string") {
      children.push(entry);
      pending.push(entry);
      if (entry === name) unexpected.push(`${name}: missing or cyclic advisory provenance (self-loop)`);
      continue;
    }
    const advisoryUrl = entry && typeof entry.url === "string" ? entry.url : "";
    if (allowedPackages.has(name) && allowedAdvisories.has(advisoryUrl)) {
      evidence.add("metro");
      observedAdvisories.add(advisoryUrl);
    } else if (name === "node-forge" && advisoryUrl === forgeProof.advisory &&
      entry.name === name && entry.dependency === name && entry.severity === "high" && entry.range === "<=1.4.0") {
      evidence.add("forge");
      observedAdvisories.add(advisoryUrl);
    } else if (name === "braces" && vulnerability.severity === "high" && advisoryUrl === bracesProof.advisory &&
      entry.name === name && entry.dependency === name && entry.severity === "high" && entry.range === "<=3.0.3") {
      evidence.add("braces");
      observedAdvisories.add(advisoryUrl);
    } else {
      unexpected.push(`${name}: unexpected advisory ${advisoryUrl || "without URL"}`);
    }
  }
  graph.set(name, children);
  evidenceCache.set(name, evidence);
}
let changed;
do {
  changed = false;
  for (const [name, children] of graph) {
    const evidence = evidenceCache.get(name);
    for (const child of children) {
      for (const kind of evidenceCache.get(child) ?? []) {
        const covered = kind === "forge" ? forgeEdges[name]?.includes(child)
          : kind === "braces" ? bracesProof.auditEdges[name]?.includes(child)
          : allowedPackages.has(name);
        if (covered && !evidence.has(kind)) {
          evidence.add(kind);
          changed = true;
        }
      }
    }
  }
} while (changed);
for (const [name, children] of graph) {
  const evidence = evidenceCache.get(name);
  for (const child of children) {
    for (const kind of evidenceCache.get(child) ?? []) {
      if (kind === "forge" && !forgeEdges[name]?.includes(child)) {
        unexpected.push(`${name}: uncovered node-forge consumer chain via ${child}`);
      } else if (kind === "braces" && !bracesProof.auditEdges[name]?.includes(child)) {
        unexpected.push(`${name}: uncovered braces consumer chain via ${child}`);
      } else if (kind === "metro" && !allowedPackages.has(name)) {
        unexpected.push(`${name}: package is outside the Metro exception`);
      }
    }
  }
  for (const [kind, proof] of [["forge", forgeProof], ["braces", bracesProof]]) {
    if (!evidence.has(kind)) continue;
    const expected = proof.auditNodes[name];
    const nodes = report.vulnerabilities[name].nodes;
    if (!expected || !Array.isArray(nodes) ||
      JSON.stringify([...nodes].sort()) !== JSON.stringify([...expected].sort())) {
      unexpected.push(`${name}: audit includes uncovered ${kind === "forge" ? "node-forge" : "braces"} installation paths`);
    }
  }
  if (evidence.size === 0) unexpected.push(`${name}: no verified advisory provenance`);
}

// Find strongly connected components without recursively walking untrusted
// audit data. Only the pinned Metro component may cycle, and only when every
// member reaches the verified braces leaf through its exact policy edges.
const seen = new Set();
const order = [];
for (const start of graph.keys()) {
  if (seen.has(start)) continue;
  seen.add(start);
  const stack = [[start, 0]];
  while (stack.length > 0) {
    const frame = stack[stack.length - 1];
    const children = graph.get(frame[0]);
    if (frame[1] < children.length) {
      const child = children[frame[1]++];
      if (graph.has(child) && !seen.has(child)) {
        seen.add(child);
        stack.push([child, 0]);
      }
    } else {
      order.push(frame[0]);
      stack.pop();
    }
  }
}
const reversed = new Map([...graph.keys()].map((name) => [name, []]));
for (const [name, children] of graph) {
  for (const child of children) reversed.get(child)?.push(name);
}
seen.clear();
const expectedMetroCycle = ["metro", "metro-config", "metro-transform-worker"];
for (const start of order.reverse()) {
  if (seen.has(start)) continue;
  const component = [];
  const stack = [start];
  seen.add(start);
  while (stack.length > 0) {
    const name = stack.pop();
    component.push(name);
    for (const parent of reversed.get(name)) {
      if (!seen.has(parent)) { seen.add(parent); stack.push(parent); }
    }
  }
  if (component.length <= 1) continue;
  const covered = JSON.stringify(component.sort()) === JSON.stringify(expectedMetroCycle)
    && component.every((name) => evidenceCache.get(name).has("braces")
      && graph.get(name).every((child) => bracesProof.auditEdges[name]?.includes(child)));
  if (!covered) unexpected.push(`${component.join(", ")}: missing or cyclic advisory provenance`);
}

if (unexpected.length > 0) fail("new or changed high/critical findings detected", unexpected);
if (observedAdvisories.size === 0) {
  fail("allowlisted package chain no longer resolves to the documented advisories");
}

console.log("Production dependency audit passed with verified, bounded mitigations.");
if (observedAdvisories.has(forgeProof.advisory)) {
  console.warn(`node-forge ${forgeProof.version}: local upstream patch verified (${forgeProof.fileCount} file hashes, ${forgeProof.cases} RSA parser cases); review expires ${forgeProof.expiresOn}. npm audit still flags the published version.`);
}
if (observedAdvisories.has(bracesProof.advisory)) {
  console.warn(`braces ${bracesProof.version}: local mitigation verified (${bracesProof.fileCount} file hashes, ${bracesProof.cases} bounded parser cases); review expires ${bracesProof.expiresOn}. npm audit still flags the published version.`);
}
if ([...observedAdvisories].some((advisory) => allowedAdvisories.has(advisory))) {
  console.warn(`Temporary, documented Metro/image-size exception through ${allowlist.expiresOn}.`);
  console.warn(allowlist.reason);
}
for (const advisory of [...observedAdvisories].sort()) console.warn(`- ${advisory}`);
