import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { verifyNodeForgePatch } from "./node-forge-patch.mjs";

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
function inspectFinding(name, ancestors = new Set()) {
  if (evidenceCache.has(name)) return evidenceCache.get(name);
  const vulnerability = report.vulnerabilities[name];
  if (!vulnerability || ancestors.has(name)) {
    unexpected.push(`${name}: missing or cyclic advisory provenance`);
    return new Set();
  }
  const evidence = new Set();
  const chain = new Set([...ancestors, name]);
  for (const entry of vulnerability.via) {
    if (typeof entry === "string") {
      const childEvidence = inspectFinding(entry, chain);
      for (const kind of childEvidence) {
        if (kind === "forge" && !forgeEdges[name]?.includes(entry)) {
          unexpected.push(`${name}: uncovered node-forge consumer chain via ${entry}`);
        } else if (kind === "metro" && !allowedPackages.has(name)) {
          unexpected.push(`${name}: package is outside the Metro exception`);
        } else {
          evidence.add(kind);
        }
      }
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
    } else {
      unexpected.push(`${name}: unexpected advisory ${advisoryUrl || "without URL"}`);
    }
  }
  if (evidence.has("forge")) {
    const expected = forgeProof.auditNodes[name];
    if (!expected || !Array.isArray(vulnerability.nodes) ||
      JSON.stringify([...vulnerability.nodes].sort()) !== JSON.stringify(expected)) {
      unexpected.push(`${name}: audit includes uncovered node-forge installation paths`);
    }
  }
  if (evidence.size === 0) unexpected.push(`${name}: no verified advisory provenance`);
  evidenceCache.set(name, evidence);
  return evidence;
}
for (const [name] of severe) inspectFinding(name);

if (unexpected.length > 0) fail("new or changed high/critical findings detected", unexpected);
if (observedAdvisories.size === 0) {
  fail("allowlisted package chain no longer resolves to the documented advisories");
}

console.log("Production dependency audit passed with verified, bounded mitigations.");
if (observedAdvisories.has(forgeProof.advisory)) {
  console.warn(`node-forge ${forgeProof.version}: local upstream patch verified (${forgeProof.fileCount} file hashes, ${forgeProof.cases} RSA parser cases); review expires ${forgeProof.expiresOn}. npm audit still flags the published version.`);
}
if ([...observedAdvisories].some((advisory) => allowedAdvisories.has(advisory))) {
  console.warn(`Temporary, documented Metro/image-size exception through ${allowlist.expiresOn}.`);
  console.warn(allowlist.reason);
}
for (const advisory of [...observedAdvisories].sort()) console.warn(`- ${advisory}`);
