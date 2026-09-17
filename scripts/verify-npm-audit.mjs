import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

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

const severe = Object.entries(report?.vulnerabilities ?? {})
  .filter(([, value]) => value && ["high", "critical"].includes(value.severity));
if (severe.length === 0) {
  console.log("Production dependency audit passed with no high or critical findings.");
  process.exit(0);
}

const unexpected = [];
const observedAdvisories = new Set();
for (const [name, vulnerability] of severe) {
  if (!allowedPackages.has(name)) {
    unexpected.push(`${name}: unexpected ${vulnerability.severity} vulnerability`);
  }
  const via = Array.isArray(vulnerability.via) ? vulnerability.via : [];
  if (via.length === 0) unexpected.push(`${name}: missing advisory provenance`);
  for (const entry of via) {
    if (typeof entry === "string") {
      if (!allowedPackages.has(entry)) {
        unexpected.push(`${name}: depends on unexpected vulnerable package ${entry}`);
      }
      continue;
    }
    const advisoryUrl = entry && typeof entry.url === "string" ? entry.url : "";
    if (!allowedAdvisories.has(advisoryUrl)) {
      unexpected.push(`${name}: unexpected advisory ${advisoryUrl || "without URL"}`);
    } else {
      observedAdvisories.add(advisoryUrl);
    }
  }
}

if (unexpected.length > 0) fail("new or changed high/critical findings detected", unexpected);
if (observedAdvisories.size === 0) {
  fail("allowlisted package chain no longer resolves to the documented advisories");
}

console.warn(
  `Production dependency audit passed with a temporary, documented Metro/image-size exception through ${allowlist.expiresOn}.`,
);
console.warn(allowlist.reason);
for (const advisory of [...observedAdvisories].sort()) console.warn(`- ${advisory}`);
