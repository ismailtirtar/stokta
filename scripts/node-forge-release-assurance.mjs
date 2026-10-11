// Release hold, not a cryptographic fix. Remove only in a separately reviewed
// remediation that resolves the coverage gap and documents the release evidence.
// No time-based expiry or environment-variable bypass may grant approval.
export function assertNodeForgeReleaseAssurance() {
  throw new Error(
    "node-forge release assurance is blocked: malformed-encoding coverage remains unresolved; " +
    "the existing 60 parser cases do not establish complete mitigation. " +
    "See security/node-forge-patch.md. Raw npm audit --omit=dev --json remains available for diagnostics.",
  );
}
