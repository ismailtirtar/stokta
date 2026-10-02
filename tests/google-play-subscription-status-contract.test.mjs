import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const migration = readFileSync(
  new URL("../supabase/migrations/20260922214445_inactive_payment_grace_period.sql", import.meta.url),
  "utf8",
);
const verifier = readFileSync(
  new URL("../supabase/functions/_shared/google_play_sync.ts", import.meta.url),
  "utf8",
);

function quotedValues(source) {
  return [...source.matchAll(/'([^']+)'/g)].map((match) => match[1]);
}

test("Google Play ledger accepts every organization subscription status", () => {
  const dbConstraint = migration.match(
    /add constraint organizations_subscription_status_check\s+check \(subscription_status in \(([^)]+)\)\)/,
  );
  const edgeStatuses = verifier.match(/const statuses = new Set\(\[([\s\S]*?)\]\);/);
  const edgeType = verifier.match(/subscriptionStatus: ([^;]+);/);
  assert.ok(dbConstraint, "organization status constraint is present");
  assert.ok(edgeStatuses, "Edge status validator is present");
  assert.ok(edgeType, "Edge status type is present");

  const databaseStatuses = quotedValues(dbConstraint[1]);
  const validatedStatuses = [...edgeStatuses[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
  const typedStatuses = [...edgeType[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(new Set(validatedStatuses), new Set(databaseStatuses));
  assert.deepEqual(new Set(typedStatuses), new Set(databaseStatuses));
});
