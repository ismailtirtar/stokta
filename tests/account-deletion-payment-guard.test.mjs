import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const edge = readFileSync(new URL("../supabase/functions/delete-account/index.ts", import.meta.url), "utf8");
const paymentSchema = readFileSync(
  new URL("../supabase/migrations/20260922120000_web_payment_notifications.sql", import.meta.url),
  "utf8",
);

test("payment-linked account deletion stops before any user or tenant cleanup", () => {
  assert.match(paymentSchema, /organization_id uuid not null references public\.organizations\(id\) on delete restrict/);
  assert.match(paymentSchema, /submitted_by uuid not null references public\.profiles\(id\) on delete restrict/);

  const guard = edge.indexOf('const paymentRecordColumn = caller.role === "admin" ? "organization_id" : "submitted_by"');
  const support = edge.indexOf('code: "PAYMENT_RECORDS_REQUIRE_REVIEW"');
  const reauthenticate = edge.indexOf("auth.signInWithPassword");
  const ban = edge.indexOf('ban_duration: "876000h"');
  const deleteData = edge.indexOf('.from("stock_movements")');

  assert.ok(guard >= 0 && support > guard);
  assert.ok(reauthenticate > support && ban > support && deleteData > support);
  assert.match(edge.slice(guard, support), /\.eq\(paymentRecordColumn, paymentRecordId\)/);
  assert.match(edge.slice(guard, support), /caller\.role === "admin" \? caller\.organization_id : caller\.id/);
  assert.match(edge.slice(guard, support), /if \(paymentRecordError\)[\s\S]*return json\(503/);
});
