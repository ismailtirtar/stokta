import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const migrations = new URL("../supabase/migrations/", import.meta.url);
const migrationName = readdirSync(migrations)
  .find((name) => name.endsWith("_inactive_payment_grace_period.sql"));

assert.ok(migrationName, "İnaktif ödeme süresi migration dosyası bulunamadı");
const source = readFileSync(new URL(`../supabase/migrations/${migrationName}`, import.meta.url), "utf8");

test("adds the inactive tenant state with an indexed grace timestamp", () => {
  assert.match(source, /add column if not exists inactive_since timestamptz/);
  assert.match(source, /'trial', 'active', 'inactive', 'past_due', 'suspended', 'canceled'/);
  assert.match(source, /subscription_status <> 'inactive' or inactive_since is not null/);
  assert.match(source, /organizations_inactive_since_idx/);
});

test("moves expired tenants through a seven-day inactive grace period", () => {
  assert.match(source, /create or replace function private\.refresh_expired_organization_statuses/);
  assert.match(source, /subscription_status = 'inactive'/);
  assert.match(source, /when subscription_status = 'trial' then trial_ends_at/);
  assert.match(source, /else current_period_end/);
  assert.match(source, /inactive_since <= now\(\) - interval '7 days'/);
  assert.match(source, /set subscription_status = 'suspended'/);
});

test("keeps a tenant inactive while its payment notice is pending", () => {
  assert.match(source, /not exists \([\s\S]*web_payment_notifications[\s\S]*notification\.status = 'pending'/);
  assert.match(source, /subscription_status <> 'inactive'[\s\S]*inactive_since > now\(\) - interval '7 days'/);
});

test("runs the transition automatically without exposing the privileged function", () => {
  assert.match(source, /create extension if not exists pg_cron/);
  assert.match(source, /cron\.schedule\([\s\S]*stokdas-refresh-expired-organizations[\s\S]*\*\/15 \* \* \* \*/);
  assert.match(source, /security definer\s+set search_path = ''/);
  assert.match(source, /revoke all on function private\.refresh_expired_organization_statuses\(\)[\s\S]*from public, anon, authenticated, service_role/);
});

test("clears stale inactive timestamps when billing becomes authoritative again", () => {
  assert.match(source, /create or replace function private\.normalize_organization_inactive_since/);
  assert.match(source, /subscription_status in \('trial', 'active', 'past_due', 'canceled'\)/);
  assert.match(source, /new\.inactive_since := null/);
  assert.match(source, /create trigger organizations_normalize_inactive_since/);
});
