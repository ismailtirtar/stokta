import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

function source(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const migrationName = readdirSync(new URL("../supabase/migrations/", import.meta.url))
  .find((name) => name.endsWith("_web_payment_notifications.sql"));

assert.ok(migrationName, "Web ödeme migration dosyası bulunamadı");
const migrationSource = source(`supabase/migrations/${migrationName}`);

test("IBAN ayarları yalnızca etkin olduğunda işletme yöneticisine görünür", () => {
  assert.match(migrationSource, /create table public\.web_payment_settings/);
  assert.match(migrationSource, /iban text not null check \(iban ~ '\^TR\[0-9\]\{24\}\$'\)/);
  assert.match(migrationSource, /for select\s+to authenticated\s+using \(\s*is_enabled/);
  assert.match(migrationSource, /and role = 'admin'/);
  assert.match(migrationSource, /and is_active/);
  assert.match(migrationSource, /and not must_change_password/);
});

test("işletme yalnızca kendi adına ve güncel tutarla bekleyen bildirim oluşturabilir", () => {
  assert.match(migrationSource, /submitted_by = \(select auth\.uid\(\)\)/);
  assert.match(migrationSource, /payment_reference = public\.web_payment_reference\(organization_id\)/);
  assert.match(migrationSource, /amount_cents = web_payment_notifications\.amount_cents/);
  assert.match(migrationSource, /currency = web_payment_notifications\.currency/);
  assert.match(migrationSource, /paid_at <= current_date/);
  assert.match(migrationSource, /web_payment_one_pending_per_organization/);
  assert.match(migrationSource, /grant insert \([\s\S]*organization_id,[\s\S]*note[\s\S]*\) on table public\.web_payment_notifications/);
  assert.doesNotMatch(migrationSource, /grant (?:all|update|delete).*web_payment_notifications to authenticated/i);
});

test("aktif Google Play veya web dönemi varken ikinci bildirim engellenir", () => {
  assert.match(migrationSource, /subscription_status = 'active'/);
  assert.match(migrationSource, /current_period_end is null or current_period_end > now\(\)/);
  assert.match(migrationSource, /subscription_status <> 'suspended'/);
});

test("yalnızca service role atomik operatör kararını çalıştırabilir", () => {
  assert.match(migrationSource, /create or replace function private\.service_review_web_payment_notification/);
  assert.match(migrationSource, /language plpgsql\s+security definer\s+set search_path = ''/);
  assert.match(migrationSource, /and is_platform_operator/);
  assert.match(migrationSource, /and is_active/);
  assert.match(migrationSource, /for update/);
  assert.match(migrationSource, /status <> 'pending'/);
  assert.match(migrationSource, /create or replace function public\.service_review_web_payment_notification[\s\S]*language sql\s+security invoker/);
  assert.match(migrationSource, /select private\.service_review_web_payment_notification/);
  assert.match(migrationSource, /revoke all on function private\.service_review_web_payment_notification\(uuid, text, uuid, text\)[\s\S]*from public, anon, authenticated/);
  assert.match(migrationSource, /revoke all on function public\.service_review_web_payment_notification\(uuid, text, uuid, text\)[\s\S]*from public, anon, authenticated/);
  assert.match(migrationSource, /grant execute on function public\.service_review_web_payment_notification\(uuid, text, uuid, text\)[\s\S]*to service_role/);
});

test("onay kalan deneme veya abonelik süresini koruyup 30 gün ekler", () => {
  assert.match(migrationSource, /activation_base := greatest\(/);
  assert.match(migrationSource, /current_organization\.current_period_end/);
  assert.match(migrationSource, /current_organization\.trial_ends_at/);
  assert.match(migrationSource, /activation_end := activation_base \+ interval '30 days'/);
  assert.match(migrationSource, /subscription_status = 'active'/);
  assert.match(migrationSource, /current_period_end = activation_end/);
  assert.match(migrationSource, /activated_until = activation_end/);
});
