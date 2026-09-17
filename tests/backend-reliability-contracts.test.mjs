import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("inventory writes require idempotency/CAS and reads remain keyset bounded", () => {
  const sql = read("supabase/migrations/20260911070000_backend_stock_consistency_and_pagination.sql");

  assert.match(sql, /p_request_id uuid\s*\)\s*returns public\.products/);
  assert.match(sql, /if p_request_id is null then\s*raise exception 'İstek kimliği gerekli'/);
  assert.match(sql, /if p_expected_updated_at is null then/);
  assert.doesNotMatch(sql, /p_request_id uuid default null/);
  assert.match(sql, /drop function if exists private\.record_stock_movement\(uuid, text, numeric, text\)/);
  assert.match(sql, /stock_movements_arithmetic_check/);
  assert.match(sql, /protect_stock_movement_history/);
  assert.match(sql, /alter publication supabase_realtime add table public\.products/);
  assert.match(sql, /alter publication supabase_realtime add table public\.stock_movements/);
  assert.match(sql, /create or replace function public\.list_inventory_products\([\s\S]*?p_query text default null,[\s\S]*?p_only_low boolean default false/);
  assert.match(sql, /create or replace function public\.get_inventory_summary\(\)/);
  assert.match(sql, /order by p\.name, p\.id\s*limit p_limit/);
  assert.match(sql, /order by m\.event_sequence desc\s*limit p_limit/);
});

test("platform updates share one revision stream, durable fence and cross-tenant lock", () => {
  const sql = read("supabase/migrations/20260911071000_platform_business_subscription_idempotency.sql");

  assert.match(sql, /create trigger enforce_subscription_revision\s*before update on public\.organizations/);
  assert.match(sql, /new\.subscription_revision := old\.subscription_revision \+ 1/);
  assert.match(sql, /where f\.organization_id = p_organization_id\s*\) then/);
  assert.doesNotMatch(
    sql.slice(sql.indexOf("create or replace function private.assert_organization_not_deleting")),
    /f\.expires_at\s*>/,
  );
  assert.match(sql, /pg_advisory_xact_lock\(7346501135020481::bigint\)/);
  assert.match(sql, /next_platform_entitlement_until := greatest\([\s\S]*?organization\.current_period_end[\s\S]*?organization\.platform_entitlement_until/);
  assert.match(sql, /current_period_end = next_platform_entitlement_until,[\s\S]*?platform_entitlement_until = next_platform_entitlement_until/);
  assert.match(sql, /organization\.subscription_revision <> p_expected_revision/);
  assert.match(sql, /'request_id', p_request_id/);
});

test("UGC v2 requires exact digest, request ids and retires unsafe service RPCs", () => {
  const terms = read("supabase/migrations/20260911130000_ugc_terms_v2.sql");
  const ugc = read("supabase/migrations/20260911131000_ugc_authorization_concurrency.sql");

  assert.match(terms, /create table private\.ugc_terms_documents/);
  assert.match(terms, /ugc_terms_documents_digest_matches_text/);
  assert.match(terms, /create table private\.ugc_terms_acceptances/);
  assert.match(terms, /service_store_pending_registration\([\s\S]*?p_ugc_terms_digest text/);
  assert.match(ugc, /accept_current_ugc_terms\(\s*p_version text,\s*p_digest text/);
  assert.match(ugc, /p_digest is distinct from current_digest/);
  assert.match(ugc, /if p_request_id is null then\s*raise exception 'İstek kimliği gerekli'/);
  assert.match(ugc, /drop function if exists public\.service_list_platform_content_reports\(text\)/);
  assert.match(ugc, /drop function if exists public\.service_moderate_platform_content_report\(uuid, text, text\)/);
  assert.match(ugc, /service_moderate_platform_content_report\(\s*p_request_id uuid,/);
  assert.match(ugc, /Yıkıcı moderasyon işlemleri için gerekçe zorunludur/);
  assert.match(ugc, /pg_advisory_xact_lock\(7346501135020481::bigint\)/);
  assert.match(ugc, /service_purge_command_receipts/);
  assert.match(ugc, /completed_at is not null[\s\S]*?for update skip locked/);
});

test("manage-businesses streams bounded JSON and delegates authorization/mutation to RPC", () => {
  const edge = read("supabase/functions/manage-businesses/index.ts");

  assert.match(edge, /readBoundedJson\(req, 16 \* 1024\)/);
  assert.doesNotMatch(edge, /await req\.(?:text|json)\(\)/);
  assert.match(edge, /service_list_platform_businesses/);
  assert.match(edge, /service_update_platform_subscription/);
  assert.match(edge, /p_request_id: requestId/);
  assert.match(edge, /p_expected_revision: expectedRevision/);
  assert.match(edge, /reason\.length < 1 \|\| reason\.length > 500/);
  assert.match(edge, /"Access-Control-Allow-Methods": "GET, POST, OPTIONS"/);
});
