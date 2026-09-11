import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const migration = read("supabase/migrations/20260911123000_google_play_subscription_lifecycle_v2.sql");

test("Google Play observations use global generations and exact durable leases", () => {
  assert.match(migration, /create sequence if not exists private\.google_play_subscription_observation_generation_seq/);
  assert.match(migration, /purchase_token_hash text primary key/);
  assert.match(migration, /nextval\('private\.google_play_subscription_observation_generation_seq'/);
  assert.match(migration, /lease_id is distinct from p_lease_id[\s\S]*?generation is distinct from p_generation/);
  assert.match(migration, /last_observation_generation > p_generation[\s\S]*?'stale'/);
  assert.match(migration, /last_observation_generation = p_generation[\s\S]*?divergent_observation/);
});

test("ACK is server-only, two-observation, void-first and disabled during deletion", () => {
  assert.match(migration, /v_prior_exact :=[\s\S]*?last_observation_generation < p_generation[\s\S]*?ACKNOWLEDGEMENT_STATE_PENDING/);
  assert.match(migration, /v_ack_allowed := p_mode <> 'deletion'[\s\S]*?v_order_not_voided and v_prior_exact/);
  assert.match(migration, /private\.google_play_voided_orders vo[\s\S]*?vo\.order_id_hash = p_latest_order_id_hash/);
  const sync = read("supabase/functions/_shared/google_play_subscription_sync.ts");
  assert.match(sync, /acknowledgeSubscription[\s\S]*?inspectSubscription[\s\S]*?writeObservation/);
  assert.doesNotMatch(sync, /acknowledgementState:\s*"ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"/);
});

test("purchase intent binding requires exact entitled non-voided identity and remains seven days", () => {
  assert.match(migration, /v_now \+ interval '7 days'/);
  assert.match(migration, /v_identity_valid and v_google_entitled and v_order_not_voided and v_intent\.id is not null[\s\S]*?bound_purchase_token_hash = p_purchase_token_hash/);
  assert.match(migration, /bound_purchase_token_hash is null or bound_purchase_token_hash = p_purchase_token_hash/);
  assert.match(migration, /p_linked_purchase_token_hash[\s\S]*?Bağlantılı Google Play satın alma sahibi eşleşmiyor/);
});

test("RTDN is strict, durable, fair per token and independently authenticated", () => {
  const edge = read("supabase/functions/google-play-rtdn/index.ts");
  const config = read("supabase/config.toml");
  assert.match(config, /\[functions\.google-play-rtdn\]\s*verify_jwt = false/);
  assert.match(edge, /envelope\.subscription !== expectedSubscription/);
  assert.match(edge, /notification\.version !== "1\.0"/);
  assert.match(edge, /subscription\.version !== "1\.0"/);
  assert.doesNotMatch(edge, /subscription\.subscriptionId/);
  assert.match(edge, /voided\.productType !== 1/);
  assert.match(edge, /\[1, 2\]\.includes\(voided\.refundType\)/);
  assert.match(migration, /google_play_notification_receipts[\s\S]*?payload_fingerprint/);
  assert.match(migration, /active\.purchase_token_hash = i\.purchase_token_hash[\s\S]*?earlier\.purchase_token_hash = i\.purchase_token_hash/);
  assert.match(migration, /deterministic_failure_count < 3/);
});

test("reconcile is void-first, cursor-safe, bounded and starvation resistant", () => {
  const worker = read("supabase/functions/google-play-reconcile/index.ts");
  assert.match(worker, /maxJobs === undefined \? 3/);
  assert.match(worker, /workerDeadline = Date\.now\(\) \+ 50_000/);
  assert.ok(worker.indexOf("listVoidedPurchases") < worker.indexOf("service_claim_due_google_play_rtdn"));
  assert.match(worker, /iade taraması yeniden başlatılmalı/);
  assert.match(worker, /service_defer_google_play_reconcile/);
  assert.match(migration, /join private\.google_play_token_vault v[\s\S]*?for update of s skip locked[\s\S]*?limit p_limit/);
  assert.match(migration, /voided_scan_started_at_ms[\s\S]*?v_scan_started_at_ms - 300000/);
});

test("account deletion is canonical, fenced, request-bound and crash resumable", () => {
  const edge = read("supabase/functions/delete-account/index.ts");
  assert.match(edge, /admin\.auth\.getClaims\(token\)/);
  assert.match(edge, /service_find_active_account_deletion_request/);
  assert.match(edge, /requestId = activeRequestId/);
  assert.match(edge, /requestId = normalizeUuid\(begun\.requestId\)!/);
  assert.doesNotMatch(edge, /ban_duration/);
  assert.match(edge, /service_finalize_google_play_organization_deletion[\s\S]*?service_erase_organization_after_billing_finalize/);
  assert.match(migration, /billing_finalized_at is not null/);
  assert.match(migration, /Google Play sonlandırmasından sonra silme isteği iptal edilemez/);
  assert.match(migration, /delete from auth\.sessions where user_id = any/);
  assert.match(migration, /account_deletion_one_processing_subject_idx/);
  assert.match(migration, /state = 'completed' and purge_after <= v_now/);
});

test("deleted-token ciphertext and Auth cleanup cannot be silently retained or forgotten", () => {
  assert.match(migration, /ciphertext_purge_deadline/);
  assert.match(migration, /least\(coalesce\(v\.first_stored_at \+ interval '120 days', v_now\), v_now \+ interval '30 days'\)/);
  assert.match(migration, /where state = 'completed' and completed_at < v_now - interval '30 days'/);
  assert.doesNotMatch(
    migration,
    /delete from private\.account_auth_cleanup_jobs\s+where state in \('completed','quarantined'\)/,
  );
  const cleanup = read("supabase/functions/account-auth-cleanup/index.ts");
  assert.match(cleanup, /alreadyMissing/);
  assert.match(cleanup, /service_finish_account_auth_cleanup/);
});

test("Google lifecycle respects administrative and manual platform overlays", () => {
  assert.match(migration, /administratively_suspended_at is not null then 'suspended'/);
  assert.match(migration, /platform_entitlement_until > v_now then 'active'/);
  assert.match(migration, /greatest\([\s\S]*?p_expiry_time,[\s\S]*?o\.platform_entitlement_until/);
});
