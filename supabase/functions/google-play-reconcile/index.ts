import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import { GooglePlayClient, GooglePlayError } from "../_shared/google_play.ts";
import {
  decryptPurchaseToken,
  encryptPurchaseToken,
  synchronizeGooglePlaySubscription,
} from "../_shared/google_play_subscription_sync.ts";
import {
  bearerToken,
  constantTimeTextEqual,
  HttpInputError,
  isRecord,
  json,
  readBoundedJson,
  sha256,
} from "../_shared/security.ts";

type RtdnJob = {
  messageId: string;
  purchaseTokenHash: string;
  attemptCount: number;
  leaseId: string;
  tokenCiphertext: string;
  tokenNonce: string;
  tokenKeyVersion: number;
  deletedOwner: boolean;
};

type VaultToken = {
  purchaseTokenHash: string;
  tokenCiphertext: string;
  tokenNonce: string;
  tokenKeyVersion: number;
};

function parseArray<T extends RtdnJob | VaultToken>(value: unknown, job: boolean): T[] {
  if (!Array.isArray(value)) throw new Error("Google Play iş listesi doğrulanamadı");
  return value.map((item) => {
    if (!isRecord(item)
      || typeof item.purchaseTokenHash !== "string"
      || typeof item.tokenCiphertext !== "string"
      || typeof item.tokenNonce !== "string"
      || typeof item.tokenKeyVersion !== "number"
      || (job && (typeof item.messageId !== "string"
        || typeof item.attemptCount !== "number"
        || typeof item.leaseId !== "string"
        || typeof item.deletedOwner !== "boolean"))) {
      throw new Error("Google Play iş listesi doğrulanamadı");
    }
    return item as T;
  });
}

function transient(error: unknown) {
  return error instanceof GooglePlayError
    ? error.code === "UNAVAILABLE" || error.code === "CONFIGURATION"
    : isRecord(error) && error.code === "55P03";
}

function errorCode(error: unknown) {
  if (error instanceof GooglePlayError) return error.code;
  return error instanceof Error ? error.message.slice(0, 64) : "UNKNOWN";
}

async function finish(admin: any, job: RtdnJob, outcome: "success" | "transient" | "deterministic", code?: string) {
  const { data, error } = await admin.rpc("service_finish_google_play_rtdn", {
    p_message_id: job.messageId,
    p_lease_id: job.leaseId,
    p_outcome: outcome,
    p_error_code: code ?? null,
  });
  if (error || !isRecord(data)) throw new Error("RTDN işi tamamlanamadı");
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });
  try {
    const expectedSecret = Deno.env.get("GOOGLE_PLAY_RECONCILE_SECRET") ?? "";
    const suppliedSecret = bearerToken(req) ?? "";
    if (expectedSecret.length < 32 || !constantTimeTextEqual(expectedSecret, suppliedSecret)) {
      return json(401, { error: "Geçersiz uzlaştırma kimliği" });
    }
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });
    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const body = await readBoundedJson(req, 2_048);
    if (!isRecord(body) || Object.keys(body).some((key) => key !== "maxJobs")) {
      throw new HttpInputError(400, "Geçersiz uzlaştırma isteği");
    }
    const maxJobs = body.maxJobs === undefined ? 3 : body.maxJobs;
    if (typeof maxJobs !== "number" || !Number.isInteger(maxJobs) || maxJobs < 1 || maxJobs > 5) {
      throw new HttpInputError(400, "Geçersiz uzlaştırma iş sayısı");
    }
    const workerDeadline = Date.now() + 50_000;
    const googlePlay = await GooglePlayClient.fromEnvironment();
    let voided = 0;
    let notifications = 0;
    let reconciled = 0;
    let failed = 0;

    // Refund/void evidence is committed first. A subsequent lifecycle GET can
    // only grant a different latest order id.
    const { data: cursorData, error: cursorError } = await admin.rpc(
      "service_get_google_play_voided_cursor",
    );
    if (cursorError || !isRecord(cursorData)
      || typeof cursorData.startTimeMillis !== "number"
      || (cursorData.pageToken !== null && typeof cursorData.pageToken !== "string")) {
      throw new Error("Google Play iade imleci okunamadı");
    }
    try {
      const page = await googlePlay.listVoidedPurchases(
        cursorData.startTimeMillis,
        cursorData.pageToken as string | null,
      );
      for (const purchase of page.purchases) {
        const tokenHash = await sha256(purchase.purchaseToken);
        const secret = await encryptPurchaseToken(purchase.purchaseToken);
        const { error } = await admin.rpc("service_record_google_play_voided_notification", {
          p_message_id: `void:${await sha256(`${purchase.orderId}:${purchase.voidedTimeMillis}`)}`,
          p_purchase_token_hash: tokenHash,
          p_order_id_hash: await sha256(purchase.orderId),
          p_event_time: new Date(purchase.voidedTimeMillis).toISOString(),
          p_token_ciphertext: secret.ciphertext,
          p_token_nonce: secret.nonce,
          p_token_key_version: secret.keyVersion,
        });
        if (error) throw Object.assign(new Error("VOID_LEDGER_FAILED"), { code: error.code });
        voided += 1;
      }
      const { data: advanced, error: advanceError } = await admin.rpc(
        "service_advance_google_play_voided_cursor",
        {
          p_expected_page_token: cursorData.pageToken,
          p_next_page_token: page.nextPageToken,
          p_scan_completed_at_ms: Date.now(),
        },
      );
      if (advanceError || advanced !== true) throw new Error("Google Play iade imleci güncellenemedi");
    } catch (error) {
      if (error instanceof GooglePlayError && error.responseStatus === 400
        && cursorData.pageToken !== null) {
        const { data: reset, error: resetError } = await admin.rpc(
          "service_reset_google_play_voided_cursor",
          {
          p_expected_page_token: cursorData.pageToken,
          },
        );
        if (resetError || reset !== true) throw new Error("Google Play iade imleci sıfırlanamadı");
        // Refund scan must succeed before any lifecycle grant in this run.
        throw new Error("Google Play iade taraması yeniden başlatılmalı");
      } else {
        throw error;
      }
    }

    const { data: jobsData, error: jobsError } = await admin.rpc(
      "service_claim_due_google_play_rtdn",
      { p_limit: maxJobs },
    );
    if (jobsError) throw Object.assign(new Error("RTDN_CLAIM_FAILED"), { code: jobsError.code });
    const jobs = parseArray<RtdnJob>(jobsData, true);
    for (const job of jobs) {
      if (Date.now() > workerDeadline - 15_000) {
        await finish(admin, job, "transient", "WORKER_DEADLINE");
        failed += 1;
        continue;
      }
      try {
        const token = await decryptPurchaseToken(
          job.tokenCiphertext,
          job.tokenNonce,
          job.tokenKeyVersion,
          job.purchaseTokenHash,
        );
        if (job.deletedOwner) {
          let proof = await googlePlay.inspectSubscription(token);
          if (proof.autoRenewEnabled !== false) {
            await googlePlay.cancelSubscription(token);
            proof = await googlePlay.inspectSubscription(token);
          }
          if (proof.autoRenewEnabled !== false) throw new Error("STOP_NOT_VERIFIED");
        } else {
          const result = await synchronizeGooglePlaySubscription({
            admin, googlePlay, purchaseToken: token, mode: "rtdn",
          });
          if (result.disposition === "quarantined") throw new Error("QUARANTINED_OBSERVATION");
        }
        await finish(admin, job, "success");
        notifications += 1;
      } catch (error) {
        await finish(admin, job, transient(error) ? "transient" : "deterministic", errorCode(error));
        failed += 1;
      }
    }

    const { data: tokensData, error: tokensError } = await admin.rpc(
      "service_list_google_play_reconcile_tokens",
      { p_limit: maxJobs },
    );
    if (tokensError) throw Object.assign(new Error("RECONCILE_LIST_FAILED"), { code: tokensError.code });
    const tokens = parseArray<VaultToken>(tokensData, false);
    for (const item of tokens) {
      if (Date.now() > workerDeadline - 15_000) {
        await admin.rpc("service_defer_google_play_reconcile", {
          p_purchase_token_hash: item.purchaseTokenHash,
          p_transient: true,
        });
        failed += 1;
        continue;
      }
      try {
        const token = await decryptPurchaseToken(
          item.tokenCiphertext,
          item.tokenNonce,
          item.tokenKeyVersion,
          item.purchaseTokenHash,
        );
        const result = await synchronizeGooglePlaySubscription({
          admin, googlePlay, purchaseToken: token, mode: "reconcile",
        });
        if (result.disposition === "quarantined") {
          throw new Error("QUARANTINED_OBSERVATION");
        }
        reconciled += 1;
      } catch (error) {
        const { error: deferError } = await admin.rpc("service_defer_google_play_reconcile", {
          p_purchase_token_hash: item.purchaseTokenHash,
          p_transient: transient(error),
        });
        if (deferError) console.error("Reconcile backoff could not be recorded", {
          tokenHashPrefix: item.purchaseTokenHash.slice(0, 12),
          code: deferError.code ?? "unknown",
        });
        if (!transient(error)) console.error("Deterministic reconcile failure", {
          tokenHashPrefix: item.purchaseTokenHash.slice(0, 12),
          code: errorCode(error),
        });
        failed += 1;
      }
    }
    await admin.rpc("service_purge_google_play_lifecycle_data");
    return json(200, { ok: true, voided, notifications, reconciled, failed });
  } catch (error) {
    if (error instanceof HttpInputError) return json(error.status, { error: error.message });
    console.error("Google Play reconciliation failed", {
      name: error instanceof Error ? error.name : "unknown",
      code: errorCode(error),
    });
    return json(503, { error: "Google Play uzlaştırması tamamlanamadı" });
  }
});
