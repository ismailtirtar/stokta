import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import { GooglePlayClient, GooglePlayError } from "../_shared/google_play.ts";
import { decryptPurchaseToken } from "../_shared/google_play_token.ts";
import {
  PlayClaim,
  PlayOwner,
  processGooglePlayToken,
  transientPlayFailure,
} from "../_shared/google_play_sync.ts";
import { bearerToken, json, sha256 } from "../_shared/security.ts";

type DueToken = PlayClaim & PlayOwner & {
  purchaseTokenHash: string;
  tokenCiphertext: string;
  tokenNonce: string;
  keyVersion: number;
};
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function authorized(req: Request) {
  const expected = Deno.env.get("GOOGLE_PLAY_RECONCILE_SECRET") ?? "";
  const supplied = bearerToken(req) ?? "";
  if (expected.length < 32 || supplied.length !== expected.length || supplied.length > 256) {
    return false;
  }
  const digest = async (value: string) => new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
  const [left, right] = await Promise.all([digest(expected), digest(supplied)]);
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

function parseDueTokens(value: unknown): DueToken[] {
  if (!Array.isArray(value) || value.length > 2) throw new Error("İş listesi geçersiz");
  return value.map((item) => {
    if (!isRecord(item) || !HASH.test(item.purchaseTokenHash as string)
      || !UUID.test(item.userId as string) || !UUID.test(item.organizationId as string)
      || !UUID.test(item.leaseId as string)
      || !Number.isSafeInteger(item.generation) || (item.generation as number) < 1
      || typeof item.tokenCiphertext !== "string"
      || typeof item.tokenNonce !== "string" || item.keyVersion !== 1) {
      throw new Error("İş listesi geçersiz");
    }
    return item as DueToken;
  });
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });
  if (!await authorized(req)) return json(401, { error: "Geçersiz işleyici kimliği" });
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  try {
    const googlePlay = await GooglePlayClient.fromEnvironment();
    const { data: cursor, error: cursorError } = await admin.rpc(
      "service_get_google_play_void_cursor",
    );
    if (cursorError || !isRecord(cursor)
      || !Number.isSafeInteger(cursor.startTimeMillis)
      || (cursor.pageToken !== null && typeof cursor.pageToken !== "string")) {
      throw new Error("İade imleci okunamadı");
    }
    const storedStart = cursor.startTimeMillis as number;
    const pageToken = cursor.pageToken as string | null;
    const safeStart = Math.max(storedStart, Date.now() - 29 * 24 * 60 * 60 * 1000);
    if (storedStart < safeStart && pageToken === null) {
      console.error("Google Play voided scan exceeded its 29-day recovery window");
    }

    let page;
    try {
      page = await googlePlay.listVoidedPurchases(safeStart, pageToken);
    } catch (error) {
      if (pageToken !== null && error instanceof GooglePlayError
        && error.code === "INVALID_PURCHASE") {
        const reset = await admin.rpc("service_reset_google_play_void_cursor", {
          p_expected_start: storedStart, p_expected_page: pageToken,
        });
        if (reset.error || reset.data !== true) throw new Error("İade imleci sıfırlanamadı");
      }
      // Never grant in this run if the refund scan did not succeed.
      throw error;
    }

    for (const purchase of page.purchases) {
      const { error } = await admin.rpc("service_record_google_play_void", {
        p_token_hash: await sha256(purchase.purchaseToken),
        p_order_hash: await sha256(purchase.orderId),
        p_event_time: purchase.eventTime,
      });
      if (error) throw new Error(`İade çiti yazılamadı: ${error.code ?? "unknown"}`);
    }
    const { data: advanced, error: advanceError } = await admin.rpc(
      "service_advance_google_play_void_cursor",
      {
        p_expected_start: storedStart,
        p_expected_page: pageToken,
        p_next_page: page.nextPageToken,
      },
    );
    if (advanceError || advanced !== true) throw new Error("İade imleci ilerletilemedi");

    const { data: due, error: claimError } = await admin.rpc(
      "service_claim_due_google_play_tokens", { p_limit: 2 },
    );
    if (claimError) throw new Error(`Uzlaştırma işi alınamadı: ${claimError.code ?? "unknown"}`);
    const jobs = parseDueTokens(due);
    let reconciled = 0;
    let failed = 0;
    for (const job of jobs) {
      try {
        const token = await decryptPurchaseToken(
          job.purchaseTokenHash, job.tokenCiphertext, job.tokenNonce, job.keyVersion,
        );
        const result = await processGooglePlayToken(admin, token, "reconcile", {
          owner: {
            userId: job.userId, organizationId: job.organizationId,
            accountHash: await sha256(job.userId),
            profileHash: await sha256(job.organizationId),
          },
          claim: { leaseId: job.leaseId, generation: job.generation },
          googlePlay,
        });
        if (result.disposition !== "recorded") throw new Error("Owned token became unowned");
        reconciled++;
      } catch (error) {
        failed++;
        const { error: deferError } = await admin.rpc("service_defer_google_play_token", {
          p_token_hash: job.purchaseTokenHash,
          p_lease_id: job.leaseId,
          p_deterministic: !transientPlayFailure(error),
        });
        console.error("Google Play reconciliation failed", {
          code: error instanceof GooglePlayError ? error.code
            : error instanceof Error ? error.name : "unknown",
          deferCode: deferError?.code ?? null,
        });
      }
    }
    return json(200, {
      ok: true, voided: page.purchases.length,
      moreVoidPages: page.nextPageToken !== null,
      reconciled, failed,
    });
  } catch (error) {
    console.error("Google Play reconciliation stopped", {
      code: error instanceof GooglePlayError ? error.code
        : error instanceof Error ? error.message.slice(0, 80) : "unknown",
    });
    return json(503, { error: "Google Play uzlaştırması tamamlanamadı" });
  }
});
