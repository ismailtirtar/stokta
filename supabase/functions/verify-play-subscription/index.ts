import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  GooglePlayAcknowledgementState,
  GooglePlayClient,
  GooglePlayError,
  GOOGLE_PLAY_BASE_PLAN_ID,
  GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID,
  VerifiedGooglePlaySubscription,
  validateGooglePlayPurchaseToken,
} from "../_shared/google_play.ts";
import {
  bearerToken,
  corsJsonHeaders,
  json,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const subscriptionStatuses = new Set([
  "trial",
  "active",
  "past_due",
  "suspended",
  "canceled",
]);

type CallerProfile = {
  id: string;
  organization_id: string;
  role: "admin" | "member";
  is_active: boolean;
  must_change_password: boolean;
};

type LedgerResult = {
  entitled: boolean;
  subscriptionStatus: "trial" | "active" | "past_due" | "suspended" | "canceled";
  currentPeriodEnd: string | null;
};

class LedgerError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "LedgerError";
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readBoundedJson(req: Request, maxBytes: number) {
  if (!req.body) throw new LedgerError(400, "Geçersiz istek gövdesi");
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new LedgerError(413, "İstek gövdesi çok büyük");
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new LedgerError(400, "Geçersiz istek gövdesi");
  }
}

function validateLedgerResult(value: unknown): LedgerResult {
  if (!isRecord(value)
    || typeof value.entitled !== "boolean"
    || typeof value.subscriptionStatus !== "string"
    || !subscriptionStatuses.has(value.subscriptionStatus)
    || (value.currentPeriodEnd !== null && typeof value.currentPeriodEnd !== "string")) {
    throw new LedgerError(503, "Abonelik kaydı doğrulanamadı");
  }
  if (typeof value.currentPeriodEnd === "string"
    && !Number.isFinite(Date.parse(value.currentPeriodEnd))) {
    throw new LedgerError(503, "Abonelik kaydı doğrulanamadı");
  }
  return value as LedgerResult;
}

async function recordVerifiedSubscription(
  admin: any,
  caller: CallerProfile,
  purchaseTokenHash: string,
  externalAccountIdHash: string,
  externalProfileIdHash: string,
  verified: VerifiedGooglePlaySubscription,
  acknowledgementState: GooglePlayAcknowledgementState,
  activateEntitlement: boolean,
) {
  const latestOrderIdHash = verified.latestSuccessfulOrderId
    ? await sha256(verified.latestSuccessfulOrderId)
    : null;

  const { data, error } = await admin.rpc("service_record_google_play_subscription", {
    p_purchase_token_hash: purchaseTokenHash,
    p_user_id: caller.id,
    p_organization_id: caller.organization_id,
    p_product_id: GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID,
    p_base_plan_id: GOOGLE_PLAY_BASE_PLAN_ID,
    p_subscription_state: verified.subscriptionState,
    p_acknowledgement_state: acknowledgementState,
    p_activate_entitlement: activateEntitlement,
    p_google_verified_at: verified.verifiedAt,
    p_expiry_time: verified.expiryTime,
    p_auto_renew_enabled: verified.autoRenewEnabled,
    p_is_test_purchase: verified.isTestPurchase,
    p_latest_order_id_hash: latestOrderIdHash,
    p_external_account_id_hash: externalAccountIdHash,
    p_external_profile_id_hash: externalProfileIdHash,
  });

  if (error) {
    const code = typeof error.code === "string" ? error.code : "unknown";
    console.error("Google Play subscription ledger update failed", { code });
    if (code === "23505") {
      throw new LedgerError(409, "Google Play satın alma başka bir hesaba bağlı");
    }
    if (code === "22023") {
      throw new LedgerError(400, "Google Play abonelik bilgisi geçersiz");
    }
    if (code === "42501") {
      throw new LedgerError(403, "Bu işlem yalnızca işletme yöneticisine açıktır");
    }
    throw new LedgerError(503, "Abonelik kaydı şu anda güncellenemiyor");
  }
  return validateLedgerResult(data);
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const token = bearerToken(req);
    if (!token) return json(401, { error: "Oturum gerekli" });

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: callerData, error: callerAuthError } = await admin.auth.getUser(token);
    if (callerAuthError || !callerData.user) return json(401, { error: "Geçersiz oturum" });

    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc(
      "service_has_live_session",
      { p_user_id: callerData.user.id, p_session_id: sessionId },
    );
    if (liveSessionError || !liveSession) return json(401, { error: "Oturum sona erdi" });

    const { data: callerDataRow, error: callerError } = await admin
      .from("profiles")
      .select("id,organization_id,role,is_active,must_change_password")
      .eq("id", callerData.user.id)
      .maybeSingle();
    if (callerError) throw new LedgerError(503, "İşletme yöneticisi doğrulanamadı");
    const caller = callerDataRow as CallerProfile | null;
    if (!caller?.is_active || caller.role !== "admin" || caller.must_change_password) {
      return json(403, { error: "Bu işlem yalnızca etkin işletme yöneticisine açıktır" });
    }

    const body = await readBoundedJson(req, 8_192);
    if (!isRecord(body)
      || Object.keys(body).some((key) => !["purchaseToken", "productId"].includes(key))
      || body.productId !== GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID) {
      return json(400, { error: "Desteklenmeyen Google Play aboneliği" });
    }
    const purchaseToken = validateGooglePlayPurchaseToken(body.purchaseToken);
    const purchaseTokenHash = await sha256(purchaseToken);

    const rateKey = await sha256(`stokdas:google-play-verify:v1:${caller.id}`);
    const { data: allowed, error: rateError } = await admin.rpc("consume_auth_rate_limit", {
      p_scope: "google-play-verify",
      p_key_hash: rateKey,
      p_max_attempts: 60,
      p_window_seconds: 600,
    });
    if (rateError) {
      console.error("Google Play verification rate limiter unavailable", {
        code: typeof rateError.code === "string" ? rateError.code : "unknown",
      });
      return json(503, { error: "Abonelik doğrulaması şu anda kullanılamıyor" });
    }
    if (!allowed) {
      return json(429, { error: "Çok fazla abonelik doğrulaması yapıldı. Lütfen daha sonra tekrar deneyin." });
    }

    const externalAccountIdHash = await sha256(caller.id);
    const externalProfileIdHash = await sha256(caller.organization_id);
    const googlePlay = await GooglePlayClient.fromEnvironment();
    const verified = await googlePlay.verifySubscription(
      purchaseToken,
      externalAccountIdHash,
      externalProfileIdHash,
    );

    let ledger = await recordVerifiedSubscription(
      admin,
      caller,
      purchaseTokenHash,
      externalAccountIdHash,
      externalProfileIdHash,
      verified,
      verified.acknowledgementState,
      verified.acknowledgementState === "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
    );

    let acknowledged =
      verified.acknowledgementState === "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED";
    if (verified.entitled && !acknowledged) {
      // Reserve ownership before the external acknowledgement call, but do not
      // grant entitlement yet. If the second ledger write fails, a retry reads
      // Google's acknowledged state and safely completes local activation.
      await googlePlay.acknowledgeSubscription(purchaseToken);
      ledger = await recordVerifiedSubscription(
        admin,
        caller,
        purchaseTokenHash,
        externalAccountIdHash,
        externalProfileIdHash,
        verified,
        "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
        true,
      );
      acknowledged = true;
    }

    return json(200, {
      store: "google",
      entitled: ledger.entitled,
      subscriptionStatus: ledger.subscriptionStatus,
      currentPeriodEnd: ledger.currentPeriodEnd,
      acknowledged,
    });
  } catch (error) {
    if (error instanceof GooglePlayError) {
      console.error("Google Play subscription verification failed", {
        code: error.code,
        status: error.responseStatus,
      });
      return json(error.responseStatus, { error: error.message, code: error.code });
    }
    if (error instanceof LedgerError) {
      return json(error.status, { error: error.message });
    }
    console.error("Google Play subscription verification failed", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return json(500, { error: "Abonelik doğrulanamadı. Lütfen tekrar deneyin." });
  }
});
