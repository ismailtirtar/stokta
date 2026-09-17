import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  GooglePlayClient,
  GooglePlayError,
  GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID,
  validateGooglePlayPurchaseToken,
} from "../_shared/google_play.ts";
import { synchronizeGooglePlaySubscription } from "../_shared/google_play_subscription_sync.ts";
import {
  bearerToken,
  corsJsonHeaders,
  HttpInputError,
  isRecord,
  json,
  readBoundedJson,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

type Caller = {
  id: string;
  organization_id: string;
  role: "admin" | "member";
  is_active: boolean;
  must_change_password: boolean;
};

class SubscriptionRequestError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "SubscriptionRequestError";
    this.status = status;
    this.code = code;
  }
}

function validateUuid(value: unknown) {
  if (typeof value !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new SubscriptionRequestError(400, "INVALID_INTENT", "Satın alma niyeti geçersiz");
  }
  return value;
}

function rpcError(error: { code?: string } | null): never {
  const code = error?.code ?? "unknown";
  if (code === "22023") {
    throw new SubscriptionRequestError(409, "INVALID_INTENT", "Satın alma niyeti geçersiz veya süresi dolmuş");
  }
  if (code === "23505") {
    throw new SubscriptionRequestError(409, "OWNERSHIP_CONFLICT", "Google Play satın alma başka bir hesaba bağlı");
  }
  if (code === "42501") {
    throw new SubscriptionRequestError(403, "NOT_AUTHORIZED", "Bu işlem yalnızca etkin işletme yöneticisine açıktır");
  }
  if (code === "55P03") {
    throw new SubscriptionRequestError(409, "SYNC_IN_PROGRESS", "Abonelik başka bir istek tarafından güncelleniyor");
  }
  console.error("Google Play lifecycle RPC failed", { code });
  throw new SubscriptionRequestError(503, "LEDGER_UNAVAILABLE", "Abonelik kaydı şu anda güncellenemiyor");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const accessToken = bearerToken(req);
    if (!accessToken) return json(401, { error: "Oturum gerekli" });
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: authData, error: authError } = await admin.auth.getUser(accessToken);
    if (authError || !authData.user) return json(401, { error: "Geçersiz oturum" });
    const sessionId = sessionIdFromAccessToken(accessToken);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: live, error: liveError } = await admin.rpc("service_has_live_session", {
      p_user_id: authData.user.id,
      p_session_id: sessionId,
    });
    if (liveError || live !== true) return json(401, { error: "Oturum sona erdi" });

    const { data: profileData, error: profileError } = await admin
      .from("profiles")
      .select("id,organization_id,role,is_active,must_change_password")
      .eq("id", authData.user.id)
      .maybeSingle();
    if (profileError) throw new SubscriptionRequestError(503, "PROFILE_UNAVAILABLE", "İşletme yöneticisi doğrulanamadı");
    const caller = profileData as Caller | null;
    if (!caller?.is_active || caller.role !== "admin" || caller.must_change_password) {
      return json(403, { error: "Bu işlem yalnızca etkin işletme yöneticisine açıktır" });
    }

    const body = await readBoundedJson(req, 8_192);
    if (!isRecord(body)) throw new HttpInputError(400, "Geçersiz istek gövdesi");
    const action = body.action === undefined ? "restore" : body.action;
    if (!["begin", "verify", "restore"].includes(String(action))
      || body.productId !== GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID) {
      throw new SubscriptionRequestError(400, "INVALID_REQUEST", "Desteklenmeyen Google Play aboneliği");
    }

    const allowedKeys = action === "begin"
      ? ["action", "productId"]
      : action === "verify"
      ? ["action", "productId", "purchaseToken", "purchaseIntentId"]
      : ["action", "productId", "purchaseToken"];
    if (Object.keys(body).some((key) => !allowedKeys.includes(key))) {
      throw new SubscriptionRequestError(400, "INVALID_REQUEST", "İstek alanları geçersiz");
    }

    const rateKey = await sha256(`stokdas:google-play:${String(action)}:v2:${caller.id}`);
    const { data: allowed, error: rateError } = await admin.rpc("consume_auth_rate_limit", {
      p_scope: `google-play-${String(action)}`,
      p_key_hash: rateKey,
      p_max_attempts: action === "begin" ? 20 : 60,
      p_window_seconds: 600,
    });
    if (rateError || typeof allowed !== "boolean") {
      return json(503, { error: "Abonelik doğrulaması şu anda kullanılamıyor" });
    }
    if (!allowed) return json(429, { error: "Çok fazla abonelik isteği yapıldı. Lütfen daha sonra tekrar deneyin." });

    if (action === "begin") {
      const { data, error } = await admin.rpc("service_begin_google_play_purchase_intent", {
        p_user_id: caller.id,
        p_organization_id: caller.organization_id,
      });
      if (error) rpcError(error);
      if (!isRecord(data)
        || typeof data.purchaseIntentId !== "string"
        || typeof data.obfuscatedAccountId !== "string"
        || typeof data.obfuscatedProfileId !== "string"
        || typeof data.expiresAt !== "string") {
        throw new SubscriptionRequestError(503, "LEDGER_UNAVAILABLE", "Satın alma niyeti oluşturulamadı");
      }
      return json(200, data);
    }

    const purchaseToken = validateGooglePlayPurchaseToken(body.purchaseToken);
    const purchaseIntentId = action === "verify" ? validateUuid(body.purchaseIntentId) : null;
    const googlePlay = await GooglePlayClient.fromEnvironment();
    const result = await synchronizeGooglePlaySubscription({
      admin,
      googlePlay,
      purchaseToken,
      mode: action === "verify" ? "intent" : "restore",
      userId: caller.id,
      organizationId: caller.organization_id,
      purchaseIntentId,
    });
    return json(200, { store: "google", ...result });
  } catch (error) {
    if (error instanceof HttpInputError) return json(error.status, { error: error.message });
    if (error instanceof GooglePlayError) {
      console.error("Google Play request failed", { code: error.code, status: error.responseStatus });
      return json(error.responseStatus, { error: error.message, code: error.code });
    }
    if (error instanceof SubscriptionRequestError) {
      return json(error.status, { error: error.message, code: error.code });
    }
    const code = isRecord(error) && typeof error.code === "string" ? error.code : "unknown";
    if (code === "22023") return json(409, { error: "Satın alma niyeti geçersiz veya süresi dolmuş", code: "INVALID_INTENT" });
    if (code === "42501") return json(403, { error: "Bu işlem yalnızca etkin işletme yöneticisine açıktır", code: "NOT_AUTHORIZED" });
    if (code === "55000") return json(409, { error: "İşletme silme işlemi devam ediyor", code: "ACCOUNT_DELETION_IN_PROGRESS" });
    if (code === "55P03") return json(409, { error: "Abonelik güncellemesi devam ediyor", code: "SYNC_IN_PROGRESS" });
    if (code === "23505") return json(409, { error: "Google Play satın alma başka bir hesaba bağlı", code: "OWNERSHIP_CONFLICT" });
    console.error("Google Play subscription verification failed", {
      name: error instanceof Error ? error.name : "unknown",
      code,
    });
    return json(500, { error: "Abonelik doğrulanamadı. Lütfen tekrar deneyin." });
  }
});
