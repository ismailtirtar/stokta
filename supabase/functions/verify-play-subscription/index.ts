import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  GooglePlayError,
  GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID,
  validateGooglePlayPurchaseToken,
} from "../_shared/google_play.ts";
import { PlaySyncError, processGooglePlayToken } from "../_shared/google_play_sync.ts";
import {
  bearerToken,
  corsJsonHeaders,
  json,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

type CallerProfile = {
  id: string;
  organization_id: string;
  role: "admin" | "member";
  is_active: boolean;
  must_change_password: boolean;
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
    const result = await processGooglePlayToken(admin, purchaseToken, "verify", {
      owner: {
        userId: caller.id,
        organizationId: caller.organization_id,
        accountHash: externalAccountIdHash,
        profileHash: externalProfileIdHash,
      },
    });
    if (result.disposition !== "recorded") {
      throw new LedgerError(503, "Abonelik kaydı doğrulanamadı");
    }
    const { ledger, acknowledged } = result;

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
    if (error instanceof PlaySyncError) {
      return json(error.status, { error: error.message });
    }
    console.error("Google Play subscription verification failed", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return json(500, { error: "Abonelik doğrulanamadı. Lütfen tekrar deneyin." });
  }
});
