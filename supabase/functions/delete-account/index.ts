import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import { GooglePlayClient, GooglePlayError } from "../_shared/google_play.ts";
import { decryptPurchaseToken, synchronizeGooglePlaySubscription } from "../_shared/google_play_subscription_sync.ts";
import {
  bearerToken, corsJsonHeaders, HttpInputError, isRecord, json, normalizeUuid,
  readBoundedJson, sessionIdFromAccessToken,
} from "../_shared/security.ts";

type AdminClient = ReturnType<typeof createClient<any>>;
type Caller = {
  id: string; username: string; role: "admin" | "member"; organization_id: string;
  is_platform_operator: boolean; is_active: boolean; must_change_password: boolean;
};
type Receipt = {
  state: "processing" | "completed"; scope: "account" | "organization";
  organizationId: string;
};
type DeletionToken = {
  purchaseTokenHash: string; tokenCiphertext: string; tokenNonce: string;
  tokenKeyVersion: number; needsStop: boolean;
};

class DeletionError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "DeletionError";
  }
}

function jwtSubject(token: string) {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const padded = part.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(part.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded));
    return isRecord(payload) ? normalizeUuid(payload.sub) : null;
  } catch {
    return null;
  }
}

function parseReceipt(value: unknown): Receipt | null {
  if (!isRecord(value) || Object.keys(value).length === 0) return null;
  if (!["processing", "completed"].includes(String(value.state))
    || !["account", "organization"].includes(String(value.scope))
    || normalizeUuid(value.organizationId) === null) {
    throw new DeletionError(503, "RECEIPT_INVALID", "Hesap silme kaydı doğrulanamadı");
  }
  return value as Receipt;
}

function parseDeletionPlan(value: unknown) {
  if (!isRecord(value) || typeof value.ready !== "boolean" || typeof value.busy !== "boolean"
    || typeof value.missingToken !== "boolean"
    || (value.reason !== null && typeof value.reason !== "string") || !Array.isArray(value.tokens)) {
    throw new DeletionError(503, "BILLING_PLAN_INVALID", "Google Play silme planı doğrulanamadı");
  }
  const tokens = value.tokens.map((item): DeletionToken => {
    if (!isRecord(item) || typeof item.purchaseTokenHash !== "string"
      || typeof item.tokenCiphertext !== "string" || typeof item.tokenNonce !== "string"
      || typeof item.tokenKeyVersion !== "number" || typeof item.needsStop !== "boolean") {
      throw new DeletionError(503, "BILLING_PLAN_INVALID", "Google Play silme planı doğrulanamadı");
    }
    return item as DeletionToken;
  });
  return { ready: value.ready, busy: value.busy, missingToken: value.missingToken, reason: value.reason, tokens };
}

function rpcFailure(error: { code?: string } | null, fallback: string): never {
  const code = error?.code ?? "unknown";
  if (["40P01", "55P03", "40001"].includes(code)) {
    throw new DeletionError(409, "DELETION_RETRY_REQUIRED", "Silme işlemi güvenle bekletildi; aynı istekle tekrar deneyin");
  }
  if (code === "42501") throw new DeletionError(403, "NOT_AUTHORIZED", "Hesap silme yetkisi doğrulanamadı");
  if (code === "23505") throw new DeletionError(409, "REQUEST_ID_CONFLICT", "Silme istek kimliği başka bir işleme ait");
  if (code === "22023") throw new DeletionError(400, "INVALID_REQUEST", "Hesap silme isteği geçersiz");
  if (code === "55000") throw new DeletionError(409, "DELETION_PROOF_REQUIRED", "Silme kanıtı henüz tamamlanmadı; aynı istekle tekrar deneyin");
  console.error(fallback, { code });
  throw new DeletionError(503, "DELETION_UNAVAILABLE", fallback);
}

async function rpc(admin: AdminClient, name: string, args: Record<string, unknown>) {
  const { data, error } = await admin.rpc(name, args);
  if (error) rpcFailure(error, "Hesap silme kaydı şu anda güncellenemiyor");
  return data;
}

async function stopAndRecordGooglePlay(admin: AdminClient, googlePlay: GooglePlayClient, item: DeletionToken) {
  const purchaseToken = await decryptPurchaseToken(
    item.tokenCiphertext, item.tokenNonce, item.tokenKeyVersion, item.purchaseTokenHash,
  );
  let observed = await googlePlay.inspectSubscription(purchaseToken);
  if (observed.autoRenewEnabled !== false) {
    let cancellationError: unknown = null;
    try {
      await googlePlay.cancelSubscription(purchaseToken);
    } catch (error) {
      cancellationError = error;
    }
    // A timed-out cancellation may have succeeded. A fresh Publisher GET is
    // the only proof; the cancellation HTTP response never grants proof.
    observed = await googlePlay.inspectSubscription(purchaseToken);
    if (observed.autoRenewEnabled !== false) {
      if (cancellationError) throw cancellationError;
      throw new DeletionError(503, "GOOGLE_STOP_UNVERIFIED", "Google Play yenilemesinin durduğu doğrulanamadı");
    }
  }
  const result = await synchronizeGooglePlaySubscription({
    admin, googlePlay, purchaseToken, mode: "deletion",
  });
  if (result.disposition === "quarantined") {
    throw new DeletionError(503, "GOOGLE_STOP_UNVERIFIED", "Google Play silme kanıtı karantinaya alındı");
  }
}

async function abortBeforeExternalSideEffect(admin: AdminClient, requestId: string, userId: string) {
  const { error } = await admin.rpc("service_abort_account_deletion_request", {
    p_request_id: requestId, p_user_id: userId,
  });
  if (error) console.error("Pre-effect deletion abort failed", { code: error.code ?? "unknown" });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });
  let canonicalRequestId: string | null = null;
  try {
    const token = bearerToken(req);
    const subject = token ? jwtSubject(token) : null;
    if (!token || !subject) return json(401, { error: "Oturum gerekli" });
    const body = await readBoundedJson(req, 4_096);
    if (!isRecord(body)
      || Object.keys(body).some((key) => !["deletionRequestId", "confirmation", "currentPassword"].includes(key))) {
      throw new HttpInputError(400, "Geçersiz hesap silme isteği");
    }
    const suppliedRequestId = normalizeUuid(body.deletionRequestId);
    if (!suppliedRequestId) throw new DeletionError(400, "INVALID_REQUEST", "Silme istek kimliği geçersiz");

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) return json(500, { error: "Sunucu yapılandırması eksik" });
    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    // Verify the JWT signature/issuer before using its subject in any receipt
    // lookup. getClaims remains usable for a completed replay after the Auth
    // user itself has already been removed by the cleanup worker.
    const { data: verifiedClaims, error: claimsError } = await admin.auth.getClaims(token);
    if (claimsError || normalizeUuid(verifiedClaims?.claims?.sub) !== subject) {
      return json(401, { error: "Geçersiz oturum" });
    }
    const active = await rpc(admin, "service_find_active_account_deletion_request", {
      p_user_id: subject,
    });
    let requestId = suppliedRequestId;
    if (isRecord(active) && Object.keys(active).length > 0) {
      const activeRequestId = normalizeUuid(active.requestId);
      if (!activeRequestId) {
        throw new DeletionError(503, "RECEIPT_INVALID", "Hesap silme kaydı doğrulanamadı");
      }
      requestId = activeRequestId;
    }
    canonicalRequestId = requestId;
    const receipt = parseReceipt(await rpc(admin, "service_get_account_deletion_receipt", {
      p_request_id: requestId, p_user_id: subject,
    }));
    if (receipt?.state === "completed") {
      return json(200, { deleted: true, scope: receipt.scope, deletionRequestId: requestId, replayed: true });
    }

    const { data: profileData, error: profileError } = await admin.from("profiles")
      .select("id,username,role,organization_id,is_platform_operator,is_active,must_change_password")
      .eq("id", subject).maybeSingle();
    if (profileError) throw new DeletionError(503, "PROFILE_UNAVAILABLE", "Kullanıcı profili doğrulanamadı");
    const caller = profileData as Caller | null;
    if (!caller?.is_active || caller.must_change_password) {
      throw new DeletionError(403, "NOT_AUTHORIZED", "Etkin kullanıcı profili bulunamadı");
    }
    if (caller.is_platform_operator) {
      throw new DeletionError(403, "PLATFORM_ACCOUNT", "Platform yöneticisi hesabı uygulama içinden silinemez");
    }
    const scope = caller.role === "admin" ? "organization" : "account";
    if (receipt && (receipt.organizationId !== caller.organization_id || receipt.scope !== scope)) {
      throw new DeletionError(409, "REQUEST_ID_CONFLICT", "Silme istek kimliği başka bir işleme ait");
    }

    if (!receipt) {
      const { data: userData, error: userError } = await admin.auth.getUser(token);
      if (userError || userData.user?.id !== subject) return json(401, { error: "Geçersiz oturum" });
      const sessionId = sessionIdFromAccessToken(token);
      if (!sessionId) return json(401, { error: "Geçersiz oturum" });
      const { data: live, error: liveError } = await admin.rpc("service_has_live_session", {
        p_user_id: subject, p_session_id: sessionId,
      });
      if (liveError || live !== true) return json(401, { error: "Oturum sona erdi" });
      const confirmation = typeof body.confirmation === "string" ? body.confirmation.trim() : "";
      const expected = caller.role === "admin" ? "STOKDAŞ" : caller.username;
      const confirmed = caller.role === "admin"
        ? confirmation === "STOKDAŞ" || confirmation === "STOKTA"
        : confirmation === expected;
      if (!confirmed) throw new DeletionError(400, "INVALID_CONFIRMATION", `Onay alanına ${expected} yazılmalı`);
      const password = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const email = userData.user.email;
      if (!email || password.length < 1 || password.length > 72) {
        throw new DeletionError(400, "PASSWORD_REQUIRED", "Hesabı silmek için mevcut şifrenizi girin");
      }
      const reauth = createClient(supabaseUrl, anonKey, { auth: { autoRefreshToken: false, persistSession: false } });
      const { data: reauthData, error: reauthError } = await reauth.auth.signInWithPassword({ email, password });
      if (reauthError || reauthData.user?.id !== subject || !reauthData.session) {
        throw new DeletionError(401, "PASSWORD_INVALID", "Mevcut şifre hatalı");
      }
      const reauthSessionId = sessionIdFromAccessToken(reauthData.session.access_token);
      if (!reauthSessionId) throw new DeletionError(503, "REAUTH_FAILED", "Kimlik doğrulama oturumu kapatılamadı");
      const { data: revoked, error: revokeError } = await admin.rpc("service_revoke_session", {
        p_user_id: subject, p_session_id: reauthSessionId,
      });
      await reauth.auth.signOut({ scope: "local" });
      if (revokeError || revoked !== true) {
        throw new DeletionError(503, "REAUTH_FAILED", "Kimlik doğrulama oturumu kapatılamadı");
      }
      const begun = await rpc(admin, "service_begin_account_deletion_request", {
        p_request_id: requestId, p_user_id: subject, p_scope: scope,
        p_organization_id: scope === "organization" ? caller.organization_id : null,
      });
      if (!isRecord(begun) || !normalizeUuid(begun.requestId)) {
        throw new DeletionError(503, "RECEIPT_INVALID", "Hesap silme kaydı doğrulanamadı");
      }
      requestId = normalizeUuid(begun.requestId)!;
      canonicalRequestId = requestId;
    }

    if (caller.role === "admin") {
      const { data: profiles, error: profilesError } = await admin.from("profiles")
        .select("id,is_platform_operator").eq("organization_id", caller.organization_id);
      if (profilesError) throw new DeletionError(503, "PROFILE_UNAVAILABLE", "İşletme kullanıcıları doğrulanamadı");
      if ((profiles ?? []).some((profile) => profile.is_platform_operator)) {
        await abortBeforeExternalSideEffect(admin, requestId, subject);
        throw new DeletionError(403, "PLATFORM_ACCOUNT", "Platform yöneticisinin bulunduğu işletme silinemez");
      }
      const prepareArgs = {
        p_request_id: requestId, p_user_id: subject, p_organization_id: caller.organization_id,
      };
      let plan = parseDeletionPlan(await rpc(admin, "service_prepare_google_play_organization_deletion", prepareArgs));
      if (plan.busy) {
        if (plan.reason === "PURCHASE_INTENT_IN_PROGRESS") {
          await abortBeforeExternalSideEffect(admin, requestId, subject);
          throw new DeletionError(409, "PURCHASE_INTENT_IN_PROGRESS", "Devam eden Google Play satın alma işlemini tamamlayın veya süresinin dolmasını bekleyin");
        }
        throw new DeletionError(409, "DELETION_RETRY_REQUIRED", "Abonelik doğrulaması sürüyor; aynı istekle tekrar deneyin");
      }
      if (plan.missingToken) {
        await abortBeforeExternalSideEffect(admin, requestId, subject);
        throw new DeletionError(409, "RESTORE_PURCHASES_REQUIRED", "Silmeden önce Google Play satın alımlarını geri yükleyin");
      }
      if (!plan.ready) {
        const googlePlay = await GooglePlayClient.fromEnvironment();
        for (const item of plan.tokens) await stopAndRecordGooglePlay(admin, googlePlay, item);
        plan = parseDeletionPlan(await rpc(admin, "service_prepare_google_play_organization_deletion", prepareArgs));
        if (!plan.ready) {
          throw new DeletionError(409, "DELETION_RETRY_REQUIRED", "Google Play durdurma kanıtı işleniyor; aynı istekle tekrar deneyin");
        }
      }
      await rpc(admin, "service_finalize_google_play_organization_deletion", prepareArgs);
      await rpc(admin, "service_erase_organization_after_billing_finalize", {
        p_request_id: requestId, p_user_id: subject, p_organization_id: caller.organization_id,
      });
      return json(200, {
        deleted: true, scope: "organization", deletionRequestId: requestId, authCleanupQueued: true,
      });
    }

    await rpc(admin, "service_finalize_member_account_deletion", {
      p_request_id: requestId, p_user_id: subject, p_organization_id: caller.organization_id,
    });
    return json(200, { deleted: true, scope: "account", deletionRequestId: requestId, authCleanupQueued: true });
  } catch (error) {
    if (error instanceof HttpInputError) {
      return json(error.status, { error: error.message, deletionRequestId: canonicalRequestId ?? undefined });
    }
    if (error instanceof DeletionError) {
      return json(error.status, {
        error: error.message, code: error.code,
        deletionRequestId: canonicalRequestId ?? undefined,
      });
    }
    if (error instanceof GooglePlayError) {
      console.error("Google Play account deletion failed", { code: error.code, status: error.responseStatus });
      return json(error.code === "IDENTITY_MISMATCH" || error.code === "INVALID_PURCHASE" ? 409 : 503, {
        error: "Google Play yenilemesinin durduğu henüz doğrulanamadı; aynı istekle tekrar deneyin",
        code: "GOOGLE_STOP_UNVERIFIED",
        deletionRequestId: canonicalRequestId ?? undefined,
      });
    }
    const code = isRecord(error) && typeof error.code === "string" ? error.code : "unknown";
    console.error("Account deletion failed", { name: error instanceof Error ? error.name : "unknown", code });
    if (["40P01", "55P03", "40001"].includes(code)) {
      return json(409, {
        error: "Silme işlemi güvenle bekletildi; aynı istekle tekrar deneyin",
        code: "DELETION_RETRY_REQUIRED",
        deletionRequestId: canonicalRequestId ?? undefined,
      });
    }
    return json(503, {
      error: "Hesap silme işlemi güvenle bekletildi. Aynı istekle tekrar deneyin.",
      code: "DELETION_UNAVAILABLE",
      deletionRequestId: canonicalRequestId ?? undefined,
    });
  }
});
