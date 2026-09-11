import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  json,
  normalizeUsername,
  readJsonObject,
  requestBodyErrorResponse,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const invalidCode = { error: "Doğrulama kodu geçersiz veya süresi dolmuş" };

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsJsonHeaders });
  }
  if (req.method !== "POST") {
    return json(405, { error: "Yalnızca POST desteklenir" });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const body = await readJsonObject(req, 4 * 1024);
    const username = normalizeUsername(body.username);
    const code = typeof body.code === "string" ? body.code.trim() : "";
    const rateUsername = username ?? "invalid";
    const ip = requestIp(req);
    const [identityHash, accountHash, ipHash] = await Promise.all([
      sha256(
        `stokta:verify-email:v1:${ip}:${rateUsername}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:verify-email-account:v1:${rateUsername}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:verify-email-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`,
      ),
    ]);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const limits = await Promise.all([
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "verify-email",
        p_key_hash: identityHash,
        p_max_attempts: 8,
        p_window_seconds: 900,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "verify-email-account",
        p_key_hash: accountHash,
        p_max_attempts: 10,
        p_window_seconds: 900,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "verify-email-ip",
        p_key_hash: ipHash,
        p_max_attempts: 40,
        p_window_seconds: 900,
      }),
    ]);
    if (limits.some((limit) => limit.error)) {
      console.error("Email verification rate limiter unavailable");
      return json(503, { error: "Doğrulama hizmeti şu anda kullanılamıyor" });
    }
    if (limits.some((limit) => limit.data !== true)) {
      return json(429, {
        error:
          "Çok fazla kod denemesi yapıldı. Lütfen daha sonra tekrar deneyin.",
      });
    }

    if (!username || !/^[0-9]{6,10}$/.test(code)) return json(401, invalidCode);

    const { data: pending, error: pendingError } = await admin
      .from("pending_account_registrations")
      .select(
        "auth_user_id,registration_kind,email,expires_at,cleanup_claimed_at",
      )
      .eq("username", username)
      .maybeSingle();
    if (pendingError) {
      console.error("Pending registration lookup failed", pendingError);
      return json(503, { error: "Doğrulama hizmeti şu anda kullanılamıyor" });
    }
    if (
      !pending ||
      pending.cleanup_claimed_at ||
      new Date(pending.expires_at).getTime() <= Date.now()
    ) {
      return json(401, invalidCode);
    }

    const { data: verificationData, error: verificationError } =
      await authClient.auth.verifyOtp({
        email: pending.email,
        token: code,
        type: "email",
      });
    const verifiedUser = verificationData.user;
    if (
      verificationError ||
      !verificationData.session ||
      !verifiedUser ||
      verifiedUser.id !== pending.auth_user_id
    ) {
      return json(401, invalidCode);
    }

    const marker = verifiedUser.app_metadata?.stokta_pending_registration;
    if (marker !== pending.registration_kind) {
      const rejectedSessionId = sessionIdFromAccessToken(
        verificationData.session.access_token,
      );
      if (rejectedSessionId) {
        await admin.rpc("service_revoke_session", {
          p_user_id: pending.auth_user_id,
          p_session_id: rejectedSessionId,
        });
      }
      return json(401, invalidCode);
    }

    let { data: finalized, error: finalizeError } = await admin.rpc(
      "service_finalize_pending_registration",
      { p_auth_user_id: pending.auth_user_id, p_username: username },
    );
    // The RPC is transactionally idempotent. A single controlled retry repairs
    // a committed response timeout and transient serialization/deadlock errors.
    if (finalizeError) {
      const retry = await admin.rpc("service_finalize_pending_registration", {
        p_auth_user_id: pending.auth_user_id,
        p_username: username,
      });
      finalized = retry.data;
      finalizeError = retry.error;
    }
    if (finalizeError) {
      console.error("Verified registration finalization failed", finalizeError);
      const verifiedSessionId = sessionIdFromAccessToken(
        verificationData.session.access_token,
      );
      if (verifiedSessionId) {
        await admin.rpc("service_revoke_session", {
          p_user_id: pending.auth_user_id,
          p_session_id: verifiedSessionId,
        });
      }
      const normalized = finalizeError.message.toLowerCase();
      const conflict = finalizeError.code === "23505" ||
        normalized.includes("limit") ||
        normalized.includes("kullanılıyor");
      const expired = normalized.includes("süresi doldu");

      return json(expired ? 410 : conflict ? 409 : 500, {
        error: expired
          ? "Doğrulama isteğinin süresi doldu"
          : conflict
          ? "Hesap kurulumu tamamlanamadı; kullanıcı limiti veya benzersiz alan çakışmasını kontrol edin."
          : "E-posta doğrulandı ancak kurulum tamamlanamadı. Aynı kullanıcı adı ve şifreyle giriş yaparak tekrar deneyin.",
      });
    }

    const { data: latestUserData, error: latestUserError } = await admin.auth
      .admin.getUserById(pending.auth_user_id);
    const cleanedMetadata = {
      ...(latestUserData.user?.app_metadata ?? verifiedUser.app_metadata),
    } as Record<string, unknown>;
    delete cleanedMetadata.stokta_pending_registration;
    delete cleanedMetadata.stokta_registration_request_id;
    delete cleanedMetadata.username;
    delete cleanedMetadata.organization_id;
    delete cleanedMetadata.created_by;
    const cleanedUserMetadata = {
      ...(latestUserData.user?.user_metadata ?? verifiedUser.user_metadata),
    } as Record<string, unknown>;
    delete cleanedUserMetadata.stokta_registration_request_id;
    delete cleanedUserMetadata.organization_id;
    const metadataUpdate = latestUserError
      ? { error: latestUserError }
      : await admin.auth.admin.updateUserById(pending.auth_user_id, {
        app_metadata: cleanedMetadata,
        user_metadata: cleanedUserMetadata,
      });
    if (metadataUpdate.error) {
      console.error(
        "Finalized registration metadata cleanup failed",
        metadataUpdate.error,
      );
      const completedSessionId = sessionIdFromAccessToken(
        verificationData.session.access_token,
      );
      if (completedSessionId) {
        await admin.rpc("service_revoke_session", {
          p_user_id: pending.auth_user_id,
          p_session_id: completedSessionId,
        });
      }
      return json(503, {
        error:
          "Hesap kuruldu; güvenli giriş için kullanıcı adı ve şifrenizle yeniden giriş yapın.",
        code: "REGISTRATION_COMPLETED_REAUTH_REQUIRED",
      });
    }

    await Promise.all([
      admin.rpc("clear_auth_rate_limit", {
        p_scope: "verify-email",
        p_key_hash: identityHash,
      }),
      admin.rpc("clear_auth_rate_limit", {
        p_scope: "verify-email-account",
        p_key_hash: accountHash,
      }),
    ]);

    return json(200, {
      verified: true,
      session: verificationData.session,
      registration: finalized,
    });
  } catch (error) {
    const inputError = requestBodyErrorResponse(error);
    if (inputError) return inputError;
    console.error("Email code verification failed", error);
    return json(500, { error: "Doğrulama tamamlanamadı" });
  }
});
