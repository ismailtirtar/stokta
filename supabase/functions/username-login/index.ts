import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  json,
  maskEmail,
  normalizeUsername,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const invalidCredentials = { error: "Kullanıcı adı veya şifre hatalı" };

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const body = await req.json() as Record<string, unknown>;
    const username = normalizeUsername(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    const rateUsername = username ?? "invalid";
    const ip = requestIp(req);
    const [identityHash, accountHash, ipHash] = await Promise.all([
      sha256(`stokta:login:v1:${ip}:${rateUsername}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:login-account:v1:${rateUsername}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:login-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`),
    ]);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const [
      { data: identityAllowed, error: identityRateError },
      { data: accountAllowed, error: accountRateError },
      { data: ipAllowed, error: ipRateError },
    ] =
      await Promise.all([
        admin.rpc("consume_auth_rate_limit", {
          p_scope: "username-login",
          p_key_hash: identityHash,
          p_max_attempts: 8,
          p_window_seconds: 900,
        }),
        admin.rpc("consume_auth_rate_limit", {
          p_scope: "username-login-account",
          p_key_hash: accountHash,
          p_max_attempts: 12,
          p_window_seconds: 900,
        }),
        admin.rpc("consume_auth_rate_limit", {
          p_scope: "username-login-ip",
          p_key_hash: ipHash,
          p_max_attempts: 60,
          p_window_seconds: 900,
        }),
      ]);
    if (identityRateError || accountRateError || ipRateError) {
      console.error("Username login rate limiter unavailable", {
        identityRateError,
        accountRateError,
        ipRateError,
      });
      return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
    }
    if (!identityAllowed || !accountAllowed || !ipAllowed) {
      return json(429, { error: "Çok fazla giriş denemesi yapıldı. Lütfen daha sonra tekrar deneyin." });
    }

    if (!username || password.length < 1 || password.length > 72) {
      return json(401, invalidCredentials);
    }

    const { data: profile, error: profileError } = await admin
      .from("profiles")
      .select("id,must_change_password")
      .eq("username", username)
      .eq("is_active", true)
      .maybeSingle();
    if (profileError) {
      console.error("Username lookup failed", profileError);
      return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
    }
    let email: string;
    let expectedUserId: string;
    let pendingRegistrationKind: string | null = null;
    let pendingExpiresAt: string | null = null;

    if (profile?.id) {
      const { data: authUserData, error: authUserError } =
        await admin.auth.admin.getUserById(profile.id);
      email = authUserData.user?.email ?? "";
      if (authUserError || !email) {
        if (authUserError) console.error("Username auth identity lookup failed", authUserError);
        return json(401, invalidCredentials);
      }
      expectedUserId = profile.id;
    } else {
      const { data: pending, error: pendingError } = await admin
        .from("pending_account_registrations")
        .select("auth_user_id,registration_kind,email,expires_at")
        .eq("username", username)
        .maybeSingle();
      if (pendingError) {
        console.error("Pending username lookup failed", pendingError);
        return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
      }
      if (!pending || new Date(pending.expires_at).getTime() <= Date.now()) {
        return json(401, invalidCredentials);
      }
      email = pending.email;
      expectedUserId = pending.auth_user_id;
      pendingRegistrationKind = pending.registration_kind;
      pendingExpiresAt = pending.expires_at;
    }

    const { data: signInData, error: signInError } = await authClient.auth.signInWithPassword({
      email,
      password,
    });
    if (signInError) {
      if (pendingRegistrationKind && signInError.code === "email_not_confirmed") {
        return json(403, {
          error: "E-posta doğrulaması gerekli",
          code: "EMAIL_VERIFICATION_REQUIRED",
          errorCode: "EMAIL_VERIFICATION_REQUIRED",
          username,
          maskedEmail: maskEmail(email),
          expiresAt: pendingExpiresAt,
        });
      }
      return json(401, invalidCredentials);
    }
    if (!signInData.session || signInData.user.id !== expectedUserId) {
      return json(401, invalidCredentials);
    }

    let mustChangePassword = profile?.must_change_password ?? false;
    if (pendingRegistrationKind) {
      if (signInData.user.app_metadata?.stokta_pending_registration !== pendingRegistrationKind) {
        const rejectedSessionId = sessionIdFromAccessToken(signInData.session.access_token);
        if (rejectedSessionId) {
          await admin.rpc("service_revoke_session", {
            p_user_id: expectedUserId,
            p_session_id: rejectedSessionId,
          });
        }
        return json(401, invalidCredentials);
      }
      const { data: finalized, error: finalizeError } = await admin.rpc(
        "service_finalize_pending_registration",
        { p_auth_user_id: expectedUserId, p_username: username },
      );
      if (finalizeError) {
        console.error("Confirmed pending login finalization failed", finalizeError);
        const failedSessionId = sessionIdFromAccessToken(signInData.session.access_token);
        if (failedSessionId) {
          await admin.rpc("service_revoke_session", {
            p_user_id: expectedUserId,
            p_session_id: failedSessionId,
          });
        }
        return json(409, {
          error: "E-posta doğrulandı ancak hesap kurulumu tamamlanamadı. Destek ile iletişime geçin.",
        });
      }
      mustChangePassword = Boolean(finalized?.user?.mustChangePassword);

      const cleanedMetadata = { ...signInData.user.app_metadata } as Record<string, unknown>;
      delete cleanedMetadata.stokta_pending_registration;
      delete cleanedMetadata.created_by;
      await admin.auth.admin.updateUserById(expectedUserId, { app_metadata: cleanedMetadata });
    }

    const [{ error: clearIdentityError }, { error: clearAccountError }] = await Promise.all([
      admin.rpc("clear_auth_rate_limit", {
        p_scope: "username-login",
        p_key_hash: identityHash,
      }),
      admin.rpc("clear_auth_rate_limit", {
        p_scope: "username-login-account",
        p_key_hash: accountHash,
      }),
    ]);
    if (clearIdentityError || clearAccountError) {
      console.error("Username login rate-limit cleanup failed", {
        clearIdentityError,
        clearAccountError,
      });
    }

    return json(200, {
      session: signInData.session,
      mustChangePassword,
    });
  } catch (error) {
    console.error("Username login failed", error);
    return json(500, { error: "Giriş tamamlanamadı. Lütfen tekrar deneyin." });
  }
});
