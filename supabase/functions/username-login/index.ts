import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  json,
  maskEmail,
  normalizeRecoveryEmail,
  normalizeUsername,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const invalidCredentials = { error: "Kullanıcı adı, e-posta veya şifre hatalı" };

type SupabaseErrorLike = {
  code?: string;
  message?: string;
  name?: string;
  status?: number;
};

type SupabaseResultLike = {
  error: unknown | null;
  status?: number;
};

function isTransientSupabaseError(error: unknown, responseStatus?: number) {
  if (!error) return false;

  const candidate = error as SupabaseErrorLike;
  const status = responseStatus ?? candidate.status;
  if (status === 408 || status === 425 || (typeof status === "number" && status >= 500)) {
    return true;
  }
  if (candidate.name === "AuthRetryableFetchError" || candidate.name === "AuthUnknownError") {
    return true;
  }

  const diagnostic = `${candidate.code ?? ""} ${candidate.message ?? ""}`.toLowerCase();
  return /\b(network|fetch|timeout|timed out|connection|gateway)\b/.test(diagnostic);
}

async function retryTransientSupabaseOperation<T extends SupabaseResultLike>(
  operation: () => Promise<T>,
) {
  const firstResult = await operation();
  if (!isTransientSupabaseError(firstResult.error, firstResult.status)) return firstResult;

  await new Promise((resolve) => setTimeout(resolve, 350));
  return operation();
}

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
    const identifierValue = typeof body.identifier === "string"
      ? body.identifier
      : typeof body.username === "string"
      ? body.username
      : "";
    const identifierLooksLikeEmail = identifierValue.includes("@");
    const recoveryEmail = identifierLooksLikeEmail ? normalizeRecoveryEmail(identifierValue) : null;
    const username = identifierLooksLikeEmail ? null : normalizeUsername(identifierValue);
    const password = typeof body.password === "string" ? body.password : "";
    const normalizedIdentifier = username ?? recoveryEmail ?? "invalid";
    const ip = requestIp(req);
    const [identityHash, ipHash] = await Promise.all([
      sha256(`stokta:login:v1:${ip}:${normalizedIdentifier}:${supabaseUrl}:${serviceRoleKey}`),
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
          p_scope: "username-login-ip",
          p_key_hash: ipHash,
          p_max_attempts: 60,
          p_window_seconds: 900,
        }),
      ]);
    if (identityRateError || ipRateError) {
      console.error("Username login rate limiter unavailable", {
        identityRateError,
        ipRateError,
      });
      return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
    }
    if (!identityAllowed || !ipAllowed) {
      return json(429, { error: "Çok fazla giriş denemesi yapıldı. Lütfen daha sonra tekrar deneyin." });
    }

    if ((!username && !recoveryEmail) || password.length < 1 || password.length > 72) {
      return json(401, invalidCredentials);
    }

    let profileQuery = admin
      .from("profiles")
      .select("id,username,must_change_password,recovery_email,recovery_email_verified_at")
      .eq("is_active", true);
    profileQuery = username
      ? profileQuery.eq("username", username)
      : profileQuery
        .eq("recovery_email", recoveryEmail as string)
        .not("recovery_email_verified_at", "is", null);
    const { data: profile, error: profileError } = await retryTransientSupabaseOperation(() =>
      profileQuery.maybeSingle()
    );
    if (profileError) {
      console.error("Username lookup failed", profileError);
      return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
    }
    let email: string | null = null;
    let expectedUserId: string | null = null;
    let resolvedUsername = profile?.username ?? username ?? "";
    let pendingRegistrationKind: string | null = null;
    let pendingExpiresAt: string | null = null;

    if (profile?.id) {
      const verifiedRecoveryEmail = profile.recovery_email_verified_at
        ? profile.recovery_email?.trim().toLowerCase() ?? ""
        : "";

      if (verifiedRecoveryEmail) {
        email = verifiedRecoveryEmail;
      } else {
        const { data: authUserData, error: authUserError } =
          await retryTransientSupabaseOperation(() => admin.auth.admin.getUserById(profile.id));
        email = authUserData.user?.email ?? "";
        if (authUserError) {
          console.error("Username auth identity lookup failed", authUserError);
          return json(
            isTransientSupabaseError(authUserError) ? 503 : 401,
            isTransientSupabaseError(authUserError)
              ? { error: "Giriş hizmeti şu anda kullanılamıyor" }
              : invalidCredentials,
          );
        }
        if (!email) return json(401, invalidCredentials);
      }
      expectedUserId = profile.id;
    } else {
      let pendingQuery = admin
        .from("pending_account_registrations")
        .select("auth_user_id,registration_kind,email,expires_at,username");
      pendingQuery = username
        ? pendingQuery.eq("username", username)
        : pendingQuery.eq("email", recoveryEmail as string);
      const { data: pending, error: pendingError } = await pendingQuery.maybeSingle();
      if (pendingError) {
        console.error("Pending registration lookup failed", pendingError);
        return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
      }
      if (pending && new Date(pending.expires_at).getTime() > Date.now()) {
        email = pending.email;
        expectedUserId = pending.auth_user_id;
        resolvedUsername = pending.username;
        pendingRegistrationKind = pending.registration_kind;
        pendingExpiresAt = pending.expires_at;
      }
    }

    const accountHash = await sha256(
      `stokta:login-account:v2:${expectedUserId ?? `unknown:${normalizedIdentifier}`}:${supabaseUrl}:${serviceRoleKey}`,
    );
    const { data: accountAllowed, error: accountRateError } = await admin.rpc(
      "consume_auth_rate_limit",
      {
        p_scope: "username-login-account",
        p_key_hash: accountHash,
        p_max_attempts: 12,
        p_window_seconds: 900,
      },
    );
    if (accountRateError) {
      console.error("Username login account rate limiter unavailable", accountRateError);
      return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
    }
    if (!accountAllowed) {
      return json(401, invalidCredentials);
    }
    if (!expectedUserId || !email) return json(401, invalidCredentials);

    const { data: signInData, error: signInError } =
      await retryTransientSupabaseOperation(() => authClient.auth.signInWithPassword({
        email,
        password,
      }));
    if (signInError) {
      if (pendingRegistrationKind && signInError.code === "email_not_confirmed") {
        return json(403, {
          error: "E-posta doğrulaması gerekli",
          code: "EMAIL_VERIFICATION_REQUIRED",
          errorCode: "EMAIL_VERIFICATION_REQUIRED",
          username: resolvedUsername,
          maskedEmail: maskEmail(email),
          expiresAt: pendingExpiresAt,
        });
      }
      if (isTransientSupabaseError(signInError)) {
        console.error("Username password sign-in temporarily unavailable", signInError);
        return json(503, { error: "Giriş hizmeti şu anda kullanılamıyor" });
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
        { p_auth_user_id: expectedUserId, p_username: resolvedUsername },
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
