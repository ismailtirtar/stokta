import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  json,
  maskEmail,
  normalizeUsername,
  readJsonObject,
  requestBodyErrorResponse,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const invalidCredentials = { error: "Kullanıcı adı veya geçici şifre hatalı" };

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

    const body = await readJsonObject(req, 8 * 1024);
    const username = normalizeUsername(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    const rateUsername = username ?? "invalid";
    const ip = requestIp(req);
    const [accountHash, ipHash] = await Promise.all([
      sha256(
        `stokta:resend-email-account:v1:${rateUsername}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:resend-email-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`,
      ),
    ]);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const [
      { data: accountAllowed, error: accountRateError },
      { data: ipAllowed, error: ipRateError },
    ] = await Promise.all([
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "resend-email-account",
        p_key_hash: accountHash,
        p_max_attempts: 3,
        p_window_seconds: 3600,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "resend-email-ip",
        p_key_hash: ipHash,
        p_max_attempts: 20,
        p_window_seconds: 3600,
      }),
    ]);
    if (accountRateError || ipRateError) {
      console.error("Email resend rate limiter unavailable", {
        accountRateError,
        ipRateError,
      });
      return json(503, { error: "Doğrulama hizmeti şu anda kullanılamıyor" });
    }
    if (!accountAllowed || !ipAllowed) {
      return json(429, { error: "Çok fazla kod gönderme isteği yapıldı" });
    }

    if (!username || password.length < 1 || password.length > 72) {
      return json(401, invalidCredentials);
    }
    const { data: pending, error: pendingError } = await admin
      .from("pending_account_registrations")
      .select("auth_user_id,email,expires_at,cleanup_claimed_at")
      .eq("username", username)
      .maybeSingle();
    if (pendingError) {
      console.error("Pending email resend lookup failed", pendingError);
      return json(503, { error: "Doğrulama hizmeti şu anda kullanılamıyor" });
    }
    if (
      !pending ||
      pending.cleanup_claimed_at ||
      new Date(pending.expires_at).getTime() <= Date.now()
    ) {
      return json(401, invalidCredentials);
    }

    const { data: signInData, error: signInError } = await authClient.auth
      .signInWithPassword({
        email: pending.email,
        password,
      });
    if (signInData.session) {
      const verifiedSessionId = sessionIdFromAccessToken(
        signInData.session.access_token,
      );
      if (verifiedSessionId) {
        await admin.rpc("service_revoke_session", {
          p_user_id: pending.auth_user_id,
          p_session_id: verifiedSessionId,
        });
      }
      return json(409, {
        error:
          "E-posta zaten doğrulanmış. Kullanıcı adı ve şifrenizle giriş yapın.",
        code: "EMAIL_ALREADY_VERIFIED",
      });
    }
    if (signInError?.code !== "email_not_confirmed") {
      return json(401, invalidCredentials);
    }

    const { error: resendError } = await authClient.auth.resend({
      type: "signup",
      email: pending.email,
    });
    if (resendError) {
      console.error("Signup verification code resend failed", resendError);
      if (resendError.code === "over_email_send_rate_limit") {
        return json(429, { error: "Yeni kod göndermek için biraz bekleyin" });
      }
      return json(503, { error: "Doğrulama kodu gönderilemedi" });
    }

    await admin.rpc("service_record_security_event", {
      p_event_type: "email.verification_resent",
      p_subject_id: pending.auth_user_id,
      p_ip_hash: ipHash,
      p_metadata: { username },
    });

    return json(202, {
      accepted: true,
      maskedEmail: maskEmail(pending.email),
      message: "Yeni doğrulama kodu e-postanıza gönderildi.",
    });
  } catch (error) {
    const inputError = requestBodyErrorResponse(error);
    if (inputError) return inputError;
    console.error("Email verification resend failed", error);
    return json(500, { error: "Doğrulama kodu gönderilemedi" });
  }
});
