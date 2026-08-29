import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  json,
  normalizeRecoveryEmail,
  normalizeUsername,
  randomOpaqueToken,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const invalidCode = { error: "Şifre yenileme kodu geçersiz veya süresi dolmuş" };

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
    const username = normalizeUsername(identifierValue);
    const recoveryEmail = username ? null : normalizeRecoveryEmail(identifierValue);
    const code = typeof body.code === "string" ? body.code.trim() : "";
    const normalizedIdentifier = username ?? recoveryEmail ?? "invalid";
    const ip = requestIp(req);
    const [identityHash, accountHash, ipHash] = await Promise.all([
      sha256(`stokta:verify-reset:v2:${ip}:${normalizedIdentifier}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:verify-reset-account:v2:${normalizedIdentifier}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:verify-reset-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`),
    ]);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const limits = await Promise.all([
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "verify-reset",
        p_key_hash: identityHash,
        p_max_attempts: 6,
        p_window_seconds: 900,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "verify-reset-account",
        p_key_hash: accountHash,
        p_max_attempts: 8,
        p_window_seconds: 900,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "verify-reset-ip",
        p_key_hash: ipHash,
        p_max_attempts: 30,
        p_window_seconds: 900,
      }),
    ]);
    if (limits.some((limit) => limit.error)) {
      console.error("Password reset verification rate limiter unavailable");
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    if (limits.some((limit) => limit.data !== true)) {
      return json(429, { error: "Çok fazla kod denemesi yapıldı. Lütfen daha sonra tekrar deneyin." });
    }

    if ((!username && !recoveryEmail) || !/^[0-9]{6,10}$/.test(code)) {
      return json(401, invalidCode);
    }

    let profileQuery = admin
      .from("profiles")
      .select("id,organization_id,recovery_email")
      .eq("is_active", true)
      .not("recovery_email", "is", null)
      .not("recovery_email_verified_at", "is", null);
    profileQuery = username
      ? profileQuery.eq("username", username)
      : profileQuery.eq("recovery_email", recoveryEmail as string);
    const { data: profile, error: profileError } = await profileQuery.maybeSingle();
    if (profileError) {
      console.error("Password reset verification profile lookup failed", profileError);
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    if (!profile) return json(401, invalidCode);

    const { data: userData, error: userError } = await admin.auth.admin.getUserById(profile.id);
    const email = userData.user?.email?.toLowerCase();
    if (userError
      || !email
      || email.endsWith("@stokta.invalid")
      || email !== profile.recovery_email) return json(401, invalidCode);

    const { data: verificationData, error: verificationError } = await authClient.auth.verifyOtp({
      email,
      token: code,
      type: "recovery",
    });
    if (verificationError
      || !verificationData.session
      || verificationData.user?.id !== profile.id) {
      return json(401, invalidCode);
    }

    const recoverySessionId = sessionIdFromAccessToken(verificationData.session.access_token);
    if (!recoverySessionId) {
      console.error("Recovery OTP session did not contain a session_id claim");
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    const { data: recoveryRevoked, error: recoveryRevokeError } = await admin.rpc(
      "service_revoke_session",
      { p_user_id: profile.id, p_session_id: recoverySessionId },
    );
    if (recoveryRevokeError || !recoveryRevoked) {
      console.error("Server-side recovery session revocation failed", recoveryRevokeError);
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }

    const resetTicket = randomOpaqueToken();
    const ticketHash = await sha256(
      `stokta:reset-ticket:v1:${resetTicket}:${supabaseUrl}:${serviceRoleKey}`,
    );
    const { error: staleTicketError } = await admin
      .from("password_reset_challenges")
      .delete()
      .eq("user_id", profile.id)
      .is("consumed_at", null);
    if (staleTicketError) {
      console.error("Previous password reset ticket cleanup failed", staleTicketError);
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    const { error: ticketError } = await admin.from("password_reset_challenges").insert({
      ticket_hash: ticketHash,
      user_id: profile.id,
      organization_id: profile.organization_id,
    });
    if (ticketError) {
      console.error("Password reset ticket could not be stored", ticketError);
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }

    await Promise.all([
      admin.rpc("clear_auth_rate_limit", { p_scope: "verify-reset", p_key_hash: identityHash }),
      admin.rpc("clear_auth_rate_limit", { p_scope: "verify-reset-account", p_key_hash: accountHash }),
      admin.rpc("service_record_security_event", {
        p_event_type: "password.reset_code_verified",
        p_organization_id: profile.organization_id,
        p_subject_id: profile.id,
        p_ip_hash: ipHash,
      }),
    ]);

    return json(200, { verified: true, resetTicket, expiresIn: 600 });
  } catch (error) {
    console.error("Password reset code verification failed", error);
    return json(500, { error: "Şifre yenileme kodu doğrulanamadı" });
  }
});
