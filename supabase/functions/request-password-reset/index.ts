import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  json,
  normalizeRecoveryEmail,
  normalizeUsername,
  readJsonObject,
  requestBodyErrorResponse,
  requestIp,
  sha256,
} from "../_shared/security.ts";

const acceptedResponse = {
  accepted: true,
  message:
    "Bu hesapta doğrulanmış e-posta varsa şifre yenileme kodu gönderildi.",
};

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
    const identifierValue = typeof body.identifier === "string"
      ? body.identifier
      : typeof body.username === "string"
      ? body.username
      : "";
    const username = normalizeUsername(identifierValue);
    const recoveryEmail = username
      ? null
      : normalizeRecoveryEmail(identifierValue);
    const normalizedIdentifier = username ?? recoveryEmail ?? "invalid";
    const ip = requestIp(req);
    const [identityHash, accountHash, ipHash] = await Promise.all([
      sha256(
        `stokta:password-reset:v2:${ip}:${normalizedIdentifier}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:password-reset-account:v2:${normalizedIdentifier}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:password-reset-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`,
      ),
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
    ] = await Promise.all([
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "password-reset",
        p_key_hash: identityHash,
        p_max_attempts: 3,
        p_window_seconds: 3600,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "password-reset-account",
        p_key_hash: accountHash,
        p_max_attempts: 3,
        p_window_seconds: 3600,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "password-reset-ip",
        p_key_hash: ipHash,
        p_max_attempts: 20,
        p_window_seconds: 3600,
      }),
    ]);
    if (identityRateError || accountRateError || ipRateError) {
      console.error("Password reset rate limiter unavailable", {
        identityRateError,
        accountRateError,
        ipRateError,
      });
      return json(503, {
        error: "Şifre kurtarma hizmeti şu anda kullanılamıyor",
      });
    }
    if (!identityAllowed || !accountAllowed || !ipAllowed) {
      return json(429, {
        error: "Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.",
      });
    }

    if (!username && !recoveryEmail) return json(202, acceptedResponse);

    let profileQuery = admin
      .from("profiles")
      .select("id,organization_id,recovery_email,recovery_email_verified_at")
      .eq("is_active", true)
      .not("recovery_email", "is", null)
      .not("recovery_email_verified_at", "is", null);
    profileQuery = username
      ? profileQuery.eq("username", username)
      : profileQuery.eq("recovery_email", recoveryEmail as string);
    const { data: profile, error: profileError } = await profileQuery
      .maybeSingle();
    if (profileError) {
      console.error("Password reset profile lookup failed", profileError);
      return json(202, acceptedResponse);
    }
    if (!profile?.id) return json(202, acceptedResponse);

    const { data: authUserData, error: authUserError } = await admin.auth.admin
      .getUserById(profile.id);
    const email = authUserData.user?.email?.toLowerCase();
    if (
      authUserError ||
      !email ||
      email.endsWith("@stokta.invalid") ||
      email !== profile.recovery_email
    ) {
      if (authUserError) {
        console.error("Password reset identity lookup failed", authUserError);
      }
      return json(202, acceptedResponse);
    }

    // The Recovery email template must contain {{ .Token }}. No custom URL or
    // bearer token is placed in the message.
    const { error: resetError } = await authClient.auth.resetPasswordForEmail(
      email,
    );
    if (resetError) {
      console.error("Password reset email request failed", resetError);
    }

    await admin.rpc("service_record_security_event", {
      p_event_type: "password.reset_requested",
      p_organization_id: profile.organization_id,
      p_subject_id: profile.id,
      p_ip_hash: ipHash,
      p_metadata: { deliveryAccepted: !resetError },
    });

    return json(202, acceptedResponse);
  } catch (error) {
    const inputError = requestBodyErrorResponse(error);
    if (inputError) return inputError;
    console.error("Password reset request failed", error);
    return json(202, acceptedResponse);
  }
});
