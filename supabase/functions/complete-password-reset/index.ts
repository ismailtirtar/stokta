import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  isStrongPassword,
  json,
  requestIp,
  sha256,
} from "../_shared/security.ts";

type ResetClaim = {
  userId: string;
  organizationId: string;
};

const invalidTicket = { error: "Şifre yenileme isteği geçersiz veya süresi dolmuş" };

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const body = await req.json() as Record<string, unknown>;
    const resetTicket = typeof body.resetTicket === "string" ? body.resetTicket.trim() : "";
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
    if (!/^[A-Za-z0-9_-]{43}$/.test(resetTicket)) return json(401, invalidTicket);
    if (!isStrongPassword(newPassword)) {
      return json(400, {
        error: "Yeni şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli",
      });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const ip = requestIp(req);
    const [ticketHash, ipHash] = await Promise.all([
      sha256(`stokta:reset-ticket:v1:${resetTicket}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:complete-reset-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`),
    ]);

    const [{ data: ticketAllowed, error: ticketRateError }, { data: ipAllowed, error: ipRateError }] =
      await Promise.all([
        admin.rpc("consume_auth_rate_limit", {
          p_scope: "complete-password-reset-ticket",
          p_key_hash: ticketHash,
          p_max_attempts: 3,
          p_window_seconds: 900,
        }),
        admin.rpc("consume_auth_rate_limit", {
          p_scope: "complete-password-reset-ip",
          p_key_hash: ipHash,
          p_max_attempts: 30,
          p_window_seconds: 900,
        }),
      ]);
    if (ticketRateError || ipRateError) {
      console.error("Password reset completion rate limiter unavailable", {
        ticketRateError,
        ipRateError,
      });
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    if (!ticketAllowed || !ipAllowed) {
      return json(429, { error: "Çok fazla şifre yenileme denemesi yapıldı" });
    }

    const { data: claimData, error: claimError } = await admin.rpc(
      "service_claim_password_reset",
      { p_ticket_hash: ticketHash },
    );
    if (claimError) {
      console.error("Password reset ticket claim failed", claimError);
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    const claim = claimData as ResetClaim | null;
    if (!claim?.userId || !claim.organizationId) return json(401, invalidTicket);

    const { data: profile, error: profileError } = await admin
      .from("profiles")
      .select("id")
      .eq("id", claim.userId)
      .eq("organization_id", claim.organizationId)
      .eq("is_active", true)
      .maybeSingle();
    if (profileError) {
      console.error("Password reset profile validation failed", profileError);
      return json(503, { error: "Şifre kurtarma hizmeti şu anda kullanılamıyor" });
    }
    if (!profile) return json(401, invalidTicket);

    const { error: preChangeRevokeError } = await admin.rpc(
      "service_revoke_user_sessions",
      { p_user_id: claim.userId, p_except_session_id: null },
    );
    if (preChangeRevokeError) {
      console.error("Password reset pre-update session revocation failed", preChangeRevokeError);
      return json(503, {
        error: "Açık oturumlar güvenli biçimde kapatılamadı; şifre değiştirilmedi. Yeni bir kod isteyin.",
      });
    }

    const { error: passwordError } = await admin.auth.admin.updateUserById(claim.userId, {
      password: newPassword,
    });
    if (passwordError) {
      console.error("Password reset Auth update failed", passwordError);
      return json(400, { error: "Yeni şifre kaydedilemedi. Yeni bir kod isteyin." });
    }

    const { error: completionError } = await admin.rpc("service_complete_password_change", {
      p_user_id: claim.userId,
    });
    if (completionError) {
      console.error("Password reset session revocation failed", completionError);
      return json(500, {
        error: "Şifre değişti ancak oturum güvenliği tamamlanamadı. Destek ile iletişime geçin.",
      });
    }

    await admin.rpc("service_record_security_event", {
      p_event_type: "password.reset_completed",
      p_organization_id: claim.organizationId,
      p_subject_id: claim.userId,
      p_ip_hash: ipHash,
    });

    return json(200, { updated: true, reauthenticationRequired: true });
  } catch (error) {
    console.error("Password reset completion failed", error);
    return json(500, { error: "Şifre yenileme tamamlanamadı" });
  }
});
