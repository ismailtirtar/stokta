import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  json,
  sessionIdFromAccessToken,
} from "../_shared/security.ts";

type Organization = {
  id: string;
  name: string;
  slug: string;
  subscription_status: "trial" | "active" | "past_due" | "suspended" | "canceled";
  trial_ends_at: string | null;
  current_period_end: string | null;
  max_members: number;
  max_products: number;
  created_at: string;
};

function boundedInteger(value: unknown, fallback: number, min: number, max: number) {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });

  try {
    const token = bearerToken(req);
    if (!token) return json(401, { error: "Oturum gerekli" });

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: userData, error: userError } = await admin.auth.getUser(token);
    if (userError || !userData.user) return json(401, { error: "Geçersiz oturum" });
    const { data: claimsData, error: claimsError } = await admin.auth.getClaims(token);
    if (claimsError || !claimsData?.claims || claimsData.claims.sub !== userData.user.id) {
      return json(401, { error: "Geçersiz oturum" });
    }
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc("service_has_live_session", {
      p_user_id: userData.user.id,
      p_session_id: sessionId,
    });
    if (liveSessionError || !liveSession) return json(401, { error: "Oturum sona erdi" });

    const { data: caller, error: callerError } = await admin
      .from("profiles")
      .select("id,is_platform_operator,must_change_password")
      .eq("id", userData.user.id)
      .eq("is_active", true)
      .maybeSingle();
    if (callerError || !caller?.is_platform_operator || caller.must_change_password) {
      return json(403, { error: "Bu işlem yalnızca Stokdaş platform yöneticisine açıktır" });
    }
    const hasVerifiedTotp = userData.user.factors?.some((factor) =>
      factor.factor_type === "totp" && factor.status === "verified"
    ) ?? false;
    if (!hasVerifiedTotp) {
      return json(403, {
        error: "Platform yönetimi için doğrulanmış bir TOTP faktörü gerekli",
        code: "MFA_ENROLLMENT_REQUIRED",
      });
    }
    if (claimsData.claims.aal !== "aal2") {
      return json(403, {
        error: "Platform yönetimi için iki adımlı doğrulama gerekli",
        code: "MFA_REQUIRED",
      });
    }
    const hasTotpAmr = Array.isArray(claimsData.claims.amr)
      && claimsData.claims.amr.some((entry) => {
        const method = typeof entry === "string" ? entry : entry?.method;
        return method === "totp" || method === "mfa/totp";
      });
    if (!hasTotpAmr) {
      return json(403, {
        error: "Bu oturum TOTP ile doğrulanmalıdır",
        code: "TOTP_VERIFICATION_REQUIRED",
      });
    }
    const { data: liveTotpSession, error: liveTotpSessionError } = await admin.rpc(
      "service_has_live_totp_aal2_session",
      { p_user_id: userData.user.id, p_session_id: sessionId },
    );
    if (liveTotpSessionError || !liveTotpSession) {
      return json(403, {
        error: "TOTP ile doğrulanmış canlı AAL2 oturumu gerekli",
        code: "TOTP_SESSION_REQUIRED",
      });
    }

    if (req.method === "GET") {
      const { data: organizations, error: organizationError } = await admin
        .from("organizations")
        .select("id,name,slug,subscription_status,trial_ends_at,current_period_end,max_members,max_products,created_at")
        .order("created_at", { ascending: false });
      if (organizationError) throw organizationError;

      const [{ data: profiles, error: profileError }, { data: products, error: productError }] = await Promise.all([
        admin.from("profiles").select("organization_id").eq("is_active", true),
        admin.from("products").select("organization_id").eq("active", true),
      ]);
      if (profileError) throw profileError;
      if (productError) throw productError;

      const memberCounts = new Map<string, number>();
      const productCounts = new Map<string, number>();
      for (const profile of profiles ?? []) {
        memberCounts.set(profile.organization_id, (memberCounts.get(profile.organization_id) ?? 0) + 1);
      }
      for (const product of products ?? []) {
        productCounts.set(product.organization_id, (productCounts.get(product.organization_id) ?? 0) + 1);
      }

      return json(200, {
        organizations: ((organizations ?? []) as Organization[]).map((organization) => ({
          ...organization,
          member_count: memberCounts.get(organization.id) ?? 0,
          product_count: productCounts.get(organization.id) ?? 0,
        })),
      });
    }

    if (req.method !== "POST") return json(405, { error: "Yalnızca GET ve POST desteklenir" });
    const body = await req.json() as Record<string, unknown>;
    const action = typeof body.action === "string" ? body.action : "create";

    if (action === "update_subscription") {
      const organizationId = typeof body.organizationId === "string" ? body.organizationId : "";
      const status = typeof body.status === "string" ? body.status : "";
      if (!/^[0-9a-f-]{36}$/i.test(organizationId)) return json(400, { error: "Geçersiz işletme" });
      if (!["trial", "active", "past_due", "suspended", "canceled"].includes(status)) {
        return json(400, { error: "Geçersiz abonelik durumu" });
      }

      const maxMembers = boundedInteger(body.maxMembers, 5, 1, 10000);
      const maxProducts = boundedInteger(body.maxProducts, 1000, 1, 1000000);
      const periodDays = boundedInteger(body.periodDays, 30, 1, 3660);
      const update: Record<string, unknown> = {
        subscription_status: status,
        max_members: maxMembers,
        max_products: maxProducts,
        updated_at: new Date().toISOString(),
      };
      if (status === "trial") {
        update.trial_ends_at = new Date(Date.now() + periodDays * 86400000).toISOString();
        update.current_period_end = null;
      } else if (status === "active") {
        update.current_period_end = new Date(Date.now() + periodDays * 86400000).toISOString();
        update.trial_ends_at = null;
      } else {
        update.current_period_end = null;
      }

      const { data: organization, error: updateError } = await admin
        .from("organizations")
        .update(update)
        .eq("id", organizationId)
        .select("id,name,slug,subscription_status,trial_ends_at,current_period_end,max_members,max_products")
        .single();
      if (updateError) throw updateError;
      await admin.rpc("service_record_security_event", {
        p_event_type: "organization.subscription_updated",
        p_organization_id: organizationId,
        p_actor_id: caller.id,
        p_metadata: { status, maxMembers, maxProducts, periodDays },
      });
      return json(200, { organization });
    }

    if (action === "create") {
      return json(410, {
        error: "Yeni işletmeler yalnız e-posta doğrulamalı kayıt ekranından oluşturulabilir",
        code: "BUSINESS_CREATION_SELF_SERVICE_ONLY",
      });
    }
    return json(400, { error: "Geçersiz işlem" });
  } catch (error) {
    console.error("Business management failed", error);
    return json(500, { error: "İşletme yönetimi işlemi tamamlanamadı" });
  }
});
