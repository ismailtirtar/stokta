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
  subscription_status: "trial" | "active" | "inactive" | "past_due" | "suspended" | "canceled";
  trial_ends_at: string | null;
  current_period_end: string | null;
  inactive_since: string | null;
  max_members: number;
  max_products: number;
  created_at: string;
};

type PaymentOrganization = { name: string; slug: string } | Array<{ name: string; slug: string }> | null;

function boundedInteger(value: unknown, fallback: number, min: number, max: number) {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

function cleanText(value: unknown, maxLength: number) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
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
      const [organizationResult, profileResult, productResult, settingsResult, notificationResult] = await Promise.all([
        admin
          .from("organizations")
          .select("id,name,slug,subscription_status,trial_ends_at,current_period_end,inactive_since,max_members,max_products,created_at")
          .order("created_at", { ascending: false }),
        admin.from("profiles").select("organization_id").eq("is_active", true),
        admin.from("products").select("organization_id").eq("active", true),
        admin
          .from("web_payment_settings")
          .select("id,recipient_name,bank_name,iban,amount_cents,currency,is_enabled,updated_at")
          .eq("id", 1)
          .maybeSingle(),
        admin
          .from("web_payment_notifications")
          .select("id,organization_id,sender_name,amount_cents,currency,paid_at,bank_reference,payment_reference,note,status,reviewed_at,rejection_reason,activated_until,created_at,organization:organizations!web_payment_notifications_organization_id_fkey(name,slug)")
          .order("created_at", { ascending: false })
          .limit(100),
      ]);
      if (organizationResult.error) throw organizationResult.error;
      if (profileResult.error) throw profileResult.error;
      if (productResult.error) throw productResult.error;
      if (settingsResult.error) throw settingsResult.error;
      if (notificationResult.error) throw notificationResult.error;

      const memberCounts = new Map<string, number>();
      const productCounts = new Map<string, number>();
      for (const profile of profileResult.data ?? []) {
        memberCounts.set(profile.organization_id, (memberCounts.get(profile.organization_id) ?? 0) + 1);
      }
      for (const product of productResult.data ?? []) {
        productCounts.set(product.organization_id, (productCounts.get(product.organization_id) ?? 0) + 1);
      }

      return json(200, {
        organizations: ((organizationResult.data ?? []) as Organization[]).map((organization) => ({
          ...organization,
          member_count: memberCounts.get(organization.id) ?? 0,
          product_count: productCounts.get(organization.id) ?? 0,
        })),
        paymentSettings: settingsResult.data,
        paymentNotifications: (notificationResult.data ?? []).map((notification) => {
          const relation = notification.organization as PaymentOrganization;
          const organization = Array.isArray(relation) ? relation[0] : relation;
          const { organization: _organization, ...paymentNotification } = notification;
          return {
            ...paymentNotification,
            organization_name: organization?.name ?? null,
            organization_slug: organization?.slug ?? null,
          };
        }),
      });
    }

    if (req.method !== "POST") return json(405, { error: "Yalnızca GET ve POST desteklenir" });
    const body = await req.json() as Record<string, unknown>;
    const action = typeof body.action === "string" ? body.action : "create";

    if (action === "update_web_payment_settings") {
      const recipientName = cleanText(body.recipientName, 120);
      const bankName = cleanText(body.bankName, 120);
      const iban = typeof body.iban === "string" ? body.iban.toUpperCase().replace(/\s+/g, "") : "";
      const amountCents = Number(body.amountCents);
      const isEnabled = body.isEnabled;

      if (recipientName.length < 2 || bankName.length < 2) {
        return json(400, { error: "Alıcı ve banka adı 2-120 karakter olmalı" });
      }
      if (!/^TR[0-9]{24}$/.test(iban)) {
        return json(400, { error: "Geçerli bir Türkiye IBAN’ı gerekli" });
      }
      if (!Number.isSafeInteger(amountCents) || amountCents < 100 || amountCents > 100000000) {
        return json(400, { error: "Geçerli bir aylık tutar gerekli" });
      }
      if (typeof isEnabled !== "boolean") return json(400, { error: "Geçersiz ödeme durumu" });

      const { data: paymentSettings, error: settingsError } = await admin
        .from("web_payment_settings")
        .upsert({
          id: 1,
          recipient_name: recipientName,
          bank_name: bankName,
          iban,
          amount_cents: amountCents,
          currency: "TRY",
          is_enabled: isEnabled,
          updated_by: caller.id,
          updated_at: new Date().toISOString(),
        }, { onConflict: "id" })
        .select("id,recipient_name,bank_name,iban,amount_cents,currency,is_enabled,updated_at")
        .single();
      if (settingsError) throw settingsError;

      await admin.rpc("service_record_security_event", {
        p_event_type: "web_payment.settings_updated",
        p_organization_id: null,
        p_actor_id: caller.id,
        p_metadata: { bankName, amountCents, isEnabled },
      });
      return json(200, { paymentSettings });
    }

    if (action === "review_web_payment") {
      const notificationId = typeof body.notificationId === "string" ? body.notificationId : "";
      const decision = body.decision === "approved" || body.decision === "rejected" ? body.decision : "";
      const rejectionReason = decision === "rejected" ? cleanText(body.rejectionReason, 300) : null;

      if (!isUuid(notificationId)) return json(400, { error: "Geçersiz ödeme bildirimi" });
      if (!decision) return json(400, { error: "Geçersiz ödeme kararı" });
      if (decision === "rejected" && (rejectionReason?.length ?? 0) < 3) {
        return json(400, { error: "Ret nedeni en az 3 karakter olmalı" });
      }

      const { data: review, error: reviewError } = await admin.rpc(
        "service_review_web_payment_notification",
        {
          p_notification_id: notificationId,
          p_decision: decision,
          p_reviewer_id: caller.id,
          p_rejection_reason: rejectionReason,
        },
      );
      if (reviewError) throw reviewError;

      await admin.rpc("service_record_security_event", {
        p_event_type: `web_payment.${decision}`,
        p_organization_id: review?.organization_id ?? null,
        p_actor_id: caller.id,
        p_metadata: { notificationId, decision },
      });
      return json(200, { review });
    }

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
        .select("id,name,slug,subscription_status,trial_ends_at,current_period_end,inactive_since,max_members,max_products")
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
