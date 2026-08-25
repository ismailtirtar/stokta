import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";

const jsonHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

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

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: jsonHeaders });
}

function normalizeUsername(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalized) ? normalized : null;
}

function normalizeSlug(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9-]{2,47}$/.test(normalized) ? normalized : null;
}

function isStrongPassword(value: string) {
  return value.length >= 8 && value.length <= 72
    && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number) {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: jsonHeaders });

  try {
    const authorization = req.headers.get("Authorization");
    const token = authorization?.replace(/^Bearer\s+/i, "");
    if (!token) return json(401, { error: "Oturum gerekli" });

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: userData, error: userError } = await admin.auth.getUser(token);
    if (userError || !userData.user) return json(401, { error: "Geçersiz oturum" });

    const { data: caller, error: callerError } = await admin
      .from("profiles")
      .select("id, is_platform_operator")
      .eq("id", userData.user.id)
      .single();
    if (callerError || !caller?.is_platform_operator) {
      return json(403, { error: "Bu işlem yalnızca Stokta platform yöneticisine açıktır" });
    }

    if (req.method === "GET") {
      const { data: organizations, error: organizationError } = await admin
        .from("organizations")
        .select("id,name,slug,subscription_status,trial_ends_at,current_period_end,max_members,max_products,created_at")
        .order("created_at", { ascending: false });
      if (organizationError) throw organizationError;

      const [{ data: profiles, error: profileError }, { data: products, error: productError }] = await Promise.all([
        admin.from("profiles").select("organization_id"),
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
      return json(200, { organization });
    }

    if (action !== "create") return json(400, { error: "Geçersiz işlem" });

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const slug = normalizeSlug(body.slug);
    const username = normalizeUsername(body.username);
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const trialDays = boundedInteger(body.trialDays, 14, 1, 365);
    const maxMembers = boundedInteger(body.maxMembers, 5, 1, 10000);
    const maxProducts = boundedInteger(body.maxProducts, 1000, 1, 1000000);

    if (name.length < 2 || name.length > 100) return json(400, { error: "İşletme adı 2-100 karakter olmalı" });
    if (!slug) return json(400, { error: "İşletme kodu 3-48 karakter olmalı; a-z, 0-9 ve tire kullanılabilir" });
    if (!username) return json(400, { error: "Yönetici kullanıcı adı geçersiz" });
    if (displayName.length < 1 || displayName.length > 80) return json(400, { error: "Yönetici adı 1-80 karakter olmalı" });
    if (!isStrongPassword(password)) {
      return json(400, { error: "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli" });
    }

    const { data: organization, error: organizationError } = await admin
      .from("organizations")
      .insert({
        name,
        slug,
        subscription_status: "trial",
        trial_ends_at: new Date(Date.now() + trialDays * 86400000).toISOString(),
        max_members: maxMembers,
        max_products: maxProducts,
        created_by: caller.id,
      })
      .select("id,name,slug,subscription_status,trial_ends_at,max_members,max_products")
      .single();
    if (organizationError || !organization) {
      return json(organizationError?.code === "23505" ? 409 : 500, {
        error: organizationError?.code === "23505" ? "Bu işletme kodu zaten kullanılıyor" : "İşletme oluşturulamadı",
      });
    }

    const email = `${username}@stokta.invalid`;
    const { data: authData, error: authError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      app_metadata: {
        provisioned_by_platform: true,
        organization_id: organization.id,
        username,
        display_name: displayName,
      },
      user_metadata: { display_name: displayName },
    });
    if (authError || !authData.user) {
      await admin.from("organizations").delete().eq("id", organization.id);
      return json(400, { error: authError?.message ?? "Yönetici giriş hesabı oluşturulamadı" });
    }

    const { error: profileError } = await admin.from("profiles").insert({
      id: authData.user.id,
      organization_id: organization.id,
      username,
      display_name: displayName,
      role: "admin",
      created_by: null,
      is_platform_operator: false,
    });
    if (profileError) {
      await admin.auth.admin.deleteUser(authData.user.id);
      await admin.from("organizations").delete().eq("id", organization.id);
      return json(profileError.code === "23505" ? 409 : 500, {
        error: profileError.code === "23505" ? "Bu kullanıcı adı zaten kullanılıyor" : "Yönetici profili oluşturulamadı",
      });
    }

    return json(201, { organization, admin: { username, displayName } });
  } catch (error) {
    console.error("Business management failed", error);
    return json(500, { error: error instanceof Error ? error.message : "Beklenmeyen hata" });
  }
});
