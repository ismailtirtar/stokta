import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";

const jsonHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: jsonHeaders });
}

function normalizeUsername(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value
    .trim()
    .toLocaleLowerCase("tr-TR")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ı/g, "i");
  return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalized) ? normalized : null;
}

function slugBase(value: string) {
  return value
    .trim()
    .toLocaleLowerCase("tr-TR")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ı/g, "i")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 38) || "isletme";
}

function isStrongPassword(value: string) {
  return value.length >= 8 && value.length <= 72
    && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requestIp(req: Request) {
  return req.headers.get("cf-connecting-ip")
    ?? req.headers.get("x-real-ip")
    ?? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    ?? "unknown";
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: jsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });

    const body = await req.json() as Record<string, unknown>;
    const organizationName = typeof body.organizationName === "string" ? body.organizationName.trim() : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const username = normalizeUsername(body.username);
    const password = typeof body.password === "string" ? body.password : "";

    if (organizationName.length < 2 || organizationName.length > 100) {
      return json(400, { error: "İşletme adı 2-100 karakter olmalı" });
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return json(400, { error: "Ad ve soyad 1-80 karakter olmalı" });
    }
    if (!username) {
      return json(400, { error: "Kullanıcı adı 3-32 karakter olmalı; yalnızca a-z, 0-9, nokta, alt çizgi ve tire kullanılabilir" });
    }
    if (!isStrongPassword(password)) {
      return json(400, { error: "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli" });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const keyHash = await sha256(`stokta:self-register:v1:${requestIp(req)}:${supabaseUrl}`);
    const { data: allowed, error: rateLimitError } = await admin.rpc("consume_signup_rate_limit", {
      p_key_hash: keyHash,
    });
    if (rateLimitError) {
      console.error("Registration rate limit failed", rateLimitError);
      return json(503, { error: "Kayıt hizmeti şu anda kullanılamıyor. Lütfen daha sonra tekrar deneyin." });
    }
    if (!allowed) {
      return json(429, { error: "Çok fazla kayıt denemesi yapıldı. Bir saat sonra tekrar deneyin." });
    }

    const email = `${username}@stokta.invalid`;
    const { data: authData, error: authError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      app_metadata: {
        self_registered: true,
        username,
        display_name: displayName,
      },
      user_metadata: { display_name: displayName },
    });
    if (authError || !authData.user) {
      const alreadyExists = authError?.message.toLowerCase().includes("already")
        || authError?.message.toLowerCase().includes("registered");
      return json(alreadyExists ? 409 : 400, {
        error: alreadyExists ? "Bu kullanıcı adı zaten kullanılıyor" : (authError?.message ?? "Giriş hesabı oluşturulamadı"),
      });
    }

    const organizationSlug = `${slugBase(organizationName)}-${crypto.randomUUID().slice(0, 8)}`.slice(0, 48);
    const { data: organization, error: organizationError } = await admin
      .from("organizations")
      .insert({
        name: organizationName,
        slug: organizationSlug,
        subscription_status: "trial",
        trial_ends_at: new Date(Date.now() + 14 * 86400000).toISOString(),
        max_members: 5,
        max_products: 1000,
        created_by: authData.user.id,
      })
      .select("id,name,trial_ends_at,max_members,max_products")
      .single();
    if (organizationError || !organization) {
      console.error("Self-service organization creation failed", organizationError);
      await admin.auth.admin.deleteUser(authData.user.id);
      return json(500, { error: "İşletme oluşturulamadı. Lütfen tekrar deneyin." });
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
      console.error("Self-service admin profile creation failed", profileError);
      await admin.from("organizations").delete().eq("id", organization.id);
      await admin.auth.admin.deleteUser(authData.user.id);
      return json(profileError.code === "23505" ? 409 : 500, {
        error: profileError.code === "23505"
          ? "Bu kullanıcı adı zaten kullanılıyor"
          : "Yönetici hesabı tamamlanamadı. Lütfen tekrar deneyin.",
      });
    }

    return json(201, {
      organization: {
        id: organization.id,
        name: organization.name,
        trialEndsAt: organization.trial_ends_at,
        maxMembers: organization.max_members,
        maxProducts: organization.max_products,
      },
      admin: { id: authData.user.id, username, displayName },
    });
  } catch (error) {
    console.error("Self-service registration failed", error);
    return json(500, { error: "Kayıt tamamlanamadı. Lütfen tekrar deneyin." });
  }
});

