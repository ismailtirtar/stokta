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
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalized) ? normalized : null;
}

function isStrongPassword(value: string) {
  return value.length >= 8 && value.length <= 72
    && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: jsonHeaders });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { count, error: countError } = await admin
      .from("profiles")
      .select("id", { count: "exact", head: true });
    if (countError) throw countError;
    if (req.method === "GET") {
      return json(200, { initialized: (count ?? 0) > 0 });
    }
    if (req.method !== "POST") return json(405, { error: "Yalnızca GET ve POST desteklenir" });
    if ((count ?? 0) > 0) {
      return json(409, { error: "Yönetici hesabı daha önce oluşturulmuş" });
    }

    const body = await req.json();
    const username = normalizeUsername(body.username);
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";

    if (!username) {
      return json(400, { error: "Kullanıcı adı 3-32 karakter olmalı; yalnızca a-z, 0-9, nokta, alt çizgi ve tire kullanılabilir" });
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return json(400, { error: "Görünen ad 1-80 karakter olmalı" });
    }
    if (!isStrongPassword(password)) {
      return json(400, { error: "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli" });
    }

    const email = `${username}@stokta.invalid`;
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      app_metadata: {
        bootstrap_admin: true,
        platform_operator: true,
        username,
        display_name: displayName,
      },
      user_metadata: { display_name: displayName },
    });
    if (error) return json(400, { error: error.message });

    const organizationSlug = `${username}-isletmesi`.slice(0, 48);
    const { data: organization, error: organizationError } = await admin
      .from("organizations")
      .insert({
        name: `${displayName} İşletmesi`.slice(0, 100),
        slug: organizationSlug,
        subscription_status: "active",
        max_members: 25,
        max_products: 10000,
        created_by: data.user.id,
      })
      .select("id")
      .single();
    if (organizationError || !organization) {
      console.error("Bootstrap organization creation failed", organizationError);
      await admin.auth.admin.deleteUser(data.user.id);
      return json(500, { error: "İlk işletme oluşturulamadı. Lütfen tekrar deneyin." });
    }

    const { error: profileError } = await admin.from("profiles").insert({
      id: data.user.id,
      organization_id: organization.id,
      username,
      display_name: displayName,
      role: "admin",
      created_by: null,
      is_platform_operator: true,
    });
    if (profileError) {
      console.error("Bootstrap profile creation failed", profileError);
      const { error: organizationCleanupError } = await admin
        .from("organizations")
        .delete()
        .eq("id", organization.id);
      if (organizationCleanupError) console.error("Bootstrap organization cleanup failed", organizationCleanupError);
      const { error: cleanupError } = await admin.auth.admin.deleteUser(data.user.id);
      if (cleanupError) console.error("Bootstrap user cleanup failed", cleanupError);

      return json(profileError.code === "23505" ? 409 : 500, {
        error: profileError.code === "23505"
          ? "Yönetici hesabı daha önce oluşturulmuş"
          : "Yönetici profili oluşturulamadı. Lütfen tekrar deneyin.",
      });
    }

    return json(201, {
      id: data.user.id,
      username,
      displayName,
      role: "admin",
      organizationId: organization.id,
    });
  } catch (error) {
    return json(500, { error: error instanceof Error ? error.message : "Beklenmeyen hata" });
  }
});
