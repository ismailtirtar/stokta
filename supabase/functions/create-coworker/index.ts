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
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

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
      .select("id, role, organization_id")
      .eq("id", userData.user.id)
      .single();
    if (callerError || caller?.role !== "admin") {
      return json(403, { error: "Bu işlem yalnızca yöneticiye açıktır" });
    }

    const { data: organization, error: organizationError } = await admin
      .from("organizations")
      .select("id, subscription_status, trial_ends_at, current_period_end, max_members")
      .eq("id", caller.organization_id)
      .single();
    if (organizationError || !organization) return json(404, { error: "İşletme bulunamadı" });

    const now = Date.now();
    const trialExpired = organization.subscription_status === "trial"
      && (!organization.trial_ends_at || new Date(organization.trial_ends_at).getTime() <= now);
    const periodExpired = organization.subscription_status === "active"
      && organization.current_period_end
      && new Date(organization.current_period_end).getTime() <= now;
    if (trialExpired || periodExpired || !["trial", "active"].includes(organization.subscription_status)) {
      return json(403, { error: "İşletmenin kiralama durumu yeni çalışan eklemeye açık değil" });
    }

    const { count: memberCount, error: memberCountError } = await admin
      .from("profiles")
      .select("id", { count: "exact", head: true })
      .eq("organization_id", caller.organization_id);
    if (memberCountError) throw memberCountError;
    if ((memberCount ?? 0) >= organization.max_members) {
      return json(409, { error: `Kullanıcı limitine ulaşıldı (${organization.max_members})` });
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
        provisioned_by_admin: true,
        username,
        display_name: displayName,
        created_by: caller.id,
        organization_id: caller.organization_id,
      },
      user_metadata: { display_name: displayName },
    });
    if (error) return json(400, { error: error.message });

    const { error: profileError } = await admin.from("profiles").insert({
      id: data.user.id,
      organization_id: caller.organization_id,
      username,
      display_name: displayName,
      role: "member",
      created_by: caller.id,
    });
    if (profileError) {
      console.error("Coworker profile creation failed", profileError);
      const { error: cleanupError } = await admin.auth.admin.deleteUser(data.user.id);
      if (cleanupError) console.error("Coworker user cleanup failed", cleanupError);

      return json(profileError.code === "23505" ? 409 : 500, {
        error: profileError.code === "23505"
          ? "Bu kullanıcı adı zaten kullanılıyor"
          : "Çalışan profili oluşturulamadı. Lütfen tekrar deneyin.",
      });
    }

    return json(201, {
      id: data.user.id,
      username,
      displayName,
      role: "member",
    });
  } catch (error) {
    return json(500, { error: error instanceof Error ? error.message : "Beklenmeyen hata" });
  }
});
