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
      .select("id, username, role, organization_id, is_platform_operator")
      .eq("id", userData.user.id)
      .single();
    if (callerError || !caller) return json(404, { error: "Kullanıcı profili bulunamadı" });
    if (caller.is_platform_operator) {
      return json(403, { error: "Platform yöneticisi hesabı uygulama içinden silinemez" });
    }

    const body = await req.json() as { confirmation?: unknown };
    const confirmation = typeof body.confirmation === "string" ? body.confirmation.trim() : "";
    const expectedConfirmation = caller.role === "admin" ? "STOKDAŞ" : caller.username;
    const isValidConfirmation = caller.role === "admin"
      ? confirmation === expectedConfirmation || confirmation === "STOKTA"
      : confirmation === expectedConfirmation;
    if (!isValidConfirmation) {
      return json(400, { error: `Onay alanına ${expectedConfirmation} yazılmalı` });
    }

    if (caller.role === "admin") {
      const { data: profiles, error: profilesError } = await admin
        .from("profiles")
        .select("id")
        .eq("organization_id", caller.organization_id);
      if (profilesError) throw profilesError;

      const { error: movementError } = await admin
        .from("stock_movements")
        .delete()
        .eq("organization_id", caller.organization_id);
      if (movementError) throw movementError;
      const { error: productError } = await admin
        .from("products")
        .delete()
        .eq("organization_id", caller.organization_id);
      if (productError) throw productError;
      const { error: unlinkProfilesError } = await admin
        .from("profiles")
        .update({ created_by: null })
        .eq("organization_id", caller.organization_id);
      if (unlinkProfilesError) throw unlinkProfilesError;
      const { error: profileError } = await admin
        .from("profiles")
        .delete()
        .eq("organization_id", caller.organization_id);
      if (profileError) throw profileError;

      const { error: organizationError } = await admin
        .from("organizations")
        .delete()
        .eq("id", caller.organization_id);
      if (organizationError) throw organizationError;

      const userIds = (profiles ?? []).map((profile) => profile.id as string);
      for (const userId of userIds) {
        const { error: deleteUserError } = await admin.auth.admin.deleteUser(userId);
        if (deleteUserError) {
          console.error("Auth user deletion failed", { userId, deleteUserError });
          return json(500, {
            error: "Stok verileri silindi ancak bir kullanıcı hesabı temizlenemedi. Supabase Auth kayıtlarını kontrol edin.",
          });
        }
      }

      return json(200, { deleted: true, scope: "organization" });
    }

    const { error: anonymizeError } = await admin
      .from("stock_movements")
      .update({ actor_id: null, actor_name: "Silinmiş kullanıcı" })
      .eq("actor_id", caller.id);
    if (anonymizeError) throw anonymizeError;

    const { error: profileDeleteError } = await admin
      .from("profiles")
      .delete()
      .eq("id", caller.id);
    if (profileDeleteError) throw profileDeleteError;

    const { error: authDeleteError } = await admin.auth.admin.deleteUser(caller.id);
    if (authDeleteError) {
      console.error("Auth user deletion failed", authDeleteError);
      return json(500, {
        error: "Profil silindi ancak giriş kaydı temizlenemedi. Supabase Auth kayıtlarını kontrol edin.",
      });
    }

    return json(200, { deleted: true, scope: "account" });
  } catch (error) {
    console.error("Account deletion failed", error);
    return json(500, { error: "Hesap silinemedi. Lütfen tekrar deneyin." });
  }
});
