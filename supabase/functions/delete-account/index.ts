import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  json,
  sessionIdFromAccessToken,
} from "../_shared/security.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const token = bearerToken(req);
    if (!token) return json(401, { error: "Oturum gerekli" });

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: userData, error: userError } = await admin.auth.getUser(token);
    if (userError || !userData.user) return json(401, { error: "Geçersiz oturum" });
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc("service_has_live_session", {
      p_user_id: userData.user.id,
      p_session_id: sessionId,
    });
    if (liveSessionError || !liveSession) return json(401, { error: "Oturum sona erdi" });

    const { data: caller, error: callerError } = await admin
      .from("profiles")
      .select("id,username,role,organization_id,is_platform_operator,is_active,must_change_password")
      .eq("id", userData.user.id)
      .maybeSingle();
    if (callerError || !caller?.is_active) return json(404, { error: "Etkin kullanıcı profili bulunamadı" });
    if (caller.is_platform_operator) {
      return json(403, { error: "Platform yöneticisi hesabı uygulama içinden silinemez" });
    }
    if (caller.must_change_password) {
      return json(403, {
        error: "Hesabı silmeden önce geçici şifrenizi değiştirin",
        code: "PASSWORD_CHANGE_REQUIRED",
      });
    }

    const body = await req.json() as { confirmation?: unknown; currentPassword?: unknown };
    const confirmation = typeof body.confirmation === "string" ? body.confirmation.trim() : "";
    const expectedConfirmation = caller.role === "admin" ? "STOKDAŞ" : caller.username;
    const isValidConfirmation = caller.role === "admin"
      ? confirmation === expectedConfirmation || confirmation === "STOKTA"
      : confirmation === expectedConfirmation;
    if (!isValidConfirmation) {
      return json(400, { error: `Onay alanına ${expectedConfirmation} yazılmalı` });
    }

    const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
    const callerEmail = userData.user.email;
    if (!callerEmail || currentPassword.length < 1 || currentPassword.length > 72) {
      return json(400, { error: "Hesabı silmek için mevcut şifrenizi girin" });
    }
    const reauthClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: reauthData, error: reauthError } = await reauthClient.auth.signInWithPassword({
      email: callerEmail,
      password: currentPassword,
    });
    if (reauthError || !reauthData.session || reauthData.user.id !== caller.id) {
      return json(401, { error: "Mevcut şifre hatalı" });
    }
    const reauthSessionId = sessionIdFromAccessToken(reauthData.session.access_token);
    if (!reauthSessionId) {
      return json(503, { error: "Kimlik doğrulama oturumu kapatılamadı" });
    }
    const { data: reauthRevoked, error: reauthRevokeError } = await admin.rpc(
      "service_revoke_session",
      { p_user_id: caller.id, p_session_id: reauthSessionId },
    );
    await reauthClient.auth.signOut({ scope: "local" });
    if (reauthRevokeError || !reauthRevoked) {
      return json(503, { error: "Kimlik doğrulama oturumu kapatılamadı" });
    }

    if (caller.role === "admin") {
      const { data: profiles, error: profilesError } = await admin
        .from("profiles")
        .select("id,is_platform_operator")
        .eq("organization_id", caller.organization_id);
      if (profilesError) throw profilesError;
      if ((profiles ?? []).some((profile) => profile.is_platform_operator)) {
        return json(403, { error: "Platform yöneticisinin bulunduğu işletme silinemez" });
      }

      const { data: pendingAccounts, error: pendingAccountsError } = await admin
        .from("pending_account_registrations")
        .select("auth_user_id")
        .eq("organization_id", caller.organization_id);
      if (pendingAccountsError) throw pendingAccountsError;
      const { data: pendingRecoveryAccounts, error: pendingRecoveryAccountsError } = await admin
        .from("pending_recovery_email_verifications")
        .select("target_user_id,verification_user_id,verification_kind")
        .eq("organization_id", caller.organization_id);
      if (pendingRecoveryAccountsError) throw pendingRecoveryAccountsError;

      for (const profile of profiles ?? []) {
        const { error: banError } = await admin.auth.admin.updateUserById(profile.id, {
          ban_duration: "876000h",
        });
        if (banError) {
          console.error("Organization deletion pre-ban failed", { userId: profile.id, banError });
          return json(500, { error: "İşletme kullanıcıları güvenli biçimde kilitlenemedi" });
        }
        const { error: revokeError } = await admin.rpc("service_revoke_user_sessions", {
          p_user_id: profile.id,
          p_except_session_id: null,
        });
        if (revokeError) {
          console.error("Organization deletion session revocation failed", {
            userId: profile.id,
            revokeError,
          });
          return json(500, { error: "İşletme kullanıcı oturumları kapatılamadı" });
        }
      }

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

      const userIds = [...new Set([
        ...(profiles ?? []).map((profile) => profile.id as string),
        ...(pendingAccounts ?? []).map((pending) => pending.auth_user_id as string),
        ...(pendingRecoveryAccounts ?? [])
          .filter((pending) => pending.verification_kind === "temporary_signup")
          .map((pending) => pending.verification_user_id as string),
      ])];
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

    const { data: pendingRecovery, error: pendingRecoveryError } = await admin
      .from("pending_recovery_email_verifications")
      .select("verification_user_id,verification_kind")
      .eq("target_user_id", caller.id)
      .maybeSingle();
    if (pendingRecoveryError) throw pendingRecoveryError;

    const { data: organizationAdmin, error: organizationAdminError } = await admin
      .from("profiles")
      .select("id")
      .eq("organization_id", caller.organization_id)
      .eq("role", "admin")
      .eq("is_active", true)
      .maybeSingle();
    if (organizationAdminError) throw organizationAdminError;
    if (!organizationAdmin) {
      return json(409, {
        error: "Hesap verilerini devralacak etkin işletme yöneticisi bulunamadı",
      });
    }

    const { error: banError } = await admin.auth.admin.updateUserById(caller.id, {
      ban_duration: "876000h",
    });
    if (banError) {
      console.error("Account deletion pre-ban failed", banError);
      return json(500, { error: "Hesap güvenli biçimde kilitlenemedi" });
    }
    const { error: revokeError } = await admin.rpc("service_revoke_user_sessions", {
      p_user_id: caller.id,
      p_except_session_id: null,
    });
    if (revokeError) {
      console.error("Account deletion session revocation failed", revokeError);
      return json(500, { error: "Hesap oturumları kapatılamadı" });
    }

    const { error: anonymizeError } = await admin
      .from("stock_movements")
      .update({ actor_id: null, actor_name: "Silinmiş kullanıcı" })
      .eq("actor_id", caller.id);
    if (anonymizeError) throw anonymizeError;

    const { error: productOwnershipError } = await admin
      .from("products")
      .update({ created_by: organizationAdmin.id })
      .eq("organization_id", caller.organization_id)
      .eq("created_by", caller.id);
    if (productOwnershipError) throw productOwnershipError;

    const { error: profileOwnershipError } = await admin
      .from("profiles")
      .update({ created_by: organizationAdmin.id })
      .eq("organization_id", caller.organization_id)
      .eq("created_by", caller.id);
    if (profileOwnershipError) throw profileOwnershipError;

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

    if (pendingRecovery?.verification_kind === "temporary_signup"
      && pendingRecovery.verification_user_id !== caller.id) {
      const { data: verificationUserData } = await admin.auth.admin.getUserById(
        pendingRecovery.verification_user_id,
      );
      if (verificationUserData.user?.app_metadata?.stokta_verification_only === true
        && verificationUserData.user.app_metadata?.target_user_id === caller.id) {
        const { error: cleanupVerificationError } = await admin.auth.admin.deleteUser(
          pendingRecovery.verification_user_id,
        );
        if (cleanupVerificationError) {
          console.error("Temporary recovery identity cleanup failed", cleanupVerificationError);
        }
      }
    }

    return json(200, { deleted: true, scope: "account" });
  } catch (error) {
    console.error("Account deletion failed", error);
    return json(500, { error: "Hesap silinemedi. Lütfen tekrar deneyin." });
  }
});

