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

    // The RPC takes an exclusive tenant lock, decides whether any pending or
    // reviewed bank-transfer notice blocks deletion, then performs all
    // database cleanup in one transaction. No account is banned beforehand.
    const { data: deletionData, error: deletionError } = await admin.rpc(
      "service_delete_account_data",
      { p_user_id: caller.id },
    );
    if (deletionError) {
      console.error("Account deletion transaction failed", {
        code: typeof deletionError.code === "string" ? deletionError.code : "unknown",
      });
      return json(503, { error: "Hesap silme işlemi tamamlanamadı. Lütfen daha sonra tekrar deneyin." });
    }

    const deletion = deletionData as Record<string, unknown> | null;
    if (deletion?.code === "PAYMENT_RECORDS_REQUIRE_REVIEW") {
      return json(409, {
        code: "PAYMENT_RECORDS_REQUIRE_REVIEW",
        error: deletion.paymentStatus === "pending"
          ? "Ödeme bildiriminiz henüz inceleniyor. Hesap ve veri silme talebinizi tirtarismail@gmail.com adresine iletin."
          : "Bu hesapla ilişkili incelenmiş ödeme kayıtları var. Hesap ve veri silme talebinizi tirtarismail@gmail.com adresine iletin.",
        supportEmail: "tirtarismail@gmail.com",
      });
    }
    if (deletion?.code === "ACTIVE_GOOGLE_PLAY_SUBSCRIPTION") {
      return json(409, {
        code: "ACTIVE_GOOGLE_PLAY_SUBSCRIPTION",
        error: "İşletmeyi silmeden önce Google Play aboneliğini iptal edin ve Stokdaş'ta satın alımları geri yükleyin",
      });
    }
    if (deletion?.code === "PLATFORM_OPERATOR_IN_ORGANIZATION"
      || deletion?.code === "PLATFORM_OPERATOR") {
      return json(403, { error: "Platform yöneticisinin hesabı veya işletmesi uygulama içinden silinemez" });
    }
    if (deletion?.code === "PASSWORD_CHANGE_REQUIRED") {
      return json(403, { error: "Hesabı silmeden önce geçici şifrenizi değiştirin", code: deletion.code });
    }
    if (deletion?.code === "ORGANIZATION_ADMIN_NOT_FOUND") {
      return json(409, { error: "Hesap verilerini devralacak etkin işletme yöneticisi bulunamadı" });
    }
    if (deletion?.code === "ACCOUNT_NOT_FOUND") {
      return json(404, { error: "Etkin kullanıcı profili bulunamadı" });
    }
    if (deletion?.deleted !== true
      || (deletion.scope !== "organization" && deletion.scope !== "account")
      || !Array.isArray(deletion.authUserIds)) {
      console.error("Account deletion transaction returned an invalid result");
      return json(503, { error: "Hesap silme sonucu doğrulanamadı. Destek ile iletişime geçin." });
    }

    // Auth Admin is outside the database transaction. A failure here requires
    // an explicit recovery workflow before this draft can ship.
    let authCleanupFailed = false;
    for (const userId of deletion.authUserIds) {
      if (typeof userId !== "string") {
        authCleanupFailed = true;
        continue;
      }
      const { error: banError } = await admin.auth.admin.updateUserById(userId, {
        ban_duration: "876000h",
      });
      if (banError) console.error("Account deletion Auth ban failed", { userId, banError });

      const { error: revokeError } = await admin.rpc("service_revoke_user_sessions", {
        p_user_id: userId,
        p_except_session_id: null,
      });
      if (revokeError) console.error("Account deletion session revocation failed", { userId, revokeError });

      const { error: deleteUserError } = await admin.auth.admin.deleteUser(userId);
      if (deleteUserError) {
        authCleanupFailed = true;
        console.error("Account deletion Auth user cleanup failed", { userId, deleteUserError });
      }
    }

    if (deletion.scope === "account" && typeof deletion.verificationUserId === "string"
      && deletion.verificationUserId !== caller.id) {
      const { data: verificationUserData, error: verificationLookupError } = await admin.auth.admin.getUserById(
        deletion.verificationUserId,
      );
      if (verificationLookupError) {
        authCleanupFailed = true;
        console.error("Temporary recovery identity lookup failed", verificationLookupError);
      } else if (verificationUserData.user?.app_metadata?.stokta_verification_only === true
        && verificationUserData.user.app_metadata?.target_user_id === caller.id) {
        const { error: cleanupVerificationError } = await admin.auth.admin.deleteUser(
          deletion.verificationUserId,
        );
        if (cleanupVerificationError) {
          authCleanupFailed = true;
          console.error("Temporary recovery identity cleanup failed", cleanupVerificationError);
        }
      }
    }

    if (authCleanupFailed) {
      return json(503, {
        code: "AUTH_CLEANUP_PENDING",
        error: "Hesap verileri silindi ancak giriş kayıtlarının temizliği tamamlanamadı. Lütfen tirtarismail@gmail.com adresine yazın.",
        supportEmail: "tirtarismail@gmail.com",
      });
    }

    return json(200, { deleted: true, scope: deletion.scope });
  } catch (error) {
    console.error("Account deletion failed", error);
    return json(500, { error: "Hesap silinemedi. Lütfen tekrar deneyin." });
  }
});
