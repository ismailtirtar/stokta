import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  isStrongPassword,
  json,
  maskEmail,
  normalizeRecoveryEmail,
  randomStrongPassword,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

type Profile = {
  id: string;
  organization_id: string;
  recovery_email: string | null;
  recovery_email_verified_at: string | null;
  must_change_password: boolean;
};

type PendingVerification = {
  target_user_id: string;
  verification_user_id: string;
  verification_kind: "temporary_signup" | "existing_identity";
  email: string;
  requested_session_id: string;
  expires_at: string;
};

function statusBody(
  profile: Profile,
  authEmail: string,
  pendingEmail: string | null,
) {
  const realEmail = !authEmail.endsWith("@stokta.invalid") ? authEmail : null;
  const recoveryEmailVerified = Boolean(
    realEmail
    && profile.recovery_email_verified_at
    && profile.recovery_email === realEmail,
  );
  return {
    recoveryEmail: recoveryEmailVerified ? realEmail : null,
    recoveryEmailMasked: recoveryEmailVerified && realEmail ? maskEmail(realEmail) : null,
    recoveryEmailVerified,
    pendingRecoveryEmailMasked: pendingEmail ? maskEmail(pendingEmail) : null,
    mustChangePassword: profile.must_change_password,
  };
}

async function reauthenticate(
  authClient: any,
  email: string,
  password: string,
  expectedUserId: string,
) {
  const { data, error } = await authClient.auth.signInWithPassword({ email, password });
  if (error || !data.session || data.user.id !== expectedUserId) return null;
  return sessionIdFromAccessToken(data.session.access_token);
}

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
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: callerData, error: callerAuthError } = await admin.auth.getUser(token);
    if (callerAuthError || !callerData.user) return json(401, { error: "Geçersiz oturum" });
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc("service_has_live_session", {
      p_user_id: callerData.user.id,
      p_session_id: sessionId,
    });
    if (liveSessionError || !liveSession) return json(401, { error: "Oturum sona erdi" });

    const { data: profile, error: profileError } = await admin
      .from("profiles")
      .select("id,organization_id,recovery_email,recovery_email_verified_at,must_change_password")
      .eq("id", callerData.user.id)
      .eq("is_active", true)
      .maybeSingle();
    if (profileError) throw profileError;
    if (!profile) return json(403, { error: "Bu hesap etkin değil" });

    const { data: authUserData, error: authUserError } = await admin.auth.admin.getUserById(profile.id);
    const authUser = authUserData.user;
    const authEmail = authUser?.email?.toLowerCase();
    if (authUserError || !authUser || !authEmail) {
      console.error("Account security identity lookup failed", authUserError);
      return json(500, { error: "Hesap güvenliği bilgileri alınamadı" });
    }

    const body = await req.json() as Record<string, unknown>;
    const action = typeof body.action === "string" ? body.action : "status";
    const { data: currentPending } = await admin
      .from("pending_recovery_email_verifications")
      .select("target_user_id,verification_user_id,verification_kind,email,requested_session_id,expires_at")
      .eq("target_user_id", profile.id)
      .maybeSingle();

    if (action === "status") {
      const pendingEmail = currentPending
        && new Date(currentPending.expires_at).getTime() > Date.now()
        ? currentPending.email
        : null;
      return json(200, statusBody(profile as Profile, authEmail, pendingEmail));
    }
    if (!["request-recovery-email", "verify-recovery-email", "change-password"].includes(action)) {
      return json(400, { error: "Geçersiz işlem" });
    }
    if (profile.must_change_password && action !== "change-password") {
      return json(403, {
        error: "Hesap güvenliği işlemlerinden önce geçici şifrenizi değiştirin",
        code: "PASSWORD_CHANGE_REQUIRED",
      });
    }

    const operationHash = await sha256(
      `stokta:account-security:v2:${profile.id}:${action}:${supabaseUrl}:${serviceRoleKey}`,
    );
    const { data: allowed, error: rateError } = await admin.rpc("consume_auth_rate_limit", {
      p_scope: "account-security",
      p_key_hash: operationHash,
      p_max_attempts: action === "verify-recovery-email" ? 8 : 10,
      p_window_seconds: 3600,
    });
    if (rateError) {
      console.error("Account security rate limiter unavailable", rateError);
      return json(503, { error: "Hesap güvenliği hizmeti şu anda kullanılamıyor" });
    }
    if (!allowed) {
      return json(429, { error: "Çok fazla güvenlik işlemi denendi. Lütfen daha sonra tekrar deneyin." });
    }

    if (action === "verify-recovery-email") {
      const code = typeof body.code === "string" ? body.code.trim() : "";
      if (!/^[0-9]{6,10}$/.test(code)) {
        return json(400, { error: "Doğrulama kodu geçersiz veya süresi dolmuş" });
      }
      const pending = currentPending as PendingVerification | null;
      if (!pending
        || pending.requested_session_id !== sessionId
        || new Date(pending.expires_at).getTime() <= Date.now()) {
        return json(400, { error: "Doğrulama isteği bulunamadı veya süresi doldu" });
      }

      const { data: verificationData, error: verificationError } = await authClient.auth.verifyOtp({
        email: pending.email,
        token: code,
        type: "email",
      });
      const verifiedUser = verificationData.user;
      if (verificationError
        || !verificationData.session
        || !verifiedUser
        || verifiedUser.id !== pending.verification_user_id) {
        return json(400, { error: "Doğrulama kodu geçersiz veya süresi dolmuş" });
      }

      const verificationSessionId = sessionIdFromAccessToken(
        verificationData.session.access_token,
      );
      if (!verificationSessionId) {
        return json(503, { error: "E-posta doğrulaması güvenli biçimde tamamlanamadı" });
      }

      if (pending.verification_kind === "temporary_signup"
        && (verifiedUser.app_metadata?.stokta_verification_only !== true
          || verifiedUser.app_metadata?.target_user_id !== profile.id)) {
        await admin.rpc("service_revoke_session", {
          p_user_id: pending.verification_user_id,
          p_session_id: verificationSessionId,
        });
        return json(400, { error: "Doğrulama isteği geçersiz" });
      }

      const { error: preChangeRevokeError } = await admin.rpc(
        "service_revoke_user_sessions",
        { p_user_id: profile.id, p_except_session_id: null },
      );
      if (preChangeRevokeError) {
        console.error("Recovery email pre-change session revocation failed", preChangeRevokeError);
        await admin.rpc("service_revoke_session", {
          p_user_id: pending.verification_user_id,
          p_session_id: verificationSessionId,
        });
        return json(503, {
          error: "Açık oturumlar güvenli biçimde kapatılamadı; e-posta değiştirilmedi",
        });
      }

      if (pending.verification_kind === "existing_identity") {
        const { error: verifiedError } = await admin.rpc("service_mark_recovery_email_verified", {
          p_user_id: profile.id,
          p_expected_email: pending.email,
        });
        if (verifiedError) {
          console.error("Existing recovery email could not be marked verified", verifiedError);
          return json(500, { error: "E-posta doğrulaması kaydedilemedi" });
        }
        await admin.from("pending_recovery_email_verifications")
          .delete().eq("target_user_id", profile.id);
      } else {
        const { error: deleteVerificationUserError } =
          await admin.auth.admin.deleteUser(pending.verification_user_id);
        if (deleteVerificationUserError) {
          console.error("Temporary verification identity cleanup failed", deleteVerificationUserError);
          await admin.rpc("service_revoke_session", {
            p_user_id: pending.verification_user_id,
            p_session_id: verificationSessionId,
          });
          return json(500, { error: "E-posta doğrulaması tamamlanamadı" });
        }

        const verifiedAt = new Date().toISOString();
        const { data: updatedUserData, error: updateEmailError } =
          await admin.auth.admin.updateUserById(profile.id, {
            email: pending.email,
            email_confirm: true,
            app_metadata: {
              ...authUser.app_metadata,
              stokta_recovery_email_verified_at: verifiedAt,
            },
          });
        if (updateEmailError || !updatedUserData.user) {
          console.error("Verified recovery email could not be assigned", updateEmailError);
          const duplicate = updateEmailError?.code === "email_exists"
            || updateEmailError?.code === "user_already_exists"
            || updateEmailError?.message.toLowerCase().includes("registered")
            || updateEmailError?.message.toLowerCase().includes("already");
          return json(duplicate ? 409 : 500, {
            error: duplicate
              ? "Bu e-posta adresi başka bir hesapta kullanılıyor"
              : "Doğrulanan e-posta hesaba kaydedilemedi",
          });
        }

        const { error: verifiedError } = await admin.rpc("service_mark_recovery_email_verified", {
          p_user_id: profile.id,
          p_expected_email: pending.email,
        });
        if (verifiedError) {
          console.error("Recovery email verification flag could not be stored", verifiedError);
          return json(500, { error: "E-posta kaydedildi ancak doğrulama durumu tamamlanamadı" });
        }
      }

      const { error: revokeTargetSessionsError } = await admin.rpc(
        "service_revoke_user_sessions",
        { p_user_id: profile.id, p_except_session_id: null },
      );
      if (revokeTargetSessionsError) {
        console.error("Recovery email post-change session revocation failed", revokeTargetSessionsError);
        return json(500, {
          error: "E-posta doğrulandı ancak açık oturumlar kapatılamadı. Yeniden giriş yapın.",
        });
      }

      const verifiedProfile = {
        ...(profile as Profile),
        recovery_email: pending.email,
        recovery_email_verified_at: new Date().toISOString(),
      };
      return json(200, {
        updated: true,
        reauthenticationRequired: true,
        ...statusBody(verifiedProfile, pending.email, null),
      });
    }

    const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
    if (currentPassword.length < 1 || currentPassword.length > 72) {
      return json(400, { error: "Mevcut şifre gerekli" });
    }
    const reauthSessionId = await reauthenticate(authClient, authEmail, currentPassword, profile.id);
    if (!reauthSessionId) return json(401, { error: "Mevcut şifre hatalı" });
    const { data: reauthRevoked, error: reauthRevokeError } = await admin.rpc(
      "service_revoke_session",
      { p_user_id: profile.id, p_session_id: reauthSessionId },
    );
    if (reauthRevokeError || !reauthRevoked) {
      return json(503, { error: "Kimlik doğrulama oturumu güvenli biçimde kapatılamadı" });
    }
    await authClient.auth.signOut({ scope: "local" });

    try {
      if (action === "request-recovery-email") {
        const recoveryEmail = normalizeRecoveryEmail(body.recoveryEmail);
        if (!recoveryEmail) return json(400, { error: "Geçerli bir kurtarma e-postası girin" });

        if (currentPending) {
          if (currentPending.verification_user_id !== profile.id) {
            const { data: previousUser } = await admin.auth.admin.getUserById(
              currentPending.verification_user_id,
            );
            if (previousUser.user?.app_metadata?.stokta_verification_only === true
              && previousUser.user.app_metadata?.target_user_id === profile.id) {
              await admin.auth.admin.deleteUser(currentPending.verification_user_id);
            }
          }
          await admin.from("pending_recovery_email_verifications")
            .delete().eq("target_user_id", profile.id);
        }

        let verificationUserId: string;
        let verificationKind: "temporary_signup" | "existing_identity";

        if (authEmail === recoveryEmail) {
          const { error: otpError } = await authClient.auth.signInWithOtp({
            email: recoveryEmail,
            options: { shouldCreateUser: false },
          });
          if (otpError) {
            console.error("Existing recovery identity OTP request failed", otpError);
            return json(400, { error: "Doğrulama kodu gönderilemedi" });
          }
          verificationUserId = profile.id;
          verificationKind = "existing_identity";
        } else {
          const startedAt = Date.now();
          const { data: signupData, error: signupError } = await authClient.auth.signUp({
            email: recoveryEmail,
            password: randomStrongPassword(),
            options: { data: { verification_only: true } },
          });
          if (signupError || !signupData.user) {
            const duplicate = signupError?.code === "email_exists"
              || signupError?.code === "user_already_exists"
              || signupError?.message.toLowerCase().includes("registered")
              || signupError?.message.toLowerCase().includes("already");
            return json(duplicate ? 409 : 400, {
              error: duplicate
                ? "Bu e-posta adresi başka bir hesapta kullanılıyor"
                : "Doğrulama kodu gönderilemedi",
            });
          }
          if (signupData.session) {
            await authClient.auth.signOut({ scope: "local" });
            await admin.auth.admin.deleteUser(signupData.user.id);
            return json(503, { error: "E-posta doğrulaması sunucuda etkin değil" });
          }

          const { data: temporaryUserData } = await admin.auth.admin.getUserById(signupData.user.id);
          const temporaryUser = temporaryUserData.user;
          const createdAt = temporaryUser ? new Date(temporaryUser.created_at).getTime() : 0;
          if (!temporaryUser
            || temporaryUser.email?.toLowerCase() !== recoveryEmail
            || temporaryUser.email_confirmed_at
            || createdAt < startedAt - 60000) {
            return json(409, { error: "Bu e-posta adresi başka bir hesapta kullanılıyor" });
          }

          const { error: markerError } = await admin.auth.admin.updateUserById(temporaryUser.id, {
            app_metadata: {
              ...temporaryUser.app_metadata,
              stokta_verification_only: true,
              target_user_id: profile.id,
            },
          });
          if (markerError) {
            await admin.auth.admin.deleteUser(temporaryUser.id);
            return json(500, { error: "Doğrulama isteği hazırlanamadı" });
          }
          verificationUserId = temporaryUser.id;
          verificationKind = "temporary_signup";
        }

        const { error: pendingError } = await admin
          .from("pending_recovery_email_verifications")
          .insert({
            target_user_id: profile.id,
            verification_user_id: verificationUserId,
            verification_kind: verificationKind,
            organization_id: profile.organization_id,
            email: recoveryEmail,
            requested_session_id: sessionId,
          });
        if (pendingError) {
          console.error("Recovery email verification could not be stored", pendingError);
          if (verificationKind === "temporary_signup") {
            await admin.auth.admin.deleteUser(verificationUserId);
          }
          return json(pendingError.code === "23505" ? 409 : 500, {
            error: pendingError.code === "23505"
              ? "Bu e-posta için başka bir doğrulama bekleniyor"
              : "Doğrulama isteği hazırlanamadı",
          });
        }

        await admin.rpc("service_record_security_event", {
          p_event_type: "recovery_email.verification_requested",
          p_organization_id: profile.organization_id,
          p_actor_id: profile.id,
          p_subject_id: profile.id,
          p_metadata: { verificationKind },
        });

        return json(202, {
          accepted: true,
          verificationRequired: true,
          pendingRecoveryEmailMasked: maskEmail(recoveryEmail),
          message: "E-postanıza gönderilen doğrulama kodunu girin.",
        });
      }

      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
      if (!isStrongPassword(newPassword)) {
        return json(400, {
          error: "Yeni şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli",
        });
      }
      if (newPassword === currentPassword) {
        return json(400, { error: "Yeni şifre mevcut şifreden farklı olmalı" });
      }

      const { error: preChangeRevokeError } = await admin.rpc(
        "service_revoke_user_sessions",
        { p_user_id: profile.id, p_except_session_id: null },
      );
      if (preChangeRevokeError) {
        console.error("Password change pre-update session revocation failed", preChangeRevokeError);
        return json(503, {
          error: "Açık oturumlar güvenli biçimde kapatılamadı; şifre değiştirilmedi",
        });
      }

      const { error: passwordError } = await admin.auth.admin.updateUserById(profile.id, {
        password: newPassword,
      });
      if (passwordError) {
        console.error("Account password update failed", passwordError);
        return json(400, { error: "Şifre değiştirilemedi" });
      }
      const { error: completionError } = await admin.rpc("service_complete_password_change", {
        p_user_id: profile.id,
      });
      if (completionError) {
        console.error("Password change completion failed", completionError);
        return json(500, { error: "Şifre değişti ancak oturumlar kapatılamadı. Yeniden giriş yapın." });
      }

      return json(200, { updated: true, reauthenticationRequired: true });
    } finally {
      await authClient.auth.signOut({ scope: "local" });
    }
  } catch (error) {
    console.error("Account security operation failed", error);
    return json(500, { error: "Hesap güvenliği işlemi tamamlanamadı" });
  }
});
