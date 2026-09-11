import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  isStrongPassword,
  json,
  maskEmail,
  normalizeRecoveryEmail,
  normalizeUuid,
  randomStrongPassword,
  readJsonObject,
  requestBodyErrorResponse,
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
  request_id: string;
  target_user_id: string;
  verification_user_id: string;
  verification_kind: "temporary_signup" | "existing_identity";
  email: string;
  requested_session_id: string;
  expires_at: string;
};

type RecoveryEmailIntent = {
  state: "reserved" | "bound" | "pending" | "cleanup_required";
  requestId: string;
  verificationUserId?: string | null;
  verificationKind: "temporary_signup" | "existing_identity";
};

type RecoveryEmailIdentity = {
  verificationUserId: string;
  emailConfirmed: boolean;
};

type RecoveryVerificationClaim = {
  requestId: string;
  targetUserId: string;
  organizationId: string;
  verificationUserId: string;
  verificationKind: "temporary_signup" | "existing_identity";
  email: string;
  prepared: boolean;
};

function statusBody(
  profile: Profile,
  authEmail: string,
  pendingEmail: string | null,
) {
  const realEmail = !authEmail.endsWith("@stokta.invalid") ? authEmail : null;
  const recoveryEmailVerified = Boolean(
    realEmail &&
      profile.recovery_email_verified_at &&
      profile.recovery_email === realEmail,
  );
  return {
    recoveryEmail: recoveryEmailVerified ? realEmail : null,
    recoveryEmailMasked: recoveryEmailVerified && realEmail
      ? maskEmail(realEmail)
      : null,
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
  const { data, error } = await authClient.auth.signInWithPassword({
    email,
    password,
  });
  if (error || !data.session || data.user.id !== expectedUserId) return null;
  return sessionIdFromAccessToken(data.session.access_token);
}

async function retireTemporaryVerificationIdentity(
  admin: any,
  verificationUserId: string,
  targetUserId: string,
  expectedEmail: string,
) {
  const { data, error } = await admin.auth.admin.getUserById(
    verificationUserId,
  );
  if (error && error.status !== 404) throw error;
  const user = data.user;
  if (!user) return;
  if (
    user.app_metadata?.stokta_verification_only !== true ||
    user.app_metadata?.target_user_id !== targetUserId
  ) {
    throw new Error("Temporary verification identity marker mismatch");
  }

  const tombstoneEmail = `verification-${verificationUserId}@stokta.invalid`;
  const currentEmail = user.email?.toLowerCase();
  if (currentEmail === tombstoneEmail) return;
  if (currentEmail !== expectedEmail) {
    throw new Error("Temporary verification identity email mismatch");
  }

  const { error: retireError } = await admin.auth.admin.updateUserById(
    verificationUserId,
    {
      email: tombstoneEmail,
      email_confirm: true,
      app_metadata: {
        ...user.app_metadata,
        stokta_verification_retired: true,
      },
    },
  );
  if (retireError) throw retireError;
}

async function cleanupRecoveryEmailIntent(admin: any, requestId: string) {
  const { data: claim, error: claimError } = await admin.rpc(
    "service_claim_recovery_email_intent_cleanup",
    { p_request_id: requestId },
  );
  if (claimError || !claim) {
    throw claimError ?? new Error("Recovery email cleanup was not authorized");
  }
  if (claim.finished === true) return;
  if (typeof claim.userId !== "string") {
    throw new Error("Recovery email cleanup identity is missing");
  }
  const { error: deleteError } = await admin.auth.admin.deleteUser(
    claim.userId,
  );
  if (deleteError) throw deleteError;
  const { data: finished, error: finishError } = await admin.rpc(
    "service_finish_recovery_email_intent_cleanup",
    { p_request_id: requestId, p_verification_user_id: claim.userId },
  );
  if (finishError || finished !== true) {
    throw finishError ??
      new Error("Recovery email cleanup could not be committed");
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsJsonHeaders });
  }
  if (req.method !== "POST") {
    return json(405, { error: "Yalnızca POST desteklenir" });
  }

  try {
    const token = bearerToken(req);
    if (!token) return json(401, { error: "Oturum gerekli" });

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const body = await readJsonObject(req, 8 * 1024);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: callerData, error: callerAuthError } = await admin.auth
      .getUser(token);
    if (callerAuthError || !callerData.user) {
      return json(401, { error: "Geçersiz oturum" });
    }
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc(
      "service_has_live_session",
      {
        p_user_id: callerData.user.id,
        p_session_id: sessionId,
      },
    );
    if (liveSessionError || !liveSession) {
      return json(401, { error: "Oturum sona erdi" });
    }

    const { data: profile, error: profileError } = await admin
      .from("profiles")
      .select(
        "id,organization_id,recovery_email,recovery_email_verified_at,must_change_password",
      )
      .eq("id", callerData.user.id)
      .eq("is_active", true)
      .maybeSingle();
    if (profileError) throw profileError;
    if (!profile) return json(403, { error: "Bu hesap etkin değil" });

    const { data: authUserData, error: authUserError } = await admin.auth.admin
      .getUserById(profile.id);
    const authUser = authUserData.user;
    const authEmail = authUser?.email?.toLowerCase();
    if (authUserError || !authUser || !authEmail) {
      console.error("Account security identity lookup failed", authUserError);
      return json(500, { error: "Hesap güvenliği bilgileri alınamadı" });
    }

    const action = typeof body.action === "string" ? body.action : "status";
    const { data: currentPending, error: currentPendingError } = await admin
      .from("pending_recovery_email_verifications")
      .select(
        "request_id,target_user_id,verification_user_id,verification_kind,email,requested_session_id,expires_at",
      )
      .eq("target_user_id", profile.id)
      .maybeSingle();
    if (currentPendingError) {
      console.error(
        "Recovery email verification lookup failed",
        currentPendingError,
      );
      return json(503, {
        error: "Hesap güvenliği hizmeti şu anda kullanılamıyor",
      });
    }

    if (action === "status") {
      const pendingEmail = currentPending &&
          new Date(currentPending.expires_at).getTime() > Date.now()
        ? currentPending.email
        : null;
      return json(200, statusBody(profile as Profile, authEmail, pendingEmail));
    }
    if (
      !["request-recovery-email", "verify-recovery-email", "change-password"]
        .includes(action)
    ) {
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
    const { data: allowed, error: rateError } = await admin.rpc(
      "consume_auth_rate_limit",
      {
        p_scope: "account-security",
        p_key_hash: operationHash,
        p_max_attempts: action === "verify-recovery-email" ? 8 : 10,
        p_window_seconds: 3600,
      },
    );
    if (rateError) {
      console.error("Account security rate limiter unavailable", rateError);
      return json(503, {
        error: "Hesap güvenliği hizmeti şu anda kullanılamıyor",
      });
    }
    if (!allowed) {
      return json(429, {
        error:
          "Çok fazla güvenlik işlemi denendi. Lütfen daha sonra tekrar deneyin.",
      });
    }

    if (action === "verify-recovery-email") {
      const code = typeof body.code === "string" ? body.code.trim() : "";
      if (!/^[0-9]{6,10}$/.test(code)) {
        return json(400, {
          error: "Doğrulama kodu geçersiz veya süresi dolmuş",
        });
      }
      const pending = currentPending as PendingVerification | null;
      if (
        !pending ||
        pending.requested_session_id !== sessionId ||
        new Date(pending.expires_at).getTime() <= Date.now()
      ) {
        return json(400, {
          error: "Doğrulama isteği bulunamadı veya süresi doldu",
        });
      }

      const attemptHash = await sha256(
        `stokta:recovery-email-attempt:v1:${profile.id}:${pending.verification_user_id}:${sessionId}:${code}:${supabaseUrl}:${serviceRoleKey}`,
      );
      const { data: claimData, error: claimError } = await admin.rpc(
        "service_claim_recovery_email_verification",
        {
          p_target_user_id: profile.id,
          p_requested_session_id: sessionId,
          p_attempt_hash: attemptHash,
        },
      );
      const claim = claimData as RecoveryVerificationClaim | null;
      if (claimError) {
        console.error("Recovery email verification claim failed", claimError);
        return json(503, {
          error: "E-posta doğrulaması şu anda tamamlanamıyor",
        });
      }
      if (
        !claim ||
        claim.requestId !== pending.request_id ||
        claim.targetUserId !== profile.id ||
        claim.verificationUserId !== pending.verification_user_id ||
        claim.email !== pending.email ||
        claim.verificationKind !== pending.verification_kind
      ) {
        return json(409, {
          error: "Doğrulama isteği başka bir işlem tarafından kullanılıyor",
        });
      }

      if (!claim.prepared) {
        const { data: verificationData, error: verificationError } =
          await authClient.auth.verifyOtp({
            email: claim.email,
            token: code,
            type: "email",
          });
        const verifiedUser = verificationData.user;
        if (
          verificationError ||
          !verificationData.session ||
          !verifiedUser ||
          verifiedUser.id !== claim.verificationUserId
        ) {
          await admin.rpc("service_release_recovery_email_verification_claim", {
            p_target_user_id: profile.id,
            p_attempt_hash: attemptHash,
          });
          return json(400, {
            error: "Doğrulama kodu geçersiz veya süresi dolmuş",
          });
        }

        const verificationSessionId = sessionIdFromAccessToken(
          verificationData.session.access_token,
        );
        if (!verificationSessionId) {
          return json(503, {
            error: "E-posta doğrulaması güvenli biçimde tamamlanamadı",
          });
        }

        const {
          data: verificationSessionRevoked,
          error: verificationSessionRevokeError,
        } = await admin.rpc("service_revoke_session", {
          p_user_id: claim.verificationUserId,
          p_session_id: verificationSessionId,
        });
        if (
          verificationSessionRevokeError || verificationSessionRevoked !== true
        ) {
          return json(503, {
            error: "Doğrulama oturumu güvenli biçimde kapatılamadı",
          });
        }

        if (
          claim.verificationKind === "temporary_signup" &&
          (verifiedUser.app_metadata?.stokta_verification_only !== true ||
            verifiedUser.app_metadata?.target_user_id !== profile.id)
        ) {
          return json(400, { error: "Doğrulama isteği geçersiz" });
        }

        const { data: prepared, error: prepareError } = await admin.rpc(
          "service_prepare_recovery_email_verification",
          {
            p_target_user_id: profile.id,
            p_verification_user_id: claim.verificationUserId,
            p_attempt_hash: attemptHash,
          },
        );
        if (prepareError || prepared !== true) {
          console.error(
            "Recovery email verification preparation failed",
            prepareError,
          );
          return json(503, {
            error:
              "Kod doğrulandı ancak değişiklik hazırlanamadı. Yeni bir kod isteyin.",
          });
        }
      }

      if (claim.verificationKind === "temporary_signup") {
        try {
          await retireTemporaryVerificationIdentity(
            admin,
            claim.verificationUserId,
            profile.id,
            claim.email,
          );
        } catch (retireError) {
          console.error(
            "Temporary verification identity could not be retired",
            retireError,
          );
          return json(503, {
            error:
              "Doğrulanan e-posta hazırlanamadı; aynı kodla tekrar deneyin",
          });
        }

        const { data: latestTargetData, error: latestTargetError } = await admin
          .auth.admin.getUserById(profile.id);
        const latestTarget = latestTargetData.user;
        if (latestTargetError || !latestTarget) {
          return json(503, { error: "Hedef hesap kimliği alınamadı" });
        }
        const alreadyUpdated =
          latestTarget.email?.toLowerCase() === claim.email &&
          Boolean(latestTarget.email_confirmed_at);
        const verifiedAt = new Date().toISOString();
        const updateResult = alreadyUpdated
          ? { data: { user: latestTarget }, error: null }
          : await admin.auth.admin.updateUserById(profile.id, {
            email: pending.email,
            email_confirm: true,
            app_metadata: {
              ...latestTarget.app_metadata,
              stokta_recovery_email_verified_at: verifiedAt,
            },
          });
        if (updateResult.error || !updateResult.data.user) {
          console.error(
            "Verified recovery email could not be assigned",
            updateResult.error,
          );
          const duplicate = updateResult.error?.code === "email_exists" ||
            updateResult.error?.code === "user_already_exists" ||
            updateResult.error?.message.toLowerCase().includes("registered") ||
            updateResult.error?.message.toLowerCase().includes("already");
          return json(duplicate ? 409 : 500, {
            error: duplicate
              ? "Bu e-posta adresi başka bir hesapta kullanılıyor"
              : "Doğrulanan e-posta hesaba kaydedilemedi; aynı kodla tekrar deneyin",
          });
        }
      }

      const { data: verifiedAt, error: finishError } = await admin.rpc(
        "service_finish_recovery_email_verification",
        { p_target_user_id: profile.id, p_attempt_hash: attemptHash },
      );
      if (finishError || !verifiedAt) {
        console.error(
          "Recovery email verification finalization failed",
          finishError,
        );
        return json(503, {
          error:
            "E-posta doğrulandı; güvenlik kapanışı için aynı kodla tekrar deneyin",
        });
      }

      if (claim.verificationKind === "temporary_signup") {
        const { error: cleanupError } = await admin.auth.admin.deleteUser(
          claim.verificationUserId,
        );
        if (cleanupError) {
          // The identity has already been retired to a random @stokta.invalid
          // address with no known password.  Cleanup can be retried separately;
          // it cannot own the newly verified address or gain tenant access.
          console.error(
            "Retired verification identity cleanup failed",
            cleanupError,
          );
        }
      }

      const verifiedProfile = {
        ...(profile as Profile),
        recovery_email: claim.email,
        recovery_email_verified_at: verifiedAt,
      };
      return json(200, {
        updated: true,
        reauthenticationRequired: true,
        ...statusBody(verifiedProfile, claim.email, null),
      });
    }

    const currentPassword = typeof body.currentPassword === "string"
      ? body.currentPassword
      : "";
    if (currentPassword.length < 1 || currentPassword.length > 72) {
      return json(400, { error: "Mevcut şifre gerekli" });
    }
    const reauthSessionId = await reauthenticate(
      authClient,
      authEmail,
      currentPassword,
      profile.id,
    );
    if (!reauthSessionId) return json(401, { error: "Mevcut şifre hatalı" });
    const { data: reauthRevoked, error: reauthRevokeError } = await admin.rpc(
      "service_revoke_session",
      { p_user_id: profile.id, p_session_id: reauthSessionId },
    );
    if (reauthRevokeError || !reauthRevoked) {
      return json(503, {
        error: "Kimlik doğrulama oturumu güvenli biçimde kapatılamadı",
      });
    }
    await authClient.auth.signOut({ scope: "local" });

    try {
      if (action === "request-recovery-email") {
        const recoveryEmail = normalizeRecoveryEmail(body.recoveryEmail);
        if (!recoveryEmail) {
          return json(400, { error: "Geçerli bir kurtarma e-postası girin" });
        }
        const normalizedRequestId = normalizeUuid(body.requestId);
        if (body.requestId !== undefined && !normalizedRequestId) {
          return json(400, {
            error: "İstek kimliği geçerli bir UUID olmalıdır",
          });
        }
        let requestId = normalizedRequestId ?? crypto.randomUUID();

        if (
          currentPending &&
          currentPending.target_user_id === profile.id &&
          currentPending.requested_session_id === sessionId &&
          currentPending.email === recoveryEmail &&
          new Date(currentPending.expires_at).getTime() > Date.now()
        ) {
          const canonicalRequestId = normalizeUuid(currentPending.request_id);
          if (!canonicalRequestId) {
            return json(503, { error: "Doğrulama isteği doğrulanamadı" });
          }
          requestId = canonicalRequestId;
          return json(202, {
            accepted: true,
            verificationRequired: true,
            requestId,
            pendingRecoveryEmailMasked: maskEmail(recoveryEmail),
            message: "E-postanıza gönderilen doğrulama kodunu girin.",
          });
        }

        const { data: retiredPending, error: retirePendingError } = await admin
          .rpc(
            "service_retire_pending_recovery_email_verification",
            { p_target_user_id: profile.id, p_requested_session_id: sessionId },
          );
        if (retirePendingError) {
          console.error(
            "Previous recovery verification could not be retired",
            retirePendingError,
          );
          return json(409, {
            error:
              "Önceki doğrulama tamamlanıyor; aynı kodla devam edin veya süresinin dolmasını bekleyin",
          });
        }
        if (
          retiredPending?.retired === true &&
          retiredPending.verificationKind === "temporary_signup" &&
          typeof retiredPending.verificationUserId === "string"
        ) {
          try {
            await retireTemporaryVerificationIdentity(
              admin,
              retiredPending.verificationUserId,
              profile.id,
              retiredPending.email,
            );
            const { error: deleteRetiredError } = await admin.auth.admin
              .deleteUser(retiredPending.verificationUserId);
            if (deleteRetiredError) {
              console.error(
                "Retired recovery verification cleanup failed",
                deleteRetiredError,
              );
            }
          } catch (retiredIdentityError) {
            console.error(
              "Previous verification identity could not be retired",
              retiredIdentityError,
            );
            return json(503, {
              error: "Önceki doğrulama güvenli biçimde kapatılamadı",
            });
          }
        }

        const verificationKind: "temporary_signup" | "existing_identity" =
          authEmail === recoveryEmail
            ? "existing_identity"
            : "temporary_signup";
        const beginArgs = {
          p_request_id: requestId,
          p_target_user_id: profile.id,
          p_organization_id: profile.organization_id,
          p_requested_session_id: sessionId,
          p_email: recoveryEmail,
          p_verification_kind: verificationKind,
        };
        let intent: RecoveryEmailIntent | null = null;
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const { data, error } = await admin.rpc(
            "service_begin_recovery_email_intent",
            beginArgs,
          );
          if (error) {
            console.error("Recovery email intent could not be reserved", error);
            return json(error.code === "23505" ? 409 : 503, {
              error: error.code === "23505"
                ? "Bu e-posta için başka bir doğrulama bekleniyor"
                : "Kurtarma e-postası doğrulaması şu anda başlatılamıyor",
            });
          }
          intent = data as RecoveryEmailIntent | null;
          if (!intent) {
            return json(503, {
              error: "Doğrulama isteği güvenli biçimde oluşturulamadı",
            });
          }
          const canonicalRequestId = normalizeUuid(intent.requestId);
          if (!canonicalRequestId) {
            return json(503, { error: "Doğrulama isteği doğrulanamadı" });
          }
          requestId = canonicalRequestId;
          if (intent.state !== "cleanup_required") break;
          try {
            await cleanupRecoveryEmailIntent(admin, intent.requestId);
          } catch (cleanupError) {
            console.error(
              "Expired recovery email intent cleanup failed",
              cleanupError,
            );
            return json(503, {
              error: "Önceki doğrulama denemesi güvenli biçimde kapatılamadı",
            });
          }
        }
        if (!intent || intent.state === "cleanup_required") {
          return json(503, {
            error: "Önceki doğrulama denemesi güvenli biçimde kapatılamadı",
          });
        }
        if (intent.state === "pending") {
          return json(202, {
            accepted: true,
            verificationRequired: true,
            requestId,
            pendingRecoveryEmailMasked: maskEmail(recoveryEmail),
            message: "E-postanıza gönderilen doğrulama kodunu girin.",
          });
        }

        let verificationUserId: string;
        if (verificationKind === "existing_identity") {
          const { error: otpError } = await authClient.auth.signInWithOtp({
            email: recoveryEmail,
            options: { shouldCreateUser: false },
          });
          if (otpError) {
            console.error(
              "Existing recovery identity OTP request failed",
              otpError,
            );
            return json(400, { error: "Doğrulama kodu gönderilemedi" });
          }
          verificationUserId = profile.id;
        } else {
          const recovered = await admin.rpc(
            "service_recover_recovery_email_identity",
            {
              p_request_id: requestId,
            },
          );
          if (recovered.error) {
            console.error(
              "Recovery email identity recovery failed",
              recovered.error,
            );
            return json(503, {
              error: "Doğrulama kimliği şu anda hazırlanamadı",
            });
          }
          let identity = recovered.data as RecoveryEmailIdentity | null;
          let signupError: { code?: string; message: string } | null = null;
          let createdSignupUserId: string | null = null;
          let signupReturnedDuplicate = false;
          if (!identity) {
            const signup = await authClient.auth.signUp({
              email: recoveryEmail,
              password: randomStrongPassword(),
              options: {
                data: {
                  verification_only: true,
                  stokta_recovery_request_id: requestId,
                  target_user_id: profile.id,
                },
              },
            });
            signupError = signup.error;
            signupReturnedDuplicate =
              Array.isArray(signup.data.user?.identities) &&
              signup.data.user.identities.length === 0;
            createdSignupUserId = signupReturnedDuplicate
              ? null
              : signup.data.user?.id ?? null;
            if (signup.data.user) {
              const bound = await admin.rpc(
                "service_bind_recovery_email_identity",
                {
                  p_request_id: requestId,
                  p_verification_user_id: signup.data.user.id,
                },
              );
              if (bound.error) {
                console.error(
                  "Recovery email identity bind failed",
                  bound.error,
                );
                return json(503, {
                  error: "Doğrulama kimliği şu anda hazırlanamadı",
                });
              }
              identity = bound.data as RecoveryEmailIdentity | null;
            }
            if (!identity) {
              const retryRecovery = await admin.rpc(
                "service_recover_recovery_email_identity",
                {
                  p_request_id: requestId,
                },
              );
              if (retryRecovery.error) {
                return json(503, {
                  error: "Doğrulama kimliği şu anda hazırlanamadı",
                });
              }
              identity = retryRecovery.data as RecoveryEmailIdentity | null;
            }
            if (signup.data.session) {
              await authClient.auth.signOut({ scope: "local" });
            }
          }
          if (!identity) {
            const duplicate = signupReturnedDuplicate ||
              signupError?.code === "email_exists" ||
              signupError?.code === "user_already_exists" ||
              signupError?.message.toLowerCase().includes("registered") ||
              signupError?.message.toLowerCase().includes("already");
            if (createdSignupUserId) {
              const { error: deleteUnboundError } = await admin.auth.admin
                .deleteUser(createdSignupUserId);
              if (deleteUnboundError) {
                console.error(
                  "Unbound recovery email identity cleanup failed",
                  deleteUnboundError,
                );
                return json(503, {
                  error: "Doğrulama kimliği güvenli biçimde kapatılamadı",
                });
              }
            }
            try {
              await cleanupRecoveryEmailIntent(admin, requestId);
            } catch (cleanupError) {
              console.error(
                "Unbound recovery email intent cleanup failed",
                cleanupError,
              );
              return json(503, {
                error: "Doğrulama denemesi güvenli biçimde kapatılamadı",
              });
            }
            return json(duplicate ? 409 : 400, {
              error: duplicate
                ? "Bu e-posta adresi başka bir hesapta kullanılıyor"
                : "Doğrulama kodu gönderilemedi",
            });
          }
          if (identity.emailConfirmed) {
            try {
              await cleanupRecoveryEmailIntent(admin, requestId);
            } catch (cleanupError) {
              console.error(
                "Unexpected confirmed verification cleanup failed",
                cleanupError,
              );
              return json(503, {
                error: "Doğrulama kimliği güvenli biçimde kapatılamadı",
              });
            }
            return json(503, {
              error: "E-posta doğrulaması sunucuda etkin değil",
            });
          }

          const { data: temporaryUserData, error: temporaryUserError } =
            await admin.auth.admin.getUserById(identity.verificationUserId);
          const temporaryUser = temporaryUserData.user;
          if (temporaryUserError || !temporaryUser) {
            console.error(
              "Reserved recovery identity lookup failed",
              temporaryUserError,
            );
            return json(503, {
              error: "Doğrulama kimliği şu anda doğrulanamadı",
            });
          }
          if (
            temporaryUser.email?.toLowerCase() !== recoveryEmail ||
            temporaryUser.email_confirmed_at
          ) {
            return json(409, {
              error: "Bu e-posta adresi başka bir hesapta kullanılıyor",
            });
          }

          const { error: markerError } = await admin.auth.admin.updateUserById(
            temporaryUser.id,
            {
              app_metadata: {
                ...temporaryUser.app_metadata,
                stokta_verification_only: true,
                stokta_recovery_request_id: requestId,
                target_user_id: profile.id,
              },
            },
          );
          if (markerError) {
            console.error("Recovery email Auth marker failed", markerError);
            return json(503, {
              error: "Doğrulama isteği şu anda hazırlanamadı",
            });
          }
          verificationUserId = temporaryUser.id;
        }

        const { data: pendingStored, error: pendingError } = await admin.rpc(
          "service_store_recovery_email_verification",
          {
            p_target_user_id: profile.id,
            p_request_id: requestId,
            p_requested_session_id: sessionId,
            p_verification_user_id: verificationUserId,
            p_verification_kind: verificationKind,
            p_email: recoveryEmail,
          },
        );
        if (pendingError || pendingStored !== true) {
          console.error(
            "Recovery email verification could not be stored",
            pendingError,
          );
          const duplicate = pendingError?.code === "23505";
          if (duplicate) {
            try {
              await cleanupRecoveryEmailIntent(admin, requestId);
            } catch (cleanupError) {
              console.error(
                "Conflicting recovery email cleanup failed",
                cleanupError,
              );
              return json(503, {
                error:
                  "Çakışan doğrulama denemesi güvenli biçimde kapatılamadı",
              });
            }
          }
          return json(duplicate ? 409 : 503, {
            error: pendingError?.code === "23505"
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
          requestId,
          pendingRecoveryEmailMasked: maskEmail(recoveryEmail),
          message: "E-postanıza gönderilen doğrulama kodunu girin.",
        });
      }

      const newPassword = typeof body.newPassword === "string"
        ? body.newPassword
        : "";
      if (!isStrongPassword(newPassword)) {
        return json(400, {
          error:
            "Yeni şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli",
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
        console.error(
          "Password change pre-update session revocation failed",
          preChangeRevokeError,
        );
        return json(503, {
          error:
            "Açık oturumlar güvenli biçimde kapatılamadı; şifre değiştirilmedi",
        });
      }

      const { error: passwordError } = await admin.auth.admin.updateUserById(
        profile.id,
        {
          password: newPassword,
        },
      );
      if (passwordError) {
        console.error("Account password update failed", passwordError);
        return json(400, { error: "Şifre değiştirilemedi" });
      }
      const { error: completionError } = await admin.rpc(
        "service_complete_password_change",
        {
          p_user_id: profile.id,
        },
      );
      if (completionError) {
        console.error("Password change completion failed", completionError);
        return json(500, {
          error:
            "Şifre değişti ancak oturumlar kapatılamadı. Yeniden giriş yapın.",
        });
      }

      return json(200, { updated: true, reauthenticationRequired: true });
    } finally {
      await authClient.auth.signOut({ scope: "local" });
    }
  } catch (error) {
    const inputError = requestBodyErrorResponse(error);
    if (inputError) return inputError;
    console.error("Account security operation failed", error);
    return json(500, { error: "Hesap güvenliği işlemi tamamlanamadı" });
  }
});
