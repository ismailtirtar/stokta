import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  isStrongPassword,
  json,
  normalizeRecoveryEmail,
  normalizeUsername,
  normalizeUuid,
  readJsonObject,
  requestBodyErrorResponse,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

type PendingRow = { id: string; auth_user_id: string; expires_at: string };

type RegistrationIntent = {
  state: "reserved" | "bound" | "pending" | "cleanup_required";
  requestId: string;
  authUserId?: string | null;
};

type RegistrationIdentity = {
  authUserId: string;
  emailConfirmed: boolean;
  createdAt: string;
};

const CURRENT_UGC_TERMS_VERSION = "2026-09-11-v2";

async function removeExpiredPending(
  admin: any,
  rows: PendingRow[],
) {
  for (const row of rows) {
    if (new Date(row.expires_at).getTime() > Date.now()) continue;
    const { data: claim, error: claimError } = await admin.rpc(
      "service_claim_expired_pending_registration",
      { p_auth_user_id: row.auth_user_id },
    );
    if (claimError) throw claimError;
    if (claim?.claimed === true && claim.userId === row.auth_user_id) {
      const { error: deleteError } = await admin.auth.admin.deleteUser(
        row.auth_user_id,
      );
      if (deleteError) throw deleteError;
    }
  }
}

async function cleanupRegistrationIntent(admin: any, requestId: string) {
  const { data: claim, error: claimError } = await admin.rpc(
    "service_claim_registration_intent_cleanup",
    { p_request_id: requestId },
  );
  if (claimError || !claim) {
    throw claimError ?? new Error("Registration cleanup was not authorized");
  }
  if (claim.finished === true) return;
  if (typeof claim.userId !== "string") {
    throw new Error("Registration cleanup identity is missing");
  }

  const { error: deleteError } = await admin.auth.admin.deleteUser(
    claim.userId,
  );
  if (deleteError) throw deleteError;
  const { data: finished, error: finishError } = await admin.rpc(
    "service_finish_registration_intent_cleanup",
    { p_request_id: requestId, p_auth_user_id: claim.userId },
  );
  if (finishError || finished !== true) {
    throw finishError ??
      new Error("Registration cleanup could not be committed");
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

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: userData, error: userError } = await admin.auth.getUser(
      token,
    );
    if (userError || !userData.user) {
      return json(401, { error: "Geçersiz oturum" });
    }
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc(
      "service_has_live_session",
      {
        p_user_id: userData.user.id,
        p_session_id: sessionId,
      },
    );
    if (liveSessionError || !liveSession) {
      return json(401, { error: "Oturum sona erdi" });
    }

    const { data: caller, error: callerError } = await admin
      .from("profiles")
      .select(
        "id,role,organization_id,ugc_terms_version,ugc_terms_accepted_at,is_active,must_change_password",
      )
      .eq("id", userData.user.id)
      .eq("is_active", true)
      .maybeSingle();
    if (callerError) throw callerError;
    if (!caller || caller.role !== "admin" || caller.must_change_password) {
      return json(403, {
        error: "Bu işlem yalnızca işletme yöneticisine açıktır",
      });
    }
    if (
      !caller.ugc_terms_accepted_at ||
      caller.ugc_terms_version !== CURRENT_UGC_TERMS_VERSION
    ) {
      return json(403, {
        error:
          "Çalışan eklemek için güncel Kullanım Koşulları ve Topluluk Kuralları kabul edilmelidir",
      });
    }

    const { data: organization, error: organizationError } = await admin
      .from("organizations")
      .select(
        "id,subscription_status,trial_ends_at,current_period_end,max_members",
      )
      .eq("id", caller.organization_id)
      .single();
    if (organizationError || !organization) {
      return json(404, { error: "İşletme bulunamadı" });
    }

    const now = Date.now();
    const trialExpired = organization.subscription_status === "trial" &&
      (!organization.trial_ends_at ||
        new Date(organization.trial_ends_at).getTime() <= now);
    const periodExpired = organization.subscription_status === "active" &&
      organization.current_period_end &&
      new Date(organization.current_period_end).getTime() <= now;
    if (
      trialExpired || periodExpired ||
      !["trial", "active"].includes(organization.subscription_status)
    ) {
      return json(403, {
        error: "İşletmenin kiralama durumu yeni çalışan eklemeye açık değil",
      });
    }

    const body = await readJsonObject(req, 8 * 1024);
    const username = normalizeUsername(body.username);
    const displayName = typeof body.displayName === "string"
      ? body.displayName.trim()
      : "";
    const recoveryEmail = normalizeRecoveryEmail(body.recoveryEmail);
    const password = typeof body.password === "string" ? body.password : "";
    const normalizedRequestId = normalizeUuid(body.requestId);
    if (body.requestId !== undefined && !normalizedRequestId) {
      return json(400, { error: "İstek kimliği geçerli bir UUID olmalıdır" });
    }
    let requestId = normalizedRequestId ?? crypto.randomUUID();

    if (!username) {
      return json(400, {
        error:
          "Kullanıcı adı 3-32 karakter olmalı; yalnızca a-z, 0-9, nokta, alt çizgi ve tire kullanılabilir",
      });
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return json(400, { error: "Görünen ad 1-80 karakter olmalı" });
    }
    if (!recoveryEmail) {
      return json(400, { error: "Geçerli bir çalışan e-postası girin" });
    }
    if (!isStrongPassword(password)) {
      return json(400, {
        error:
          "Geçici şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli",
      });
    }

    const { data: replay, error: replayError } = await admin
      .from("pending_account_registrations")
      .select(
        "request_id,registration_kind,username,email,display_name,organization_id,created_by,expires_at,cleanup_claimed_at",
      )
      .eq("request_id", requestId)
      .maybeSingle();
    if (replayError) {
      return json(503, {
        error: "Çalışan ekleme hizmeti şu anda kullanılamıyor",
      });
    }
    if (replay) {
      const exactReplay = replay.registration_kind === "coworker" &&
        replay.username === username &&
        replay.email === recoveryEmail &&
        replay.display_name === displayName &&
        replay.organization_id === caller.organization_id &&
        replay.created_by === caller.id &&
        !replay.cleanup_claimed_at &&
        new Date(replay.expires_at).getTime() > Date.now();
      if (!exactReplay) {
        return json(409, {
          error: "İstek kimliği farklı bir çalışan daveti için kullanılmış",
        });
      }
      return json(202, {
        accepted: true,
        verificationRequired: true,
        requestId,
        username,
        displayName,
        message: "Çalışanın e-postasına doğrulama kodu gönderildi.",
      });
    }

    const ip = requestIp(req);
    const [actorHash, emailHash, ipHash] = await Promise.all([
      sha256(
        `stokta:coworker-create-actor:v1:${caller.id}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:coworker-create-email:v1:${recoveryEmail}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:coworker-create-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`,
      ),
    ]);
    const createLimits = await Promise.all([
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "coworker-create-actor",
        p_key_hash: actorHash,
        p_max_attempts: 20,
        p_window_seconds: 3600,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "coworker-create-email",
        p_key_hash: emailHash,
        p_max_attempts: 3,
        p_window_seconds: 3600,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "coworker-create-ip",
        p_key_hash: ipHash,
        p_max_attempts: 50,
        p_window_seconds: 3600,
      }),
    ]);
    if (createLimits.some((limit) => limit.error)) {
      console.error("Coworker creation rate limiter unavailable");
      return json(503, {
        error: "Çalışan ekleme hizmeti şu anda kullanılamıyor",
      });
    }
    if (createLimits.some((limit) => limit.data !== true)) {
      return json(429, {
        error:
          "Çok fazla çalışan daveti gönderildi. Lütfen daha sonra tekrar deneyin.",
      });
    }

    const [existingProfileResult, usernamePending, emailPending] = await Promise
      .all([
        admin.from("profiles").select("id").eq("username", username)
          .maybeSingle(),
        admin.from("pending_account_registrations")
          .select("id,auth_user_id,expires_at").eq("username", username),
        admin.from("pending_account_registrations")
          .select("id,auth_user_id,expires_at").eq("email", recoveryEmail),
      ]);
    if (
      existingProfileResult.error || usernamePending.error || emailPending.error
    ) {
      console.error("Coworker uniqueness lookup failed", {
        profile: existingProfileResult.error,
        username: usernamePending.error,
        email: emailPending.error,
      });
      return json(503, {
        error: "Çalışan ekleme hizmeti şu anda kullanılamıyor",
      });
    }
    const existingProfile = existingProfileResult.data;
    if (existingProfile) {
      return json(409, { error: "Bu kullanıcı adı zaten kullanılıyor" });
    }

    const pendingById = new Map<string, PendingRow>();
    for (
      const row of [
        ...(usernamePending.data ?? []),
        ...(emailPending.data ?? []),
      ] as PendingRow[]
    ) {
      pendingById.set(row.id, row);
    }
    await removeExpiredPending(admin, [...pendingById.values()]);

    const [liveUsernameResult, liveEmailResult] = await Promise.all([
      admin.from("pending_account_registrations").select(
        "id,request_id,registration_kind,username,email,display_name,organization_id,created_by,expires_at,cleanup_claimed_at",
      ).eq("username", username).maybeSingle(),
      admin.from("pending_account_registrations").select(
        "id,request_id,registration_kind,username,email,display_name,organization_id,created_by,expires_at,cleanup_claimed_at",
      ).eq("email", recoveryEmail).maybeSingle(),
    ]);
    if (liveUsernameResult.error || liveEmailResult.error) {
      return json(503, {
        error: "Çalışan ekleme hizmeti şu anda kullanılamıyor",
      });
    }
    const liveUsernamePending = liveUsernameResult.data;
    const liveEmailPending = liveEmailResult.data;
    if (liveUsernamePending || liveEmailPending) {
      const sameRow = !liveUsernamePending || !liveEmailPending ||
        liveUsernamePending.id === liveEmailPending.id;
      const candidate = liveUsernamePending ?? liveEmailPending;
      const exactResume = sameRow && candidate &&
        candidate.registration_kind === "coworker" &&
        candidate.username === username &&
        candidate.email === recoveryEmail &&
        candidate.display_name === displayName &&
        candidate.organization_id === caller.organization_id &&
        candidate.created_by === caller.id &&
        !candidate.cleanup_claimed_at &&
        new Date(candidate.expires_at).getTime() > Date.now() &&
        normalizeUuid(candidate.request_id);
      if (exactResume) {
        requestId = candidate.request_id;
        return json(202, {
          accepted: true,
          verificationRequired: true,
          requestId,
          username,
          displayName,
          message: "Çalışanın e-postasına doğrulama kodu gönderildi.",
        });
      }
      return json(409, {
        error: liveUsernamePending
          ? "Bu kullanıcı adı için doğrulama zaten bekleniyor"
          : "Bu e-posta için doğrulama zaten bekleniyor",
      });
    }

    const beginArgs = {
      p_request_id: requestId,
      p_registration_kind: "coworker",
      p_username: username,
      p_email: recoveryEmail,
      p_display_name: displayName,
      p_organization_name: null,
      p_organization_slug: null,
      p_organization_id: caller.organization_id,
      p_created_by: caller.id,
      p_requested_session_id: sessionId,
      p_ugc_terms_version: null,
    };
    let intent: RegistrationIntent | null = null;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const { data, error } = await admin.rpc(
        "service_begin_registration_intent",
        beginArgs,
      );
      if (error) {
        console.error(
          "Coworker registration intent could not be reserved",
          error,
        );
        return json(error.code === "23505" ? 409 : 503, {
          error: error.code === "23505"
            ? "Kullanıcı adı veya e-posta zaten kullanılıyor"
            : "Çalışan ekleme hizmeti şu anda kullanılamıyor",
        });
      }
      intent = data as RegistrationIntent | null;
      if (!intent) {
        return json(503, {
          error: "Çalışan daveti güvenli biçimde oluşturulamadı",
        });
      }
      const canonicalRequestId = normalizeUuid(intent.requestId);
      if (!canonicalRequestId) {
        return json(503, { error: "Çalışan daveti doğrulanamadı" });
      }
      requestId = canonicalRequestId;
      if (intent.state !== "cleanup_required") break;
      try {
        await cleanupRegistrationIntent(admin, intent.requestId);
      } catch (cleanupError) {
        console.error(
          "Expired coworker registration intent cleanup failed",
          cleanupError,
        );
        return json(503, {
          error: "Önceki çalışan daveti güvenli biçimde kapatılamadı",
        });
      }
    }
    if (!intent || intent.state === "cleanup_required") {
      return json(503, {
        error: "Önceki çalışan daveti güvenli biçimde kapatılamadı",
      });
    }
    if (intent.state === "pending") {
      return json(202, {
        accepted: true,
        verificationRequired: true,
        requestId,
        username,
        displayName,
        message: "Çalışanın e-postasına doğrulama kodu gönderildi.",
      });
    }

    let identity: RegistrationIdentity | null = null;
    const recovered = await admin.rpc("service_recover_registration_identity", {
      p_request_id: requestId,
    });
    if (recovered.error) {
      console.error(
        "Coworker registration identity recovery failed",
        recovered.error,
      );
      return json(503, { error: "Çalışan kimliği şu anda hazırlanamadı" });
    }
    identity = recovered.data as RegistrationIdentity | null;

    if (!identity) {
      const { data: signupData, error: signupError } = await authClient.auth
        .signUp({
          email: recoveryEmail,
          password,
          options: {
            data: {
              display_name: displayName,
              stokta_registration_request_id: requestId,
              organization_id: caller.organization_id,
            },
          },
        });

      if (signupData.user) {
        const bound = await admin.rpc("service_bind_registration_identity", {
          p_request_id: requestId,
          p_auth_user_id: signupData.user.id,
        });
        if (bound.error) {
          console.error(
            "Coworker registration identity bind failed",
            bound.error,
          );
          return json(503, { error: "Çalışan kimliği şu anda hazırlanamadı" });
        }
        identity = bound.data as RegistrationIdentity | null;
      }
      if (!identity) {
        const retryRecovery = await admin.rpc(
          "service_recover_registration_identity",
          {
            p_request_id: requestId,
          },
        );
        if (retryRecovery.error) {
          return json(503, { error: "Çalışan kimliği şu anda hazırlanamadı" });
        }
        identity = retryRecovery.data as RegistrationIdentity | null;
      }
      if (!identity) {
        const signupReturnedDuplicate =
          Array.isArray(signupData.user?.identities) &&
          signupData.user.identities.length === 0;
        const duplicate = signupReturnedDuplicate ||
          signupError?.code === "user_already_exists" ||
          signupError?.message.toLowerCase().includes("registered") ||
          signupError?.message.toLowerCase().includes("already");
        try {
          await cleanupRegistrationIntent(admin, requestId);
        } catch (cleanupError) {
          console.error(
            "Unbound coworker registration intent cleanup failed",
            cleanupError,
          );
          return json(503, {
            error: "Çalışan daveti güvenli biçimde kapatılamadı",
          });
        }
        return json(duplicate ? 409 : 400, {
          error: duplicate
            ? "Bu e-posta adresi kullanılamıyor"
            : "Doğrulama e-postası gönderilemedi",
        });
      }
      if (signupData.session) await authClient.auth.signOut({ scope: "local" });
    }

    if (identity.emailConfirmed) {
      try {
        await cleanupRegistrationIntent(admin, requestId);
      } catch (cleanupError) {
        console.error(
          "Unexpected confirmed coworker cleanup failed",
          cleanupError,
        );
        return json(503, {
          error: "Doğrulanmış çalışan kimliği güvenli biçimde kapatılamadı",
        });
      }
      return json(503, {
        error:
          "E-posta doğrulaması sunucuda etkinleştirilmeden çalışan eklenemez",
      });
    }

    const { data: createdUserData, error: createdUserError } = await admin.auth
      .admin.getUserById(identity.authUserId);
    const createdUser = createdUserData.user;
    if (createdUserError || !createdUser) {
      console.error(
        "Reserved coworker identity lookup failed",
        createdUserError,
      );
      return json(503, { error: "Çalışan kimliği şu anda doğrulanamadı" });
    }
    if (
      createdUser.email?.toLowerCase() !== recoveryEmail ||
      createdUser.email_confirmed_at
    ) {
      return json(409, {
        error: "Çalışan kimliği beklenen e-posta ile eşleşmiyor",
      });
    }

    const { error: markerError } = await admin.auth.admin.updateUserById(
      createdUser.id,
      {
        app_metadata: {
          ...createdUser.app_metadata,
          stokta_pending_registration: "coworker",
          stokta_registration_request_id: requestId,
          organization_id: caller.organization_id,
          created_by: caller.id,
          username,
        },
      },
    );
    if (markerError) {
      console.error("Coworker registration Auth marker failed", markerError);
      return json(503, { error: "Çalışan doğrulaması şu anda hazırlanamadı" });
    }

    const { data: pendingId, error: pendingError } = await admin.rpc(
      "service_store_pending_registration",
      {
        p_auth_user_id: createdUser.id,
        p_request_id: requestId,
        p_registration_kind: "coworker",
        p_username: username,
        p_email: recoveryEmail,
        p_display_name: displayName,
        p_organization_name: null,
        p_organization_slug: null,
        p_organization_id: caller.organization_id,
        p_created_by: caller.id,
        p_ugc_terms_version: null,
        p_ugc_terms_accepted_at: null,
        p_ugc_terms_digest: null,
      },
    );
    if (pendingError || !pendingId) {
      console.error(
        "Pending coworker registration could not be stored",
        pendingError,
      );
      const duplicate = pendingError?.code === "23505";
      if (duplicate) {
        try {
          await cleanupRegistrationIntent(admin, requestId);
        } catch (cleanupError) {
          console.error(
            "Conflicting coworker registration cleanup failed",
            cleanupError,
          );
          return json(503, {
            error: "Çakışan çalışan daveti güvenli biçimde kapatılamadı",
          });
        }
      }
      return json(duplicate ? 409 : 503, {
        error: duplicate
          ? "Kullanıcı adı veya e-posta zaten kullanılıyor"
          : "Çalışan doğrulaması hazırlanamadı",
      });
    }

    await admin.rpc("service_record_security_event", {
      p_event_type: "coworker.registration_requested",
      p_organization_id: caller.organization_id,
      p_actor_id: caller.id,
      p_subject_id: createdUser.id,
      p_ip_hash: ipHash,
      p_metadata: { username },
    });

    return json(202, {
      accepted: true,
      verificationRequired: true,
      requestId,
      username,
      displayName,
      message: "Çalışanın e-postasına doğrulama kodu gönderildi.",
    });
  } catch (error) {
    const inputError = requestBodyErrorResponse(error);
    if (inputError) return inputError;
    console.error("Coworker registration failed", error);
    return json(500, { error: "Çalışan ekleme başlatılamadı" });
  }
});
