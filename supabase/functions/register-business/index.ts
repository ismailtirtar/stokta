import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  isStrongPassword,
  json,
  normalizeRecoveryEmail,
  normalizeUsername,
  normalizeUuid,
  readJsonObject,
  requestBodyErrorResponse,
  requestIp,
  sha256,
} from "../_shared/security.ts";

type PendingRow = {
  id: string;
  auth_user_id: string;
  expires_at: string;
};

type RegistrationIntent = {
  state: "reserved" | "bound" | "pending" | "cleanup_required";
  requestId: string;
  authUserId?: string | null;
  acceptedAt?: string | null;
  organizationSlug?: string | null;
};

type RegistrationIdentity = {
  authUserId: string;
  emailConfirmed: boolean;
  createdAt: string;
};

const CURRENT_UGC_TERMS_VERSION = "2026-09-11-v2";
const CURRENT_UGC_TERMS_DIGEST =
  "062c24aec9fcfb9a2eda5ede2c7c0e833b40b4c80ff0c35cde46f7ed3f9560fe";

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
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const body = await readJsonObject(req, 8 * 1024);
    const organizationName = typeof body.organizationName === "string"
      ? body.organizationName.trim()
      : "";
    const displayName = typeof body.displayName === "string"
      ? body.displayName.trim()
      : "";
    const username = normalizeUsername(body.username);
    const recoveryEmail = normalizeRecoveryEmail(body.recoveryEmail);
    const password = typeof body.password === "string" ? body.password : "";
    const ugcTermsAccepted = body.ugcTermsAccepted === true;
    const ugcTermsVersion = typeof body.ugcTermsVersion === "string"
      ? body.ugcTermsVersion
      : "";
    const ugcTermsDigest = typeof body.ugcTermsDigest === "string"
      ? body.ugcTermsDigest
      : "";
    const normalizedRequestId = normalizeUuid(body.requestId);
    if (body.requestId !== undefined && !normalizedRequestId) {
      return json(400, { error: "İstek kimliği geçerli bir UUID olmalıdır" });
    }
    let requestId = normalizedRequestId ?? crypto.randomUUID();

    if (
      !ugcTermsAccepted ||
      ugcTermsVersion !== CURRENT_UGC_TERMS_VERSION ||
      ugcTermsDigest !== CURRENT_UGC_TERMS_DIGEST
    ) {
      return json(400, {
        error:
          "Güncel Kullanım Koşulları ve Topluluk Kuralları kabul edilmelidir",
      });
    }
    if (organizationName.length < 2 || organizationName.length > 100) {
      return json(400, { error: "İşletme adı 2-100 karakter olmalı" });
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return json(400, { error: "Ad ve soyad 1-80 karakter olmalı" });
    }
    if (!username) {
      return json(400, {
        error:
          "Kullanıcı adı 3-32 karakter olmalı; yalnızca a-z, 0-9, nokta, alt çizgi ve tire kullanılabilir",
      });
    }
    if (!recoveryEmail) {
      return json(400, { error: "Geçerli bir e-posta adresi girin" });
    }
    if (!isStrongPassword(password)) {
      return json(400, {
        error:
          "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli",
      });
    }
    let organizationSlug = `${slugBase(organizationName)}-${
      requestId.replaceAll("-", "").slice(0, 8)
    }`
      .slice(0, 48);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: replay, error: replayError } = await admin
      .from("pending_account_registrations")
      .select(
        "request_id,registration_kind,username,email,display_name,organization_name,expires_at,cleanup_claimed_at",
      )
      .eq("request_id", requestId)
      .maybeSingle();
    if (replayError) {
      return json(503, { error: "Kayıt hizmeti şu anda kullanılamıyor" });
    }
    if (replay) {
      const exactReplay = replay.registration_kind === "business_admin" &&
        replay.username === username &&
        replay.email === recoveryEmail &&
        replay.display_name === displayName &&
        replay.organization_name === organizationName &&
        !replay.cleanup_claimed_at &&
        new Date(replay.expires_at).getTime() > Date.now();
      if (!exactReplay) {
        return json(409, {
          error: "İstek kimliği farklı bir kayıt için kullanılmış",
        });
      }
      return json(202, {
        accepted: true,
        verificationRequired: true,
        requestId,
        username,
        message: "E-postanıza gönderilen doğrulama kodunu girin.",
      });
    }

    const ip = requestIp(req);
    const [ipHash, accountHash, emailHash] = await Promise.all([
      sha256(
        `stokta:self-register-ip:v2:${ip}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:self-register-account:v2:${username}:${supabaseUrl}:${serviceRoleKey}`,
      ),
      sha256(
        `stokta:self-register-email:v2:${recoveryEmail}:${supabaseUrl}:${serviceRoleKey}`,
      ),
    ]);
    const [
      { data: ipAllowed, error: signupRateError },
      { data: accountAllowed, error: accountRateError },
      { data: emailAllowed, error: emailRateError },
    ] = await Promise.all([
      admin.rpc("consume_signup_rate_limit", { p_key_hash: ipHash }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "business-register-account",
        p_key_hash: accountHash,
        p_max_attempts: 5,
        p_window_seconds: 3600,
      }),
      admin.rpc("consume_auth_rate_limit", {
        p_scope: "business-register-email",
        p_key_hash: emailHash,
        p_max_attempts: 3,
        p_window_seconds: 3600,
      }),
    ]);
    if (signupRateError || accountRateError || emailRateError) {
      console.error("Registration rate limiter unavailable", {
        signupRateError,
        accountRateError,
        emailRateError,
      });
      return json(503, { error: "Kayıt hizmeti şu anda kullanılamıyor" });
    }
    if (!ipAllowed || !accountAllowed || !emailAllowed) {
      return json(429, {
        error:
          "Çok fazla kayıt denemesi yapıldı. Lütfen daha sonra tekrar deneyin.",
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
      console.error("Registration uniqueness lookup failed", {
        profile: existingProfileResult.error,
        username: usernamePending.error,
        email: emailPending.error,
      });
      return json(503, { error: "Kayıt hizmeti şu anda kullanılamıyor" });
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
        "id,request_id,registration_kind,username,email,display_name,organization_name,expires_at,cleanup_claimed_at",
      ).eq("username", username).maybeSingle(),
      admin.from("pending_account_registrations").select(
        "id,request_id,registration_kind,username,email,display_name,organization_name,expires_at,cleanup_claimed_at",
      ).eq("email", recoveryEmail).maybeSingle(),
    ]);
    if (liveUsernameResult.error || liveEmailResult.error) {
      return json(503, { error: "Kayıt hizmeti şu anda kullanılamıyor" });
    }
    const liveUsernamePending = liveUsernameResult.data;
    const liveEmailPending = liveEmailResult.data;
    if (liveUsernamePending || liveEmailPending) {
      const sameRow = !liveUsernamePending || !liveEmailPending ||
        liveUsernamePending.id === liveEmailPending.id;
      const candidate = liveUsernamePending ?? liveEmailPending;
      const exactResume = sameRow && candidate &&
        candidate.registration_kind === "business_admin" &&
        candidate.username === username &&
        candidate.email === recoveryEmail &&
        candidate.display_name === displayName &&
        candidate.organization_name === organizationName &&
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
          message: "E-postanıza gönderilen doğrulama kodunu girin.",
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
      p_registration_kind: "business_admin",
      p_username: username,
      p_email: recoveryEmail,
      p_display_name: displayName,
      p_organization_name: organizationName,
      p_organization_slug: organizationSlug,
      p_organization_id: null,
      p_created_by: null,
      p_requested_session_id: null,
      p_ugc_terms_version: CURRENT_UGC_TERMS_VERSION,
    };
    let intent: RegistrationIntent | null = null;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const { data, error } = await admin.rpc(
        "service_begin_registration_intent",
        beginArgs,
      );
      if (error) {
        console.error(
          "Business registration intent could not be reserved",
          error,
        );
        return json(error.code === "23505" ? 409 : 503, {
          error: error.code === "23505"
            ? "Kullanıcı adı veya e-posta zaten kullanılıyor"
            : "Kayıt hizmeti şu anda kullanılamıyor",
        });
      }
      intent = data as RegistrationIntent | null;
      if (!intent) {
        return json(503, {
          error: "Kayıt niyeti güvenli biçimde oluşturulamadı",
        });
      }
      const canonicalRequestId = normalizeUuid(intent.requestId);
      if (!canonicalRequestId) {
        return json(503, { error: "Kayıt isteği doğrulanamadı" });
      }
      requestId = canonicalRequestId;
      if (intent.organizationSlug !== undefined) {
        if (
          typeof intent.organizationSlug !== "string" ||
          !/^[a-z0-9][a-z0-9-]{2,47}$/.test(intent.organizationSlug)
        ) {
          return json(503, { error: "Kayıt işletmesi doğrulanamadı" });
        }
        organizationSlug = intent.organizationSlug;
      }
      if (intent.state !== "cleanup_required") break;
      try {
        await cleanupRegistrationIntent(admin, intent.requestId);
      } catch (cleanupError) {
        console.error(
          "Expired business registration intent cleanup failed",
          cleanupError,
        );
        return json(503, {
          error: "Önceki kayıt denemesi güvenli biçimde kapatılamadı",
        });
      }
    }
    if (!intent || intent.state === "cleanup_required") {
      return json(503, {
        error: "Önceki kayıt denemesi güvenli biçimde kapatılamadı",
      });
    }
    if (intent.state === "pending") {
      return json(202, {
        accepted: true,
        verificationRequired: true,
        requestId,
        username,
        message: "E-postanıza gönderilen doğrulama kodunu girin.",
      });
    }

    let identity: RegistrationIdentity | null = null;
    const recovered = await admin.rpc("service_recover_registration_identity", {
      p_request_id: requestId,
    });
    if (recovered.error) {
      console.error(
        "Business registration identity recovery failed",
        recovered.error,
      );
      return json(503, { error: "Kayıt kimliği şu anda hazırlanamadı" });
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
            "Business registration identity bind failed",
            bound.error,
          );
          return json(503, { error: "Kayıt kimliği şu anda hazırlanamadı" });
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
          return json(503, { error: "Kayıt kimliği şu anda hazırlanamadı" });
        }
        identity = retryRecovery.data as RegistrationIdentity | null;
      }
      if (!identity) {
        const signupReturnedDuplicate =
          Array.isArray(signupData.user?.identities) &&
          signupData.user.identities.length === 0;
        const duplicate = signupReturnedDuplicate ||
          signupError?.code === "email_exists" ||
          signupError?.code === "user_already_exists" ||
          signupError?.message.toLowerCase().includes("registered") ||
          signupError?.message.toLowerCase().includes("already");
        try {
          await cleanupRegistrationIntent(admin, requestId);
        } catch (cleanupError) {
          console.error(
            "Unbound business registration intent cleanup failed",
            cleanupError,
          );
          return json(503, {
            error: "Kayıt denemesi güvenli biçimde kapatılamadı",
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

    // A confirmed sign-up means project-level email confirmations are disabled.
    // The durable receipt lets cleanup be retried without losing the identity.
    if (identity.emailConfirmed) {
      try {
        await cleanupRegistrationIntent(admin, requestId);
      } catch (cleanupError) {
        console.error(
          "Unexpected confirmed registration cleanup failed",
          cleanupError,
        );
        return json(503, {
          error: "Doğrulanmamış kayıt kimliği güvenli biçimde kapatılamadı",
        });
      }
      return json(503, {
        error: "E-posta doğrulaması sunucuda etkinleştirilmeden kayıt açılamaz",
      });
    }

    const { data: createdUserData, error: createdUserError } = await admin.auth
      .admin.getUserById(identity.authUserId);
    const createdUser = createdUserData.user;
    if (createdUserError || !createdUser) {
      console.error(
        "Reserved business identity lookup failed",
        createdUserError,
      );
      return json(503, { error: "Kayıt kimliği şu anda doğrulanamadı" });
    }
    if (
      createdUser.email?.toLowerCase() !== recoveryEmail ||
      createdUser.email_confirmed_at
    ) {
      return json(409, {
        error: "Kayıt kimliği beklenen e-posta ile eşleşmiyor",
      });
    }

    const { error: markerError } = await admin.auth.admin.updateUserById(
      createdUser.id,
      {
        app_metadata: {
          ...createdUser.app_metadata,
          stokta_pending_registration: "business_admin",
          stokta_registration_request_id: requestId,
          username,
        },
      },
    );
    if (markerError) {
      console.error("Business registration Auth marker failed", markerError);
      return json(503, { error: "Kayıt doğrulaması şu anda hazırlanamadı" });
    }

    const { data: pendingId, error: pendingError } = await admin.rpc(
      "service_store_pending_registration",
      {
        p_auth_user_id: createdUser.id,
        p_request_id: requestId,
        p_registration_kind: "business_admin",
        p_username: username,
        p_email: recoveryEmail,
        p_display_name: displayName,
        p_organization_name: organizationName,
        p_organization_slug: organizationSlug,
        p_organization_id: null,
        p_created_by: null,
        p_ugc_terms_version: CURRENT_UGC_TERMS_VERSION,
        p_ugc_terms_accepted_at: intent.acceptedAt ?? new Date().toISOString(),
        p_ugc_terms_digest: CURRENT_UGC_TERMS_DIGEST,
      },
    );
    if (pendingError || !pendingId) {
      console.error(
        "Pending business registration could not be stored",
        pendingError,
      );
      const duplicate = pendingError?.code === "23505";
      if (duplicate) {
        try {
          await cleanupRegistrationIntent(admin, requestId);
        } catch (cleanupError) {
          console.error(
            "Conflicting business registration cleanup failed",
            cleanupError,
          );
          return json(503, {
            error: "Çakışan kayıt denemesi güvenli biçimde kapatılamadı",
          });
        }
      }
      return json(duplicate ? 409 : 503, {
        error: duplicate
          ? "Kullanıcı adı veya e-posta zaten kullanılıyor"
          : "Kayıt doğrulaması hazırlanamadı",
      });
    }

    await admin.rpc("service_record_security_event", {
      p_event_type: "business.registration_requested",
      p_subject_id: createdUser.id,
      p_ip_hash: ipHash,
      p_metadata: { username },
    });

    return json(202, {
      accepted: true,
      verificationRequired: true,
      requestId,
      username,
      message: "E-postanıza gönderilen doğrulama kodunu girin.",
    });
  } catch (error) {
    const inputError = requestBodyErrorResponse(error);
    if (inputError) return inputError;
    console.error("Self-service registration failed", error);
    return json(500, { error: "Kayıt başlatılamadı. Lütfen tekrar deneyin." });
  }
});
