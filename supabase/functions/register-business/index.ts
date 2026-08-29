import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  corsJsonHeaders,
  isStrongPassword,
  json,
  normalizeRecoveryEmail,
  normalizeUsername,
  requestIp,
  sha256,
} from "../_shared/security.ts";

type PendingRow = {
  id: string;
  auth_user_id: string;
  expires_at: string;
};

const CURRENT_UGC_TERMS_VERSION = "2026-08-29-v1";

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
    const { data: profile } = await admin
      .from("profiles")
      .select("id")
      .eq("id", row.auth_user_id)
      .maybeSingle();
    if (!profile) {
      const { data: userData } = await admin.auth.admin.getUserById(row.auth_user_id);
      if (userData.user?.app_metadata?.stokta_pending_registration) {
        await admin.auth.admin.deleteUser(row.auth_user_id);
      }
    }
    await admin.from("pending_account_registrations").delete().eq("id", row.id);
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  try {
    const startedAt = Date.now();
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!supabaseUrl || !serviceRoleKey || !anonKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const body = await req.json() as Record<string, unknown>;
    const organizationName = typeof body.organizationName === "string" ? body.organizationName.trim() : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const username = normalizeUsername(body.username);
    const recoveryEmail = normalizeRecoveryEmail(body.recoveryEmail);
    const password = typeof body.password === "string" ? body.password : "";
    const ugcTermsAccepted = body.ugcTermsAccepted === true;
    const ugcTermsVersion = typeof body.ugcTermsVersion === "string" ? body.ugcTermsVersion : "";

    if (!ugcTermsAccepted || ugcTermsVersion !== CURRENT_UGC_TERMS_VERSION) {
      return json(400, { error: "Güncel Kullanım Koşulları ve Topluluk Kuralları kabul edilmelidir" });
    }
    if (organizationName.length < 2 || organizationName.length > 100) {
      return json(400, { error: "İşletme adı 2-100 karakter olmalı" });
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return json(400, { error: "Ad ve soyad 1-80 karakter olmalı" });
    }
    if (!username) {
      return json(400, { error: "Kullanıcı adı 3-32 karakter olmalı; yalnızca a-z, 0-9, nokta, alt çizgi ve tire kullanılabilir" });
    }
    if (!recoveryEmail) {
      return json(400, { error: "Geçerli bir e-posta adresi girin" });
    }
    if (!isStrongPassword(password)) {
      return json(400, { error: "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli" });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const ip = requestIp(req);
    const [ipHash, accountHash, emailHash] = await Promise.all([
      sha256(`stokta:self-register-ip:v2:${ip}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:self-register-account:v2:${username}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:self-register-email:v2:${recoveryEmail}:${supabaseUrl}:${serviceRoleKey}`),
    ]);
    const [
      { data: ipAllowed, error: signupRateError },
      { data: accountAllowed, error: accountRateError },
      { data: emailAllowed, error: emailRateError },
    ] =
      await Promise.all([
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
      return json(429, { error: "Çok fazla kayıt denemesi yapıldı. Lütfen daha sonra tekrar deneyin." });
    }

    const [{ data: existingProfile }, usernamePending, emailPending] = await Promise.all([
      admin.from("profiles").select("id").eq("username", username).maybeSingle(),
      admin.from("pending_account_registrations")
        .select("id,auth_user_id,expires_at").eq("username", username),
      admin.from("pending_account_registrations")
        .select("id,auth_user_id,expires_at").eq("email", recoveryEmail),
    ]);
    if (existingProfile) return json(409, { error: "Bu kullanıcı adı zaten kullanılıyor" });

    const pendingById = new Map<string, PendingRow>();
    for (const row of [...(usernamePending.data ?? []), ...(emailPending.data ?? [])] as PendingRow[]) {
      pendingById.set(row.id, row);
    }
    await removeExpiredPending(admin, [...pendingById.values()]);

    const [{ data: liveUsernamePending }, { data: liveEmailPending }] = await Promise.all([
      admin.from("pending_account_registrations").select("id").eq("username", username).maybeSingle(),
      admin.from("pending_account_registrations").select("id").eq("email", recoveryEmail).maybeSingle(),
    ]);
    if (liveUsernamePending) return json(409, { error: "Bu kullanıcı adı için doğrulama zaten bekleniyor" });
    if (liveEmailPending) return json(409, { error: "Bu e-posta için doğrulama zaten bekleniyor" });

    const { data: signupData, error: signupError } = await authClient.auth.signUp({
      email: recoveryEmail,
      password,
      options: { data: { display_name: displayName } },
    });
    if (signupError || !signupData.user) {
      const duplicate = signupError?.code === "email_exists"
        || signupError?.code === "user_already_exists"
        || signupError?.message.toLowerCase().includes("registered")
        || signupError?.message.toLowerCase().includes("already");
      return json(duplicate ? 409 : 400, {
        error: duplicate ? "Bu e-posta adresi kullanılamıyor" : "Doğrulama e-postası gönderilemedi",
      });
    }

    // A non-null session means project-level email confirmations are disabled.
    // Fail closed instead of silently creating an unverified customer account.
    if (signupData.session) {
      await authClient.auth.signOut({ scope: "local" });
      await admin.auth.admin.deleteUser(signupData.user.id);
      return json(503, { error: "E-posta doğrulaması sunucuda etkinleştirilmeden kayıt açılamaz" });
    }

    const { data: createdUserData, error: createdUserError } =
      await admin.auth.admin.getUserById(signupData.user.id);
    const createdUser = createdUserData.user;
    const createdAt = createdUser ? new Date(createdUser.created_at).getTime() : 0;
    if (createdUserError
      || !createdUser
      || createdUser.email?.toLowerCase() !== recoveryEmail
      || createdUser.email_confirmed_at
      || createdAt < startedAt - 60000) {
      return json(409, { error: "Bu e-posta adresi kullanılamıyor" });
    }

    const organizationSlug = `${slugBase(organizationName)}-${crypto.randomUUID().slice(0, 8)}`.slice(0, 48);
    const { error: markerError } = await admin.auth.admin.updateUserById(createdUser.id, {
      app_metadata: {
        ...createdUser.app_metadata,
        stokta_pending_registration: "business_admin",
        username,
      },
    });
    if (markerError) {
      await admin.auth.admin.deleteUser(createdUser.id);
      return json(500, { error: "Kayıt doğrulaması hazırlanamadı" });
    }

    const { error: pendingError } = await admin.from("pending_account_registrations").insert({
      auth_user_id: createdUser.id,
      registration_kind: "business_admin",
      username,
      email: recoveryEmail,
      display_name: displayName,
      organization_name: organizationName,
      organization_slug: organizationSlug,
      ugc_terms_version: CURRENT_UGC_TERMS_VERSION,
      ugc_terms_accepted_at: new Date().toISOString(),
    });
    if (pendingError) {
      console.error("Pending business registration could not be stored", pendingError);
      await admin.auth.admin.deleteUser(createdUser.id);
      const duplicate = pendingError.code === "23505";
      return json(duplicate ? 409 : 500, {
        error: duplicate ? "Kullanıcı adı veya e-posta zaten kullanılıyor" : "Kayıt doğrulaması hazırlanamadı",
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
      username,
      message: "E-postanıza gönderilen doğrulama kodunu girin.",
    });
  } catch (error) {
    console.error("Self-service registration failed", error);
    return json(500, { error: "Kayıt başlatılamadı. Lütfen tekrar deneyin." });
  }
});
