import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  isStrongPassword,
  json,
  normalizeRecoveryEmail,
  normalizeUsername,
  requestIp,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

type PendingRow = { id: string; auth_user_id: string; expires_at: string };

async function removeExpiredPending(
  admin: any,
  rows: PendingRow[],
) {
  for (const row of rows) {
    if (new Date(row.expires_at).getTime() > Date.now()) continue;
    const { data: profile } = await admin
      .from("profiles").select("id").eq("id", row.auth_user_id).maybeSingle();
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
    const token = bearerToken(req);
    if (!token) return json(401, { error: "Oturum gerekli" });

    const startedAt = Date.now();
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
      .select("id,role,organization_id,must_change_password")
      .eq("id", userData.user.id)
      .eq("is_active", true)
      .maybeSingle();
    if (callerError) throw callerError;
    if (!caller || caller.role !== "admin" || caller.must_change_password) {
      return json(403, { error: "Bu işlem yalnızca işletme yöneticisine açıktır" });
    }

    const { data: organization, error: organizationError } = await admin
      .from("organizations")
      .select("id,subscription_status,trial_ends_at,current_period_end,max_members")
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

    const [{ count: memberCount, error: memberCountError }, { count: pendingCount, error: pendingCountError }] =
      await Promise.all([
        admin.from("profiles")
          .select("id", { count: "exact", head: true })
          .eq("organization_id", caller.organization_id)
          .eq("is_active", true),
        admin.from("pending_account_registrations")
          .select("id", { count: "exact", head: true })
          .eq("organization_id", caller.organization_id)
          .eq("registration_kind", "coworker")
          .gt("expires_at", new Date().toISOString()),
      ]);
    if (memberCountError || pendingCountError) throw memberCountError ?? pendingCountError;
    if ((memberCount ?? 0) + (pendingCount ?? 0) >= organization.max_members) {
      return json(409, { error: `Kullanıcı limitine ulaşıldı (${organization.max_members})` });
    }

    const body = await req.json() as Record<string, unknown>;
    const username = normalizeUsername(body.username);
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const recoveryEmail = normalizeRecoveryEmail(body.recoveryEmail);
    const password = typeof body.password === "string" ? body.password : "";

    if (!username) {
      return json(400, { error: "Kullanıcı adı 3-32 karakter olmalı; yalnızca a-z, 0-9, nokta, alt çizgi ve tire kullanılabilir" });
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return json(400, { error: "Görünen ad 1-80 karakter olmalı" });
    }
    if (!recoveryEmail) return json(400, { error: "Geçerli bir çalışan e-postası girin" });
    if (!isStrongPassword(password)) {
      return json(400, { error: "Geçici şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli" });
    }

    const ip = requestIp(req);
    const [actorHash, emailHash, ipHash] = await Promise.all([
      sha256(`stokta:coworker-create-actor:v1:${caller.id}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:coworker-create-email:v1:${recoveryEmail}:${supabaseUrl}:${serviceRoleKey}`),
      sha256(`stokta:coworker-create-ip:v1:${ip}:${supabaseUrl}:${serviceRoleKey}`),
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
      return json(503, { error: "Çalışan ekleme hizmeti şu anda kullanılamıyor" });
    }
    if (createLimits.some((limit) => limit.data !== true)) {
      return json(429, { error: "Çok fazla çalışan daveti gönderildi. Lütfen daha sonra tekrar deneyin." });
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
    if (signupData.session) {
      await authClient.auth.signOut({ scope: "local" });
      await admin.auth.admin.deleteUser(signupData.user.id);
      return json(503, { error: "E-posta doğrulaması sunucuda etkinleştirilmeden çalışan eklenemez" });
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

    const { error: markerError } = await admin.auth.admin.updateUserById(createdUser.id, {
      app_metadata: {
        ...createdUser.app_metadata,
        stokta_pending_registration: "coworker",
        organization_id: caller.organization_id,
        created_by: caller.id,
        username,
      },
    });
    if (markerError) {
      await admin.auth.admin.deleteUser(createdUser.id);
      return json(500, { error: "Çalışan doğrulaması hazırlanamadı" });
    }

    const { error: pendingError } = await admin.from("pending_account_registrations").insert({
      auth_user_id: createdUser.id,
      registration_kind: "coworker",
      username,
      email: recoveryEmail,
      display_name: displayName,
      organization_id: caller.organization_id,
      created_by: caller.id,
    });
    if (pendingError) {
      console.error("Pending coworker registration could not be stored", pendingError);
      await admin.auth.admin.deleteUser(createdUser.id);
      const duplicate = pendingError.code === "23505";
      return json(duplicate ? 409 : 500, {
        error: duplicate ? "Kullanıcı adı veya e-posta zaten kullanılıyor" : "Çalışan doğrulaması hazırlanamadı",
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
      username,
      displayName,
      message: "Çalışanın e-postasına doğrulama kodu gönderildi.",
    });
  } catch (error) {
    console.error("Coworker registration failed", error);
    return json(500, { error: "Çalışan ekleme başlatılamadı" });
  }
});
