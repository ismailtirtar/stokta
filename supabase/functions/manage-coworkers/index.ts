import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  isStrongPassword,
  json,
  maskEmail,
  normalizeUsername,
  sessionIdFromAccessToken,
  sha256,
} from "../_shared/security.ts";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type MemberRow = {
  id: string;
  username: string;
  display_name: string;
  is_active: boolean;
  created_at: string;
  deactivated_at: string | null;
  must_change_password: boolean;
  recovery_email: string | null;
};

type PendingMemberRow = {
  id: string;
  auth_user_id: string;
  registration_kind: "coworker";
  username: string;
  email: string;
  display_name: string;
  organization_id: string;
  created_by: string;
  created_at: string;
  expires_at: string;
};

type ReauthenticationResult =
  | { ok: true }
  | { ok: false; status: number; error: string };

async function reauthenticateAdmin(
  admin: any,
  supabaseUrl: string,
  anonKey: string,
  callerId: string,
  callerEmail: string | undefined,
  currentPassword: string,
): Promise<ReauthenticationResult> {
  if (!callerEmail || currentPassword.length < 1 || currentPassword.length > 72) {
    return { ok: false, status: 400, error: "İşlemi onaylamak için yönetici şifrenizi girin" };
  }

  const reauthClient = createClient(supabaseUrl, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data: reauthData, error: reauthError } = await reauthClient.auth.signInWithPassword({
    email: callerEmail,
    password: currentPassword,
  });

  let cleanupFailed = false;
  if (reauthData.session) {
    const reauthSessionId = sessionIdFromAccessToken(reauthData.session.access_token);
    if (!reauthSessionId) {
      cleanupFailed = true;
    } else {
      const { data: revoked, error: revokeError } = await admin.rpc(
        "service_revoke_session",
        { p_user_id: reauthData.user.id, p_session_id: reauthSessionId },
      );
      cleanupFailed = Boolean(revokeError || !revoked);
      if (cleanupFailed) {
        console.error("Coworker management reauthentication cleanup failed", revokeError);
      }
    }
    await reauthClient.auth.signOut({ scope: "local" });
  }

  if (cleanupFailed) {
    return { ok: false, status: 503, error: "Yönetici doğrulama oturumu kapatılamadı" };
  }
  if (reauthError || !reauthData.session || reauthData.user.id !== callerId) {
    return { ok: false, status: 401, error: "Yönetici şifresi hatalı" };
  }
  return { ok: true };
}

function isMissingAuthUser(error: unknown) {
  const candidate = error as { code?: unknown; message?: unknown } | null;
  const code = typeof candidate?.code === "string" ? candidate.code.toLowerCase() : "";
  const message = typeof candidate?.message === "string" ? candidate.message.toLowerCase() : "";
  return code === "user_not_found" || message.includes("user not found");
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

    const { data: callerData, error: callerAuthError } = await admin.auth.getUser(token);
    if (callerAuthError || !callerData.user) return json(401, { error: "Geçersiz oturum" });
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });
    const { data: liveSession, error: liveSessionError } = await admin.rpc("service_has_live_session", {
      p_user_id: callerData.user.id,
      p_session_id: sessionId,
    });
    if (liveSessionError || !liveSession) return json(401, { error: "Oturum sona erdi" });

    const { data: caller, error: callerError } = await admin
      .from("profiles")
      .select("id,role,organization_id,must_change_password")
      .eq("id", callerData.user.id)
      .eq("is_active", true)
      .maybeSingle();
    if (callerError) throw callerError;
    if (!caller || caller.role !== "admin" || caller.must_change_password) {
      return json(403, { error: "Bu işlem yalnızca işletme yöneticisine açıktır" });
    }

    const body = await req.json() as Record<string, unknown>;
    const action = typeof body.action === "string" ? body.action : "list";

    if (action === "list") {
      const { data: organization, error: organizationError } = await admin
        .from("organizations")
        .select("max_members")
        .eq("id", caller.organization_id)
        .maybeSingle();
      if (organizationError) throw organizationError;
      if (!organization) return json(404, { error: "İşletme bulunamadı" });

      const nowIso = new Date().toISOString();
      const [activeSeatResult, pendingSeatResult] = await Promise.all([
        admin
          .from("profiles")
          .select("id", { count: "exact", head: true })
          .eq("organization_id", caller.organization_id)
          .eq("is_active", true),
        admin
          .from("pending_account_registrations")
          .select("id", { count: "exact", head: true })
          .eq("organization_id", caller.organization_id)
          .eq("registration_kind", "coworker")
          .gt("expires_at", nowIso),
      ]);
      if (activeSeatResult.error || pendingSeatResult.error) {
        throw activeSeatResult.error ?? pendingSeatResult.error;
      }

      const members: MemberRow[] = [];
      for (let offset = 0; offset < 100000; offset += 1000) {
        const { data: page, error: pageError } = await admin
          .from("profiles")
          .select("id,username,display_name,is_active,created_at,deactivated_at,must_change_password,recovery_email")
          .eq("organization_id", caller.organization_id)
          .eq("role", "member")
          .order("created_at", { ascending: true })
          .order("id", { ascending: true })
          .range(offset, offset + 999);
        if (pageError) throw pageError;
        members.push(...((page ?? []) as MemberRow[]));
        if ((page?.length ?? 0) < 1000) break;
        if (offset === 99000) {
          return json(413, { error: "Çalışan listesi tek istekte gösterilemeyecek kadar büyük" });
        }
      }

      const pendingMembers: PendingMemberRow[] = [];
      for (let offset = 0; offset < 100000; offset += 1000) {
        const { data: page, error: pageError } = await admin
          .from("pending_account_registrations")
          .select(
            "id,auth_user_id,registration_kind,username,email,display_name,organization_id,created_by,created_at,expires_at",
          )
          .eq("organization_id", caller.organization_id)
          .eq("registration_kind", "coworker")
          .order("created_at", { ascending: true })
          .order("id", { ascending: true })
          .range(offset, offset + 999);
        if (pageError) throw pageError;
        pendingMembers.push(...((page ?? []) as PendingMemberRow[]));
        if ((page?.length ?? 0) < 1000) break;
        if (offset === 99000) {
          return json(413, { error: "Bekleyen çalışan listesi tek istekte gösterilemeyecek kadar büyük" });
        }
      }

      return json(200, {
        members: members.map((member) => ({
          id: member.id,
          username: member.username,
          displayName: member.display_name,
          isActive: member.is_active,
          createdAt: member.created_at,
          deactivatedAt: member.deactivated_at,
          mustChangePassword: member.must_change_password,
          recoveryEmailMasked: member.recovery_email ? maskEmail(member.recovery_email) : null,
        })),
        pendingMembers: pendingMembers.map((member) => ({
          id: member.id,
          userId: member.auth_user_id,
          username: member.username,
          displayName: member.display_name,
          recoveryEmailMasked: maskEmail(member.email) ?? "••••",
          createdAt: member.created_at,
          expiresAt: member.expires_at,
        })),
        maxMembers: organization.max_members,
        activeSeats: activeSeatResult.count ?? 0,
        pendingSeats: pendingSeatResult.count ?? 0,
      });
    }

    if (action === "cancel_pending") {
      const userId = typeof body.userId === "string" ? body.userId : "";
      if (!uuidPattern.test(userId)) return json(400, { error: "Geçersiz bekleyen çalışan" });

      const confirmation = normalizeUsername(body.confirmation);
      if (!confirmation) {
        return json(400, { error: "İptal onayı için geçerli kullanıcı adını girin" });
      }

      const actionHash = await sha256(
        `stokta:manage-coworkers:v1:${caller.id}:${action}:${supabaseUrl}:${serviceRoleKey}`,
      );
      const { data: allowed, error: rateError } = await admin.rpc("consume_auth_rate_limit", {
        p_scope: "manage-coworkers",
        p_key_hash: actionHash,
        p_max_attempts: 10,
        p_window_seconds: 3600,
      });
      if (rateError) {
        console.error("Pending coworker cancellation rate limiter unavailable", rateError);
        return json(503, { error: "Çalışan yönetimi şu anda kullanılamıyor" });
      }
      if (!allowed) {
        return json(429, { error: "Çok fazla çalışan yönetimi işlemi yapıldı. Lütfen daha sonra tekrar deneyin." });
      }

      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const reauthentication = await reauthenticateAdmin(
        admin,
        supabaseUrl,
        anonKey,
        caller.id,
        callerData.user.email,
        currentPassword,
      );
      if (!reauthentication.ok) {
        return json(reauthentication.status, { error: reauthentication.error });
      }

      const { data: pending, error: pendingError } = await admin
        .from("pending_account_registrations")
        .select(
          "id,auth_user_id,registration_kind,username,email,display_name,organization_id,created_by,created_at,expires_at",
        )
        .eq("auth_user_id", userId)
        .eq("organization_id", caller.organization_id)
        .eq("registration_kind", "coworker")
        .maybeSingle();
      if (pendingError) {
        console.error("Pending coworker cancellation lookup failed", pendingError);
        return json(503, { error: "Bekleyen çalışan hesabı şu anda iptal edilemiyor" });
      }

      // A repeated request, an already-completed registration, a business-admin
      // registration, or another tenant's registration is deliberately a no-op.
      // This keeps cancellation idempotent without exposing foreign identities.
      if (!pending) return json(200, { success: true });
      const pendingCoworker = pending as PendingMemberRow;

      if (confirmation !== pendingCoworker.username) {
        return json(400, { error: `Onay alanına ${pendingCoworker.username} yazılmalı` });
      }

      const { data: existingProfile, error: profileLookupError } = await admin
        .from("profiles")
        .select("id")
        .eq("id", userId)
        .maybeSingle();
      if (profileLookupError) {
        console.error("Pending coworker profile guard lookup failed", profileLookupError);
        return json(503, { error: "Bekleyen çalışan hesabı şu anda iptal edilemiyor" });
      }
      if (existingProfile) {
        return json(409, { error: "Bu çalışan e-posta doğrulamasını tamamlamış; ekip listesini yenileyin" });
      }

      const { data: pendingUserData, error: pendingUserError } =
        await admin.auth.admin.getUserById(userId);
      const pendingUser = pendingUserData?.user;

      if (pendingUserError || !pendingUser) {
        if (!isMissingAuthUser(pendingUserError)) {
          console.error("Pending coworker Auth identity lookup failed", pendingUserError);
          return json(503, { error: "Bekleyen çalışan hesabı şu anda iptal edilemiyor" });
        }

        const { error: staleAuditError } = await admin.rpc("service_record_security_event", {
          p_event_type: "coworker.pending_invitation_cancelled",
          p_organization_id: caller.organization_id,
          p_actor_id: caller.id,
          p_subject_id: null,
          p_metadata: {
            authUserId: userId,
            pendingRegistrationId: pendingCoworker.id,
            username: pendingCoworker.username,
            staleAuthIdentity: true,
          },
        });
        if (staleAuditError) {
          console.error("Stale pending coworker cancellation audit failed", staleAuditError);
          return json(503, { error: "İptal işlemi güvenlik kaydına yazılamadı; kayıt silinmedi" });
        }

        const { error: staleCleanupError } = await admin
          .from("pending_account_registrations")
          .delete()
          .eq("id", pendingCoworker.id)
          .eq("auth_user_id", userId)
          .eq("organization_id", caller.organization_id)
          .eq("registration_kind", "coworker");
        if (staleCleanupError) {
          console.error("Stale pending coworker cleanup failed", staleCleanupError);
          return json(500, { error: "Bekleyen çalışan kaydı temizlenemedi" });
        }
        return json(200, { success: true });
      }

      const metadata = pendingUser.app_metadata ?? {};
      const markerMatches = metadata.stokta_pending_registration === "coworker"
        && metadata.organization_id === pendingCoworker.organization_id
        && metadata.created_by === pendingCoworker.created_by
        && metadata.username === pendingCoworker.username
        && pendingUser.email?.toLowerCase() === pendingCoworker.email;
      if (!markerMatches) {
        console.error("Pending coworker Auth marker mismatch", {
          pendingRegistrationId: pendingCoworker.id,
          authUserId: userId,
        });
        return json(409, { error: "Bekleyen hesap güvenlik doğrulamasından geçmedi; kayıt silinmedi" });
      }

      const { error: requestAuditError } = await admin.rpc("service_record_security_event", {
        p_event_type: "coworker.pending_invitation_cancellation_requested",
        p_organization_id: caller.organization_id,
        p_actor_id: caller.id,
        p_subject_id: userId,
        p_metadata: {
          pendingRegistrationId: pendingCoworker.id,
          authUserId: userId,
          username: pendingCoworker.username,
        },
      });
      if (requestAuditError) {
        console.error("Pending coworker cancellation request audit failed", requestAuditError);
        return json(503, { error: "İptal işlemi güvenlik kaydına yazılamadı; kayıt silinmedi" });
      }

      // Lock the identity before claiming the pending database row. If email
      // verification races this request, the scoped DELETE below either wins
      // first or returns no row after finalization; an active account is never
      // deleted by this path.
      const wasAlreadyBanned = Boolean(
        pendingUser.banned_until && new Date(pendingUser.banned_until).getTime() > Date.now(),
      );
      const { error: banError } = await admin.auth.admin.updateUserById(userId, {
        ban_duration: "876000h",
      });
      if (banError) {
        console.error("Pending coworker pre-cancellation ban failed", banError);
        return json(500, { error: "Bekleyen çalışan hesabı güvenli biçimde kilitlenemedi" });
      }

      const { error: revokeError } = await admin.rpc("service_revoke_user_sessions", {
        p_user_id: userId,
        p_except_session_id: null,
      });
      if (revokeError) {
        console.error("Pending coworker session revocation failed", revokeError);
        return json(503, { error: "Bekleyen çalışan oturumları kapatılamadı; hesap kilitli bırakıldı" });
      }

      const { data: deletedPending, error: pendingDeleteError } = await admin
        .from("pending_account_registrations")
        .delete()
        .eq("id", pendingCoworker.id)
        .eq("auth_user_id", userId)
        .eq("organization_id", caller.organization_id)
        .eq("created_by", pendingCoworker.created_by)
        .eq("registration_kind", "coworker")
        .eq("username", pendingCoworker.username)
        .select("id")
        .maybeSingle();
      if (pendingDeleteError) {
        console.error("Pending coworker database cancellation failed", pendingDeleteError);
        return json(500, { error: "Bekleyen çalışan kaydı iptal edilemedi; hesap kilitli bırakıldı" });
      }

      if (!deletedPending) {
        const { data: finalizedProfile } = await admin
          .from("profiles")
          .select("id")
          .eq("id", userId)
          .maybeSingle();
        if (finalizedProfile) {
          if (!wasAlreadyBanned) {
            const { error: unbanError } = await admin.auth.admin.updateUserById(userId, {
              ban_duration: "none",
            });
            if (unbanError) {
              console.error("Concurrent coworker finalization unban failed", unbanError);
              return json(503, { error: "Çalışan doğrulamayı tamamladı ancak hesabı yeniden açılamadı" });
            }
          }
          return json(409, { error: "Bu çalışan e-posta doğrulamasını tamamlamış; ekip listesini yenileyin" });
        }
      }

      const { error: auditError } = await admin.rpc("service_record_security_event", {
        p_event_type: "coworker.pending_invitation_cancelled",
        p_organization_id: caller.organization_id,
        p_actor_id: caller.id,
        p_subject_id: userId,
        p_metadata: {
          pendingRegistrationId: pendingCoworker.id,
          authUserId: userId,
          username: pendingCoworker.username,
        },
      });
      if (auditError) {
        console.error("Pending coworker cancellation audit failed", auditError);
      }

      let { error: deleteUserError } = await admin.auth.admin.deleteUser(userId);
      if (deleteUserError && !isMissingAuthUser(deleteUserError)) {
        const retry = await admin.auth.admin.deleteUser(userId);
        deleteUserError = retry.error;
      }
      if (deleteUserError && !isMissingAuthUser(deleteUserError)) {
        console.error("Pending coworker Auth deletion failed after cancellation", deleteUserError);
        return json(500, {
          error: "Bekleyen kayıt iptal edildi ancak kilitli giriş hesabı temizlenemedi; destek kaydını inceleyin",
        });
      }

      return json(200, { success: true });
    }

    if (!["reset_password", "set_active", "delete"].includes(action)) {
      return json(400, { error: "Geçersiz işlem" });
    }

    const userId = typeof body.userId === "string" ? body.userId : "";
    if (!uuidPattern.test(userId)) return json(400, { error: "Geçersiz çalışan" });

    const { data: target, error: targetError } = await admin
      .from("profiles")
      .select("id,username,is_active")
      .eq("id", userId)
      .eq("organization_id", caller.organization_id)
      .eq("role", "member")
      .eq("is_platform_operator", false)
      .maybeSingle();
    if (targetError) throw targetError;
    if (!target) return json(404, { error: "Çalışan bulunamadı" });

    const actionHash = await sha256(
      `stokta:manage-coworkers:v1:${caller.id}:${action}:${supabaseUrl}:${serviceRoleKey}`,
    );
    const { data: allowed, error: rateError } = await admin.rpc("consume_auth_rate_limit", {
      p_scope: "manage-coworkers",
      p_key_hash: actionHash,
      p_max_attempts: action === "set_active" ? 60 : 10,
      p_window_seconds: 3600,
    });
    if (rateError) {
      console.error("Coworker management rate limiter unavailable", rateError);
      return json(503, { error: "Çalışan yönetimi şu anda kullanılamıyor" });
    }
    if (!allowed) {
      return json(429, { error: "Çok fazla çalışan yönetimi işlemi yapıldı. Lütfen daha sonra tekrar deneyin." });
    }

    if (action === "reset_password" || action === "delete") {
      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const reauthentication = await reauthenticateAdmin(
        admin,
        supabaseUrl,
        anonKey,
        caller.id,
        callerData.user.email,
        currentPassword,
      );
      if (!reauthentication.ok) {
        return json(reauthentication.status, { error: reauthentication.error });
      }
    }

    if (action === "reset_password") {
      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
      if (!isStrongPassword(newPassword)) {
        return json(400, {
          error: "Yeni şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli",
        });
      }

      const { error: completionError } = await admin.rpc(
        "service_require_member_password_change",
        { p_admin_id: caller.id, p_member_id: target.id },
      );
      if (completionError) {
        console.error("Coworker forced-password state or session revocation failed", completionError);
        return json(500, {
          error: "Geçici şifre işlemi güvenli biçimde hazırlanamadı. İşlemi tekrar deneyin.",
        });
      }
      const { error: passwordError } = await admin.auth.admin.updateUserById(target.id, {
        password: newPassword,
      });
      if (passwordError) {
        console.error("Coworker password reset failed after fail-closed session revocation", passwordError);
        return json(500, {
          error: "Çalışanın erişimi güvenli biçimde kapatıldı ancak geçici şifre atanamadı. İşlemi tekrar deneyin.",
        });
      }
      await admin.rpc("service_record_security_event", {
        p_event_type: "coworker.password_reset_completed",
        p_organization_id: caller.organization_id,
        p_actor_id: caller.id,
        p_subject_id: target.id,
      });
      return json(200, { updated: true, mustChangePassword: true });
    }

    if (action === "set_active") {
      if (typeof body.isActive !== "boolean") {
        return json(400, { error: "Etkinlik durumu belirtilmeli" });
      }
      const isActive = body.isActive;

      if (!isActive) {
        if (target.is_active) {
          const { error: profileUpdateError } = await admin.rpc("service_set_member_active", {
            p_admin_id: caller.id,
            p_member_id: target.id,
            p_is_active: false,
          });
          if (profileUpdateError) {
            console.error("Coworker deactivation failed", profileUpdateError);
            return json(500, { error: "Çalışan devre dışı bırakılamadı" });
          }
        }

        // Always retry the Auth ban. A previous request may have committed the
        // database deactivation before the Auth Admin API call failed.
        const { error: banError } = await admin.auth.admin.updateUserById(target.id, {
          ban_duration: "876000h",
        });
        if (banError) {
          console.error("Coworker Auth ban failed after profile deactivation", banError);
          return json(500, {
            error: "Çalışanın veri erişimi kapatıldı ancak giriş kaydı tamamen kilitlenemedi. Tekrar deneyin.",
          });
        }
        return json(200, { updated: true, isActive: false });
      }

      // Always retry the Auth unban. This repairs a user whose profile was
      // already active while the preceding Auth Admin API call was incomplete.
      const { error: unbanError } = await admin.auth.admin.updateUserById(target.id, {
        ban_duration: "none",
      });
      if (unbanError) {
        console.error("Coworker Auth unban failed", unbanError);
        return json(500, { error: "Çalışan yeniden etkinleştirilemedi" });
      }

      if (target.is_active) return json(200, { updated: true, isActive: true });

      const { error: profileUpdateError } = await admin.rpc("service_set_member_active", {
        p_admin_id: caller.id,
        p_member_id: target.id,
        p_is_active: true,
      });
      if (profileUpdateError) {
        console.error("Coworker profile reactivation failed", profileUpdateError);
        const { error: rollbackError } = await admin.auth.admin.updateUserById(target.id, {
          ban_duration: "876000h",
        });
        if (rollbackError) console.error("Coworker reactivation rollback failed", rollbackError);
        const limitReached = profileUpdateError.message.toLowerCase().includes("limit");
        return json(limitReached ? 409 : 500, {
          error: limitReached ? "Kullanıcı limitine ulaşıldı" : "Çalışan yeniden etkinleştirilemedi",
        });
      }
      return json(200, { updated: true, isActive: true });
    }

    const confirmation = typeof body.confirmation === "string" ? body.confirmation.trim() : "";
    if (confirmation !== target.username) {
      return json(400, { error: `Onay alanına ${target.username} yazılmalı` });
    }

    const { data: pendingRecovery, error: pendingRecoveryError } = await admin
      .from("pending_recovery_email_verifications")
      .select("verification_user_id,verification_kind")
      .eq("target_user_id", target.id)
      .maybeSingle();
    if (pendingRecoveryError) {
      console.error("Coworker pending recovery cleanup lookup failed", pendingRecoveryError);
      return json(500, { error: "Çalışan silme hazırlığı tamamlanamadı" });
    }

    // Ban first so a partial failure is fail-closed. The database preparation
    // keeps the member visible and inactive, allowing the admin to retry.
    const { error: banError } = await admin.auth.admin.updateUserById(target.id, {
      ban_duration: "876000h",
    });
    if (banError && !banError.message.toLowerCase().includes("not found")) {
      console.error("Coworker deletion pre-ban failed", banError);
      return json(500, { error: "Çalışan hesabı güvenli biçimde kilitlenemedi. Tekrar deneyin." });
    }

    const { error: prepareProfileError } = await admin.rpc("service_prepare_member_deletion", {
      p_admin_id: caller.id,
      p_member_id: target.id,
    });
    if (prepareProfileError) {
      console.error("Coworker profile deletion preparation failed", prepareProfileError);
      return json(500, { error: "Çalışan silinemedi" });
    }

    const { error: deleteAuthError } = await admin.auth.admin.deleteUser(target.id);
    if (deleteAuthError && !deleteAuthError.message.toLowerCase().includes("not found")) {
      console.error("Coworker Auth deletion failed after safe profile preparation", deleteAuthError);
      return json(500, {
        error: "Çalışanın erişimi kapatıldı ancak giriş kaydı temizlenemedi. Listeden yeniden silmeyi deneyin.",
      });
    }

    if (pendingRecovery?.verification_kind === "temporary_signup"
      && pendingRecovery.verification_user_id !== target.id) {
      const { data: verificationUserData } = await admin.auth.admin.getUserById(
        pendingRecovery.verification_user_id,
      );
      if (verificationUserData.user?.app_metadata?.stokta_verification_only === true
        && verificationUserData.user.app_metadata?.target_user_id === target.id) {
        const { error: cleanupVerificationError } = await admin.auth.admin.deleteUser(
          pendingRecovery.verification_user_id,
        );
        if (cleanupVerificationError) {
          console.error("Coworker temporary recovery identity cleanup failed", cleanupVerificationError);
        }
      }
    }

    // auth.users normally cascades to profiles. This scoped cleanup also makes
    // the operation idempotent if that relationship changes in the future.
    const { error: profileCleanupError } = await admin
      .from("profiles")
      .delete()
      .eq("id", target.id)
      .eq("organization_id", caller.organization_id)
      .eq("role", "member");
    if (profileCleanupError) {
      console.error("Coworker profile cleanup failed after Auth deletion", profileCleanupError);
      return json(500, { error: "Giriş hesabı silindi ancak çalışan listesi temizlenemedi. Tekrar deneyin." });
    }

    return json(200, { deleted: true });
  } catch (error) {
    console.error("Coworker management failed", error);
    return json(500, { error: "Çalışan yönetimi işlemi tamamlanamadı" });
  }
});
