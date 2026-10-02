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

    const drainAuthJobs = async (batchId: string | null) => {
      const { data: jobs, error: listError } = await admin.rpc(
        "service_list_account_deletion_auth_jobs", { p_batch_id: batchId },
      );
      if (listError || !Array.isArray(jobs)) {
        console.error("Account deletion Auth outbox read failed", listError);
        return { failed: true, processed: 0, pending: true };
      }

      let failed = false;
      let processed = 0;
      for (const job of jobs) {
        const userId = job?.authUserId;
        const jobBatchId = job?.batchId;
        if (typeof userId !== "string" || typeof jobBatchId !== "string"
          || (job.kind !== "identity" && job.kind !== "temporary_verification")) {
          failed = true;
          console.error("Account deletion Auth outbox row is invalid");
          continue;
        }

        const failJob = async (code: string) => {
          failed = true;
          const { error: recordError } = await admin.rpc(
            "service_fail_account_deletion_auth_job",
            { p_batch_id: jobBatchId, p_auth_user_id: userId, p_error_code: code },
          );
          if (recordError) console.error("Account deletion Auth failure record failed", recordError);
        };

        const { data: lookupData, error: lookupError } = await admin.auth.admin.getUserById(userId);
        const alreadyDeleted = lookupError?.status === 404 && lookupError?.code === "user_not_found";
        if (lookupError && !alreadyDeleted) {
          await failJob(typeof lookupError.code === "string" ? lookupError.code : "auth_lookup_failed");
          continue;
        }
        if (!lookupError && !lookupData?.user) {
          await failJob("auth_lookup_empty");
          continue;
        }

        if (!alreadyDeleted && job.kind === "temporary_verification"
          && (lookupData?.user?.app_metadata?.stokta_verification_only !== true
            || lookupData?.user?.app_metadata?.target_user_id !== job.targetUserId)) {
          await failJob("verification_metadata_mismatch");
          continue;
        }

        if (!alreadyDeleted) {
          if (job.kind === "identity") {
            const { error: banError } = await admin.auth.admin.updateUserById(userId, {
              ban_duration: "876000h",
            });
            if (banError) {
              console.error("Account deletion Auth ban failed", { userId, banError });
              await failJob("auth_ban_failed");
              continue;
            }

            const { error: revokeError } = await admin.rpc("service_revoke_user_sessions", {
              p_user_id: userId, p_except_session_id: null,
            });
            if (revokeError) {
              console.error("Account deletion session revocation failed", { userId, revokeError });
              await failJob("session_revoke_failed");
              continue;
            }
          }

          const { error: deleteError } = await admin.auth.admin.deleteUser(userId);
          if (deleteError && !(deleteError.status === 404 && deleteError.code === "user_not_found")) {
            await failJob(typeof deleteError.code === "string" ? deleteError.code : "auth_delete_failed");
            continue;
          }
        }

        const { error: completeError } = await admin.rpc(
          "service_complete_account_deletion_auth_job",
          { p_batch_id: jobBatchId, p_auth_user_id: userId },
        );
        if (completeError) {
          failed = true;
          console.error("Account deletion Auth outbox completion failed", completeError);
        } else {
          processed += 1;
        }
      }

      const { data: remaining, error: remainingError } = await admin.rpc(
        "service_account_deletion_auth_batch_pending", { p_batch_id: batchId },
      );
      if (remainingError || typeof remaining !== "number" || !Number.isSafeInteger(remaining) || remaining < 0) {
        console.error("Account deletion Auth outbox verification failed", remainingError);
        return { failed: true, processed, pending: true };
      }
      return { failed, processed, pending: remaining > 0 };
    };

    // Read a clone for user requests so their deletion body remains available.
    const retryBody = (token === serviceRoleKey
      ? await req.json()
      : await req.clone().json().catch(() => null)) as { operation?: unknown; batchId?: unknown } | null;

    // The scheduled server worker retries at most 25 due jobs. A configured
    // service key or a bearer verified by a service-only RPC may invoke it.
    if (token === serviceRoleKey || retryBody?.operation === "retry-auth-cleanup") {
      if (!retryBody || typeof retryBody !== "object"
        || retryBody.operation !== "retry-auth-cleanup"
        || (retryBody.batchId !== undefined
          && (typeof retryBody.batchId !== "string"
            || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(retryBody.batchId)))) {
        return json(400, { error: "Geçersiz Auth temizlik isteği" });
      }
      if (token !== serviceRoleKey) {
        // Authenticate caller credentials independently of the runtime key,
        // never using the privileged admin client for this authorization probe.
        // PostgREST verifies the JWT and this RPC is executable only by service_role.
        const workerCaller = createClient(supabaseUrl, token, {
          auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
          global: { headers: { Authorization: `Bearer ${token}` } },
        });
        const { data: workerHealth, error: workerError } = await workerCaller.rpc(
          "service_account_deletion_auth_job_health",
        );
        if (workerError || !workerHealth || typeof workerHealth !== "object" || Array.isArray(workerHealth)
          || !Number.isSafeInteger(workerHealth.pending) || workerHealth.pending < 0
          || !Number.isSafeInteger(workerHealth.withFailures) || workerHealth.withFailures < 0
          || workerHealth.withFailures > workerHealth.pending) {
          return json(401, { error: "Geçersiz Auth temizlik yetkisi" });
        }
      }
      const retryResult = await drainAuthJobs(
        typeof retryBody.batchId === "string" ? retryBody.batchId : null,
      );
      const { data: health, error: healthError } = await admin.rpc(
        "service_account_deletion_auth_job_health",
      );
      return json(retryResult.failed || retryResult.pending || healthError ? 503 : 200, {
        ...retryResult,
        health: healthError ? null : health,
      });
    }

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
      if (typeof deletion.requestId !== "string"
        || (deletion.requestStatus !== "requested" && deletion.requestStatus !== "under_review")) {
        return json(503, { error: "Silme talebi kaydedilemedi. Lütfen tekrar deneyin." });
      }
      // Keep non-2xx for installed clients that treat every successful invoke
      // as completed deletion. The new client reads this specific request code.
      return json(409, {
        code: "DELETION_REVIEW_REQUESTED",
        requestId: deletion.requestId,
        requestStatus: deletion.requestStatus,
        error: "Silme talebiniz kaydedildi. İlişkili ödeme kayıtları incelenmeden hesap ve verileriniz silinmez. Talep durumunu Hesabım > Hesabımı sil bölümünden takip edebilirsiniz.",
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
      || typeof deletion.batchId !== "string") {
      console.error("Account deletion transaction returned an invalid result");
      return json(503, { error: "Hesap silme sonucu doğrulanamadı. Destek ile iletişime geçin." });
    }

    const cleanup = await drainAuthJobs(deletion.batchId);
    if (cleanup.failed || cleanup.pending) {
      return json(503, {
        code: "AUTH_CLEANUP_PENDING",
        dataDeleted: true,
        error: "Hesap verileri silindi; giriş kimliklerinin temizliği sıraya alındı ve sunucuda yeniden denenecek. Destek: tirtarismail@gmail.com",
        supportEmail: "tirtarismail@gmail.com",
      });
    }

    return json(200, { deleted: true, scope: deletion.scope });
  } catch (error) {
    console.error("Account deletion failed", error);
    return json(500, { error: "Hesap silinemedi. Lütfen tekrar deneyin." });
  }
});
