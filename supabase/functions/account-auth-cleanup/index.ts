import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  constantTimeTextEqual,
  HttpInputError,
  isRecord,
  json,
  readBoundedJson,
} from "../_shared/security.ts";

type CleanupJob = {
  userId: string;
  requestId: string;
  leaseId: string;
  attemptCount: number;
};

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });
  try {
    const expected = Deno.env.get("ACCOUNT_AUTH_CLEANUP_SECRET") ?? "";
    const supplied = bearerToken(req) ?? "";
    if (expected.length < 32 || !constantTimeTextEqual(expected, supplied)) {
      return json(401, { error: "Geçersiz temizleme kimliği" });
    }
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) return json(500, { error: "Sunucu yapılandırması eksik" });
    const body = await readBoundedJson(req, 1_024);
    if (!isRecord(body) || Object.keys(body).some((key) => key !== "maxJobs")) {
      throw new HttpInputError(400, "Geçersiz temizleme isteği");
    }
    const maxJobs = body.maxJobs === undefined ? 20 : body.maxJobs;
    if (typeof maxJobs !== "number" || !Number.isInteger(maxJobs) || maxJobs < 1 || maxJobs > 100) {
      throw new HttpInputError(400, "Geçersiz temizleme iş sayısı");
    }
    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data, error } = await admin.rpc("service_claim_account_auth_cleanup", {
      p_limit: maxJobs,
    });
    if (error || !Array.isArray(data)) return json(503, { error: "Temizleme kuyruğu alınamadı" });
    let completed = 0;
    let deferred = 0;
    for (const value of data) {
      if (!isRecord(value)
        || typeof value.userId !== "string"
        || typeof value.requestId !== "string"
        || typeof value.leaseId !== "string"
        || typeof value.attemptCount !== "number") {
        throw new Error("Auth temizleme işi doğrulanamadı");
      }
      const job = value as CleanupJob;
      const { error: deleteError } = await admin.auth.admin.deleteUser(job.userId);
      const alreadyMissing = deleteError?.status === 404
        || deleteError?.code === "user_not_found"
        || /not found/i.test(deleteError?.message ?? "");
      const success = !deleteError || alreadyMissing;
      const { error: finishError } = await admin.rpc("service_finish_account_auth_cleanup", {
        p_user_id: job.userId,
        p_lease_id: job.leaseId,
        p_success: success,
        p_error_code: success ? null : String(deleteError?.code ?? "AUTH_DELETE_FAILED").slice(0, 64),
      });
      if (finishError) throw new Error("Auth temizleme işi kapatılamadı");
      if (success) completed += 1;
      else deferred += 1;
    }
    return json(200, { ok: true, completed, deferred });
  } catch (error) {
    if (error instanceof HttpInputError) return json(error.status, { error: error.message });
    console.error("Auth cleanup failed", { name: error instanceof Error ? error.name : "unknown" });
    return json(503, { error: "Auth temizliği tamamlanamadı" });
  }
});
