import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  bearerToken,
  corsJsonHeaders,
  HttpInputError,
  isRecord,
  json,
  readBoundedJson,
  sessionIdFromAccessToken,
} from "../_shared/security.ts";

type Organization = {
  id: string;
  name: string;
  slug: string;
  subscription_status: "trial" | "active" | "past_due" | "suspended" | "canceled";
  trial_ends_at: string | null;
  current_period_end: string | null;
  max_members: number;
  max_products: number;
  member_count: number;
  product_count: number;
  platform_entitlement_until: string | null;
  platform_entitlement_reason: string | null;
  subscription_revision: number;
  created_at: string;
};

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function requiredInteger(value: unknown, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) return null;
  return value >= min && value <= max ? value : null;
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function organizationRows(value: unknown): Organization[] | null {
  if (!Array.isArray(value)) return null;
  const statuses = new Set(["trial", "active", "past_due", "suspended", "canceled"]);
  for (const candidate of value) {
    if (
      !isRecord(candidate) || typeof candidate.id !== "string" ||
      !uuidPattern.test(candidate.id) || typeof candidate.name !== "string" ||
      typeof candidate.slug !== "string" ||
      typeof candidate.subscription_status !== "string" ||
      !statuses.has(candidate.subscription_status) ||
      typeof candidate.created_at !== "string" ||
      (candidate.trial_ends_at !== null && typeof candidate.trial_ends_at !== "string") ||
      (candidate.current_period_end !== null && typeof candidate.current_period_end !== "string") ||
      (candidate.platform_entitlement_until !== null &&
        typeof candidate.platform_entitlement_until !== "string") ||
      (candidate.platform_entitlement_reason !== null &&
        typeof candidate.platform_entitlement_reason !== "string") ||
      !isSafeInteger(candidate.max_members) || candidate.max_members < 1 ||
      !isSafeInteger(candidate.max_products) || candidate.max_products < 1 ||
      !isSafeInteger(candidate.member_count) || candidate.member_count < 0 ||
      !isSafeInteger(candidate.product_count) || candidate.product_count < 0 ||
      !isSafeInteger(candidate.subscription_revision) || candidate.subscription_revision < 0
    ) return null;
  }
  return value as Organization[];
}

function rpcFailure(message: string) {
  if (/oturum/i.test(message)) return json(401, { error: "Oturum sona erdi" });
  if (/yalnızca etkin platform yöneticisine/i.test(message)) {
    return json(403, { error: "Bu işlem yalnızca Stokdaş platform yöneticisine açıktır" });
  }
  if (/bulunamadı/i.test(message)) return json(404, { error: message });
  if (/başka bir işlemde|eşzamanlı|revizyon/i.test(message)) {
    return json(409, { error: message, code: "STALE_ORGANIZATION_REVISION" });
  }
  if (/silme işlemi devam ediyor/i.test(message)) {
    return json(409, { error: message, code: "ORGANIZATION_DELETION_IN_PROGRESS" });
  }
  if (/çok fazla/i.test(message)) return json(429, { error: message });
  return json(400, { error: message || "İşletme yönetimi isteği geçersiz" });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: {
        ...corsJsonHeaders,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      },
    });
  }
  if (req.method !== "GET" && req.method !== "POST") {
    return json(405, { error: "Yalnızca GET ve POST desteklenir" });
  }

  try {
    const token = bearerToken(req);
    if (!token) return json(401, { error: "Oturum gerekli" });

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) {
      return json(500, { error: "Sunucu yapılandırması eksik" });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: userData, error: userError } = await admin.auth.getUser(token);
    if (userError || !userData.user) return json(401, { error: "Geçersiz oturum" });
    const sessionId = sessionIdFromAccessToken(token);
    if (!sessionId) return json(401, { error: "Geçersiz oturum" });

    if (req.method === "GET") {
      const url = new URL(req.url);
      const beforeCreatedAtInput = url.searchParams.get("beforeCreatedAt");
      const beforeId = url.searchParams.get("beforeId");
      if ((beforeCreatedAtInput === null) !== (beforeId === null)) {
        return json(400, { error: "İşletme sayfalama imleci eksik" });
      }
      if (beforeId !== null && !uuidPattern.test(beforeId)) {
        return json(400, { error: "İşletme sayfalama imleci geçersiz" });
      }

      let beforeCreatedAt: string | null = null;
      if (beforeCreatedAtInput !== null) {
        const parsed = new Date(beforeCreatedAtInput);
        if (Number.isNaN(parsed.getTime())) {
          return json(400, { error: "İşletme sayfalama zamanı geçersiz" });
        }
        beforeCreatedAt = parsed.toISOString();
      }

      const requestedLimit = Number(url.searchParams.get("limit") ?? "100");
      if (!Number.isSafeInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 100) {
        return json(400, { error: "Sayfa boyutu 1-100 arasında olmalı" });
      }

      const { data, error } = await admin.rpc("service_list_platform_businesses", {
        p_actor_id: userData.user.id,
        p_session_id: sessionId,
        p_before_created_at: beforeCreatedAt,
        p_before_id: beforeId,
        p_limit: requestedLimit + 1,
      });
      if (error) {
        console.error("Platform business list RPC failed", error.code);
        return rpcFailure(error.message);
      }

      const rows = organizationRows(data);
      if (!rows) {
        console.error("Platform business list RPC returned an invalid response");
        return json(502, { error: "İşletme listesi doğrulanamadı" });
      }
      const hasMore = rows.length > requestedLimit;
      const organizations = rows.slice(0, requestedLimit);
      const last = organizations.at(-1);
      return json(200, {
        organizations,
        nextCursor: hasMore && last
          ? { beforeCreatedAt: last.created_at, beforeId: last.id }
          : null,
      });
    }

    let body: Record<string, unknown>;
    try {
      const mediaType = req.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
      if (mediaType && mediaType !== "application/json") {
        return json(415, { error: "Content-Type application/json olmalıdır" });
      }
      const parsed = await readBoundedJson(req, 16 * 1024);
      if (!isRecord(parsed)) return json(400, { error: "JSON gövdesi bir nesne olmalıdır" });
      body = parsed;
    } catch (error) {
      if (error instanceof HttpInputError) {
        return json(error.status, { error: error.message });
      }
      return json(400, { error: "Geçerli bir JSON nesnesi gönderin" });
    }

    if (body.action === "list") {
      const beforeCreatedAtInput = typeof body.beforeCreatedAt === "string"
        ? body.beforeCreatedAt
        : null;
      const beforeId = typeof body.beforeId === "string" ? body.beforeId : null;
      if ((beforeCreatedAtInput === null) !== (beforeId === null)) {
        return json(400, { error: "İşletme sayfalama imleci eksik" });
      }
      if (beforeId !== null && !uuidPattern.test(beforeId)) {
        return json(400, { error: "İşletme sayfalama imleci geçersiz" });
      }
      let beforeCreatedAt: string | null = null;
      if (beforeCreatedAtInput !== null) {
        const parsed = new Date(beforeCreatedAtInput);
        if (Number.isNaN(parsed.getTime())) {
          return json(400, { error: "İşletme sayfalama zamanı geçersiz" });
        }
        beforeCreatedAt = parsed.toISOString();
      }
      const requestedLimit = body.limit === undefined
        ? 100
        : requiredInteger(body.limit, 1, 100);
      if (requestedLimit === null) {
        return json(400, { error: "Sayfa boyutu 1-100 arasında olmalı" });
      }
      const { data, error } = await admin.rpc("service_list_platform_businesses", {
        p_actor_id: userData.user.id,
        p_session_id: sessionId,
        p_before_created_at: beforeCreatedAt,
        p_before_id: beforeId,
        p_limit: requestedLimit + 1,
      });
      if (error) {
        console.error("Platform business list RPC failed", error.code);
        return rpcFailure(error.message);
      }
      const rows = organizationRows(data);
      if (!rows) {
        console.error("Platform business list RPC returned an invalid response");
        return json(502, { error: "İşletme listesi doğrulanamadı" });
      }
      const hasMore = rows.length > requestedLimit;
      const organizations = rows.slice(0, requestedLimit);
      const last = organizations.at(-1);
      return json(200, {
        organizations,
        nextCursor: hasMore && last
          ? { beforeCreatedAt: last.created_at, beforeId: last.id }
          : null,
      });
    }

    if (body.action !== "update_subscription") {
      if (body.action === "create" || body.action === undefined) {
        return json(410, {
          error: "Yeni işletmeler yalnız e-posta doğrulamalı kayıt ekranından oluşturulabilir",
          code: "BUSINESS_CREATION_SELF_SERVICE_ONLY",
        });
      }
      return json(400, { error: "Geçersiz işlem" });
    }

    const organizationId = typeof body.organizationId === "string" ? body.organizationId : "";
    const requestId = typeof body.requestId === "string" ? body.requestId : "";
    const status = typeof body.status === "string" ? body.status : "";
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    const expectedRevision = requiredInteger(body.expectedRevision, 0, Number.MAX_SAFE_INTEGER);
    const maxMembers = requiredInteger(body.maxMembers, 1, 10000);
    const maxProducts = requiredInteger(body.maxProducts, 1, 1000000);
    const periodDays = requiredInteger(body.periodDays, 1, 3660);

    if (!uuidPattern.test(organizationId)) return json(400, { error: "Geçersiz işletme" });
    if (!uuidPattern.test(requestId)) return json(400, { error: "Geçerli işlem kimliği gerekli" });
    if (status !== "active" && status !== "suspended") {
      return json(400, { error: "Durum yalnız active veya suspended olabilir" });
    }
    if (expectedRevision === null) return json(400, { error: "Geçerli işletme revizyonu gerekli" });
    if (maxMembers === null || maxProducts === null || periodDays === null) {
      return json(400, { error: "Dönem ve işletme limitleri geçersiz" });
    }
    if (reason.length < 1 || reason.length > 500) {
      return json(400, { error: "İşlem gerekçesi 1-500 karakter olmalı" });
    }

    const { data, error } = await admin.rpc("service_update_platform_subscription", {
      p_actor_id: userData.user.id,
      p_session_id: sessionId,
      p_request_id: requestId,
      p_organization_id: organizationId,
      p_expected_revision: expectedRevision,
      p_status: status,
      p_period_days: periodDays,
      p_max_members: maxMembers,
      p_max_products: maxProducts,
      p_reason: reason,
    });
    if (error) {
      console.error("Platform subscription RPC failed", error.code);
      return rpcFailure(error.message);
    }
    if (
      !isRecord(data) || data.request_id !== requestId ||
      !isRecord(data.organization) || data.organization.id !== organizationId ||
      !isSafeInteger(data.organization.subscription_revision)
    ) {
      console.error("Platform subscription RPC returned an invalid response");
      return json(502, { error: "Platform işlem sonucu doğrulanamadı" });
    }
    return json(200, data as Record<string, unknown>);
  } catch (error) {
    console.error("Business management failed", error);
    return json(500, { error: "İşletme yönetimi işlemi tamamlanamadı" });
  }
});
