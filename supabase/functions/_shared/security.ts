export const corsJsonHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Cache-Control": "no-store",
  "Pragma": "no-cache",
  "X-Content-Type-Options": "nosniff",
};

export class RequestBodyError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
    this.name = "RequestBodyError";
  }
}

export function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsJsonHeaders,
  });
}

/**
 * Reads a small JSON object without trusting Content-Length. Edge Functions are
 * public HTTP endpoints even when JWT verification is enabled, so bounding the
 * actual byte payload avoids turning JSON parsing into a cheap memory-DoS.
 */
export async function readJsonObject(
  req: Request,
  maxBytes = 16 * 1024,
): Promise<Record<string, unknown>> {
  const declaredLength = req.headers.get("content-length");
  if (
    declaredLength && /^\d+$/.test(declaredLength) &&
    Number(declaredLength) > maxBytes
  ) {
    throw new RequestBodyError("İstek gövdesi çok büyük", 413);
  }

  const mediaType = req.headers.get("content-type")?.split(";", 1)[0]?.trim()
    .toLowerCase();
  if (mediaType && mediaType !== "application/json") {
    throw new RequestBodyError("Content-Type application/json olmalıdır", 415);
  }

  try {
    const value = await readBoundedJson(req, maxBytes);
    if (!isRecord(value)) {
      throw new RequestBodyError("JSON gövdesi bir nesne olmalıdır");
    }
    return value;
  } catch (error) {
    if (error instanceof RequestBodyError) throw error;
    if (error instanceof HttpInputError) {
      throw new RequestBodyError(error.message, error.status);
    }
    throw error;
  }
}

export function requestBodyErrorResponse(error: unknown): Response | null {
  return error instanceof RequestBodyError
    ? json(error.status, { error: error.message })
    : null;
}

export class HttpInputError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpInputError";
    this.status = status;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function readBoundedJson(
  req: Request,
  maxBytes = 16_384,
): Promise<unknown> {
  if (!req.body) throw new HttpInputError(400, "Geçersiz istek gövdesi");
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new HttpInputError(413, "İstek gövdesi çok büyük");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new HttpInputError(400, "Geçersiz istek gövdesi");
  }
}

export function constantTimeTextEqual(left: string, right: string) {
  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

export function normalizeUsername(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value
    .trim()
    .toLocaleLowerCase("tr-TR")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ı/g, "i");
  return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalized) ? normalized : null;
}

export function normalizeRecoveryEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (normalized.length < 5 || normalized.length > 254) return null;
  if (normalized.endsWith("@stokta.invalid")) return null;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized) ? normalized : null;
}

export function isStrongPassword(value: string) {
  return value.length >= 8 && value.length <= 72 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

export function requestIp(req: Request) {
  const candidate = req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-real-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (!candidate) return "unknown";
  const bounded = candidate.trim().slice(0, 64);
  return /^[0-9a-f:.]+$/i.test(bounded) ? bounded.toLowerCase() : "unknown";
}

export async function sha256(value: string) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(
    new Uint8Array(bytes),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

export function bearerToken(req: Request) {
  const authorization = req.headers.get("Authorization");
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function normalizeUuid(value: unknown): string | null {
  return typeof value === "string" && uuidPattern.test(value)
    ? value.toLowerCase()
    : null;
}

export function sessionIdFromAccessToken(token: string): string | null {
  try {
    const payloadPart = token.split(".")[1];
    if (!payloadPart) return null;
    const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(payloadPart.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded)) as Record<string, unknown>;
    const sessionId = typeof payload.session_id === "string"
      ? payload.session_id
      : "";
    return uuidPattern.test(sessionId) ? sessionId : null;
  } catch {
    return null;
  }
}

export function randomStrongPassword() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const random = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `Aa1!${random}`;
}

export function randomOpaqueToken(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(
    /=+$/g,
    "",
  );
}

export function maskEmail(email: string) {
  const [local = "", domain = ""] = email.split("@", 2);
  if (!local || !domain) return null;
  const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
  return `${visible}${
    "*".repeat(Math.max(3, local.length - visible.length))
  }@${domain}`;
}
