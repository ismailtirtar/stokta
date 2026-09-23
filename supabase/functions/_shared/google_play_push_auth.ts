const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const CLOCK_SKEW_SECONDS = 60;
const KEY_REQUEST_TIMEOUT_MS = 5_000;
const MAX_CACHE_SECONDS = 3_600;

type JsonObject = Record<string, unknown>;
type SigningKey = {
  kid: string;
  kty: "RSA";
  n: string;
  e: string;
  alg?: string;
  use?: string;
};

type KeySet = {
  expiresAt: number;
  keys: Map<string, CryptoKey>;
};

export class GooglePushAuthUnavailable extends Error {
  constructor() {
    super("Google Pub/Sub kimlik anahtarları şu anda alınamıyor");
    this.name = "GooglePushAuthUnavailable";
  }
}

function object(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "="));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function parseJsonBytes(bytes: Uint8Array): JsonObject | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return object(value) ? value : null;
  } catch {
    return null;
  }
}

function keyCacheDuration(cacheControl: string | null): number {
  const maxAge = cacheControl?.match(/(?:^|,)\s*max-age=(\d+)(?:\s*,|\s*$)/i)?.[1];
  const seconds = maxAge ? Number(maxAge) : 300;
  return Number.isSafeInteger(seconds) ? Math.min(Math.max(seconds, 0), MAX_CACHE_SECONDS) : 300;
}

/** Pub/Sub's bearer token is a Google-signed OIDC token, never a Supabase JWT. */
export function createGooglePlayPushVerifier(
  fetcher: typeof fetch = fetch,
  now: () => number = Date.now,
) {
  let cache: KeySet | null = null;
  let lastUnknownKeyRefreshAt = -Infinity;

  async function refreshKeys(): Promise<KeySet> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), KEY_REQUEST_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetcher(GOOGLE_JWKS_URL, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
    } catch {
      throw new GooglePushAuthUnavailable();
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) throw new GooglePushAuthUnavailable();

    let data: unknown;
    try {
      data = await response.json();
    } catch {
      throw new GooglePushAuthUnavailable();
    }
    if (!object(data) || !Array.isArray(data.keys) || data.keys.length > 16) {
      throw new GooglePushAuthUnavailable();
    }

    const keys = new Map<string, CryptoKey>();
    for (const candidate of data.keys) {
      if (!object(candidate) || candidate.kty !== "RSA"
        || typeof candidate.kid !== "string" || candidate.kid.length > 256
        || !/^[A-Za-z0-9_-]+$/.test(candidate.kid)
        || typeof candidate.n !== "string" || typeof candidate.e !== "string"
        || (candidate.alg !== undefined && candidate.alg !== "RS256")
        || (candidate.use !== undefined && candidate.use !== "sig")) continue;
      const jwk = candidate as SigningKey;
      try {
        const key = await crypto.subtle.importKey(
          "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
        );
        keys.set(jwk.kid, key);
      } catch {
        continue;
      }
    }
    if (!keys.size) throw new GooglePushAuthUnavailable();
    cache = { keys, expiresAt: now() + keyCacheDuration(response.headers.get("cache-control")) * 1_000 };
    return cache;
  }

  return async function verifyGooglePlayPush(
    request: Request,
    expectedAudience: string,
    expectedServiceAccount: string,
  ): Promise<boolean> {
    if (!expectedAudience || expectedAudience.length > 2_048
      || !expectedServiceAccount || expectedServiceAccount.length > 320) return false;
    const authorization = request.headers.get("authorization") ?? "";
    const match = /^Bearer ([A-Za-z0-9._-]{20,8192})$/.exec(authorization);
    if (!match) return false;
    const token = match[1];
    if (!token) return false;
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]
      || parts[0].length > 2_048 || parts[1].length > 4_096) return false;
    const headerBytes = decodeBase64Url(parts[0]);
    const signature = decodeBase64Url(parts[2]);
    if (!headerBytes || !signature) return false;
    const header = parseJsonBytes(headerBytes);
    if (!header || header.alg !== "RS256" || (header.typ !== undefined && header.typ !== "JWT")
      || typeof header.kid !== "string" || !/^[A-Za-z0-9_-]{1,256}$/.test(header.kid)) return false;

    let keySet = cache;
    if (!keySet || keySet.expiresAt <= now()) {
      keySet = await refreshKeys();
    } else if (!keySet.keys.has(header.kid)) {
      // An unauthenticated header must not force a JWKS fetch on every request.
      if (now() - lastUnknownKeyRefreshAt < 30_000) return false;
      lastUnknownKeyRefreshAt = now();
      keySet = await refreshKeys();
    }
    const key = keySet.keys.get(header.kid);
    if (!key) return false;
    let signatureValid: boolean;
    try {
      const signatureBytes = new Uint8Array(new ArrayBuffer(signature.byteLength));
      signatureBytes.set(signature);
      signatureValid = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5", key, signatureBytes,
        new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
      );
    } catch {
      return false;
    }
    if (!signatureValid) return false;

    const payloadBytes = decodeBase64Url(parts[1]);
    const claims = payloadBytes ? parseJsonBytes(payloadBytes) : null;
    if (!claims) return false;
    const currentSeconds = Math.floor(now() / 1_000);
    return claims.iss === "accounts.google.com" || claims.iss === "https://accounts.google.com"
      ? claims.aud === expectedAudience
        && claims.email === expectedServiceAccount
        && (claims.email_verified === true || claims.email_verified === "true")
        && typeof claims.sub === "string" && claims.sub.length > 0
        && typeof claims.exp === "number" && Number.isSafeInteger(claims.exp)
        && claims.exp > currentSeconds
        && typeof claims.iat === "number" && Number.isSafeInteger(claims.iat)
        && claims.iat <= currentSeconds + CLOCK_SKEW_SECONDS
        && claims.iat >= currentSeconds - 7_200
      : false;
  };
}

export const verifyGooglePlayPush = createGooglePlayPushVerifier();
