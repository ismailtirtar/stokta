export const GOOGLE_PLAY_PACKAGE_NAME = "com.ismailtirtar.stokta";
export const GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID = "stokdas_pro";
export const GOOGLE_PLAY_BASE_PLAN_ID = "monthly";

const GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_ANDROID_PUBLISHER_SCOPE = "https://www.googleapis.com/auth/androidpublisher";
const GOOGLE_ANDROID_PUBLISHER_ROOT =
  "https://androidpublisher.googleapis.com/androidpublisher/v3";
const REQUEST_TIMEOUT_MS = 12_000;
const HASH_PATTERN = /^[a-f0-9]{64}$/;

const subscriptionStates = new Set([
  "SUBSCRIPTION_STATE_PENDING",
  "SUBSCRIPTION_STATE_ACTIVE",
  "SUBSCRIPTION_STATE_PAUSED",
  "SUBSCRIPTION_STATE_IN_GRACE_PERIOD",
  "SUBSCRIPTION_STATE_ON_HOLD",
  "SUBSCRIPTION_STATE_CANCELED",
  "SUBSCRIPTION_STATE_EXPIRED",
  "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED",
] as const);

const acknowledgementStates = new Set([
  "ACKNOWLEDGEMENT_STATE_PENDING",
  "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
] as const);

const entitlementStates = new Set([
  "SUBSCRIPTION_STATE_ACTIVE",
  "SUBSCRIPTION_STATE_IN_GRACE_PERIOD",
  "SUBSCRIPTION_STATE_CANCELED",
]);

export type GooglePlaySubscriptionState =
  | "SUBSCRIPTION_STATE_PENDING"
  | "SUBSCRIPTION_STATE_ACTIVE"
  | "SUBSCRIPTION_STATE_PAUSED"
  | "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
  | "SUBSCRIPTION_STATE_ON_HOLD"
  | "SUBSCRIPTION_STATE_CANCELED"
  | "SUBSCRIPTION_STATE_EXPIRED"
  | "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED";

export type GooglePlayAcknowledgementState =
  | "ACKNOWLEDGEMENT_STATE_PENDING"
  | "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED";

export type VerifiedGooglePlaySubscription = {
  verifiedAt: string;
  subscriptionState: GooglePlaySubscriptionState;
  acknowledgementState: GooglePlayAcknowledgementState;
  expiryTime: string | null;
  autoRenewEnabled: boolean | null;
  isTestPurchase: boolean;
  latestSuccessfulOrderId: string | null;
  entitled: boolean;
};

export type GooglePlayErrorCode =
  | "INVALID_REQUEST"
  | "INVALID_PURCHASE"
  | "IDENTITY_MISMATCH"
  | "INVALID_RESPONSE"
  | "CONFIGURATION"
  | "UNAVAILABLE";

export class GooglePlayError extends Error {
  readonly code: GooglePlayErrorCode;
  readonly responseStatus: number;

  constructor(code: GooglePlayErrorCode, responseStatus: number, message: string) {
    super(message);
    this.name = "GooglePlayError";
    this.code = code;
    this.responseStatus = responseStatus;
  }
}

type ServiceAccountCredentials = {
  clientEmail: string;
  privateKey: string;
  privateKeyId: string | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlJson(value: Record<string, unknown>) {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function decodePkcs8Pem(pem: string) {
  const encoded = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");
  if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new GooglePlayError("CONFIGURATION", 500, "Google Play anahtarı geçersiz");
  }

  try {
    const binary = atob(encoded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new GooglePlayError("CONFIGURATION", 500, "Google Play anahtarı geçersiz");
  }
}

function loadServiceAccountCredentials(): ServiceAccountCredentials {
  const source = Deno.env.get("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON");
  if (!source || source.length > 64 * 1024) {
    throw new GooglePlayError("CONFIGURATION", 500, "Google Play sunucu yapılandırması eksik");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new GooglePlayError("CONFIGURATION", 500, "Google Play sunucu yapılandırması geçersiz");
  }
  if (!isRecord(parsed)) {
    throw new GooglePlayError("CONFIGURATION", 500, "Google Play sunucu yapılandırması geçersiz");
  }

  const type = parsed.type;
  const clientEmail = parsed.client_email;
  const privateKey = parsed.private_key;
  const privateKeyId = parsed.private_key_id;
  const tokenUri = parsed.token_uri;

  if (type !== "service_account"
    || typeof clientEmail !== "string"
    || !/^[^@\s]{1,200}@[a-z0-9.-]+[.]gserviceaccount[.]com$/.test(clientEmail)
    || typeof privateKey !== "string"
    || privateKey.length < 1_000
    || privateKey.length > 16_384
    || !privateKey.includes("-----BEGIN PRIVATE KEY-----")
    || !privateKey.includes("-----END PRIVATE KEY-----")
    || (privateKeyId !== undefined
      && (typeof privateKeyId !== "string" || !/^[a-f0-9]{8,160}$/i.test(privateKeyId)))
    || (tokenUri !== undefined && tokenUri !== GOOGLE_OAUTH_TOKEN_URL)) {
    throw new GooglePlayError("CONFIGURATION", 500, "Google Play sunucu yapılandırması geçersiz");
  }

  return {
    clientEmail,
    privateKey,
    privateKeyId: typeof privateKeyId === "string" ? privateKeyId : null,
  };
}

async function fetchWithTimeout(url: string, init: RequestInit) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch {
    throw new GooglePlayError("UNAVAILABLE", 503, "Google Play bağlantısı kurulamadı");
  } finally {
    clearTimeout(timeout);
  }
}

async function parseJsonObject(response: Response) {
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play yanıtı geçersiz");
  }
  if (!isRecord(value)) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play yanıtı geçersiz");
  }
  return value;
}

function mapPublisherError(status: number): never {
  if ([400, 404, 410].includes(status)) {
    throw new GooglePlayError("INVALID_PURCHASE", 400, "Google Play satın alımı doğrulanamadı");
  }
  if ([401, 403].includes(status)) {
    throw new GooglePlayError("CONFIGURATION", 503, "Google Play doğrulama yetkisi kullanılamıyor");
  }
  if (status === 429 || status >= 500) {
    throw new GooglePlayError("UNAVAILABLE", 503, "Google Play doğrulaması geçici olarak kullanılamıyor");
  }
  throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play doğrulaması tamamlanamadı");
}

export function validateGooglePlayPurchaseToken(value: unknown) {
  if (typeof value !== "string"
    || value.length < 10
    || value.length > 4_096
    || value !== value.trim()
    || /[^\u0021-\u007e]/.test(value)) {
    throw new GooglePlayError("INVALID_REQUEST", 400, "Geçersiz Google Play satın alma anahtarı");
  }
  return value;
}

function validateHash(value: string, label: string) {
  if (!HASH_PATTERN.test(value)) {
    throw new GooglePlayError("INVALID_REQUEST", 400, `${label} geçersiz`);
  }
}

function normalizedTimestamp(value: unknown, required: boolean) {
  if (value === undefined || value === null) {
    if (required) {
      throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play bitiş zamanı eksik");
    }
    return { iso: null, milliseconds: null };
  }
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play bitiş zamanı geçersiz");
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play bitiş zamanı geçersiz");
  }
  return { iso: new Date(milliseconds).toISOString(), milliseconds };
}

function validateSubscriptionResponse(
  raw: Record<string, unknown>,
  expectedAccountId: string,
  expectedProfileId: string,
  nowMilliseconds: number,
): VerifiedGooglePlaySubscription {
  validateHash(expectedAccountId, "Hesap özeti");
  validateHash(expectedProfileId, "İşletme özeti");

  const stateValue = raw.subscriptionState;
  if (typeof stateValue !== "string" || !subscriptionStates.has(stateValue as never)) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play abonelik durumu geçersiz");
  }
  const subscriptionState = stateValue as GooglePlaySubscriptionState;

  const acknowledgementValue = raw.acknowledgementState;
  if (typeof acknowledgementValue !== "string"
    || !acknowledgementStates.has(acknowledgementValue as never)) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play onay durumu geçersiz");
  }
  const acknowledgementState = acknowledgementValue as GooglePlayAcknowledgementState;

  if (raw.linkedPurchaseToken !== undefined && raw.linkedPurchaseToken !== null) {
    // This first release has one immutable base plan and no token-replacement
    // flow. A linked token must be reconciled against the private ledger before
    // it can ever affect entitlement; rejecting here leaves current access
    // unchanged.
    throw new GooglePlayError(
      "INVALID_PURCHASE",
      409,
      "Bağlantılı Google Play aboneliği henüz desteklenmiyor",
    );
  }
  if (raw.outOfAppPurchaseContext !== undefined && raw.outOfAppPurchaseContext !== null) {
    throw new GooglePlayError(
      "INVALID_PURCHASE",
      409,
      "Google Play üzerinden yeniden abonelik henüz desteklenmiyor",
    );
  }

  const externalIdentifiers = raw.externalAccountIdentifiers;
  if (!isRecord(externalIdentifiers)
    || externalIdentifiers.obfuscatedExternalAccountId !== expectedAccountId
    || externalIdentifiers.obfuscatedExternalProfileId !== expectedProfileId) {
    throw new GooglePlayError("IDENTITY_MISMATCH", 403, "Google Play satın alma kimliği eşleşmiyor");
  }

  const lineItems = raw.lineItems;
  if (!Array.isArray(lineItems) || lineItems.length !== 1 || !isRecord(lineItems[0])) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play abonelik kalemi geçersiz");
  }
  const lineItem = lineItems[0];
  if (lineItem.productId !== GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID) {
    throw new GooglePlayError("INVALID_PURCHASE", 400, "Desteklenmeyen Google Play aboneliği");
  }

  const offerDetails = lineItem.offerDetails;
  if (!isRecord(offerDetails) || offerDetails.basePlanId !== GOOGLE_PLAY_BASE_PLAN_ID) {
    throw new GooglePlayError("INVALID_PURCHASE", 400, "Desteklenmeyen Google Play planı");
  }

  const timestampRequired = entitlementStates.has(subscriptionState);
  const expiry = normalizedTimestamp(lineItem.expiryTime, timestampRequired);

  const autoRenewingPlan = lineItem.autoRenewingPlan;
  let autoRenewEnabled: boolean | null = null;
  if (autoRenewingPlan !== undefined && autoRenewingPlan !== null) {
    if (!isRecord(autoRenewingPlan) || typeof autoRenewingPlan.autoRenewEnabled !== "boolean") {
      throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play yenileme bilgisi geçersiz");
    }
    autoRenewEnabled = autoRenewingPlan.autoRenewEnabled;
  } else if (timestampRequired) {
    throw new GooglePlayError("INVALID_PURCHASE", 400, "Desteklenmeyen Google Play plan türü");
  }

  const orderId = lineItem.latestSuccessfulOrderId;
  if (orderId !== undefined && orderId !== null
    && (typeof orderId !== "string"
      || orderId.length < 1
      || orderId.length > 256
      || /[\u0000-\u001f\u007f]/.test(orderId))) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play sipariş bilgisi geçersiz");
  }

  const testPurchase = raw.testPurchase;
  if (testPurchase !== undefined && testPurchase !== null && !isRecord(testPurchase)) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Google Play test bilgisi geçersiz");
  }

  const entitled = entitlementStates.has(subscriptionState)
    && expiry.milliseconds !== null
    && expiry.milliseconds > nowMilliseconds;

  return {
    verifiedAt: new Date(nowMilliseconds).toISOString(),
    subscriptionState,
    acknowledgementState,
    expiryTime: expiry.iso,
    autoRenewEnabled,
    isTestPurchase: testPurchase !== undefined && testPurchase !== null,
    latestSuccessfulOrderId: typeof orderId === "string" ? orderId : null,
    entitled,
  };
}

export class GooglePlayClient {
  readonly #accessToken: string;

  private constructor(accessToken: string) {
    this.#accessToken = accessToken;
  }

  static async fromEnvironment() {
    const credentials = loadServiceAccountCredentials();
    const accessToken = await GooglePlayClient.createAccessToken(credentials);
    return new GooglePlayClient(accessToken);
  }

  private static async createAccessToken(credentials: ServiceAccountCredentials) {
    const header: Record<string, unknown> = { alg: "RS256", typ: "JWT" };
    if (credentials.privateKeyId) header.kid = credentials.privateKeyId;

    const issuedAt = Math.floor(Date.now() / 1_000) - 30;
    const claims = {
      iss: credentials.clientEmail,
      scope: GOOGLE_ANDROID_PUBLISHER_SCOPE,
      aud: GOOGLE_OAUTH_TOKEN_URL,
      iat: issuedAt,
      exp: issuedAt + 3_600,
    };
    const unsigned = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;

    let privateKey: CryptoKey;
    try {
      privateKey = await crypto.subtle.importKey(
        "pkcs8",
        decodePkcs8Pem(credentials.privateKey),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"],
      );
    } catch (error) {
      if (error instanceof GooglePlayError) throw error;
      throw new GooglePlayError("CONFIGURATION", 500, "Google Play anahtarı kullanılamıyor");
    }

    let signature: ArrayBuffer;
    try {
      signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        new TextEncoder().encode(unsigned),
      );
    } catch {
      throw new GooglePlayError("CONFIGURATION", 500, "Google Play kimliği imzalanamadı");
    }
    const assertion = `${unsigned}.${base64Url(new Uint8Array(signature))}`;

    const response = await fetchWithTimeout(GOOGLE_OAUTH_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    });
    if (!response.ok) {
      if (response.status === 429 || response.status >= 500) {
        throw new GooglePlayError("UNAVAILABLE", 503, "Google kimlik hizmeti geçici olarak kullanılamıyor");
      }
      throw new GooglePlayError("CONFIGURATION", 503, "Google Play sunucu kimliği reddedildi");
    }

    const payload = await parseJsonObject(response);
    const accessToken = payload.access_token;
    const expiresIn = payload.expires_in;
    if (typeof accessToken !== "string"
      || accessToken.length < 20
      || accessToken.length > 8_192
      || typeof expiresIn !== "number"
      || !Number.isFinite(expiresIn)
      || expiresIn <= 0) {
      throw new GooglePlayError("INVALID_RESPONSE", 502, "Google kimlik yanıtı geçersiz");
    }
    return accessToken;
  }

  async verifySubscription(
    purchaseTokenValue: unknown,
    expectedAccountId: string,
    expectedProfileId: string,
  ) {
    const purchaseToken = validateGooglePlayPurchaseToken(purchaseTokenValue);
    const raw = await this.getRawSubscription(purchaseToken);
    return validateSubscriptionResponse(
      raw,
      expectedAccountId,
      expectedProfileId,
      Date.now(),
    );
  }

  async acknowledgeSubscription(purchaseTokenValue: unknown) {
    const purchaseToken = validateGooglePlayPurchaseToken(purchaseTokenValue);
    const url = `${GOOGLE_ANDROID_PUBLISHER_ROOT}/applications/${
      encodeURIComponent(GOOGLE_PLAY_PACKAGE_NAME)
    }/purchases/subscriptions/${
      encodeURIComponent(GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID)
    }/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`;

    const response = await fetchWithTimeout(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.#accessToken}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    if (response.ok) return;

    // A concurrent retry may have acknowledged the same purchase after our
    // initial GET. Re-read the resource instead of treating that race as a
    // payment failure.
    if (response.status === 400 || response.status === 409) {
      const current = await this.getRawSubscription(purchaseToken);
      if (current.acknowledgementState === "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED") return;
    }
    mapPublisherError(response.status);
  }

  async listVoidedPurchases(startTimeMillis: number, pageToken: string | null) {
    if (!Number.isSafeInteger(startTimeMillis) || startTimeMillis < 0
      || (pageToken !== null && (pageToken.length < 1 || pageToken.length > 4096))) {
      throw new GooglePlayError("INVALID_REQUEST", 400, "İade tarama imleci geçersiz");
    }
    const url = new URL(
      `${GOOGLE_ANDROID_PUBLISHER_ROOT}/applications/${encodeURIComponent(GOOGLE_PLAY_PACKAGE_NAME)}/purchases/voidedpurchases`,
    );
    url.searchParams.set("type", "1");
    url.searchParams.set("pageSelection.maxResults", "100");
    if (pageToken) url.searchParams.set("pageSelection.token", pageToken);
    else url.searchParams.set("startTime", String(startTimeMillis));
    const response = await fetchWithTimeout(url.toString(), {
      method: "GET",
      headers: { Authorization: `Bearer ${this.#accessToken}` },
    });
    if (!response.ok) mapPublisherError(response.status);
    const raw = await parseJsonObject(response);
    const entries = raw.voidedPurchases ?? [];
    if (!Array.isArray(entries) || entries.length > 100
      || (raw.tokenPagination !== undefined && !isRecord(raw.tokenPagination))) {
      throw new GooglePlayError("INVALID_RESPONSE", 502, "İade listesi geçersiz");
    }
    const nextPageToken = isRecord(raw.tokenPagination)
      ? raw.tokenPagination.nextPageToken : undefined;
    if (nextPageToken !== undefined && nextPageToken !== null
      && (typeof nextPageToken !== "string" || nextPageToken.length > 4096)) {
      throw new GooglePlayError("INVALID_RESPONSE", 502, "İade imleci geçersiz");
    }
    const purchases = entries.map((entry) => {
      if (!isRecord(entry)
        || typeof entry.orderId !== "string"
        || entry.orderId.length < 1 || entry.orderId.length > 256
        || typeof entry.voidedTimeMillis !== "string"
        || !/^\d{10,16}$/.test(entry.voidedTimeMillis)) {
        throw new GooglePlayError("INVALID_RESPONSE", 502, "İade kaydı geçersiz");
      }
      const eventTime = Number(entry.voidedTimeMillis);
      if (!Number.isSafeInteger(eventTime)) {
        throw new GooglePlayError("INVALID_RESPONSE", 502, "İade zamanı geçersiz");
      }
      return {
        purchaseToken: validateGooglePlayPurchaseToken(entry.purchaseToken),
        orderId: entry.orderId,
        eventTime: new Date(eventTime).toISOString(),
      };
    });
    return {
      purchases,
      nextPageToken: typeof nextPageToken === "string" && nextPageToken
        ? nextPageToken : null,
    };
  }

  private async getRawSubscription(purchaseToken: string) {
    const url = `${GOOGLE_ANDROID_PUBLISHER_ROOT}/applications/${
      encodeURIComponent(GOOGLE_PLAY_PACKAGE_NAME)
    }/purchases/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}`;
    const response = await fetchWithTimeout(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${this.#accessToken}` },
    });
    if (!response.ok) mapPublisherError(response.status);
    return await parseJsonObject(response);
  }
}
