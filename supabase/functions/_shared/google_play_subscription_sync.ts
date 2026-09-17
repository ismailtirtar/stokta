import {
  GooglePlayAcknowledgementState,
  GooglePlayClient,
  VerifiedGooglePlaySubscription,
} from "./google_play.ts";
import type { SupabaseClient } from "npm:@supabase/supabase-js@2.112.3";
import { sha256 } from "./security.ts";

type AdminClient = SupabaseClient<any>;

export type ObservationMode = "intent" | "restore" | "rtdn" | "reconcile" | "deletion";

type Claim = {
  leaseId: string;
  generation: number;
  ownership: "intent" | "known" | "neutral";
  expectedAccountIdHash: string | null;
  expectedProfileIdHash: string | null;
};

export type SubscriptionSyncResult = {
  entitled: boolean;
  subscriptionStatus: "trial" | "active" | "past_due" | "suspended" | "canceled";
  currentPeriodEnd: string | null;
  acknowledged: boolean;
  disposition: "applied" | "stale" | "quarantined";
  intentConsumed: boolean;
  intentClosed: boolean;
  deletedOwnerDetected: boolean;
};

type LedgerResult = SubscriptionSyncResult & {
  ackAllowed: boolean;
  repeatObservation: boolean;
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rpcFailure(error: { code?: string; message?: string } | null, fallback: string): never {
  const code = error?.code ?? "unknown";
  console.error(fallback, { code });
  const failure = new Error(fallback) as Error & { code?: string };
  failure.code = code;
  throw failure;
}

function parseClaim(value: unknown): Claim {
  if (!record(value)
    || typeof value.leaseId !== "string"
    || typeof value.generation !== "number"
    || !Number.isSafeInteger(value.generation)
    || value.generation < 1
    || !["intent", "known", "neutral"].includes(String(value.ownership))
    || (value.expectedAccountIdHash !== null && typeof value.expectedAccountIdHash !== "string")
    || (value.expectedProfileIdHash !== null && typeof value.expectedProfileIdHash !== "string")) {
    throw new Error("Google Play gözlem kilidi doğrulanamadı");
  }
  return value as Claim;
}

function parseLedger(value: unknown): LedgerResult {
  if (!record(value)
    || typeof value.entitled !== "boolean"
    || !["trial", "active", "past_due", "suspended", "canceled"].includes(
      String(value.subscriptionStatus),
    )
    || (value.currentPeriodEnd !== null && typeof value.currentPeriodEnd !== "string")
    || typeof value.acknowledged !== "boolean"
    || typeof value.ackAllowed !== "boolean"
    || typeof value.repeatObservation !== "boolean"
    || typeof value.intentConsumed !== "boolean"
    || typeof value.intentClosed !== "boolean"
    || typeof value.deletedOwnerDetected !== "boolean"
    || !["applied", "stale", "quarantined"].includes(String(value.disposition))) {
    throw new Error("Google Play abonelik kaydı doğrulanamadı");
  }
  return value as LedgerResult;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("Şifreleme anahtarı geçersiz");
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error("Şifreleme anahtarı geçersiz");
  }
}

async function tokenCipherKey() {
  const encoded = Deno.env.get("GOOGLE_PLAY_TOKEN_ENCRYPTION_KEY") ?? "";
  const raw = base64ToBytes(encoded);
  if (raw.byteLength !== 32) throw new Error("Google Play token şifreleme anahtarı eksik");
  return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptPurchaseToken(purchaseToken: string) {
  const purchaseTokenHash = await sha256(purchaseToken);
  const keyVersion = 1;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(
        `stokdas:google-play:v2:${purchaseTokenHash}:${keyVersion}`,
      ),
    },
    await tokenCipherKey(),
    new TextEncoder().encode(purchaseToken),
  ));
  return {
    ciphertext: bytesToBase64(ciphertext),
    nonce: bytesToBase64(iv),
    keyVersion,
  };
}

export async function decryptPurchaseToken(
  ciphertext: string,
  nonce: string,
  keyVersion: number,
  expectedPurchaseTokenHash: string,
) {
  if (keyVersion !== 1 || ciphertext.length > 8_192 || nonce.length > 64) {
    throw new Error("Google Play token kasası sürümü desteklenmiyor");
  }
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(nonce),
      additionalData: new TextEncoder().encode(
        `stokdas:google-play:v2:${expectedPurchaseTokenHash}:${keyVersion}`,
      ),
    },
    await tokenCipherKey(),
    base64ToBytes(ciphertext),
  );
  const token = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  if (await sha256(token) !== expectedPurchaseTokenHash) {
    throw new Error("Google Play token kasası bütünlük doğrulaması başarısız");
  }
  return token;
}

function identityState(verified: VerifiedGooglePlaySubscription, claim: Claim) {
  if (!verified.externalAccountId || !verified.externalProfileId) return "incomplete" as const;
  if (!claim.expectedAccountIdHash || !claim.expectedProfileIdHash) return "unclaimed" as const;
  return verified.externalAccountId === claim.expectedAccountIdHash
      && verified.externalProfileId === claim.expectedProfileIdHash
    ? "exact" as const
    : "mismatch" as const;
}

async function lifecycleFingerprint(verified: VerifiedGooglePlaySubscription) {
  // Acknowledgement is deliberately excluded: the second write after the
  // external ACK must be the same lifecycle observation and generation.
  return await sha256(JSON.stringify({
    subscriptionState: verified.subscriptionState,
    expiryTime: verified.expiryTime,
    autoRenewEnabled: verified.autoRenewEnabled,
    isTestPurchase: verified.isTestPurchase,
    latestSuccessfulOrderId: verified.latestSuccessfulOrderId,
    externalAccountId: verified.externalAccountId,
    externalProfileId: verified.externalProfileId,
    linkedPurchaseToken: verified.linkedPurchaseToken,
    startTime: verified.startTime,
  }));
}

async function claimObservation(
  admin: AdminClient,
  purchaseTokenHash: string,
  mode: ObservationMode,
  userId: string | null,
  organizationId: string | null,
  purchaseIntentId: string | null,
) {
  const { data, error } = await admin.rpc("service_claim_google_play_observation", {
    p_purchase_token_hash: purchaseTokenHash,
    p_mode: mode,
    p_user_id: userId,
    p_organization_id: organizationId,
    p_purchase_intent_id: purchaseIntentId,
  });
  if (error) rpcFailure(error, "Google Play gözlem kilidi alınamadı");
  return parseClaim(data);
}

async function releaseObservation(admin: AdminClient, tokenHash: string, claim: Claim) {
  const { error } = await admin.rpc("service_release_google_play_observation", {
    p_purchase_token_hash: tokenHash,
    p_lease_id: claim.leaseId,
    p_generation: claim.generation,
  });
  if (error) console.error("Google Play gözlem kilidi bırakılamadı", { code: error.code });
}

async function writeObservation(
  admin: AdminClient,
  tokenHash: string,
  tokenSecret: Awaited<ReturnType<typeof encryptPurchaseToken>>,
  claim: Claim,
  mode: ObservationMode,
  userId: string | null,
  organizationId: string | null,
  purchaseIntentId: string | null,
  verified: VerifiedGooglePlaySubscription,
  acknowledgementState: GooglePlayAcknowledgementState,
) {
  const orderHash = verified.latestSuccessfulOrderId
    ? await sha256(verified.latestSuccessfulOrderId)
    : null;
  const linkedHash = verified.linkedPurchaseToken
    ? await sha256(verified.linkedPurchaseToken)
    : null;
  const { data, error } = await admin.rpc("service_record_google_play_observation_v2", {
    p_purchase_token_hash: tokenHash,
    p_lease_id: claim.leaseId,
    p_generation: claim.generation,
    p_mode: mode,
    p_user_id: userId,
    p_organization_id: organizationId,
    p_purchase_intent_id: purchaseIntentId,
    p_identity_state: identityState(verified, claim),
    p_external_account_id_hash: verified.externalAccountId,
    p_external_profile_id_hash: verified.externalProfileId,
    p_linked_purchase_token_hash: linkedHash,
    p_purchase_start_time: verified.startTime,
    p_subscription_state: verified.subscriptionState,
    p_acknowledgement_state: acknowledgementState,
    p_source_verified_at: verified.verifiedAt,
    p_expiry_time: verified.expiryTime,
    p_auto_renew_enabled: verified.autoRenewEnabled,
    p_is_test_purchase: verified.isTestPurchase,
    p_latest_order_id_hash: orderHash,
    p_lifecycle_fingerprint: await lifecycleFingerprint(verified),
    p_token_ciphertext: tokenSecret.ciphertext,
    p_token_nonce: tokenSecret.nonce,
    p_token_key_version: tokenSecret.keyVersion,
  });
  if (error) rpcFailure(error, "Google Play abonelik gözlemi kaydedilemedi");
  return parseLedger(data);
}

export async function synchronizeGooglePlaySubscription(options: {
  admin: AdminClient;
  googlePlay: GooglePlayClient;
  purchaseToken: string;
  mode: ObservationMode;
  userId?: string | null;
  organizationId?: string | null;
  purchaseIntentId?: string | null;
}): Promise<SubscriptionSyncResult> {
  const tokenHash = await sha256(options.purchaseToken);
  const tokenSecret = await encryptPurchaseToken(options.purchaseToken);
  let last: LedgerResult | null = null;

  // Two isolated Publisher GET observations are required before this service
  // is allowed to acknowledge an unacknowledged entitlement. The durable,
  // globally monotonic lease generation makes an older response unable to
  // overtake a newer lifecycle observation.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const claim = await claimObservation(
      options.admin,
      tokenHash,
      options.mode,
      options.userId ?? null,
      options.organizationId ?? null,
      options.purchaseIntentId ?? null,
    );
    try {
      const verified = await options.googlePlay.inspectSubscription(options.purchaseToken);
      last = await writeObservation(
        options.admin,
        tokenHash,
        tokenSecret,
        claim,
        options.mode,
        options.userId ?? null,
        options.organizationId ?? null,
        options.purchaseIntentId ?? null,
        verified,
        verified.acknowledgementState,
      );
      if (options.mode !== "deletion" && last.ackAllowed && verified.entitled
        && verified.acknowledgementState === "ACKNOWLEDGEMENT_STATE_PENDING") {
        await options.googlePlay.acknowledgeSubscription(options.purchaseToken);
        const postAcknowledge = await options.googlePlay.inspectSubscription(
          options.purchaseToken,
        );
        last = await writeObservation(
          options.admin,
          tokenHash,
          tokenSecret,
          claim,
          options.mode,
          options.userId ?? null,
          options.organizationId ?? null,
          options.purchaseIntentId ?? null,
          postAcknowledge,
          postAcknowledge.acknowledgementState,
        );
      }
    } finally {
      await releaseObservation(options.admin, tokenHash, claim);
    }
    if (!last.repeatObservation) break;
  }

  if (!last) throw new Error("Google Play abonelik gözlemi tamamlanamadı");
  return {
    entitled: last.entitled,
    subscriptionStatus: last.subscriptionStatus,
    currentPeriodEnd: last.currentPeriodEnd,
    acknowledged: last.acknowledged,
    disposition: last.disposition,
    intentConsumed: last.intentConsumed,
    intentClosed: last.intentClosed,
    deletedOwnerDetected: last.deletedOwnerDetected,
  };
}
