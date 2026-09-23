import {
  GooglePlayClient,
  GooglePlayError,
  GOOGLE_PLAY_BASE_PLAN_ID,
  GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID,
  validateGooglePlayPurchaseToken,
} from "./google_play.ts";
import { encryptPurchaseToken } from "./google_play_token.ts";
import { sha256 } from "./security.ts";

export type PlayOwner = {
  userId: string;
  organizationId: string;
  accountHash: string;
  profileHash: string;
};

export type PlayClaim = { leaseId: string; generation: number };
export type PlayLedger = {
  entitled: boolean;
  subscriptionStatus: "trial" | "active" | "inactive" | "past_due" | "suspended" | "canceled";
  currentPeriodEnd: string | null;
};

const statuses = new Set(["trial", "active", "inactive", "past_due", "suspended", "canceled"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class PlaySyncError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, message: string, code = "LEDGER") {
    super(message);
    this.name = "PlaySyncError";
    this.status = status;
    this.code = code;
  }
}

export function validatePlayLedger(value: unknown): PlayLedger {
  if (!isRecord(value) || typeof value.entitled !== "boolean"
    || !statuses.has(value.subscriptionStatus as string)
    || (value.currentPeriodEnd !== null && typeof value.currentPeriodEnd !== "string")
    || (typeof value.currentPeriodEnd === "string"
      && !Number.isFinite(Date.parse(value.currentPeriodEnd)))) {
    throw new PlaySyncError(503, "Abonelik kaydı doğrulanamadı");
  }
  return value as PlayLedger;
}

function validateOwner(value: unknown): PlayOwner {
  if (!isRecord(value) || !UUID.test(value.userId as string)
    || !UUID.test(value.organizationId as string)
    || !HASH.test(value.accountHash as string)
    || !HASH.test(value.profileHash as string)) {
    throw new PlaySyncError(503, "Abonelik sahibi doğrulanamadı");
  }
  return value as PlayOwner;
}

function validateClaim(value: unknown): PlayClaim {
  if (!isRecord(value) || !UUID.test(value.leaseId as string)
    || !Number.isSafeInteger(value.generation) || (value.generation as number) < 1) {
    throw new PlaySyncError(503, "Abonelik gözlem kilidi doğrulanamadı");
  }
  return value as PlayClaim;
}

export async function getGooglePlayOwner(admin: any, tokenHash: string) {
  const { data, error } = await admin.rpc("service_get_google_play_owner", {
    p_token_hash: tokenHash,
  });
  if (error) throw new PlaySyncError(503, "Abonelik sahibi okunamadı", error.code);
  return data === null ? null : validateOwner(data);
}

async function record(
  admin: any, owner: PlayOwner, token: string, tokenHash: string,
  claim: PlayClaim, verified: Awaited<ReturnType<GooglePlayClient["verifySubscription"]>>,
) {
  const encrypted = await encryptPurchaseToken(token, tokenHash);
  const latestOrderIdHash = verified.latestSuccessfulOrderId
    ? await sha256(verified.latestSuccessfulOrderId) : null;
  const { data, error } = await admin.rpc("service_record_google_play_observation", {
    p_lease_id: claim.leaseId,
    p_generation: claim.generation,
    p_observation: {
      purchaseTokenHash: tokenHash,
      userId: owner.userId,
      organizationId: owner.organizationId,
      productId: GOOGLE_PLAY_SUBSCRIPTION_PRODUCT_ID,
      basePlanId: GOOGLE_PLAY_BASE_PLAN_ID,
      subscriptionState: verified.subscriptionState,
      acknowledgementState: verified.acknowledgementState,
      activateEntitlement: verified.entitled
        && verified.acknowledgementState === "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
      verifiedAt: verified.verifiedAt,
      expiryTime: verified.expiryTime,
      autoRenewEnabled: verified.autoRenewEnabled,
      isTestPurchase: verified.isTestPurchase,
      latestOrderIdHash,
      accountHash: owner.accountHash,
      profileHash: owner.profileHash,
    },
    p_token_ciphertext: encrypted.tokenCiphertext,
    p_token_nonce: encrypted.tokenNonce,
  });
  if (error) {
    const code = typeof error.code === "string" ? error.code : "unknown";
    console.error("Google Play ledger update failed", { code });
    if (code === "23505") throw new PlaySyncError(409, "Satın alma başka bir hesaba bağlı", code);
    if (code === "22023") throw new PlaySyncError(400, "Abonelik bilgisi geçersiz", code);
    if (code === "42501") throw new PlaySyncError(403, "İşletme yöneticisi doğrulanamadı", code);
    throw new PlaySyncError(503, "Abonelik kaydı güncellenemedi", code);
  }
  return validatePlayLedger(data);
}

export async function processGooglePlayToken(
  admin: any,
  purchaseTokenValue: unknown,
  mode: "verify" | "rtdn" | "reconcile",
  options: {
    owner?: PlayOwner;
    claim?: PlayClaim;
    googlePlay?: GooglePlayClient;
  } = {},
): Promise<{ disposition: "unowned" } | {
  disposition: "recorded"; ledger: PlayLedger; acknowledged: boolean;
}> {
  const token = validateGooglePlayPurchaseToken(purchaseTokenValue);
  const tokenHash = await sha256(token);
  const owner = options.owner ?? await getGooglePlayOwner(admin, tokenHash);
  if (owner === null) {
    if (mode === "verify") throw new PlaySyncError(403, "Satın alma sahibi bulunamadı");
    return { disposition: "unowned" };
  }
  validateOwner(owner);

  let claim = options.claim;
  if (!claim) {
    const { data, error } = await admin.rpc("service_claim_google_play_observation", {
      p_token_hash: tokenHash,
    });
    if (error) throw new PlaySyncError(503, "Abonelik gözlem kilidi alınamadı", error.code);
    if (data === null) throw new PlaySyncError(503, "Abonelik gözlemi sürüyor", "LEASE_BUSY");
    claim = validateClaim(data);
  } else {
    claim = validateClaim(claim);
  }

  let completed = false;
  try {
    const googlePlay = options.googlePlay ?? await GooglePlayClient.fromEnvironment();
    const verify = async () => {
      try {
        return await googlePlay.verifySubscription(
          token, owner.accountHash, owner.profileHash,
        );
      } catch (error) {
        if (error instanceof GooglePlayError
          && ["INVALID_PURCHASE", "IDENTITY_MISMATCH"].includes(error.code)) {
          // An established owner must not retain access after Publisher
          // rejects the token. The SQL function checks exact ledger ownership,
          // so a stolen token cannot be used to revoke somebody else's plan.
          const disabled = await admin.rpc("service_disable_google_play_token", {
            p_token_hash: tokenHash,
            p_user_id: owner.userId,
            p_organization_id: owner.organizationId,
          });
          if (disabled.error) {
            throw new PlaySyncError(503, "Abonelik erişimi güncellenemedi", disabled.error.code);
          }
        }
        throw error;
      }
    };
    let verified = await verify();
    let ledger = await record(admin, owner, token, tokenHash, claim, verified);

    if (verified.entitled
      && verified.acknowledgementState === "ACKNOWLEDGEMENT_STATE_PENDING") {
      await googlePlay.acknowledgeSubscription(token);
      // Never fabricate ACK based on a pre-ACK GET. A second Publisher read
      // controls activation; a pending response remains unentitled and is
      // retried by reconciliation.
      verified = await verify();
      ledger = await record(admin, owner, token, tokenHash, claim, verified);
    }
    completed = true;
    return {
      disposition: "recorded",
      ledger,
      acknowledged: verified.acknowledgementState === "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
    };
  } finally {
    // A scheduler-owned failed claim is left for its backoff RPC. Requests
    // that claimed locally release on both success and failure.
    if (!options.claim || completed) {
      const { error } = await admin.rpc("service_release_google_play_observation", {
        p_token_hash: tokenHash,
        p_lease_id: claim.leaseId,
      });
      if (error) console.error("Google Play observation lease release failed", {
        code: error.code ?? "unknown",
      });
    }
  }
}

export function transientPlayFailure(error: unknown) {
  if (error instanceof GooglePlayError) {
    return error.code === "UNAVAILABLE" || error.code === "CONFIGURATION";
  }
  return error instanceof PlaySyncError
    && (error.status >= 500 || error.code === "55P03");
}
