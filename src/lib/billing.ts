import * as Crypto from "expo-crypto";
import AsyncStorage from "@react-native-async-storage/async-storage";

export const PLAY_SUBSCRIPTION_PRODUCT_ID = "stokdas_pro";
export const PLAY_SUBSCRIPTION_BASE_PLAN_ID = "monthly";
export const ANDROID_PACKAGE_NAME = "com.ismailtirtar.stokta";

export type GooglePlayPurchaseIntent = {
  purchaseIntentId: string;
  obfuscatedAccountId: string;
  obfuscatedProfileId: string;
  expiresAt: string;
};

const PURCHASE_INTENT_STORAGE_PREFIX = "@stokdas/google-play-purchase-intent/v1";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/i;

/**
 * Google Play only receives stable, opaque identifiers. The user's UUID and the
 * organization UUID never leave the app as billing identifiers.
 */
export async function billingOpaqueId(value: string) {
  return Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    value,
  );
}

async function purchaseIntentStorageKey(userId: string, organizationId: string) {
  const scope = await billingOpaqueId(`${userId}:${organizationId}`);
  return `${PURCHASE_INTENT_STORAGE_PREFIX}:${scope}`;
}

export function isGooglePlayPurchaseIntent(value: unknown): value is GooglePlayPurchaseIntent {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<GooglePlayPurchaseIntent>;
  return typeof candidate.purchaseIntentId === "string"
    && UUID_PATTERN.test(candidate.purchaseIntentId)
    && typeof candidate.obfuscatedAccountId === "string"
    && SHA256_PATTERN.test(candidate.obfuscatedAccountId)
    && typeof candidate.obfuscatedProfileId === "string"
    && SHA256_PATTERN.test(candidate.obfuscatedProfileId)
    && typeof candidate.expiresAt === "string"
    && Number.isFinite(Date.parse(candidate.expiresAt));
}

export async function saveGooglePlayPurchaseIntent(
  userId: string,
  organizationId: string,
  intent: GooglePlayPurchaseIntent,
) {
  const key = await purchaseIntentStorageKey(userId, organizationId);
  await AsyncStorage.setItem(key, JSON.stringify(intent));
}

export async function readGooglePlayPurchaseIntent(userId: string, organizationId: string) {
  const key = await purchaseIntentStorageKey(userId, organizationId);
  const raw = await AsyncStorage.getItem(key);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (isGooglePlayPurchaseIntent(parsed) && Date.parse(parsed.expiresAt) > Date.now()) return parsed;
  } catch {
    // Bozuk veya eski kayıt aşağıda temizlenir.
  }
  await AsyncStorage.removeItem(key);
  return null;
}

export async function clearGooglePlayPurchaseIntent(userId: string, organizationId: string) {
  await AsyncStorage.removeItem(await purchaseIntentStorageKey(userId, organizationId));
}
