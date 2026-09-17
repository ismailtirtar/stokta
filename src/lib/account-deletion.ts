import AsyncStorage from "@react-native-async-storage/async-storage";
import * as Crypto from "expo-crypto";

export type AccountDeletionIntent = {
  deletionRequestId: string;
  createdAt: string;
};

const STORAGE_PREFIX = "@stokdas/account-deletion-intent/v1";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isDeletionRequestId(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

async function storageKey(userId: string, organizationId: string) {
  const scope = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    `${userId}:${organizationId}`,
  );
  return `${STORAGE_PREFIX}:${scope}`;
}

function isAccountDeletionIntent(value: unknown): value is AccountDeletionIntent {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<AccountDeletionIntent>;
  return isDeletionRequestId(candidate.deletionRequestId)
    && typeof candidate.createdAt === "string"
    && Number.isFinite(Date.parse(candidate.createdAt));
}

/**
 * The request ID is stored before the destructive request starts. It has no
 * client-side expiry: only a verified terminal response or an explicit
 * pre-effect rejection may forget a server-side deletion saga.
 */
export async function saveAccountDeletionIntent(
  userId: string,
  organizationId: string,
  deletionRequestId: string,
) {
  if (!isDeletionRequestId(deletionRequestId)) {
    throw new Error("Geçersiz hesap silme istek kimliği");
  }
  const key = await storageKey(userId, organizationId);
  const existing = await readAccountDeletionIntent(userId, organizationId);
  const intent: AccountDeletionIntent = {
    deletionRequestId,
    createdAt: existing?.createdAt ?? new Date().toISOString(),
  };
  await AsyncStorage.setItem(key, JSON.stringify(intent));
  return intent;
}

export async function readAccountDeletionIntent(userId: string, organizationId: string) {
  const key = await storageKey(userId, organizationId);
  const raw = await AsyncStorage.getItem(key);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (isAccountDeletionIntent(parsed)) return parsed;
  } catch {
    // Invalid local data cannot safely identify a server-side deletion saga.
  }
  await AsyncStorage.removeItem(key);
  return null;
}

export async function clearAccountDeletionIntent(userId: string, organizationId: string) {
  await AsyncStorage.removeItem(await storageKey(userId, organizationId));
}
