import AsyncStorage from "@react-native-async-storage/async-storage";
import * as Crypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";

interface AuthStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

type SecureManifest = {
  version: 1;
  generation: string;
  chunks: number;
  length: number;
  sha256: string;
};

const STORAGE_PREFIX = "stokdas.auth.v1";
const CHUNK_SIZE = 600;
const MAX_CHUNKS = 64;
const GENERATION_PATTERN = /^[a-f0-9]{32}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const secureStoreOptions: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  keychainService: "stokdas.auth",
};

let secureStoreAvailability: Promise<boolean> | null = null;

async function requireSecureStore() {
  secureStoreAvailability ??= SecureStore.isAvailableAsync();
  if (!(await secureStoreAvailability)) {
    throw new Error("Bu cihazda güvenli oturum deposu kullanılamıyor");
  }
}

async function storageScope(key: string) {
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, key, {
    encoding: Crypto.CryptoEncoding.HEX,
  });
}

function manifestKey(scope: string) {
  return `${STORAGE_PREFIX}.${scope}.meta`;
}

function chunkKey(scope: string, generation: string, index: number) {
  return `${STORAGE_PREFIX}.${scope}.${generation}.${index}`;
}

function parseManifest(value: string | null): SecureManifest | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<SecureManifest>;
    if (parsed.version !== 1
      || typeof parsed.generation !== "string"
      || !GENERATION_PATTERN.test(parsed.generation)
      || !Number.isInteger(parsed.chunks)
      || (parsed.chunks ?? 0) < 1
      || (parsed.chunks ?? 0) > MAX_CHUNKS
      || !Number.isInteger(parsed.length)
      || (parsed.length ?? -1) < 0
      || typeof parsed.sha256 !== "string"
      || !SHA256_PATTERN.test(parsed.sha256)) {
      return null;
    }
    return parsed as SecureManifest;
  } catch {
    return null;
  }
}

function splitValue(value: string) {
  const chunks: string[] = [];
  let offset = 0;
  while (offset < value.length) {
    let end = Math.min(value.length, offset + CHUNK_SIZE);
    const finalCodeUnit = value.charCodeAt(end - 1);
    const nextCodeUnit = value.charCodeAt(end);
    if (end < value.length
      && finalCodeUnit >= 0xd800
      && finalCodeUnit <= 0xdbff
      && nextCodeUnit >= 0xdc00
      && nextCodeUnit <= 0xdfff) {
      end -= 1;
    }
    chunks.push(value.slice(offset, end));
    offset = end;
  }
  return chunks.length > 0 ? chunks : [""];
}

async function deleteGeneration(scope: string, manifest: SecureManifest) {
  await Promise.allSettled(
    Array.from({ length: manifest.chunks }, (_, index) =>
      SecureStore.deleteItemAsync(
        chunkKey(scope, manifest.generation, index),
        secureStoreOptions,
      )),
  );
}

async function readSecureValue(key: string) {
  await requireSecureStore();
  const scope = await storageScope(key);
  const metaKey = manifestKey(scope);
  const manifestRaw = await SecureStore.getItemAsync(metaKey, secureStoreOptions);
  const manifest = parseManifest(manifestRaw);
  if (!manifest) {
    if (manifestRaw !== null) {
      await SecureStore.deleteItemAsync(metaKey, secureStoreOptions);
    }
    return null;
  }

  const chunks = await Promise.all(
    Array.from({ length: manifest.chunks }, (_, index) =>
      SecureStore.getItemAsync(
        chunkKey(scope, manifest.generation, index),
        secureStoreOptions,
      )),
  );
  if (chunks.some((chunk) => chunk === null)) {
    await deleteGeneration(scope, manifest);
    await SecureStore.deleteItemAsync(metaKey, secureStoreOptions);
    return null;
  }

  const value = (chunks as string[]).join("");
  const checksum = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    value,
    { encoding: Crypto.CryptoEncoding.HEX },
  );
  if (value.length !== manifest.length || checksum !== manifest.sha256) {
    await deleteGeneration(scope, manifest);
    await SecureStore.deleteItemAsync(metaKey, secureStoreOptions);
    return null;
  }
  return value;
}

async function writeSecureValue(key: string, value: string) {
  await requireSecureStore();
  const scope = await storageScope(key);
  const metaKey = manifestKey(scope);
  const previousManifest = parseManifest(
    await SecureStore.getItemAsync(metaKey, secureStoreOptions),
  );
  const generation = Crypto.randomUUID().replaceAll("-", "");
  const chunks = splitValue(value);
  if (chunks.length > MAX_CHUNKS) {
    throw new Error("Oturum verisi güvenli depolama sınırını aşıyor");
  }
  const sha256 = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    value,
    { encoding: Crypto.CryptoEncoding.HEX },
  );
  const manifest: SecureManifest = {
    version: 1,
    generation,
    chunks: chunks.length,
    length: value.length,
    sha256,
  };

  let writtenChunks = 0;
  try {
    for (let index = 0; index < chunks.length; index += 1) {
      await SecureStore.setItemAsync(
        chunkKey(scope, generation, index),
        chunks[index]!,
        secureStoreOptions,
      );
      writtenChunks += 1;
    }
    await SecureStore.setItemAsync(
      metaKey,
      JSON.stringify(manifest),
      secureStoreOptions,
    );
  } catch (error) {
    await Promise.allSettled(
      Array.from({ length: writtenChunks }, (_, index) =>
        SecureStore.deleteItemAsync(
          chunkKey(scope, generation, index),
          secureStoreOptions,
        )),
    );
    throw error;
  }

  if (previousManifest && previousManifest.generation !== generation) {
    await deleteGeneration(scope, previousManifest);
  }
}

async function deleteSecureValue(key: string) {
  await requireSecureStore();
  const scope = await storageScope(key);
  const metaKey = manifestKey(scope);
  const manifest = parseManifest(
    await SecureStore.getItemAsync(metaKey, secureStoreOptions),
  );
  if (manifest) await deleteGeneration(scope, manifest);
  await SecureStore.deleteItemAsync(metaKey, secureStoreOptions);
}

/**
 * Supabase sessions are encrypted with the platform keystore/keychain. On the
 * first launch after upgrading, an existing AsyncStorage session is migrated
 * only after the encrypted write succeeds, so users are not logged out merely
 * because they installed the security update.
 */
export const secureAuthStorage: AuthStorage = {
  async getItem(key) {
    const encryptedValue = await readSecureValue(key);
    if (encryptedValue !== null) return encryptedValue;

    const legacyValue = await AsyncStorage.getItem(key);
    if (legacyValue === null) return null;
    await writeSecureValue(key, legacyValue);
    await AsyncStorage.removeItem(key);
    return legacyValue;
  },

  async setItem(key, value) {
    await writeSecureValue(key, value);
    await AsyncStorage.removeItem(key);
  },

  async removeItem(key) {
    let secureStoreError: unknown;
    try {
      await deleteSecureValue(key);
    } catch (error) {
      secureStoreError = error;
    }
    await AsyncStorage.removeItem(key);
    if (secureStoreError) throw secureStoreError;
  },
};
