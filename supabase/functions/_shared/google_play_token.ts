import { sha256 } from "./security.ts";
import { GooglePlayError, validateGooglePlayPurchaseToken } from "./google_play.ts";

const HASH = /^[a-f0-9]{64}$/;
let cachedKey: Promise<CryptoKey> | undefined;

function base64(bytes: Uint8Array) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(value: string) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error("bad base64");
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function tokenKey() {
  if (!cachedKey) {
    cachedKey = (async () => {
      const encoded = Deno.env.get("GOOGLE_PLAY_TOKEN_ENCRYPTION_KEY") ?? "";
      let bytes: Uint8Array;
      try {
        bytes = fromBase64(encoded);
      } catch {
        throw new GooglePlayError("CONFIGURATION", 500, "Satın alma anahtarı yapılandırması geçersiz");
      }
      if (bytes.byteLength !== 32) {
        throw new GooglePlayError("CONFIGURATION", 500, "Satın alma anahtarı yapılandırması eksik");
      }
      const keyBytes = new Uint8Array(new ArrayBuffer(32));
      keyBytes.set(bytes);
      return await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
    })().catch((error) => {
      cachedKey = undefined;
      throw error;
    });
  }
  return await cachedKey;
}

export async function encryptPurchaseToken(token: string, tokenHash: string) {
  validateGooglePlayPurchaseToken(token);
  if (!HASH.test(tokenHash) || await sha256(token) !== tokenHash) {
    throw new GooglePlayError("INVALID_REQUEST", 400, "Satın alma özeti eşleşmiyor");
  }
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: nonce,
    additionalData: new TextEncoder().encode(tokenHash),
  }, await tokenKey(), new TextEncoder().encode(token));
  return {
    tokenCiphertext: base64(new Uint8Array(ciphertext)),
    tokenNonce: base64(nonce),
  };
}

export async function decryptPurchaseToken(
  tokenHash: string,
  ciphertext: string,
  nonce: string,
  keyVersion: number,
) {
  if (!HASH.test(tokenHash) || keyVersion !== 1
    || ciphertext.length > 8192 || nonce.length > 32) {
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Satın alma kasası geçersiz");
  }
  try {
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: fromBase64(nonce),
      additionalData: new TextEncoder().encode(tokenHash),
    }, await tokenKey(), fromBase64(ciphertext));
    const token = validateGooglePlayPurchaseToken(
      new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
    );
    if (await sha256(token) !== tokenHash) throw new Error("digest mismatch");
    return token;
  } catch (error) {
    if (error instanceof GooglePlayError && error.code === "CONFIGURATION") throw error;
    throw new GooglePlayError("INVALID_RESPONSE", 502, "Satın alma kasası çözülemedi");
  }
}
