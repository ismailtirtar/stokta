import * as Crypto from "expo-crypto";

export const PLAY_SUBSCRIPTION_PRODUCT_ID = "stokdas_pro";
export const PLAY_SUBSCRIPTION_BASE_PLAN_ID = "monthly";
export const ANDROID_PACKAGE_NAME = "com.ismailtirtar.stokta";

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
