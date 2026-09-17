import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const appJson = JSON.parse(readFileSync(new URL("../app.json", import.meta.url), "utf8"));
const supabaseSource = readFileSync(new URL("../src/lib/supabase.ts", import.meta.url), "utf8");
const storageSource = readFileSync(new URL("../src/lib/secure-auth-storage.ts", import.meta.url), "utf8");

test("Supabase oturumu platform güvenli deposunda ve parçalara ayrılarak saklanır", () => {
  assert.equal(packageJson.dependencies["expo-secure-store"], "~15.0.8");
  assert.match(supabaseSource, /storage:\s*secureAuthStorage/);
  assert.doesNotMatch(supabaseSource, /AsyncStorage/);
  assert.match(storageSource, /SecureStore\.WHEN_UNLOCKED_THIS_DEVICE_ONLY/);
  assert.match(storageSource, /CHUNK_SIZE\s*=\s*600/);
  assert.match(storageSource, /Crypto\.CryptoDigestAlgorithm\.SHA256/);
  assert.match(storageSource, /await writeSecureValue\(key, legacyValue\);[\s\S]*await AsyncStorage\.removeItem\(key\);/);
});

test("Kullanılmayan özel URL şeması kaldırılmış ve SecureStore eklentisi yapılandırılmıştır", () => {
  assert.equal(Object.hasOwn(appJson.expo, "scheme"), false);
  const secureStorePlugin = appJson.expo.plugins.find((plugin) =>
    Array.isArray(plugin) && plugin[0] === "expo-secure-store"
  );
  assert.ok(secureStorePlugin);
  assert.equal(secureStorePlugin[1].configureAndroidBackup, true);
  assert.equal(appJson.expo.android.allowBackup, false);
});
