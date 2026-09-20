import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

function source(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const inventorySource = source("src/screens/InventoryScreen.tsx");
const gateSource = source("src/components/PlatformMfaGate.tsx");
const businessFunctionSource = source("supabase/functions/manage-businesses/index.ts");
const migrationName = readdirSync(new URL("../supabase/migrations/", import.meta.url))
  .find((name) => name.endsWith("_platform_operator_mfa_aal2.sql"));

assert.ok(migrationName, "Platform operatörü AAL2 migration dosyası bulunamadı");
const migrationSource = source(`supabase/migrations/${migrationName}`);
const recoverySource = source("security/platform-operator-mfa-recovery-tr.md");
const supabaseConfigSource = source("supabase/config.toml");

test("TOTP kapısı yalnız platform operatörünü AAL2 doğrulamasına alır", () => {
  assert.match(inventorySource, /isPlatformOperator && platformMfaVerifiedToken !== session\.access_token/);
  assert.match(inventorySource, /setPlatformMfaVerifiedToken\(session\.access_token\)/);
  assert.doesNotMatch(inventorySource, /<PlatformModal[\s\S]*<PlatformMfaGate/);
  assert.match(gateSource, /getAuthenticatorAssuranceLevel\(\)/);
  assert.match(gateSource, /currentLevel === "aal2"/);
  assert.match(gateSource, /nextLevel === "aal2"/);
  assert.match(gateSource, /const verifiedTotp = factors\.data\.totp\[0\]/);
  assert.match(gateSource, /factorType: "totp"/);
  assert.match(gateSource, /mfa\.challenge\(\{ factorId \}\)/);
  assert.match(gateSource, /mfa\.verify\(\{/);
  assert.doesNotMatch(gateSource, /auth\.refreshSession\(\)/);
  assert.match(gateSource, /currentAuthenticationMethods\.some/);
  assert.match(gateSource, /setSecret\(""\);[\s\S]*onVerified\(\)/);
});

test("Normal yönetici ve çalışan oturumları MFA kapısına alınmaz", () => {
  assert.doesNotMatch(inventorySource, /visible=\{isAdmin && !platformMfaVerified\}/);
  assert.match(inventorySource, /\{isAdmin \? <ProductEditor/);
  assert.match(inventorySource, /\{isAdmin \? <CoworkerEditor/);
  assert.match(inventorySource, /\{isPlatformOperator \? <PlatformModal/);
  assert.match(inventorySource, /\{isAdmin \|\| isPlatformOperator \? <SafetyCenterModal/);
});

test("Service-role platform işletme işlemi doğrulanmış claim ve AAL2 olmadan çalışmaz", () => {
  assert.match(businessFunctionSource, /admin\.auth\.getUser\(token\)/);
  assert.match(businessFunctionSource, /admin\.auth\.getClaims\(token\)/);
  assert.match(businessFunctionSource, /claimsData\.claims\.sub !== userData\.user\.id/);
  assert.match(businessFunctionSource, /factor\.factor_type === "totp" && factor\.status === "verified"/);
  assert.match(businessFunctionSource, /code: "MFA_ENROLLMENT_REQUIRED"/);
  assert.match(businessFunctionSource, /claimsData\.claims\.aal !== "aal2"/);
  assert.match(businessFunctionSource, /method === "totp" \|\| method === "mfa\/totp"/);
  assert.match(businessFunctionSource, /code: "TOTP_VERIFICATION_REQUIRED"/);
  assert.match(businessFunctionSource, /service_has_live_totp_aal2_session/);
  assert.match(businessFunctionSource, /code: "TOTP_SESSION_REQUIRED"/);
  assert.match(businessFunctionSource, /code: "MFA_REQUIRED"/);
  const privilegedReadIndex = businessFunctionSource.indexOf('.from("organizations")');
  for (const marker of [
    "admin.auth.getClaims(token)",
    'code: "MFA_ENROLLMENT_REQUIRED"',
    'code: "MFA_REQUIRED"',
    'code: "TOTP_VERIFICATION_REQUIRED"',
    'code: "TOTP_SESSION_REQUIRED"',
  ]) {
    assert.ok(
      businessFunctionSource.indexOf(marker) < privilegedReadIndex,
      `${marker} kontrolü service-role organizasyon sorgusundan önce çalışmalı`,
    );
  }
});

test("Platform moderasyon RPC'leri ortak AAL2 korumasını kullanır", () => {
  assert.match(migrationSource, /create or replace function private\.require_platform_operator_aal2\(\)/);
  assert.match(migrationSource, /create or replace function public\.service_has_live_totp_aal2_session/);
  assert.match(migrationSource, /from auth\.sessions s/);
  assert.match(migrationSource, /join auth\.mfa_factors factor on factor\.id = s\.factor_id/);
  assert.match(migrationSource, /s\.aal = 'aal2'/);
  assert.match(migrationSource, /revoke all on function public\.service_has_live_totp_aal2_session\(uuid, uuid\)[\s\S]*from public, anon, authenticated, service_role/);
  assert.match(migrationSource, /grant execute on function public\.service_has_live_totp_aal2_session\(uuid, uuid\)[\s\S]*to service_role/);
  assert.match(migrationSource, /factor\.factor_type = 'totp'/);
  assert.match(migrationSource, /factor\.status = 'verified'/);
  assert.match(migrationSource, /coalesce\(\(select auth\.jwt\(\)->>'aal'\), 'aal1'\) <> 'aal2'/);
  assert.match(migrationSource, /auth\.jwt\(\)->'amr'/);
  assert.match(migrationSource, /in \('totp', 'mfa\/totp'\)/);
  assert.equal(
    (migrationSource.match(/current_profile := private\.require_platform_operator_aal2\(\);/g) ?? []).length,
    2,
  );
  assert.match(migrationSource, /create or replace function public\.list_platform_content_reports/);
  assert.match(migrationSource, /create or replace function public\.moderate_platform_content_report/);
  assert.doesNotMatch(
    migrationSource,
    /create or replace function private\.require_active_profile\(\)[\s\S]*auth\.jwt\(\)->>'aal'/,
  );
});

test("Kayıp cihaz prosedürü gizli kurtarma uç noktası eklemeden belgelenmiştir", () => {
  assert.match(recoverySource, /kurtarma kodu üretmez/i);
  assert.match(recoverySource, /auth\.admin\.mfa\.deleteFactor/);
  assert.match(recoverySource, /mobil uygulamaya açık bir “MFA sıfırla” uç noktası eklenerek yapılmaz/i);
  assert.match(recoverySource, /tüm kullanıcı oturumları güvenli yönetim ortamından ayrıca iptal edilir/i);
  assert.match(recoverySource, /password_hibp_enabled = true/);
  assert.match(recoverySource, /mfa_totp_enroll_enabled = true/);
  assert.match(recoverySource, /mfa_totp_verify_enabled = true/);
});

test("Yerel Supabase yapılandırması TOTP kayıt ve doğrulamayı açar", () => {
  assert.match(
    supabaseConfigSource,
    /\[auth\.mfa\.totp\]\s+enroll_enabled = true\s+verify_enabled = true/,
  );
});
