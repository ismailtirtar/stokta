import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

function source(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const loginFunctionSource = source("supabase/functions/username-login/index.ts");
const resetFunctionSource = source("supabase/functions/complete-password-reset/index.ts");
const mobileLoginSource = source("src/screens/LoginScreen.tsx");
const mobileSupabaseSource = source("src/lib/supabase.ts");

test("verified recovery email can sign in without being rewritten as a username", () => {
  assert.match(loginFunctionSource, /identifierLooksLikeEmail = identifierValue\.includes\("@"\)/);
  assert.match(loginFunctionSource, /identifierLooksLikeEmail \? normalizeRecoveryEmail\(identifierValue\) : null/);
  assert.match(loginFunctionSource, /identifierLooksLikeEmail \? null : normalizeUsername\(identifierValue\)/);
  assert.match(loginFunctionSource, /normalizeRecoveryEmail\(identifierValue\)/);
  assert.match(loginFunctionSource, /\.eq\("recovery_email", recoveryEmail as string\)/);
  assert.match(loginFunctionSource, /\.not\("recovery_email_verified_at", "is", null\)/);
  assert.match(loginFunctionSource, /login-account:v2:\$\{expectedUserId \?\?/);
  assert.match(mobileSupabaseSource, /function normalizeLoginIdentifier/);
  assert.match(mobileSupabaseSource, /trimmed\.includes\("@"\)/);
  assert.match(mobileLoginSource, /body: \{ username: normalizedIdentifier, password \}/);
});

test("pending registrations keep email login in the verification flow", () => {
  assert.match(loginFunctionSource, /\.select\("auth_user_id,registration_kind,email,expires_at,username"\)/);
  assert.match(loginFunctionSource, /pendingQuery\.eq\("email", recoveryEmail as string\)/);
  assert.match(loginFunctionSource, /username: resolvedUsername/);
  assert.match(loginFunctionSource, /p_username: resolvedUsername/);
});

test("unknown accounts consume a decoy account-wide limit before returning", () => {
  assert.match(loginFunctionSource, /expectedUserId \?\? `unknown:\$\{normalizedIdentifier\}`/);
  assert.match(loginFunctionSource, /if \(!accountAllowed\) \{\s*return json\(401, invalidCredentials\)/);
  assert.match(loginFunctionSource, /if \(!expectedUserId \|\| !email\) return json\(401, invalidCredentials\)/);
});

test("successful password reset clears only account-specific login locks", () => {
  assert.match(resetFunctionSource, /\.select\("id,username,recovery_email,recovery_email_verified_at"\)/);
  assert.match(resetFunctionSource, /p_scope: "username-login"/);
  assert.match(resetFunctionSource, /p_scope: "username-login-account"/);
  assert.doesNotMatch(resetFunctionSource, /clear_auth_rate_limit[\s\S]{0,180}p_scope: "username-login-ip"/);
  assert.match(resetFunctionSource, /username: profile\.username/);
  assert.match(resetFunctionSource, /accountLocksCleared/);
});

test("password recovery returns the canonical username to both clients", () => {
  assert.match(mobileLoginSource, /data\.reauthenticationRequired !== true/);
  assert.match(mobileLoginSource, /setUsername\(data\.username\)/);
  assert.match(mobileLoginSource, /Kullanıcı adı veya e-posta/);
  assert.doesNotMatch(mobileLoginSource, /recoveryIdentifier\.includes\("@"\) \? ""/);
});
