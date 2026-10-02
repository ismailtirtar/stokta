import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import test from "node:test";
import { createGooglePlayPushVerifier, GooglePushAuthUnavailable } from
  "../supabase/functions/_shared/google_play_push_auth.ts";
import { GooglePlayPushMalformed, readGooglePlayPushEvent } from
  "../supabase/functions/_shared/google_play_rtdn_payload.ts";

const now = Date.UTC(2026, 8, 23, 12);
const audience = "https://example.supabase.co/functions/v1/google-play-rtdn";
const email = "push@example.iam.gserviceaccount.com";
const subscription = "projects/stokdas-project/subscriptions/play-updates";
const packageName = "com.ismailtirtar.stokta";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

async function signer() {
  const pair = await crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
  }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  async function token(overrides = {}, headerOverrides = {}) {
    const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key", ...headerOverrides }));
    const claims = base64url(JSON.stringify({
      iss: "https://accounts.google.com", aud: audience, email,
      email_verified: true, sub: "123456789", iat: now / 1000 - 60,
      exp: now / 1000 + 3600, ...overrides,
    }));
    const message = `${header}.${claims}`;
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, Buffer.from(message));
    return `${message}.${base64url(Buffer.from(signature))}`;
  }
  return { jwk: { ...jwk, kid: "test-key", use: "sig", alg: "RS256" }, token };
}

test("Google-signed Pub/Sub OIDC accepts exact claims and rejects tampering", async () => {
  const { jwk, token } = await signer();
  let fetchCount = 0;
  const verifier = createGooglePlayPushVerifier(async (url) => {
    assert.equal(url, "https://www.googleapis.com/oauth2/v3/certs");
    fetchCount++;
    return new Response(JSON.stringify({ keys: [jwk] }), {
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=600" },
    });
  }, () => now);
  const request = (jwt) => new Request(audience, { method: "POST", headers: { Authorization: `Bearer ${jwt}` } });
  const valid = await token();
  assert.equal(await verifier(request(valid), audience, email), true);
  assert.equal(await verifier(request(valid), audience, email), true);
  assert.equal(fetchCount, 1, "verified keys are cached");
  const [header, payload, signature] = valid.split(".");
  const tamperedSignature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  assert.equal(await verifier(request(`${header}.${payload}.${tamperedSignature}`), audience, email), false);
  assert.equal(await verifier(request(await token({ aud: "https://evil.invalid" })), audience, email), false);
  assert.equal(await verifier(request(await token({ email: "other@example.iam.gserviceaccount.com" })), audience, email), false);
  assert.equal(await verifier(request(await token({ iss: "https://evil.invalid" })), audience, email), false);
  assert.equal(await verifier(request(await token({ exp: now / 1000 - 1 })), audience, email), false);
  assert.equal(await verifier(request(await token({ iat: now / 1000 + 120 })), audience, email), false);
  assert.equal(await verifier(request(await token({}, { alg: "none" })), audience, email), false);
});

test("JWKS network failure is retryable and invalid token needs no network", async () => {
  let requests = 0;
  const verifier = createGooglePlayPushVerifier(async () => {
    requests++;
    throw new Error("offline");
  }, () => now);
  const unsigned = new Request(audience, { method: "POST" });
  assert.equal(await verifier(unsigned, audience, email), false);
  assert.equal(requests, 0);
  const { token } = await signer();
  const signed = new Request(audience, { method: "POST", headers: { Authorization: `Bearer ${await token()}` } });
  await assert.rejects(verifier(signed, audience, email), GooglePushAuthUnavailable);
});

function push(notification, overrides = {}) {
  return new Request(audience, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      subscription,
      message: {
        messageId: "message-1",
        data: Buffer.from(JSON.stringify({
          version: "1.0", packageName, eventTimeMillis: String(now), ...notification,
        })).toString("base64"),
      },
      ...overrides,
    }),
  });
}

test("subscription and void events are parsed without trusting event type as status", async () => {
  const subscriptionEvent = await readGooglePlayPushEvent(push({
    subscriptionNotification: { version: "1.0", notificationType: 5, purchaseToken: "purchase-token-123" },
  }), subscription, now);
  assert.deepEqual(subscriptionEvent, {
    kind: "subscription", messageId: "message-1", purchaseToken: "purchase-token-123",
    eventTime: new Date(now).toISOString(),
  });

  const voidEvent = await readGooglePlayPushEvent(push({
    voidedPurchaseNotification: {
      productType: 1, refundType: 1, purchaseToken: "purchase-token-123", orderId: "GPA.12345.0",
    },
  }), subscription, now);
  assert.deepEqual(voidEvent, {
    kind: "void", messageId: "message-1", purchaseToken: "purchase-token-123",
    orderId: "GPA.12345.0", eventTime: new Date(now).toISOString(),
  });
});

test("unrelated event is ignored; wrong package and ambiguous payload are poison", async () => {
  assert.deepEqual(await readGooglePlayPushEvent(push({ testNotification: { version: "1.0" } }), subscription, now), {
    kind: "ignore", reason: "testNotification",
  });
  await assert.rejects(readGooglePlayPushEvent(push({ packageName: "com.other.app", testNotification: {} }), subscription, now), GooglePlayPushMalformed);
  await assert.rejects(readGooglePlayPushEvent(push({
    testNotification: {}, subscriptionNotification: { version: "1.0", notificationType: 2, purchaseToken: "purchase-token-123" },
  }), subscription, now), GooglePlayPushMalformed);
  await assert.rejects(readGooglePlayPushEvent(push({ testNotification: {} }, { subscription: "projects/other/subscriptions/other" }), subscription, now), GooglePlayPushMalformed);
  await assert.rejects(readGooglePlayPushEvent(push({
    eventTimeMillis: String(now - 121 * 24 * 60 * 60_000), testNotification: {},
  }), subscription, now), GooglePlayPushMalformed);
});

test("handler records a void fence before refresh and retries database failures", async () => {
  const previousFetch = globalThis.fetch;
  const previousDeno = globalThis.Deno;
  const { jwk, token } = await signer();
  const calls = [];
  let voidFailure = false;
  globalThis.fetch = async () => new Response(JSON.stringify({ keys: [jwk] }), {
    headers: { "Content-Type": "application/json", "Cache-Control": "max-age=600" },
  });
  globalThis.Deno = {
    env: { get: (key) => ({
      GOOGLE_PLAY_RTDN_AUDIENCE: audience,
      GOOGLE_PLAY_RTDN_SERVICE_ACCOUNT: email,
      GOOGLE_PLAY_RTDN_SUBSCRIPTION: subscription,
      SUPABASE_URL: "https://example.supabase.co",
      SUPABASE_SERVICE_ROLE_KEY: "test-service-key",
    })[key] },
    serve: (handler) => { globalThis.__pushHandler = handler; },
  };
  globalThis.__pushCreateClient = () => ({
    rpc: async (name) => {
      calls.push(name);
      return { error: voidFailure ? { code: "08006" } : null };
    },
  });
  globalThis.__pushProcess = async () => {
    calls.push("processGooglePlayToken");
    return { disposition: "unowned" };
  };
  globalThis.__pushVerify = async (request) => request.headers.get("authorization")?.startsWith("Bearer ") === true;

  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier.startsWith("jsr:")) return { url: "data:text/javascript,", shortCircuit: true };
      if (specifier.startsWith("npm:@supabase/supabase-js")) return {
        url: "data:text/javascript,export const createClient=(...args)=>globalThis.__pushCreateClient(...args)",
        shortCircuit: true,
      };
      if (specifier === "../_shared/google_play_sync.ts"
        && context.parentURL?.includes("/google-play-rtdn/index.ts")) return {
        url: "data:text/javascript,export const processGooglePlayToken=(...args)=>globalThis.__pushProcess(...args)",
        shortCircuit: true,
      };
      if (specifier === "../_shared/google_play_push_auth.ts"
        && context.parentURL?.includes("/google-play-rtdn/index.ts")) return {
        url: "data:text/javascript,export class GooglePushAuthUnavailable extends Error{};export const verifyGooglePlayPush=(...args)=>globalThis.__pushVerify(...args)",
        shortCircuit: true,
      };
      return nextResolve(specifier, context);
    },
  });

  try {
    await import("../supabase/functions/google-play-rtdn/index.ts");
    const jwt = await token({ iat: Math.floor(Date.now() / 1000) - 60, exp: Math.floor(Date.now() / 1000) + 3600 });
    const voidNotification = () => push({ voidedPurchaseNotification: {
      productType: 1, refundType: 1, purchaseToken: "purchase-token-123", orderId: "GPA.12345.0",
    }, eventTimeMillis: String(Date.now()) });
    const authenticatedRequest = async () => {
      const notification = voidNotification();
      return new Request(audience, {
        method: "POST", headers: { Authorization: `Bearer ${jwt}` },
        body: await notification.text(),
      });
    };
    assert.equal((await globalThis.__pushHandler(await authenticatedRequest())).status, 204);
    assert.deepEqual(calls, ["service_record_google_play_void", "processGooglePlayToken"]);
    calls.length = 0;
    voidFailure = true;
    assert.equal((await globalThis.__pushHandler(await authenticatedRequest())).status, 503);
    assert.deepEqual(calls, ["service_record_google_play_void"]);
    assert.equal((await globalThis.__pushHandler(new Request(audience, { method: "POST" }))).status, 401);
  } finally {
    globalThis.fetch = previousFetch;
    globalThis.Deno = previousDeno;
    delete globalThis.__pushHandler;
    delete globalThis.__pushCreateClient;
    delete globalThis.__pushProcess;
    delete globalThis.__pushVerify;
  }
});
