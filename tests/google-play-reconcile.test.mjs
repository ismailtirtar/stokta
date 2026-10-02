import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import test from "node:test";

const calls = [];
let nextPageToken = "next-page";
let voidFailure = false;

globalThis.Deno = {
  env: { get: (key) => ({
    GOOGLE_PLAY_RECONCILE_SECRET: "a-secret-with-more-than-32-characters-12345",
    SUPABASE_URL: "https://example.supabase.co",
    SUPABASE_SERVICE_ROLE_KEY: "test-service-key",
  })[key] },
  serve: (handler) => { globalThis.__reconcileHandler = handler; },
};
globalThis.__reconcileCreateClient = () => ({
  rpc: async (name) => {
    calls.push(name);
    if (name === "service_get_google_play_void_cursor") {
      return { data: { startTimeMillis: Date.now() - 1000, pageToken: null }, error: null };
    }
    if (name === "service_record_google_play_void") {
      return { error: voidFailure ? { code: "08006" } : null };
    }
    if (name === "service_advance_google_play_void_cursor") return { data: true, error: null };
    if (name === "service_claim_due_google_play_tokens") return { data: [], error: null };
    throw new Error(`Unexpected RPC: ${name}`);
  },
});
globalThis.__reconcileGoogle = class {
  static async fromEnvironment() { return new this(); }
  async listVoidedPurchases() {
    calls.push("listVoidedPurchases");
    return {
      purchases: [{ purchaseToken: "purchase-token-123", orderId: "GPA.12345.0",
        eventTime: new Date().toISOString() }],
      nextPageToken,
    };
  }
};

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith("jsr:")) return { url: "data:text/javascript,", shortCircuit: true };
    if (specifier.startsWith("npm:@supabase/supabase-js")) return {
      url: "data:text/javascript,export const createClient=(...args)=>globalThis.__reconcileCreateClient(...args)",
      shortCircuit: true,
    };
    if (specifier === "../_shared/google_play.ts"
      && context.parentURL?.includes("/google-play-reconcile/index.ts")) return {
      url: "data:text/javascript,export class GooglePlayError extends Error{};export const GooglePlayClient=globalThis.__reconcileGoogle",
      shortCircuit: true,
    };
    if (specifier === "../_shared/google_play_sync.ts"
      && context.parentURL?.includes("/google-play-reconcile/index.ts")) return {
      url: "data:text/javascript,export const processGooglePlayToken=()=>{throw Error('Must not refresh on a partial scan')};export const transientPlayFailure=()=>true",
      shortCircuit: true,
    };
    if (specifier === "../_shared/google_play_token.ts"
      && context.parentURL?.includes("/google-play-reconcile/index.ts")) return {
      url: "data:text/javascript,export const decryptPurchaseToken=()=>{throw Error('Must not decrypt on a partial scan')}",
      shortCircuit: true,
    };
    return nextResolve(specifier, context);
  },
});

await import("../supabase/functions/google-play-reconcile/index.ts");

function request() {
  return new Request("https://example.supabase.co/functions/v1/google-play-reconcile", {
    method: "POST", headers: {
      Authorization: "Bearer a-secret-with-more-than-32-characters-12345",
    },
  });
}

test("partial void sweep commits its page and defers every entitlement refresh", async () => {
  calls.length = 0;
  nextPageToken = "next-page";
  voidFailure = false;
  const response = await globalThis.__reconcileHandler(request());
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true, voided: 1, moreVoidPages: true, reconciled: 0, failed: 0,
  });
  assert.deepEqual(calls, [
    "service_get_google_play_void_cursor", "listVoidedPurchases",
    "service_record_google_play_void", "service_advance_google_play_void_cursor",
  ]);
});

test("completed void sweep may claim due tokens; failed fence cannot advance", async () => {
  calls.length = 0;
  nextPageToken = null;
  assert.equal((await globalThis.__reconcileHandler(request())).status, 200);
  assert.equal(calls.at(-1), "service_claim_due_google_play_tokens");

  calls.length = 0;
  voidFailure = true;
  assert.equal((await globalThis.__reconcileHandler(request())).status, 503);
  assert.deepEqual(calls, [
    "service_get_google_play_void_cursor", "listVoidedPurchases",
    "service_record_google_play_void",
  ]);
});
