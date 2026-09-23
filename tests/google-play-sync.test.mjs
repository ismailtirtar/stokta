import assert from "node:assert/strict";
import test from "node:test";
import { processGooglePlayToken } from
  "../supabase/functions/_shared/google_play_sync.ts";
import { sha256 } from "../supabase/functions/_shared/security.ts";

const userId = "11111111-1111-4111-8111-111111111111";
const organizationId = "22222222-2222-4222-8222-222222222222";
const purchaseToken = "purchase-token-1234567890";
const owner = {
  userId, organizationId,
  accountHash: await sha256(userId),
  profileHash: await sha256(organizationId),
};
globalThis.Deno = {
  env: { get: (name) => name === "GOOGLE_PLAY_TOKEN_ENCRYPTION_KEY"
    ? Buffer.alloc(32, 7).toString("base64") : undefined },
};

function playState(state, acknowledgementState, expiryTime = "2030-01-01T00:00:00.000Z") {
  return {
    verifiedAt: new Date().toISOString(),
    subscriptionState: state,
    acknowledgementState,
    expiryTime,
    autoRenewEnabled: true,
    isTestPurchase: true,
    latestSuccessfulOrderId: "GPA.12345.0",
    entitled: ["SUBSCRIPTION_STATE_ACTIVE", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD",
      "SUBSCRIPTION_STATE_CANCELED"].includes(state) && Date.parse(expiryTime) > Date.now(),
  };
}

function fakeAdmin() {
  const recorded = [];
  const calls = [];
  return {
    recorded, calls,
    rpc: async (name, parameters) => {
      calls.push(name);
      if (name === "service_claim_google_play_observation") {
        return { data: { leaseId: "33333333-3333-4333-8333-333333333333", generation: 1 }, error: null };
      }
      if (name === "service_record_google_play_observation") {
        recorded.push(parameters);
        assert.equal(parameters.p_observation.purchaseTokenHash, await sha256(purchaseToken));
        assert.notEqual(parameters.p_token_ciphertext, purchaseToken);
        assert.ok(parameters.p_token_ciphertext.length > purchaseToken.length);
        const active = parameters.p_observation.activateEntitlement;
        return { data: {
          entitled: active,
          subscriptionStatus: active ? "active" : "inactive",
          currentPeriodEnd: parameters.p_observation.expiryTime,
        }, error: null };
      }
      if (name === "service_release_google_play_observation") {
        return { data: true, error: null };
      }
      throw new Error(`Unexpected RPC ${name}`);
    },
  };
}

test("first purchase records pending without access, then records Google's actual ACK", async () => {
  const admin = fakeAdmin();
  let reads = 0;
  let acknowledged = false;
  const googlePlay = {
    verifySubscription: async () => {
      reads++;
      return playState("SUBSCRIPTION_STATE_ACTIVE",
        acknowledged ? "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED" : "ACKNOWLEDGEMENT_STATE_PENDING");
    },
    acknowledgeSubscription: async () => { acknowledged = true; },
  };
  const result = await processGooglePlayToken(admin, purchaseToken, "verify", { owner, googlePlay });
  assert.equal(result.disposition, "recorded");
  assert.equal(result.ledger.entitled, true);
  assert.equal(result.acknowledged, true);
  assert.equal(reads, 2);
  assert.deepEqual(admin.recorded.map((call) => call.p_observation.activateEntitlement), [false, true]);
  assert.equal(admin.calls.at(-1), "service_release_google_play_observation");
});

test("a still-pending Publisher read after ACK never fabricates access", async () => {
  const admin = fakeAdmin();
  const googlePlay = {
    verifySubscription: async () => playState(
      "SUBSCRIPTION_STATE_ACTIVE", "ACKNOWLEDGEMENT_STATE_PENDING",
    ),
    acknowledgeSubscription: async () => {},
  };
  const result = await processGooglePlayToken(admin, purchaseToken, "verify", { owner, googlePlay });
  assert.equal(result.ledger.entitled, false);
  assert.equal(result.acknowledged, false);
  assert.deepEqual(admin.recorded.map((call) => call.p_observation.activateEntitlement), [false, false]);
});

test("canceled period retains access; account hold does not", async () => {
  for (const [state, entitled] of [
    ["SUBSCRIPTION_STATE_CANCELED", true],
    ["SUBSCRIPTION_STATE_ON_HOLD", false],
  ]) {
    const admin = fakeAdmin();
    const googlePlay = {
      verifySubscription: async () => playState(state, "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"),
    };
    const result = await processGooglePlayToken(admin, purchaseToken, "verify", { owner, googlePlay });
    assert.equal(result.ledger.entitled, entitled);
    assert.equal(admin.recorded.length, 1);
  }
});
