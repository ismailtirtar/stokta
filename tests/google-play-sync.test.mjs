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

function fakeAdmin({ ownerForHash = () => null, expectedToken = purchaseToken } = {}) {
  const recorded = [];
  const calls = [];
  return {
    recorded, calls,
    rpc: async (name, parameters) => {
      calls.push(name);
      if (name === "service_get_google_play_owner") {
        return { data: ownerForHash(parameters.p_token_hash), error: null };
      }
      if (name === "service_claim_google_play_observation") {
        return { data: { leaseId: "33333333-3333-4333-8333-333333333333", generation: 1 }, error: null };
      }
      if (name === "service_record_google_play_observation") {
        recorded.push(parameters);
        assert.equal(parameters.p_observation.purchaseTokenHash, await sha256(expectedToken));
        assert.notEqual(parameters.p_token_ciphertext, expectedToken);
        assert.ok(parameters.p_token_ciphertext.length > expectedToken.length);
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

test("unknown linked RTDN token adopts only its ledger predecessor's owner before ACK", async () => {
  const oldToken = "previous-purchase-token-123";
  const newToken = "replacement-purchase-token-456";
  const oldHash = await sha256(oldToken);
  const admin = fakeAdmin({
    ownerForHash: (hash) => hash === oldHash ? owner : null,
    expectedToken: newToken,
  });
  let acknowledged = false;
  const googlePlay = {
    getSubscriptionPredecessor: async () => ({ token: oldToken, kind: "linked" }),
    verifySubscription: async (_token, account, profile) => {
      assert.equal(account, owner.accountHash);
      assert.equal(profile, owner.profileHash);
      return {
        ...playState("SUBSCRIPTION_STATE_ACTIVE", acknowledged
          ? "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED" : "ACKNOWLEDGEMENT_STATE_PENDING"),
        predecessorToken: oldToken, predecessorKind: "linked",
      };
    },
    acknowledgeSubscription: async () => {
      assert.equal(admin.recorded.length, 1);
      acknowledged = true;
    },
  };
  const result = await processGooglePlayToken(admin, newToken, "rtdn", { googlePlay });
  assert.equal(result.disposition, "recorded");
  assert.equal(result.acknowledged, true);
  assert.deepEqual(admin.recorded.map((call) => [
    call.p_observation.predecessorTokenHash,
    call.p_observation.predecessorKind,
    call.p_observation.activateEntitlement,
  ]), [[oldHash, "linked", false], [oldHash, "linked", true]]);
});

test("cross-organization predecessor never records or ACKs a purchase", async () => {
  const oldToken = "previous-purchase-token-123";
  const newToken = "replacement-purchase-token-456";
  const otherOwner = {
    ...owner,
    organizationId: "44444444-4444-4444-8444-444444444444",
    profileHash: await sha256("44444444-4444-4444-8444-444444444444"),
  };
  const awaitHash = await sha256(oldToken);
  const admin = fakeAdmin({
    ownerForHash: (hash) => hash === awaitHash ? otherOwner : null,
    expectedToken: newToken,
  });
  let ackCount = 0;
  const googlePlay = {
    verifySubscription: async () => ({
      ...playState("SUBSCRIPTION_STATE_ACTIVE", "ACKNOWLEDGEMENT_STATE_PENDING"),
      predecessorToken: oldToken, predecessorKind: "linked",
    }),
    acknowledgeSubscription: async () => { ackCount++; },
  };
  await assert.rejects(
    processGooglePlayToken(admin, newToken, "verify", { owner, googlePlay }),
    { status: 409 },
  );
  assert.equal(admin.recorded.length, 0);
  assert.equal(ackCount, 0);
});

test("unknown token without Play predecessor stays unowned and is never ACKed", async () => {
  const admin = fakeAdmin();
  let ackCount = 0;
  const googlePlay = {
    getSubscriptionPredecessor: async () => null,
    verifySubscription: async () => { throw new Error("must not verify without owner"); },
    acknowledgeSubscription: async () => { ackCount++; },
  };
  const result = await processGooglePlayToken(admin, purchaseToken, "rtdn", { googlePlay });
  assert.deepEqual(result, { disposition: "unowned" });
  assert.equal(admin.recorded.length, 0);
  assert.equal(ackCount, 0);
});

test("abandoned pending sibling is never verified, recorded or ACKed later", async () => {
  const awaitHash = await sha256(purchaseToken);
  const admin = fakeAdmin({
    ownerForHash: (hash) => hash === awaitHash
      ? { ...owner, abandoned: true } : null,
  });
  const googlePlay = {
    verifySubscription: async () => { throw new Error("must not call Publisher"); },
    acknowledgeSubscription: async () => { throw new Error("must not ACK"); },
  };
  const result = await processGooglePlayToken(admin, purchaseToken, "rtdn", { googlePlay });
  assert.deepEqual(result, { disposition: "unowned" });
  assert.equal(admin.recorded.length, 0);
  await assert.rejects(
    processGooglePlayToken(admin, purchaseToken, "verify", { owner, googlePlay }),
    { status: 409 },
  );
});

test("out-of-app RTDN persists old ownership before ACK and uses new ledger afterward", async () => {
  const oldToken = "expired-purchase-token-123";
  const newToken = "store-purchase-token-456";
  const oldHash = await sha256(oldToken);
  const newHash = await sha256(newToken);
  let recordedNewOwner = false;
  const admin = fakeAdmin({
    ownerForHash: (hash) => hash === oldHash || (recordedNewOwner && hash === newHash)
      ? owner : null,
    expectedToken: newToken,
  });
  const baseRpc = admin.rpc;
  admin.rpc = async (name, parameters) => {
    const answer = await baseRpc(name, parameters);
    if (name === "service_record_google_play_observation") recordedNewOwner = true;
    return answer;
  };
  let acknowledged = false;
  const googlePlay = {
    getSubscriptionPredecessor: async () => ({ token: oldToken, kind: "expired" }),
    verifySubscription: async (_token, _account, _profile, allowKnown) => {
      if (acknowledged) assert.equal(allowKnown, true);
      return {
        ...playState("SUBSCRIPTION_STATE_ACTIVE", acknowledged
          ? "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED" : "ACKNOWLEDGEMENT_STATE_PENDING"),
        predecessorToken: acknowledged ? null : oldToken,
        predecessorKind: acknowledged ? null : "expired",
      };
    },
    acknowledgeSubscription: async () => { acknowledged = true; },
  };
  await processGooglePlayToken(admin, newToken, "rtdn", { googlePlay });
  assert.equal(admin.recorded[0].p_observation.predecessorTokenHash, oldHash);
  assert.equal(admin.recorded[0].p_observation.predecessorKind, "expired");
  assert.equal(admin.recorded[1].p_observation.predecessorTokenHash, null);
  await processGooglePlayToken(admin, newToken, "reconcile", { googlePlay });
  assert.equal(admin.recorded[2].p_observation.predecessorTokenHash, null);
});
