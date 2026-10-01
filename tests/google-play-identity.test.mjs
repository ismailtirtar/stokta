import assert from "node:assert/strict";
import test from "node:test";
import { validateSubscriptionResponse } from
  "../supabase/functions/_shared/google_play.ts";

const account = "a".repeat(64);
const profile = "b".repeat(64);
const oldToken = "previous-purchase-token-123";
const now = Date.parse("2026-09-23T12:00:00Z");

function purchase(overrides = {}) {
  return {
    subscriptionState: "SUBSCRIPTION_STATE_ACTIVE",
    acknowledgementState: "ACKNOWLEDGEMENT_STATE_PENDING",
    externalAccountIdentifiers: {
      obfuscatedExternalAccountId: account,
      obfuscatedExternalProfileId: profile,
    },
    lineItems: [{
      productId: "stokdas_pro",
      offerDetails: { basePlanId: "monthly" },
      expiryTime: "2026-10-23T12:00:00Z",
      autoRenewingPlan: { autoRenewEnabled: true },
    }],
    ...overrides,
  };
}

test("linked Play purchase returns its old token only after plan and identity validation", () => {
  const verified = validateSubscriptionResponse(
    purchase({ linkedPurchaseToken: oldToken }), account, profile, now, false,
  );
  assert.equal(verified.predecessorToken, oldToken);
  assert.equal(verified.predecessorKind, "linked");
  assert.throws(() => validateSubscriptionResponse(
    purchase({
      linkedPurchaseToken: oldToken,
      externalAccountIdentifiers: {
        obfuscatedExternalAccountId: "c".repeat(64),
        obfuscatedExternalProfileId: profile,
      },
    }), account, profile, now, false,
  ), { code: "IDENTITY_MISMATCH" });
  assert.throws(() => validateSubscriptionResponse(
    purchase({ linkedPurchaseToken: oldToken, lineItems: [] }),
    account, profile, now, false,
  ), { code: "INVALID_RESPONSE" });
});

test("out-of-app resubscribe checks expired identifiers and exposes predecessor", () => {
  const raw = purchase({
    externalAccountIdentifiers: undefined,
    outOfAppPurchaseContext: {
      expiredPurchaseToken: oldToken,
      expiredExternalAccountIdentifiers: {
        obfuscatedExternalAccountId: account,
        obfuscatedExternalProfileId: profile,
      },
    },
  });
  const verified = validateSubscriptionResponse(raw, account, profile, now, false);
  assert.equal(verified.predecessorToken, oldToken);
  assert.equal(verified.predecessorKind, "expired");
  assert.throws(() => validateSubscriptionResponse(raw,
    "c".repeat(64), profile, now, false), { code: "IDENTITY_MISMATCH" });
  assert.throws(() => validateSubscriptionResponse({
    ...raw,
    externalAccountIdentifiers: purchase().externalAccountIdentifiers,
    outOfAppPurchaseContext: {
      ...raw.outOfAppPurchaseContext,
      expiredExternalAccountIdentifiers: {
        obfuscatedExternalAccountId: "c".repeat(64),
        obfuscatedExternalProfileId: profile,
      },
    },
  }, account, profile, now, false), { code: "IDENTITY_MISMATCH" });
});

test("known out-of-app token survives context removal after ACK; unowned token does not", () => {
  const raw = purchase({
    externalAccountIdentifiers: undefined,
    acknowledgementState: "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
  });
  assert.throws(() => validateSubscriptionResponse(
    raw, account, profile, now, false,
  ), { code: "IDENTITY_MISMATCH" });
  const verified = validateSubscriptionResponse(raw, account, profile, now, true);
  assert.equal(verified.predecessorToken, null);
  assert.equal(verified.entitled, true);
});

test("ambiguous or malformed predecessor context is never accepted", () => {
  assert.throws(() => validateSubscriptionResponse(purchase({
    linkedPurchaseToken: oldToken,
    outOfAppPurchaseContext: { expiredPurchaseToken: oldToken },
  }), account, profile, now, false), { code: "INVALID_RESPONSE" });
  assert.throws(() => validateSubscriptionResponse(purchase({
    outOfAppPurchaseContext: { expiredPurchaseToken: "bad" },
  }), account, profile, now, false), { code: "INVALID_RESPONSE" });
});

test("canceled and expired purchases accept the omitted false renewal default", () => {
  for (const [state, entitled] of [
    ["SUBSCRIPTION_STATE_CANCELED", true],
    ["SUBSCRIPTION_STATE_EXPIRED", false],
  ]) {
    const raw = purchase({
      subscriptionState: state,
      acknowledgementState: "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED",
    });
    raw.lineItems[0].autoRenewingPlan = {};
    if (state === "SUBSCRIPTION_STATE_EXPIRED") {
      raw.lineItems[0].expiryTime = "2026-09-23T11:59:00Z";
    }
    const verified = validateSubscriptionResponse(raw, account, profile, now, false);
    assert.equal(verified.autoRenewEnabled, false);
    assert.equal(verified.entitled, entitled);
  }
});

test("explicit false renewal retains the current canceled paid period", () => {
  const raw = purchase({ subscriptionState: "SUBSCRIPTION_STATE_CANCELED" });
  raw.lineItems[0].autoRenewingPlan = { autoRenewEnabled: false };
  const verified = validateSubscriptionResponse(raw, account, profile, now, false);
  assert.equal(verified.autoRenewEnabled, false);
  assert.equal(verified.entitled, true);
});

test("renewal defaults do not accept malformed plans or nonboolean values", () => {
  for (const value of [[], "", false, { autoRenewEnabled: null },
    { autoRenewEnabled: "false" }, { autoRenewEnabled: 0 }]) {
    const raw = purchase({ subscriptionState: "SUBSCRIPTION_STATE_CANCELED" });
    raw.lineItems[0].autoRenewingPlan = value;
    assert.throws(() => validateSubscriptionResponse(raw, account, profile, now, false),
      { code: "INVALID_RESPONSE" });
  }
  const raw = purchase({ subscriptionState: "SUBSCRIPTION_STATE_CANCELED" });
  delete raw.lineItems[0].autoRenewingPlan;
  assert.throws(() => validateSubscriptionResponse(raw, account, profile, now, false),
    { code: "INVALID_PURCHASE" });
});
