import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = readFileSync(new URL("../src/components/SubscriptionModal.tsx", import.meta.url), "utf8");
const start = source.indexOf("  const processPurchase = useCallback(");
const end = source.indexOf("\n  purchaseHandlerRef.current = processPurchase;", start);
assert.ok(start >= 0 && end > start, "actual purchase handler must be tested");
const executable = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

const purchase = {
  productId: "stokdas_pro",
  store: "google",
  purchaseState: "purchased",
  purchaseToken: "fixture-purchase-token",
  isAcknowledgedAndroid: false,
};

async function run(data, purchaseOverrides = {}) {
  const events = [];
  const states = [];
  const messages = [];
  const errors = [];
  const finished = [];
  const processing = new Set();
  const context = {
    PLAY_SUBSCRIPTION_PRODUCT_ID: "stokdas_pro",
    PURCHASE_REVERIFY_TTL_MS: 30_000,
    SUPPORT_EMAIL: "support@example.test",
    useCallback: (callback) => callback,
    billingOpaqueId: async () => "fixture-token-hash",
    recentlyProcessedPurchaseHashesRef: { current: new Map() },
    processingPurchaseHashesRef: { current: processing },
    setScreenState: (state) => states.push(state),
    setError: (error) => errors.push(error),
    setStoreMessage: (message) => messages.push(message),
    setTimeout: () => {},
    supabase: { functions: { invoke: async (name, args) => {
      events.push("verify");
      assert.equal(name, "verify-play-subscription");
      assert.equal(args.body.purchaseToken, purchase.purchaseToken);
      assert.equal(args.body.productId, purchase.productId);
      return { data, error: null };
    } } },
    finishTransaction: async (args) => {
      events.push("finish");
      finished.push(args);
    },
    onSubscriptionUpdatedRef: { current: async () => events.push("refresh") },
    edgeFunctionMessage: async () => "verification failed",
    friendlyBillingError: (message) => message,
    errorMessage: (error) => error.message,
  };
  vm.runInNewContext(executable + "\nthis.processPurchase = processPurchase;", context);
  await context.processPurchase({ ...purchase, ...purchaseOverrides });
  assert.equal(processing.size, 0, "processing lock is released");
  return { events, states, messages, errors, finished };
}

test("account hold refreshes the organization without acknowledging the purchase", async () => {
  const { events, states, messages, finished } = await run({
    store: "google", entitled: false, acknowledged: true, subscriptionStatus: "past_due",
  }, { isSuspendedAndroid: true });
  assert.deepEqual(events, ["verify", "refresh"]);
  assert.equal(finished.length, 0);
  assert.equal(states.at(-1), "pending");
  assert.match(messages.at(-1), /ödeme sorunu/);
});

test("expired Play verification refreshes the closed organization without acknowledgement", async () => {
  const { events, states, finished } = await run({
    store: "google", entitled: false, acknowledged: true, subscriptionStatus: "canceled",
    currentPeriodEnd: "2020-01-01T00:00:00.000Z",
  });
  assert.deepEqual(events, ["verify", "refresh"]);
  assert.equal(finished.length, 0);
  assert.equal(states.at(-1), "pending");
});

test("an active IBAN period with no Play entitlement refreshes without a Play success or ACK", async () => {
  const { events, states, messages, finished } = await run({
    store: "google", entitled: false, acknowledged: true, subscriptionStatus: "active",
    currentPeriodEnd: "2030-01-01T00:00:00.000Z",
  });
  assert.deepEqual(events, ["verify", "refresh"]);
  assert.equal(finished.length, 0);
  assert.equal(states.at(-1), "pending");
  assert.doesNotMatch(messages.at(-1), /Abonelik doğrulandı/);
});

test("a suspended organization refreshes while retaining its support-only result", async () => {
  const { events, states, messages, finished } = await run({
    store: "google", entitled: false, acknowledged: true, subscriptionStatus: "suspended",
  });
  assert.deepEqual(events, ["verify", "refresh"]);
  assert.equal(finished.length, 0);
  assert.equal(states.at(-1), "pending");
  assert.match(messages.at(-1), /Satın alımları geri yüklemek erişimi tek başına açmaz/);
});

for (const [name, acknowledged, nativeAcknowledged, shouldFinish] of [
  ["server ACK", true, false, false],
  ["native ACK", false, true, false],
  ["unacknowledged purchase", false, false, true],
]) {
  test(`active entitlement preserves ${name} finish semantics and refreshes`, async () => {
    const { events, states, messages, finished } = await run({
      store: "google", entitled: true, acknowledged, subscriptionStatus: "active",
    }, { isAcknowledgedAndroid: nativeAcknowledged });
    assert.deepEqual(events, shouldFinish ? ["verify", "finish", "refresh"] : ["verify", "refresh"]);
    assert.equal(finished.length, shouldFinish ? 1 : 0);
    if (shouldFinish) {
      assert.equal(finished[0].isConsumable, false);
      assert.equal(finished[0].purchase.purchaseToken, purchase.purchaseToken);
    }
    assert.equal(states.at(-1), "success");
    assert.equal(messages.at(-1), "Abonelik doğrulandı ve işletme erişimi güncellendi.");
  });
}

test("a raw pending purchase cannot verify, finish, refresh or report an active entitlement", async () => {
  const { events, states, messages, finished } = await run(null, { purchaseState: "pending" });
  assert.deepEqual(events, []);
  assert.equal(finished.length, 0);
  assert.deepEqual(states, ["pending"]);
  assert.equal(messages.at(-1), "Ödeme Google Play'de bekliyor. Onaylanana kadar abonelik etkinleştirilmez.");
});
