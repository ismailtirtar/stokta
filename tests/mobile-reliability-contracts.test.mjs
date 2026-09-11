import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("Android billing keeps ACK server-authoritative and clears only terminal intents", () => {
  const modal = read("src/components/SubscriptionModal.tsx");
  assert.doesNotMatch(modal, /finishTransaction|acknowledgePurchaseAndroid|consumePurchaseAndroid/);
  assert.match(modal, /if \(intent && \(data\.intentConsumed \|\| data\.intentClosed\)\)/);
  const verificationBlock = modal.slice(
    modal.indexOf("const data = verification.data"),
    modal.indexOf("const processedAt = Date.now()"),
  );
  assert.ok(
    verificationBlock.indexOf("if (!isVerificationResponse(data))")
      < verificationBlock.indexOf("clearGooglePlayPurchaseIntent(userId, organizationId)"),
    "a typed server response must be validated before terminal intent cleanup",
  );
  assert.match(modal, /action: "begin"/);
  assert.match(modal, /purchaseIntentId: intent\.purchaseIntentId/);
  assert.match(modal, /obfuscatedAccountId: intent\.obfuscatedAccountId/);
  assert.match(modal, /obfuscatedProfileId: intent\.obfuscatedProfileId/);
  assert.match(modal, /"past_due", "suspended", "canceled"/);
  assert.doesNotMatch(modal, /"cancelled"/);
  assert.match(modal, /catch \(connectionError\) \{\s*handleIapError\(iapErrorShape\(connectionError\)\)/);
  assert.match(modal, /purchaseLaunchInFlightRef\.current = false/);
  assert.match(modal, /purchaseQueueRef\.current[\s\S]*?then\(\(\) => processPurchase\(purchase\)\)/);
});

test("pinned expo-iap Android finalization performs acknowledgement", () => {
  const packageJson = JSON.parse(read("package.json"));
  const dependencySource = read("node_modules/expo-iap/src/index.ts");
  assert.equal(packageJson.dependencies["expo-iap"], "5.5.0");
  assert.match(
    dependencySource,
    /finishTransaction[\s\S]*?acknowledgePurchaseAndroid\(token\)/,
    "review this guard if expo-iap changes its Android finalization semantics",
  );
});

test("inventory is keyset-paged, remotely filtered and terms-gated", () => {
  const inventory = read("src/screens/InventoryScreen.tsx");
  assert.doesNotMatch(inventory, /MAX_PRODUCTS|20_000|loadAllProducts/);
  assert.match(inventory, /list_inventory_products/);
  assert.match(inventory, /p_after_name:/);
  assert.match(inventory, /p_after_id:/);
  assert.match(inventory, /p_query:/);
  assert.match(inventory, /p_only_low:/);
  assert.match(inventory, /get_inventory_summary/);
  assert.match(inventory, /onEndReached=\{\(\) => void loadMoreProducts\(\)\}/);

  const termsGate = inventory.indexOf("if (!termsDocumentMatches || !termsAcceptanceMatches)");
  const stockLoad = inventory.indexOf("const [productResult, movementResult, summaryResult] = await Promise.all");
  assert.ok(termsGate > 0 && stockLoad > termsGate, "terms rejection must precede private stock queries");
  assert.match(inventory, /accept_current_ugc_terms/);
  assert.match(inventory, /p_version: CURRENT_UGC_TERMS_VERSION/);
  assert.match(inventory, /p_digest: CURRENT_UGC_TERMS_DIGEST/);
});

test("stock and reporting mutations carry stable receipts and validate responses", () => {
  const inventory = read("src/screens/InventoryScreen.tsx");
  for (const rpc of ["create_inventory_product", "update_inventory_product", "record_stock_movement", "report_content"]) {
    assert.match(inventory, new RegExp(rpc));
  }
  assert.ok((inventory.match(/p_request_id:/g) ?? []).length >= 4);
  assert.match(inventory, /p_expected_updated_at: editing\.updated_at/);
  assert.match(inventory, /movementResult\.product_id !== selectedProduct\.id/);
  assert.match(inventory, /result\.request_id !== requestId/);
  assert.match(inventory, /if \(ref\.current\) return null/);
  assert.match(inventory, /isAmbiguousWriteError\(movementError\)/);
  assert.match(inventory, /unresolvedAttemptMessage\(\)/);
});

test("account deletion survives restarts and adopts a canonical server request ID", () => {
  const inventory = read("src/screens/InventoryScreen.tsx");
  const deletionStore = read("src/lib/account-deletion.ts");
  const persist = inventory.indexOf("await saveAccountDeletionIntent(session.user.id, organizationId, deletionRequestId)");
  const launch = inventory.indexOf('supabase.functions.invoke("delete-account"');
  assert.ok(persist > 0 && launch > persist, "the durable request ID must be saved before deletion starts");
  assert.match(inventory, /details\.deletionRequestId[\s\S]*?saveAccountDeletionIntent/);
  assert.match(inventory, /const canonicalRequestId = deletionResult\?\.deletionRequestId/);
  assert.match(inventory, /isDeletionRequestId\(canonicalRequestId\)/);
  assert.doesNotMatch(inventory, /canonicalRequestId !== deletionRequestId/);
  assert.match(inventory, /CLEARABLE_DELETION_CODES/);
  assert.match(deletionStore, /has no\s*\*?\s*client-side expiry/);
  assert.doesNotMatch(deletionStore, /Date\.parse\(candidate\.createdAt\) > Date\.now/);
});

test("forced password change is bounded, single-flight and handles ambiguous completion safely", () => {
  const screen = read("src/components/ForcedPasswordChange.tsx");
  assert.match(screen, /if \(actionInFlightRef\.current\) return/);
  assert.match(screen, /withOperationTimeout\(/);
  assert.match(screen, /30_000/);
  assert.match(screen, /response\?\.updated !== true \|\| response\.reauthenticationRequired !== true/);
  assert.match(screen, /promptForSafeReauthentication/);
  assert.match(screen, /önce yeni şifrenizle giriş yapın/);
  assert.match(screen, /retryTransientSupabaseOperation\([\s\S]*?supabase\.auth\.signOut/);
  assert.equal((screen.match(/functions\.invoke\("account-security"/g) ?? []).length, 1,
    "an ambiguous non-idempotent password mutation must not be sent twice automatically");
});

test("platform subscription changes require auditable reasons and reject stale completions", () => {
  const platform = read("src/components/PlatformModal.tsx");
  assert.match(platform, /normalizedReason\.length > 500/);
  assert.match(platform, /maxLength=\{500\}/);
  assert.match(platform, /reason: normalizedReason/);
  assert.match(platform, /pendingCommandIds\.current\.get\(commandKey\)/);
  assert.match(platform, /response\.request_id !== requestId/);
  assert.match(platform, /requestSequence !== listRequestSequence\.current/);
  assert.match(platform, /setLoadingMore\(false\)/);
});

test("Safety Center paginates and requires reasons for destructive moderation", () => {
  const safety = read("src/components/SafetyCenterModal.tsx");
  assert.match(safety, /p_limit: REPORT_PAGE_SIZE \+ 1/);
  assert.match(safety, /p_before_created_at: cursor\.created_at/);
  assert.match(safety, /p_before_id: cursor\.report_id/);
  assert.match(safety, /Daha fazla göster/);
  assert.match(safety, /action !== "dismiss" && !normalizedNote/);
  assert.match(safety, /p_note: normalizedNote, p_request_id: requestId/);
  assert.match(safety, /result\.request_id !== requestId/);
});

test("auth bootstrap cannot be overwritten by a stale getSession result", () => {
  const app = read("App.tsx");
  const listener = app.indexOf("onAuthStateChange");
  const initialSession = app.indexOf("supabase.auth.getSession()");
  assert.ok(listener > 0 && initialSession > listener);
  assert.match(app, /authRevision/);
  assert.match(app, /withOperationTimeout/);

  const login = read("src/screens/LoginScreen.tsx");
  assert.match(login, /https:\/\/stokdas\.com\/gizlilik/);
  assert.match(login, /ugcTermsDigest: CURRENT_UGC_TERMS_DIGEST/);
  assert.match(login, /requestId/);

  const retry = read("src/lib/auth-retry.ts");
  assert.match(retry, /finally \{\s*if \(timeout !== undefined\) clearTimeout\(timeout\)/);
});
