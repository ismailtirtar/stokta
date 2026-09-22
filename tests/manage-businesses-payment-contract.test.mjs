import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../supabase/functions/manage-businesses/index.ts", import.meta.url),
  "utf8",
);

test("operatör ödeme verilerini mevcut güvenli GET yanıtıyla birlikte alır", () => {
  assert.match(source, /service_has_live_session/);
  assert.match(source, /service_has_live_totp_aal2_session/);
  assert.match(source, /claimsData\.claims\.aal !== "aal2"/);
  assert.match(source, /from\("web_payment_settings"\)/);
  assert.match(source, /from\("web_payment_notifications"\)/);
  assert.match(source, /paymentSettings: settingsResult\.data/);
  assert.match(source, /paymentNotifications:/);
  assert.match(source, /inactive_since/);
  assert.match(source, /"inactive"/);
});

test("IBAN ayarı doğrulanır ve IBAN güvenlik olayına yazılmaz", () => {
  assert.match(source, /action === "update_web_payment_settings"/);
  assert.match(source, /\^TR\[0-9\]\{24\}\$/);
  assert.match(source, /amountCents < 100 \|\| amountCents > 100000000/);
  assert.match(source, /p_event_type: "web_payment\.settings_updated"/);
  assert.match(source, /p_metadata: \{ bankName, amountCents, isEnabled \}/);
  assert.doesNotMatch(source, /p_metadata: \{[^}]*iban/);
});

test("onay kararı yalnız atomik veritabanı RPC'sinden geçer", () => {
  assert.match(source, /action === "review_web_payment"/);
  assert.match(source, /service_review_web_payment_notification/);
  assert.match(source, /p_reviewer_id: caller\.id/);
  assert.match(source, /p_rejection_reason: rejectionReason/);
  assert.doesNotMatch(source, /from\("organizations"\)[\s\S]{0,300}\.update\([^)]*subscription_status/);
});
