import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("UGC v2 text, digest, mobile copy and public artifact stay identical", () => {
  const migration = read("supabase/migrations/20260911130000_ugc_terms_v2.sql");
  const publicTerms = read("store/terms-of-use.html");
  const constants = read("src/lib/ugc.ts");
  const modal = read("src/components/TermsModal.tsx");

  const canonical = migration.match(/\$terms_v2\$([\s\S]*?)\$terms_v2\$/)?.[1];
  const publicCopy = publicTerms.match(
    /<pre[^>]*id="terms-canonical-text"[^>]*>([\s\S]*?)<\/pre>/,
  )?.[1];
  const declaredDigest = constants.match(/CURRENT_UGC_TERMS_DIGEST\s*=\s*"([a-f0-9]{64})"/)?.[1];
  assert.ok(canonical, "canonical SQL terms were not found");
  assert.equal(publicCopy, canonical, "public terms must be the byte-identical canonical document");
  assert.equal(createHash("sha256").update(canonical).digest("hex"), declaredDigest);
  assert.match(publicTerms, new RegExp(`Belge SHA-256: ${declaredDigest}`));

  const sectionMatches = [...modal.matchAll(
    /<TermsSection title="([^"]+)">\s*([\s\S]*?)\s*<\/TermsSection>/g,
  )];
  assert.equal(sectionMatches.length, 6, "mobile terms must display all six canonical sections");
  const contact = modal.match(/<Text style=\{styles\.contact\}>([^<]+)<\/Text>/)?.[1];
  const mobileCopy = `\n${sectionMatches
    .map((match) => `${match[1]}\n${match[2].trim()}`)
    .join("\n\n")}\n\n${contact}\n`;
  assert.equal(mobileCopy, canonical, "mobile terms must render the canonical document exactly");
});

test("billing terms are separate from the immutable UGC digest", () => {
  const publicTerms = read("store/terms-of-use.html");
  const canonicalEnd = publicTerms.indexOf("</pre>");
  const billingStart = publicTerms.indexOf("Google Play abonelik koşulları");
  assert.ok(canonicalEnd > 0 && billingStart > canonicalEnd);
  assert.match(publicTerms.slice(billingStart), /otomatik yenilenen/i);
  assert.match(publicTerms.slice(billingStart), /Google Play.*iptal/i);
  assert.match(publicTerms.slice(billingStart), /geri ödeme/i);
});

test("store declarations use the current public deletion URL and disclose purchases", () => {
  const dataSafety = read("store/google-play-data-safety-tr.md");
  const listing = read("store/google-play-listing-tr.md");
  const privacy = read("store/privacy-policy.html");
  const combined = `${dataSafety}\n${listing}\n${privacy}`;

  assert.doesNotMatch(combined, /stokdas\.tirtarhan\.chatgpt\.site/);
  assert.match(dataSafety, /Finansal bilgiler > Satın alma geçmişi/);
  assert.match(dataSafety, /Toplanan: `Evet`/);
  assert.match(privacy, /id="hesap-ve-veri-silme"/);
  assert.match(privacy, /en fazla 30 gün/i);
  assert.match(privacy, /120 günden uzun/i);
});
