import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

function source(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const migrationName = readdirSync(new URL("../supabase/migrations/", import.meta.url))
  .find((name) => name.endsWith("_pdf_stock_imports.sql"));

assert.ok(migrationName, "PDF stok aktarımı migration dosyası bulunamadı");
const migrationSource = source(`supabase/migrations/${migrationName}`);

test("PDF kaynağı saklanmadan işletme içinde mükerrer aktarım önlenir", () => {
  assert.match(migrationSource, /create table private\.pdf_stock_imports/);
  assert.match(migrationSource, /unique \(organization_id, document_sha256\)/);
  assert.doesNotMatch(migrationSource, /storage\.|pdf_content|document_bytes|base64/i);
  assert.match(migrationSource, /enable row level security/);
  assert.match(
    migrationSource,
    /revoke all on table private\.pdf_stock_imports from public, anon, authenticated/,
  );
});

test("Aktarım mevcut üyelik ve işletme yazma sınırını kullanır", () => {
  assert.match(migrationSource, /current_profile := private\.require_active_profile\(\)/);
  assert.match(
    migrationSource,
    /perform private\.require_writable_organization\(current_profile\.organization_id\)/,
  );
  assert.match(migrationSource, /organization_id = current_profile\.organization_id/);
});

test("Tüm ürünler sabit sırada kilitlenir ve tek RPC işleminde uygulanır", () => {
  assert.match(migrationSource, /order by \(entry\.value ->> 'product_id'\)::uuid[\s\S]*for update/);
  assert.match(migrationSource, /if p_type = 'out' and current_line\.quantity > current_product\.stock/);
  assert.match(migrationSource, /create or replace function public\.record_pdf_stock_import/);
  assert.match(migrationSource, /language sql\s+security invoker/);
  assert.match(migrationSource, /select private\.record_pdf_stock_import/);
});
