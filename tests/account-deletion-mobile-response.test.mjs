import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = readFileSync(new URL("../src/screens/InventoryScreen.tsx", import.meta.url), "utf8");
const start = source.indexOf("  async function deleteAccount(");
const end = source.indexOf("\n  if (mustChangePassword)", start);
assert.ok(start >= 0 && end > start, "actual deletion handler must be tested");
const executable = ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

async function run(result) {
  const events = [];
  const alerts = [];
  const context = {
    supabase: { functions: { invoke: async () => result }, auth: { signOut: async () => events.push("sign-out") } },
    setSaving: () => {}, setAccountModal: () => events.push("close-account"),
    Alert: { alert: (title, message) => alerts.push({ title, message }) },
    edgeFunctionError: async () => "ordinary failure",
    isAdmin: false,
  };
  vm.runInNewContext(executable + "\nthis.deleteAccount = deleteAccount;", context);
  await context.deleteAccount("member", "password");
  return { events, alerts };
}

function rejection(body) {
  return { data: null, error: { context: new Response(JSON.stringify(body)) } };
}

test("review request keeps the account session and reports a request, not completed deletion", async () => {
  const { events, alerts } = await run(rejection({ code: "DELETION_REVIEW_REQUESTED", error: "Silme talebi inceleniyor" }));
  assert.deepEqual(events, []);
  assert.equal(alerts[0].title, "Silme talebi kaydedildi");
});

test("partial Auth cleanup closes the removed profile session and reports queued cleanup", async () => {
  const { events, alerts } = await run(rejection({ code: "AUTH_CLEANUP_PENDING", dataDeleted: true, error: "Giriş temizliği sırada" }));
  assert.deepEqual(events, ["close-account", "sign-out"]);
  assert.equal(alerts[0].title, "Giriş hesabı temizliği sürüyor");
});

test("unknown successful responses cannot trigger a false completed deletion", async () => {
  for (const data of [null, { requested: true }, { deleted: false }]) {
    const { events, alerts } = await run({ data, error: null });
    assert.deepEqual(events, []);
    assert.equal(alerts[0].title, "Silme doğrulanamadı");
  }
});

test("actual completed deletion alone signs out with the completion message", async () => {
  const { events, alerts } = await run({ data: { deleted: true, scope: "account" }, error: null });
  assert.deepEqual(events, ["close-account", "sign-out"]);
  assert.equal(alerts[0].title, "Silme tamamlandı");
});

test("ordinary failure does not close or sign out an intact account", async () => {
  const { events, alerts } = await run(rejection({ error: "Database failure" }));
  assert.deepEqual(events, []);
  assert.equal(alerts[0].title, "Hesap silinemedi");
});
