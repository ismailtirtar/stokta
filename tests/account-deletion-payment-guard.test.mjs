import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";

const edge = readFileSync(new URL("../supabase/functions/delete-account/index.ts", import.meta.url), "utf8");
const migration = readFileSync(
  new URL("../supabase/migrations/20260924165747_atomic_account_deletion_payment_guard.sql", import.meta.url),
  "utf8",
);

function runEdge(deletionResult, { deleteUserError = null, verificationLookupError = null } = {}) {
  const events = [];
  let handler;
  const caller = {
    id: "user-1",
    username: "member1",
    role: "member",
    organization_id: "organization-1",
    is_platform_operator: false,
    is_active: true,
    must_change_password: false,
  };
  const adminClient = {
    auth: {
      getUser: async () => ({ data: { user: { id: caller.id, email: "user@example.test" } }, error: null }),
      admin: {
        updateUserById: async (id) => { events.push(`ban:${id}`); return { error: null }; },
        deleteUser: async (id) => { events.push(`delete-auth:${id}`); return { error: deleteUserError }; },
        getUserById: async () => ({ data: { user: null }, error: verificationLookupError }),
      },
    },
    rpc: async (name) => {
      events.push(`rpc:${name}`);
      if (name === "service_has_live_session" || name === "service_revoke_session") {
        return { data: true, error: null };
      }
      if (name === "service_delete_account_data") return deletionResult;
      if (name === "service_revoke_user_sessions") return { data: 1, error: null };
      throw Error(`Unexpected RPC ${name}`);
    },
    from: (name) => {
      assert.equal(name, "profiles");
      return {
        select() { return this; },
        eq() { return this; },
        maybeSingle: async () => ({ data: caller, error: null }),
      };
    },
  };
  const reauthClient = {
    auth: {
      signInWithPassword: async () => ({
        data: { user: { id: caller.id }, session: { access_token: "reauth" } },
        error: null,
      }),
      signOut: async () => ({}),
    },
  };
  let createdClients = 0;
  const executable = edge.slice(edge.indexOf("Deno.serve("))
    .replace("(req: Request)", "(req)")
    .replace("await req.json() as { confirmation?: unknown; currentPassword?: unknown }", "await req.json()")
    .replace("deletionData as Record<string, unknown> | null", "deletionData");
  vm.runInNewContext(executable, {
    Deno: { env: { get: () => "configured" }, serve: (fn) => { handler = fn; } },
    createClient: () => (++createdClients === 1 ? adminClient : reauthClient),
    bearerToken: () => "caller-token",
    sessionIdFromAccessToken: () => "session-id",
    corsJsonHeaders: {},
    json: (status, body) => ({ status, body }),
    console: { error: () => {} },
  });
  const request = {
    method: "POST",
    json: async () => ({ confirmation: caller.username, currentPassword: "password" }),
  };
  return handler(request).then((response) => ({ response, events }));
}

test("pending and reviewed bank-transfer notices stop before Auth or database cleanup", async () => {
  for (const paymentStatus of ["pending", "reviewed"]) {
    const { response, events } = await runEdge({
      data: { code: "PAYMENT_RECORDS_REQUIRE_REVIEW", paymentStatus },
      error: null,
    });
    assert.equal(response.status, 409);
    assert.equal(response.body.code, "PAYMENT_RECORDS_REQUIRE_REVIEW");
    assert.deepEqual(events.filter((event) => event.startsWith("ban:") || event.startsWith("delete-auth:")), []);
    assert.equal(events.at(-1), "rpc:service_delete_account_data");
  }
});

test("database failure rolls back before Auth cleanup begins", async () => {
  const { response, events } = await runEdge({ data: null, error: { code: "23503" } });
  assert.equal(response.status, 503);
  assert.equal(events.at(-1), "rpc:service_delete_account_data");
});

test("an account with no payment notice reaches Auth cleanup only after the transaction", async () => {
  const { response, events } = await runEdge({
    data: { deleted: true, scope: "account", authUserIds: ["user-1"], verificationUserId: null },
    error: null,
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.deleted, true);
  assert.ok(events.indexOf("rpc:service_delete_account_data") < events.indexOf("ban:user-1"));
  assert.ok(events.indexOf("ban:user-1") < events.indexOf("delete-auth:user-1"));
});

test("an organization with no payment notice cleans every returned Auth identity", async () => {
  const { response, events } = await runEdge({
    data: { deleted: true, scope: "organization", authUserIds: ["admin-1", "member-1"] },
    error: null,
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.scope, "organization");
  assert.deepEqual(events.filter((event) => event.startsWith("delete-auth:")), [
    "delete-auth:admin-1", "delete-auth:member-1",
  ]);
});

test("Auth failure is reported as pending cleanup, not deletion success", async () => {
  const { response } = await runEdge({
    data: { deleted: true, scope: "account", authUserIds: ["user-1"] },
    error: null,
  }, { deleteUserError: { code: "auth_unavailable" } });
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "AUTH_CLEANUP_PENDING");
});

test("temporary recovery identity lookup failure is reported as pending cleanup", async () => {
  const { response } = await runEdge({
    data: {
      deleted: true, scope: "account", authUserIds: ["user-1"],
      verificationUserId: "verification-1",
    },
    error: null,
  }, { verificationLookupError: { code: "auth_unavailable" } });
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "AUTH_CLEANUP_PENDING");
});

test("SQL serializes payment INSERTs with its guard and rolls back database cleanup together", () => {
  const tenantLock = migration.indexOf("where id = v_organization_id for update;");
  const paymentGuard = migration.indexOf("if v_payment_state is not null then");
  const firstDelete = migration.indexOf("delete from public.stock_movements");
  const finalDelete = migration.indexOf("delete from public.organizations");
  assert.ok(tenantLock >= 0 && tenantLock < paymentGuard && paymentGuard < firstDelete);
  assert.ok(firstDelete < finalDelete);
  assert.match(migration, /create or replace function public\.service_delete_account_data\(p_user_id uuid\)[\s\S]*?delete from public\.organizations[\s\S]*?end;\s*\$\$;/);
  assert.match(migration, /revoke all on function public\.service_delete_account_data\(uuid\)[\s\S]*?grant execute on function public\.service_delete_account_data\(uuid\)\s+to service_role/);
  assert.doesNotMatch(edge, /\.from\("stock_movements"\)\s*\.delete\(/);
});
