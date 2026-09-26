import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";

const edge = readFileSync(new URL("../supabase/functions/delete-account/index.ts", import.meta.url), "utf8");
const migration = readFileSync(
  new URL("../supabase/migrations/20260924165747_atomic_account_deletion_payment_guard.sql", import.meta.url),
  "utf8",
);

function edgeHarness(deletionResult, {
  deleteUserError = null,
  verificationLookupError = null,
  authUserIds = ["user-1"],
  verificationUserId = null,
  absentUserIds = [],
  verificationMetadata = null,
  banUserError = null,
  revokeUserSessionsError = null,
  lookupFailureIds = [],
} = {}) {
  const events = [];
  const jobs = deletionResult.data?.batchId
    ? authUserIds.map((authUserId) => ({ batchId: deletionResult.data.batchId, authUserId, kind: "identity" }))
    : [];
  if (deletionResult.data?.batchId && verificationUserId) jobs.push({
    batchId: deletionResult.data.batchId,
    authUserId: verificationUserId,
    kind: "temporary_verification",
    targetUserId: "user-1",
  });
  const authUsers = new Map(jobs.map((job) => [job.authUserId, {
    id: job.authUserId,
    app_metadata: job.kind === "temporary_verification"
      ? (verificationMetadata ?? { stokta_verification_only: true, target_user_id: job.targetUserId })
      : {},
  }]));
  for (const userId of absentUserIds) authUsers.delete(userId);
  let currentDeleteUserError = deleteUserError;
  let currentBanUserError = banUserError;
  let currentRevokeUserSessionsError = revokeUserSessionsError;
  let attemptClock = 0;
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
      getUser: async (token) => token === "caller-token"
        ? { data: { user: { id: caller.id, email: "user@example.test" } }, error: null }
        : { data: { user: null }, error: { code: "invalid_token" } },
      admin: {
        updateUserById: async (id) => { events.push(`ban:${id}`); return { error: currentBanUserError }; },
        deleteUser: async (id) => {
          events.push(`delete-auth:${id}`);
          if (currentDeleteUserError) return { error: currentDeleteUserError };
          authUsers.delete(id);
          return { error: null };
        },
        getUserById: async (id) => {
          events.push(`lookup-auth:${id}`);
          if (lookupFailureIds.includes(id)) {
            return { data: { user: null }, error: { status: 503, code: "auth_unavailable" } };
          }
          if (id === verificationUserId && verificationLookupError) {
            return { data: { user: null }, error: verificationLookupError };
          }
          if (!authUsers.has(id)) return { data: { user: null }, error: { status: 404, code: "user_not_found" } };
          return { data: { user: authUsers.get(id) }, error: null };
        },
      },
    },
    rpc: async (name, params) => {
      events.push(`rpc:${name}`);
      if (name === "service_has_live_session" || name === "service_revoke_session") {
        return { data: true, error: null };
      }
      if (name === "service_delete_account_data") return deletionResult;
      if (name === "service_revoke_user_sessions") return { data: 1, error: currentRevokeUserSessionsError };
      if (name === "service_list_account_deletion_auth_jobs") {
        return { data: jobs.filter((job) => !params.p_batch_id || job.batchId === params.p_batch_id)
          .sort((left, right) => (left.lastAttemptAt ?? -1) - (right.lastAttemptAt ?? -1))
          .slice(0, 25), error: null };
      }
      if (name === "service_complete_account_deletion_auth_job") {
        const index = jobs.findIndex((job) => job.batchId === params.p_batch_id && job.authUserId === params.p_auth_user_id);
        if (index >= 0) jobs.splice(index, 1);
        return { data: index >= 0, error: null };
      }
      if (name === "service_fail_account_deletion_auth_job") {
        const job = jobs.find((row) => row.batchId === params.p_batch_id && row.authUserId === params.p_auth_user_id);
        if (job) {
          job.attempts = (job.attempts ?? 0) + 1;
          job.lastErrorCode = params.p_error_code;
          job.lastAttemptAt = ++attemptClock;
        }
        return { data: true, error: null };
      }
      if (name === "service_account_deletion_auth_job_health") {
        return { data: { pending: jobs.length, withFailures: jobs.filter((job) => job.attempts > 0).length }, error: null };
      }
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
  const executable = edge.slice(edge.indexOf("Deno.serve("))
    .replace("(req: Request)", "(req)")
    .replace("(batchId: string | null)", "(batchId)")
    .replace("(code: string)", "(code)")
    .replace("await req.json() as { operation?: unknown; batchId?: unknown }", "await req.json()")
    .replace("await req.json() as { confirmation?: unknown; currentPassword?: unknown }", "await req.json()")
    .replace("deletionData as Record<string, unknown> | null", "deletionData");
  vm.runInNewContext(executable, {
    Deno: { env: { get: (name) => name === "SUPABASE_SERVICE_ROLE_KEY" ? "service-key" : "anon-key" }, serve: (fn) => { handler = fn; } },
    createClient: (_url, key) => key === "service-key" ? adminClient : reauthClient,
    bearerToken: (req) => req.token,
    sessionIdFromAccessToken: () => "session-id",
    corsJsonHeaders: {},
    json: (status, body) => ({ status, body }),
    console: { error: () => {} },
  });
  return {
    invoke: (body = { confirmation: caller.username, currentPassword: "password" }, token = "caller-token") =>
      handler({ method: "POST", token, json: async () => body }),
    events,
    jobs,
    setDeleteUserError: (error) => { currentDeleteUserError = error; },
    setBanUserError: (error) => { currentBanUserError = error; },
    setRevokeUserSessionsError: (error) => { currentRevokeUserSessionsError = error; },
  };
}

async function runEdge(deletionResult, options = {}) {
  const harness = edgeHarness(deletionResult, options);
  const response = await harness.invoke();
  return { response, events: harness.events, jobs: harness.jobs };
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
    data: { deleted: true, scope: "account", batchId: "batch-1" },
    error: null,
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.deleted, true);
  assert.ok(events.indexOf("rpc:service_delete_account_data") < events.indexOf("ban:user-1"));
  assert.ok(events.indexOf("ban:user-1") < events.indexOf("delete-auth:user-1"));
});

test("an organization with no payment notice cleans every returned Auth identity", async () => {
  const { response, events } = await runEdge({
    data: { deleted: true, scope: "organization", batchId: "batch-1" },
    error: null,
  }, { authUserIds: ["admin-1", "member-1"] });
  assert.equal(response.status, 200);
  assert.equal(response.body.scope, "organization");
  assert.deepEqual(events.filter((event) => event.startsWith("delete-auth:")), [
    "delete-auth:admin-1", "delete-auth:member-1",
  ]);
});

test("Auth failure persists an outbox job, and a service-role retry clears it", async () => {
  const harness = edgeHarness({
    data: { deleted: true, scope: "account", batchId: "batch-1" },
    error: null,
  }, { deleteUserError: { code: "auth_unavailable" } });
  const response = await harness.invoke();
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "AUTH_CLEANUP_PENDING");
  assert.equal(harness.jobs.length, 1);
  assert.equal(harness.jobs[0].attempts, 1);
  harness.setDeleteUserError(null);
  const retryResponse = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(retryResponse.status, 200);
  assert.equal(retryResponse.body.pending, false);
  assert.equal(retryResponse.body.health.pending, 0);
  assert.equal(harness.jobs.length, 0);
});

test("temporary recovery identity lookup failure retains its retry job", async () => {
  const { response, jobs } = await runEdge({
    data: { deleted: true, scope: "account", batchId: "batch-1" },
    error: null,
  }, { verificationUserId: "verification-1", verificationLookupError: { code: "auth_unavailable" } });
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "AUTH_CLEANUP_PENDING");
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].authUserId, "verification-1");
  assert.equal(jobs[0].lastErrorCode, "auth_unavailable");
});

test("a deleted Auth identity left in the outbox is acknowledged on retry", async () => {
  const { response, jobs, events } = await runEdge({
    data: { deleted: true, scope: "account", batchId: "batch-1" }, error: null,
  }, { absentUserIds: ["user-1"] });
  assert.equal(response.status, 200);
  assert.equal(jobs.length, 0);
  assert.equal(events.includes("delete-auth:user-1"), false);
});

test("retry requires the service role key and preserves mismatched verification jobs", async () => {
  const harness = edgeHarness({
    data: { deleted: true, scope: "account", batchId: "batch-1" }, error: null,
  }, { verificationUserId: "verification-1", verificationMetadata: { stokta_verification_only: true, target_user_id: "other-user" } });
  const unauthorized = await harness.invoke({ operation: "retry-auth-cleanup" }, "wrong-key");
  assert.equal(unauthorized.status, 401);
  assert.equal(harness.jobs.length, 2);
  const result = await harness.invoke();
  assert.equal(result.status, 503);
  assert.equal(harness.jobs.length, 1);
  assert.equal(harness.jobs[0].lastErrorCode, "verification_metadata_mismatch");
});

test("operator retry resumes an interrupted deletion in bounded pages", async () => {
  const authUserIds = Array.from({ length: 30 }, (_, index) => `user-${index}`);
  const harness = edgeHarness({
    data: { deleted: true, scope: "organization", batchId: "batch-1" }, error: null,
  }, { authUserIds });
  const first = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(first.status, 503);
  assert.equal(first.body.processed, 25);
  assert.equal(first.body.health.pending, 5);
  assert.equal(harness.jobs.length, 5);
  const second = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(second.status, 200);
  assert.equal(second.body.health.pending, 0);
  assert.equal(harness.events.includes("rpc:service_delete_account_data"), false);
});

test("persistent failures rotate behind untouched outbox jobs", async () => {
  const authUserIds = Array.from({ length: 30 }, (_, index) => `user-${index}`);
  const harness = edgeHarness({
    data: { deleted: true, scope: "organization", batchId: "batch-1" }, error: null,
  }, { authUserIds, lookupFailureIds: authUserIds.slice(0, 25) });
  const first = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(first.status, 503);
  assert.equal(first.body.health.pending, 30);
  const second = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(second.status, 503);
  assert.equal(second.body.health.pending, 25);
  assert.ok(harness.events.includes("delete-auth:user-25"));
});

test("failed ban retains the job and never revokes or deletes Auth until retry", async () => {
  const harness = edgeHarness({
    data: { deleted: true, scope: "account", batchId: "batch-1" }, error: null,
  }, { banUserError: { code: "auth_unavailable" } });
  const response = await harness.invoke();
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "AUTH_CLEANUP_PENDING");
  assert.equal(harness.jobs.length, 1);
  assert.equal(harness.jobs[0].attempts, 1);
  assert.equal(harness.jobs[0].lastErrorCode, "auth_ban_failed");
  assert.equal(harness.events.includes("rpc:service_revoke_user_sessions"), false);
  assert.equal(harness.events.includes("delete-auth:user-1"), false);
  harness.setBanUserError(null);
  const retry = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(retry.status, 200);
  assert.equal(harness.jobs.length, 0);
  assert.equal(harness.events.filter((event) => event === "delete-auth:user-1").length, 1);
});

test("failed session revocation retains the job and never deletes Auth until retry", async () => {
  const harness = edgeHarness({
    data: { deleted: true, scope: "account", batchId: "batch-1" }, error: null,
  }, { revokeUserSessionsError: { code: "database_unavailable" } });
  const response = await harness.invoke();
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "AUTH_CLEANUP_PENDING");
  assert.equal(harness.jobs.length, 1);
  assert.equal(harness.jobs[0].attempts, 1);
  assert.equal(harness.jobs[0].lastErrorCode, "session_revoke_failed");
  assert.equal(harness.events.includes("ban:user-1"), true);
  assert.equal(harness.events.includes("delete-auth:user-1"), false);
  harness.setRevokeUserSessionsError(null);
  const retry = await harness.invoke({ operation: "retry-auth-cleanup" }, "service-key");
  assert.equal(retry.status, 200);
  assert.equal(harness.jobs.length, 0);
  assert.equal(harness.events.filter((event) => event === "delete-auth:user-1").length, 1);
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
  assert.match(migration, /create table private\.account_deletion_auth_jobs[\s\S]*?primary key \(batch_id, auth_user_id\)/);
  assert.match(migration, /delete from public\.organizations[\s\S]*?insert into private\.account_deletion_auth_jobs/);
  assert.match(migration, /limit 25/);
  assert.match(migration, /order by last_attempt_at nulls first, created_at, auth_user_id/);
  assert.doesNotMatch(edge, /\.from\("stock_movements"\)\s*\.delete\(/);
});
