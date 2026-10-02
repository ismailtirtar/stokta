#!/usr/bin/env bash
set -euo pipefail

# This proof commits a fixture so two PostgreSQL sessions can see it.
# Refuse to run against anything except the disposable Supabase CI database.
if [[ ${PGHOST:-} != 127.0.0.1 || ${PGPORT:-} != 54322 ||
      ${PGDATABASE:-} != postgres || ${PGUSER:-} != postgres ]]; then
  echo 'Refund race proof requires the disposable local Supabase database' >&2
  exit 1
fi

psql -X -v ON_ERROR_STOP=1 -q <<'SQL'
do $$
declare
  purchaser uuid;
  test_organization uuid;
  token_a text := repeat('1', 64);
  token_b text := repeat('2', 64);
  account_hash text;
  profile_hash text;
begin
  select p.id, p.organization_id into purchaser, test_organization
  from public.profiles p
  join public.organizations o on o.id = p.organization_id
  where o.name = 'CI Test Shop' and p.role = 'admin'
    and p.is_active and not p.must_change_password
    and not exists (select 1 from private.google_play_subscriptions s
      where s.organization_id = p.organization_id)
  limit 1;
  if purchaser is null then
    raise exception 'Disposable CI admin is missing or already has Play data';
  end if;
  account_hash := encode(extensions.digest(convert_to(purchaser::text, 'UTF8'), 'sha256'), 'hex');
  profile_hash := encode(extensions.digest(convert_to(test_organization::text, 'UTF8'), 'sha256'), 'hex');
  update private.google_play_void_scan_state
    set page_token = null, last_completed_at = now() where singleton = true;
  perform public.service_activate_google_play_lifecycle();
  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), now() + interval '30 days', true, true,
    repeat('3', 64), account_hash, profile_hash
  );
  perform public.service_record_google_play_subscription(
    token_b, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), now() + interval '60 days', true, true,
    repeat('4', 64), account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled
        and e.current_purchase_token_hash = token_b) then
    raise exception 'B did not become the current entitlement';
  end if;
end;
$$;
SQL

# The first session holds A's row lock until the refund has committed. The
# readiness marker is emitted only after FOR UPDATE succeeds, so no sleep
# duration determines whether the race was actually exercised.
coproc LOCKER { psql -X -qAt -v ON_ERROR_STOP=1; }
locker_pid=$LOCKER_PID
cleanup() {
  if kill -0 "$locker_pid" 2>/dev/null; then
    { printf 'ROLLBACK;\n\\q\n' >&"${LOCKER[1]}"; } 2>/dev/null || true
    kill "$locker_pid" 2>/dev/null || true
    wait "$locker_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
printf '%s\n' \
  'BEGIN;' \
  "SELECT 1 FROM private.google_play_subscriptions WHERE purchase_token_hash = repeat('1', 64) FOR UPDATE;" \
  "SELECT 'LOCKED_A';" >&"${LOCKER[1]}"

ready=false
while IFS= read -r -t 30 line <&"${LOCKER[0]}"; do
  if [[ $line == LOCKED_A ]]; then ready=true; break; fi
done
if [[ $ready != true ]]; then
  echo 'A ledger row lock was not acquired' >&2
  exit 1
fi

psql -X -v ON_ERROR_STOP=1 -q <<'SQL'
set statement_timeout = '5s';
do $$
declare
  test_organization uuid;
begin
  select id into test_organization from public.organizations
  where name = 'CI Test Shop';
  if not public.service_record_google_play_void(
      repeat('2', 64), repeat('4', 64), now()) then
    raise exception 'B refund was not applied';
  end if;
  if not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization
        and e.current_purchase_token_hash = repeat('2', 64)
        and not e.entitled)
     or not exists (select 1 from private.google_play_subscriptions s
       where s.purchase_token_hash = repeat('1', 64) and s.entitled)
     or exists (select 1 from private.google_play_subscriptions s
       where s.purchase_token_hash = repeat('2', 64) and s.entitled)
     or not exists (select 1 from private.google_play_voided_orders v
       where v.purchase_token_hash = repeat('2', 64)
         and v.order_id_hash = repeat('4', 64))
     or not exists (select 1 from public.organizations o
       where o.id = test_organization and o.subscription_status = 'past_due') then
    raise exception 'Locked A was incorrectly restored or B retained access';
  end if;
end;
$$;
SQL

printf 'COMMIT;\n\\q\n' >&"${LOCKER[1]}"
wait "$locker_pid"
trap - EXIT

psql -X -v ON_ERROR_STOP=1 -q <<'SQL'
set statement_timeout = '5s';
do $$
declare
  test_organization uuid;
begin
  select id into test_organization from public.organizations
  where name = 'CI Test Shop';
  if not public.service_record_google_play_void(
      repeat('2', 64), repeat('4', 64), now()) then
    raise exception 'Idempotent B refund did not replay';
  end if;
  if not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization
        and e.current_purchase_token_hash = repeat('1', 64)
        and e.entitled
        and e.current_period_end = (
          select s.expiry_time from private.google_play_subscriptions s
          where s.purchase_token_hash = repeat('1', 64)))
     or not exists (select 1 from public.organizations o
       where o.id = test_organization and o.subscription_status = 'active'
         and o.current_period_end = (
           select s.expiry_time from private.google_play_subscriptions s
           where s.purchase_token_hash = repeat('1', 64)))
     or exists (select 1 from private.google_play_subscriptions s
       where s.purchase_token_hash = repeat('2', 64) and s.entitled) then
    raise exception 'Retry did not restore valid A after lock release';
  end if;
end;
$$;
SQL

echo 'Refund lock race proof passed'
