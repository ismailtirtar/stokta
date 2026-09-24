#!/usr/bin/env bash
# Exercise both sides of the payment INSERT / account-deletion race against
# disposable local Supabase Postgres. A deliberate product-delete pause makes
# the lock order observable without relying on a lucky scheduler interleaving.
set -euo pipefail

if [[ "${DISPOSABLE_DB:-}" != YES || "${PGHOST:-}" != 127.0.0.1 || "${PGPORT:-}" != 54322 || "${PGDATABASE:-}" != postgres ]]; then
  echo 'Race proof requires the disposable local Supabase database.' >&2
  exit 2
fi

proof_dir=$(mktemp -d)
IFS='|' read -r admin_first admin_second org_first org_second <<< "$(psql -XAt -F '|' -c 'select gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid()')"
suffix=${org_first//-/}

cleanup() {
  psql -X -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL || true
drop trigger if exists test_account_deletion_race_sleep on public.products;
drop function if exists public.test_account_deletion_race_sleep();
delete from public.web_payment_notifications
where organization_id in ('$org_first'::uuid, '$org_second'::uuid);
select public.service_delete_account_data('$admin_first'::uuid);
select public.service_delete_account_data('$admin_second'::uuid);
delete from private.account_deletion_auth_jobs
where auth_user_id in ('$admin_first'::uuid, '$admin_second'::uuid);
delete from auth.users where id in ('$admin_first'::uuid, '$admin_second'::uuid);
SQL
  rm -rf "$proof_dir"
}
trap cleanup EXIT

psql -X -v ON_ERROR_STOP=1 >/dev/null <<SQL
insert into auth.users (
  id, instance_id, aud, role, email, encrypted_password,
  email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data
) values
  ('$admin_first', '00000000-0000-0000-0000-000000000000', 'authenticated',
   'authenticated', 'race-first-$suffix@example.test', 'test',
   now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
  ('$admin_second', '00000000-0000-0000-0000-000000000000', 'authenticated',
   'authenticated', 'race-second-$suffix@example.test', 'test',
   now(), now(), now(), '{}'::jsonb, '{}'::jsonb);
insert into public.organizations (
  id, name, slug, subscription_status, trial_ends_at, created_by
) values
  ('$org_first', 'Race first', 'race-first-${suffix:0:20}', 'trial', now() + interval '14 days', '$admin_first'),
  ('$org_second', 'Race second', 'race-second-${suffix:0:20}', 'trial', now() + interval '14 days', '$admin_second');
insert into public.profiles (id, username, display_name, role, organization_id)
values
  ('$admin_first', 'racefirst${suffix:0:8}', 'Race First', 'admin', '$org_first'),
  ('$admin_second', 'racesecond${suffix:0:8}', 'Race Second', 'admin', '$org_second');
insert into public.products (name, sku, stock, created_by, organization_id)
values ('Race fixture', 'RACE-${suffix:0:16}', 0, '$admin_first', '$org_first');
create function public.test_account_deletion_race_sleep()
returns trigger language plpgsql as \$\$
begin
  perform pg_sleep(8);
  return old;
end;
\$\$;
create trigger test_account_deletion_race_sleep
before delete on public.products for each row
execute function public.test_account_deletion_race_sleep();
SQL

wait_for_activity() {
  local app=$1 expected=$2 state
  for ((attempt=0; attempt<100; attempt++)); do
    state=$(psql -XAt -c "select exists (
      select 1 from pg_stat_activity
      where application_name = '$app'
        and $expected
    )")
    if [[ $state == t ]]; then return 0; fi
    sleep 0.1
  done
  echo "Timed out waiting for $app: $expected" >&2
  return 1
}

# Deletion obtains the tenant lock. A later notice INSERT must wait, then
# fail its FK check once the tenant is deleted.
PGAPPNAME=deletion-race-first psql -XAt -v ON_ERROR_STOP=1 \
  -c "select public.service_delete_account_data('$admin_first'::uuid)->>'deleted'" \
  >"$proof_dir/deletion-first.out" 2>"$proof_dir/deletion-first.err" &
deletion_pid=$!
wait_for_activity deletion-race-first "wait_event = 'PgSleep'"

PGAPPNAME=payment-race-late psql -XAt -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
  -c "insert into public.web_payment_notifications (
    organization_id, submitted_by, sender_name, amount_cents, paid_at, payment_reference
  ) values (
    '$org_first', '$admin_first', 'Race Sender', 29900, current_date,
    public.web_payment_reference('$org_first'::uuid)
  )" >"$proof_dir/payment-late.out" 2>"$proof_dir/payment-late.err" &
payment_pid=$!
wait_for_activity payment-race-late "wait_event_type = 'Lock'"

wait "$deletion_pid"
if wait "$payment_pid"; then
  echo 'Late payment INSERT unexpectedly succeeded.' >&2
  exit 1
fi
if [[ $(cat "$proof_dir/deletion-first.out") != true ]] || ! grep -q '23503' "$proof_dir/payment-late.err"; then
  echo 'Deletion-first race did not commit deletion and reject the late FK INSERT.' >&2
  cat "$proof_dir/deletion-first.err" "$proof_dir/payment-late.err" >&2
  exit 1
fi

# A notice INSERT holds its FK KEY SHARE lock until commit. Deletion must
# wait for that transaction, then see the committed notice and return 409.
PGAPPNAME=payment-race-first psql -XAt -v ON_ERROR_STOP=1 \
  -c "begin;
    insert into public.web_payment_notifications (
      organization_id, submitted_by, sender_name, amount_cents, paid_at, payment_reference
    ) values (
      '$org_second', '$admin_second', 'Race Sender', 29900, current_date,
      public.web_payment_reference('$org_second'::uuid)
    );
    select pg_sleep(8);
    commit;" >"$proof_dir/payment-first.out" 2>"$proof_dir/payment-first.err" &
payment_pid=$!
wait_for_activity payment-race-first "wait_event = 'PgSleep'"

PGAPPNAME=deletion-race-late psql -XAt -v ON_ERROR_STOP=1 \
  -c "select public.service_delete_account_data('$admin_second'::uuid)->>'code'" \
  >"$proof_dir/deletion-late.out" 2>"$proof_dir/deletion-late.err" &
deletion_pid=$!
wait_for_activity deletion-race-late "wait_event_type = 'Lock'"

wait "$payment_pid"
wait "$deletion_pid"
if [[ $(cat "$proof_dir/deletion-late.out") != PAYMENT_RECORDS_REQUIRE_REVIEW ]] ||
   [[ $(psql -XAt -c "select exists (select 1 from public.organizations where id = '$org_second'::uuid)") != t ]]; then
  echo 'Payment-first race did not preserve the tenant and block deletion.' >&2
  cat "$proof_dir/payment-first.err" "$proof_dir/deletion-late.err" >&2
  exit 1
fi

echo 'Both payment/deletion lock orders passed.'
