-- Keep the payment-notice decision and all database deletion steps in one
-- transaction. The existing RESTRICT links remain until retention is decided.

begin;

set local statement_timeout = '30s';

-- Auth Admin API calls cannot join a PostgreSQL transaction. Persist their
-- intent with the data deletion so a failed or interrupted Edge request can
-- resume from the remaining rows. Keep only Auth UUIDs, no email or name.
create table private.account_deletion_auth_jobs (
  batch_id uuid not null,
  auth_user_id uuid not null,
  kind text not null check (kind in ('identity', 'temporary_verification')),
  target_user_id uuid,
  attempts integer not null default 0 check (attempts >= 0),
  last_attempt_at timestamptz,
  last_error_code text check (last_error_code is null or char_length(last_error_code) <= 80),
  created_at timestamptz not null default now(),
  constraint account_deletion_auth_job_target_check check (
    (kind = 'identity' and target_user_id is null)
    or (kind = 'temporary_verification' and target_user_id is not null)
  ),
  primary key (batch_id, auth_user_id)
);

create index account_deletion_auth_jobs_created_idx
  on private.account_deletion_auth_jobs (created_at, batch_id);

alter table private.account_deletion_auth_jobs enable row level security;
revoke all on private.account_deletion_auth_jobs
  from public, anon, authenticated, service_role;

create or replace function public.service_delete_account_data(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_organization_id uuid;
  v_caller public.profiles;
  v_payment_state text;
  v_admin_id uuid;
  v_auth_user_ids uuid[];
  v_verification_user_id uuid;
  v_batch_id uuid := gen_random_uuid();
begin
  if p_user_id is null then
    return jsonb_build_object('code', 'ACCOUNT_NOT_FOUND');
  end if;

  -- An exclusive tenant lock conflicts with the FK KEY SHARE lock taken by a
  -- concurrent payment-notice INSERT. Re-read the profile after acquiring it.
  select organization_id into v_organization_id
  from public.profiles where id = p_user_id;
  if v_organization_id is null then
    return jsonb_build_object('code', 'ACCOUNT_NOT_FOUND');
  end if;

  perform 1 from public.organizations
  where id = v_organization_id for update;
  if not found then
    return jsonb_build_object('code', 'ACCOUNT_NOT_FOUND');
  end if;

  select * into v_caller from public.profiles
  where id = p_user_id for update;
  if v_caller.id is null or v_caller.organization_id <> v_organization_id
     or not v_caller.is_active then
    return jsonb_build_object('code', 'ACCOUNT_NOT_FOUND');
  end if;
  if v_caller.is_platform_operator then
    return jsonb_build_object('code', 'PLATFORM_OPERATOR');
  end if;
  if v_caller.must_change_password then
    return jsonb_build_object('code', 'PASSWORD_CHANGE_REQUIRED');
  end if;

  if v_caller.role = 'admin' then
    select case when bool_or(status = 'pending') then 'pending'
                when count(*) > 0 then 'reviewed'
                else null end
      into v_payment_state
    from public.web_payment_notifications
    where organization_id = v_organization_id;
  else
    select case when bool_or(status = 'pending') then 'pending'
                when count(*) > 0 then 'reviewed'
                else null end
      into v_payment_state
    from public.web_payment_notifications
    where submitted_by = p_user_id;
  end if;

  if v_payment_state is not null then
    return jsonb_build_object(
      'code', 'PAYMENT_RECORDS_REQUIRE_REVIEW',
      'paymentStatus', v_payment_state
    );
  end if;

  if v_caller.role = 'admin' then
    if public.service_google_play_subscription_requires_cancellation(v_organization_id) then
      return jsonb_build_object('code', 'ACTIVE_GOOGLE_PLAY_SUBSCRIPTION');
    end if;

    if exists (
      select 1 from public.profiles
      where organization_id = v_organization_id and is_platform_operator
    ) then
      return jsonb_build_object('code', 'PLATFORM_OPERATOR_IN_ORGANIZATION');
    end if;

    select coalesce(array_agg(distinct user_id), '{}'::uuid[])
      into v_auth_user_ids
    from (
      select id as user_id from public.profiles
      where organization_id = v_organization_id
      union
      select auth_user_id from public.pending_account_registrations
      where organization_id = v_organization_id
      union
      select verification_user_id from public.pending_recovery_email_verifications
      where organization_id = v_organization_id
        and verification_kind = 'temporary_signup'
    ) as users_to_delete;

    delete from public.stock_movements
    where organization_id = v_organization_id;
    -- PDF source files never leave the device. Remove the stored duplicate
    -- detection and actor metadata before the tenant row (RESTRICT FK).
    delete from private.pdf_stock_imports
    where organization_id = v_organization_id;
    delete from public.products
    where organization_id = v_organization_id;
    update public.profiles set created_by = null
    where organization_id = v_organization_id;
    delete from public.profiles
    where organization_id = v_organization_id;
    delete from public.organizations
    where id = v_organization_id;

    insert into private.account_deletion_auth_jobs (
      batch_id, auth_user_id, kind
    )
    select v_batch_id, pending_user.auth_user_id, 'identity'
    from unnest(v_auth_user_ids) as pending_user(auth_user_id);

    return jsonb_build_object(
      'deleted', true,
      'scope', 'organization',
      'batchId', v_batch_id
    );
  end if;

  select id into v_admin_id from public.profiles
  where organization_id = v_organization_id
    and role = 'admin' and is_active
  for share;
  if v_admin_id is null then
    return jsonb_build_object('code', 'ORGANIZATION_ADMIN_NOT_FOUND');
  end if;

  select verification_user_id into v_verification_user_id
  from public.pending_recovery_email_verifications
  where target_user_id = p_user_id
    and verification_kind = 'temporary_signup';

  update public.stock_movements
  set actor_id = null, actor_name = 'Silinmiş kullanıcı'
  where actor_id = p_user_id;
  update private.pdf_stock_imports
  set actor_id = null, actor_name = 'Silinmiş kullanıcı'
  where actor_id = p_user_id;
  update public.products set created_by = v_admin_id
  where organization_id = v_organization_id and created_by = p_user_id;
  update public.profiles set created_by = v_admin_id
  where organization_id = v_organization_id and created_by = p_user_id;
  delete from public.profiles where id = p_user_id;

  insert into private.account_deletion_auth_jobs (
    batch_id, auth_user_id, kind
  ) values (v_batch_id, p_user_id, 'identity');
  if v_verification_user_id is not null
     and v_verification_user_id <> p_user_id then
    insert into private.account_deletion_auth_jobs (
      batch_id, auth_user_id, kind, target_user_id
    ) values (v_batch_id, v_verification_user_id, 'temporary_verification', p_user_id);
  end if;

  return jsonb_build_object(
    'deleted', true,
    'scope', 'account',
    'batchId', v_batch_id
  );
end;
$$;

revoke all on function public.service_delete_account_data(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_delete_account_data(uuid)
  to service_role;

comment on function public.service_delete_account_data(uuid) is
  'Service-role-only, atomic database deletion. Blocks pending and reviewed web payment notices until retention and support deletion are defined.';

create or replace function public.service_list_account_deletion_auth_jobs(p_batch_id uuid default null)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'batchId', jobs.batch_id,
        'authUserId', jobs.auth_user_id,
        'kind', jobs.kind,
        'targetUserId', jobs.target_user_id,
        'attempts', jobs.attempts,
        'lastErrorCode', jobs.last_error_code
      ) order by jobs.created_at, jobs.auth_user_id
    ),
    '[]'::jsonb
  )
  from (
    select batch_id, auth_user_id, kind, target_user_id,
           attempts, last_error_code, created_at
    from private.account_deletion_auth_jobs
    where p_batch_id is null or batch_id = p_batch_id
    order by created_at, auth_user_id
    limit 25
  ) as jobs;
$$;

revoke all on function public.service_list_account_deletion_auth_jobs(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_list_account_deletion_auth_jobs(uuid)
  to service_role;

create or replace function public.service_complete_account_deletion_auth_job(
  p_batch_id uuid, p_auth_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from private.account_deletion_auth_jobs
  where batch_id = p_batch_id and auth_user_id = p_auth_user_id;
  return found;
end;
$$;

revoke all on function public.service_complete_account_deletion_auth_job(uuid, uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_complete_account_deletion_auth_job(uuid, uuid)
  to service_role;

create or replace function public.service_fail_account_deletion_auth_job(
  p_batch_id uuid, p_auth_user_id uuid, p_error_code text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  update private.account_deletion_auth_jobs
  set attempts = attempts + 1,
      last_attempt_at = now(),
      last_error_code = left(coalesce(p_error_code, 'unknown'), 80)
  where batch_id = p_batch_id and auth_user_id = p_auth_user_id;
  return found;
end;
$$;

revoke all on function public.service_fail_account_deletion_auth_job(uuid, uuid, text)
  from public, anon, authenticated, service_role;
grant execute on function public.service_fail_account_deletion_auth_job(uuid, uuid, text)
  to service_role;

create or replace function public.service_account_deletion_auth_job_health()
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'pending', count(*),
    'withFailures', count(*) filter (where attempts > 0),
    'oldestCreatedAt', min(created_at),
    'latestAttemptAt', max(last_attempt_at)
  )
  from private.account_deletion_auth_jobs;
$$;

revoke all on function public.service_account_deletion_auth_job_health()
  from public, anon, authenticated, service_role;
grant execute on function public.service_account_deletion_auth_job_health()
  to service_role;

commit;
