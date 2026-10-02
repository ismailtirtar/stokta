-- Keep the payment-notice decision and all database deletion steps in one
-- transaction. The existing RESTRICT links remain until retention is decided.

begin;

set local statement_timeout = '30s';

-- A displaced or refunded token can still renew independently. Cancellation
-- is a property of every Play subscription, not the current entitlement.
create or replace function public.service_google_play_subscription_requires_cancellation(p_organization_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from private.google_play_subscriptions s
    where s.organization_id = p_organization_id
      and s.auto_renew_enabled is true
      and s.subscription_state not in (
        'SUBSCRIPTION_STATE_EXPIRED', 'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
      )
      -- Activated predecessor and abandoned-token observations are permanent
      -- no-ops in the lifecycle recorder; their last renewal flag is stale.
      -- A pending replacement has no activated_at and must still block.
      and not exists (
        select 1 from private.google_play_token_replacements r
        where r.old_token_hash = s.purchase_token_hash and r.activated_at is not null
      )
      and not exists (
        select 1 from private.google_play_abandoned_tokens a
        where a.purchase_token_hash = s.purchase_token_hash
      )
  );
$$;
revoke all on function public.service_google_play_subscription_requires_cancellation(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_google_play_subscription_requires_cancellation(uuid) to service_role;

-- Payment records remain intact until their retention/minimization decision
-- has been reviewed. A blocked deletion creates an actionable request rather
-- than asking the user to start again in an untracked support channel.
create table private.account_deletion_requests (
  id uuid primary key default gen_random_uuid(),
  requester_user_id uuid references auth.users(id) on delete set null,
  organization_id uuid references public.organizations(id) on delete set null,
  scope text not null check (scope in ('account', 'organization')),
  payment_status text check (payment_status in ('pending', 'reviewed')),
  status text not null default 'requested' check (
    status in ('requested', 'under_review', 'auth_cleanup_pending', 'completed')
  ),
  batch_id uuid,
  requested_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id) on delete set null,
  completed_at timestamptz
);
create unique index account_deletion_requests_open_owner_idx
  on private.account_deletion_requests (requester_user_id)
  where status in ('requested', 'under_review');
create index account_deletion_requests_queue_idx
  on private.account_deletion_requests (status, requested_at);
alter table private.account_deletion_requests enable row level security;
revoke all on private.account_deletion_requests from public, anon, authenticated, service_role;

create or replace function public.get_my_account_deletion_request()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare current_profile public.profiles; result jsonb;
begin
  current_profile := private.require_active_profile();
  select jsonb_build_object('id', r.id, 'status', r.status,
    'requestedAt', r.requested_at, 'paymentStatus', r.payment_status)
  into result from private.account_deletion_requests r
  where r.requester_user_id = current_profile.id
    and r.status in ('requested', 'under_review')
  order by r.requested_at desc limit 1;
  return result;
end;
$$;
revoke all on function public.get_my_account_deletion_request() from public, anon, authenticated, service_role;
grant execute on function public.get_my_account_deletion_request() to authenticated;

create or replace function public.platform_list_account_deletion_requests()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  perform private.require_platform_operator_aal2();
  return coalesce((select jsonb_agg(jsonb_build_object(
    'id', r.id, 'status', r.status, 'scope', r.scope,
    'requestedAt', r.requested_at, 'paymentStatus', r.payment_status,
    'username', p.username, 'organizationName', o.name
  ) order by r.requested_at)
  from private.account_deletion_requests r
  left join public.profiles p on p.id = r.requester_user_id
  left join public.organizations o on o.id = r.organization_id
  where r.status in ('requested', 'under_review')), '[]'::jsonb);
end;
$$;
revoke all on function public.platform_list_account_deletion_requests() from public, anon, authenticated, service_role;
grant execute on function public.platform_list_account_deletion_requests() to authenticated;

-- This is an acknowledgement of review only. It cannot purge payment records,
-- complete deletion, bypass the cancellation guard, or impersonate an owner.
create or replace function public.platform_review_account_deletion_request(p_request_id uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare operator_profile public.profiles; result jsonb;
begin
  operator_profile := private.require_platform_operator_aal2();
  update private.account_deletion_requests
  set status = 'under_review', reviewed_at = coalesce(reviewed_at, now()),
      reviewed_by = coalesce(reviewed_by, operator_profile.id)
  where id = p_request_id and status in ('requested', 'under_review')
  returning jsonb_build_object('id', id, 'status', status) into result;
  if result is null then raise exception 'İncelenecek silme talebi bulunamadı'; end if;
  return result;
end;
$$;
revoke all on function public.platform_review_account_deletion_request(uuid) from public, anon, authenticated, service_role;
grant execute on function public.platform_review_account_deletion_request(uuid) to authenticated;

-- Authentication FK nulling alone would leave the username in JSON metadata.
-- Apply the scrub to every profile deletion path, including worker management.
create or replace function private.scrub_deleted_profile_audit_metadata()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  update public.security_audit_events
  set metadata = metadata - 'username',
      actor_id = case when actor_id = old.id then null else actor_id end,
      subject_id = case when subject_id = old.id then null else subject_id end
  where actor_id = old.id or subject_id = old.id;
  return old;
end;
$$;
revoke all on function private.scrub_deleted_profile_audit_metadata() from public, anon, authenticated, service_role;
create trigger scrub_deleted_profile_audit_metadata
before delete on public.profiles for each row
execute function private.scrub_deleted_profile_audit_metadata();

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
  next_attempt_at timestamptz not null default now(),
  last_error_code text check (last_error_code is null or char_length(last_error_code) <= 80),
  created_at timestamptz not null default now(),
  constraint account_deletion_auth_job_target_check check (
    (kind = 'identity' and target_user_id is null)
    or (kind = 'temporary_verification' and target_user_id is not null)
  ),
  primary key (batch_id, auth_user_id)
);

create index account_deletion_auth_jobs_retry_idx
  on private.account_deletion_auth_jobs
  (next_attempt_at, created_at, batch_id, auth_user_id);

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
  v_request_id uuid;
  v_request_status text;
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
    insert into private.account_deletion_requests (
      requester_user_id, organization_id, scope, payment_status
    ) values (
      p_user_id, v_organization_id,
      case when v_caller.role = 'admin' then 'organization' else 'account' end,
      v_payment_state
    ) on conflict (requester_user_id) where status in ('requested', 'under_review')
      do update set payment_status = excluded.payment_status
    returning id, status into v_request_id, v_request_status;
    return jsonb_build_object(
      'code', 'PAYMENT_RECORDS_REQUIRE_REVIEW',
      'paymentStatus', v_payment_state,
      'requestId', v_request_id, 'requestStatus', v_request_status
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
    update private.account_deletion_requests
    set status = 'auth_cleanup_pending', batch_id = v_batch_id
    where organization_id = v_organization_id and status in ('requested', 'under_review');
    update public.security_audit_events
    set metadata = metadata - 'username'
    where organization_id = v_organization_id
      or actor_id = any(v_auth_user_ids) or subject_id = any(v_auth_user_ids);
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
  update private.account_deletion_requests
  set status = 'auth_cleanup_pending', batch_id = v_batch_id
  where requester_user_id = p_user_id and status in ('requested', 'under_review');
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
  'Service-role-only atomic database deletion; payment-linked cases persist owner-authenticated requests for AAL2 operator review without deleting accounting records.';

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
      ) order by jobs.last_attempt_at nulls first,
                 jobs.created_at, jobs.auth_user_id
    ),
    '[]'::jsonb
  )
  from (
    select batch_id, auth_user_id, kind, target_user_id,
           attempts, last_error_code, last_attempt_at, created_at
    from private.account_deletion_auth_jobs
    where (p_batch_id is null or batch_id = p_batch_id)
      and next_attempt_at <= now()
    -- Retried failures move behind never-attempted and older jobs. A single
    -- permanent failure cannot starve later batches behind LIMIT 25.
    order by last_attempt_at nulls first, created_at, auth_user_id
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
  if not found then return false; end if;
  if not exists (select 1 from private.account_deletion_auth_jobs where batch_id = p_batch_id) then
    update private.account_deletion_requests
    set status = 'completed', completed_at = now(), requester_user_id = null,
        organization_id = null, payment_status = null, reviewed_by = null
    where batch_id = p_batch_id and status = 'auth_cleanup_pending';
  end if;
  return true;
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
      next_attempt_at = now() + make_interval(secs => least(3600, (60 * power(2, least(attempts, 6)))::integer)),
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

-- Count every remaining batch job, including jobs delayed by backoff. A due-
-- only fetch cannot establish completion after a transient Auth failure.
create or replace function public.service_account_deletion_auth_batch_pending(p_batch_id uuid)
returns bigint language sql stable security definer set search_path = '' as $$
  select count(*) from private.account_deletion_auth_jobs
  where p_batch_id is null or batch_id = p_batch_id;
$$;
revoke all on function public.service_account_deletion_auth_batch_pending(uuid) from public, anon, authenticated, service_role;
grant execute on function public.service_account_deletion_auth_batch_pending(uuid) to service_role;

revoke all on function public.service_account_deletion_auth_job_health()
  from public, anon, authenticated, service_role;
grant execute on function public.service_account_deletion_auth_job_health()
  to service_role;

commit;
