begin;

set local statement_timeout = '30s';

alter table public.organizations
  add column if not exists inactive_since timestamptz;

alter table public.organizations
  drop constraint if exists organizations_subscription_status_check;

alter table public.organizations
  add constraint organizations_subscription_status_check
  check (subscription_status in ('trial', 'active', 'inactive', 'past_due', 'suspended', 'canceled'));

alter table public.organizations
  drop constraint if exists organizations_inactive_since_required_check;

alter table public.organizations
  add constraint organizations_inactive_since_required_check
  check (subscription_status <> 'inactive' or inactive_since is not null);

create index if not exists organizations_inactive_since_idx
  on public.organizations (inactive_since)
  where subscription_status = 'inactive';

create or replace function private.normalize_organization_inactive_since()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.subscription_status = 'inactive' and new.inactive_since is null then
    new.inactive_since := now();
  elsif new.subscription_status in ('trial', 'active', 'past_due', 'canceled') then
    new.inactive_since := null;
  end if;

  return new;
end;
$$;

drop trigger if exists organizations_normalize_inactive_since
  on public.organizations;

create trigger organizations_normalize_inactive_since
before insert or update of subscription_status, inactive_since
on public.organizations
for each row
execute function private.normalize_organization_inactive_since();

create or replace function private.refresh_expired_organization_statuses()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  inactive_count integer := 0;
  suspended_count integer := 0;
begin
  update public.organizations
  set subscription_status = 'inactive',
      inactive_since = case
        when subscription_status = 'trial' then trial_ends_at
        else current_period_end
      end,
      updated_at = now()
  where (
      subscription_status = 'trial'
      and trial_ends_at is not null
      and trial_ends_at <= now()
    ) or (
      subscription_status = 'active'
      and current_period_end is not null
      and current_period_end <= now()
    );
  get diagnostics inactive_count = row_count;

  update public.organizations as organization
  set subscription_status = 'suspended',
      updated_at = now()
  where organization.subscription_status = 'inactive'
    and organization.inactive_since <= now() - interval '7 days'
    and not exists (
      select 1
      from public.web_payment_notifications as notification
      where notification.organization_id = organization.id
        and notification.status = 'pending'
    );
  get diagnostics suspended_count = row_count;

  return jsonb_build_object(
    'inactive_count', inactive_count,
    'suspended_count', suspended_count,
    'processed_at', now()
  );
end;
$$;

revoke all on function private.normalize_organization_inactive_since()
  from public, anon, authenticated, service_role;
revoke all on function private.refresh_expired_organization_statuses()
  from public, anon, authenticated, service_role;

drop policy if exists web_payment_notifications_insert_own_organization
  on public.web_payment_notifications;

create policy web_payment_notifications_insert_own_organization
on public.web_payment_notifications
for insert
to authenticated
with check (
  status = 'pending'
  and reviewed_by is null
  and reviewed_at is null
  and rejection_reason is null
  and activated_until is null
  and paid_at <= current_date
  and organization_id = (
    select organization_id
    from public.profiles
    where id = (select auth.uid())
      and role = 'admin'
      and is_active
      and not must_change_password
  )
  and submitted_by = (select auth.uid())
  and payment_reference = public.web_payment_reference(organization_id)
  and exists (
    select 1
    from public.web_payment_settings
    where id = 1
      and is_enabled
      and amount_cents = web_payment_notifications.amount_cents
      and currency = web_payment_notifications.currency
  )
  and exists (
    select 1
    from public.organizations
    where id = web_payment_notifications.organization_id
      and subscription_status <> 'suspended'
      and (
        subscription_status <> 'inactive'
        or inactive_since > now() - interval '7 days'
      )
      and not (
        subscription_status = 'active'
        and (current_period_end is null or current_period_end > now())
      )
  )
);

create extension if not exists pg_cron;

do $$
begin
  if not exists (
    select 1
    from cron.job
    where jobname = 'stokdas-refresh-expired-organizations'
  ) then
    perform cron.schedule(
      'stokdas-refresh-expired-organizations',
      '*/15 * * * *',
      'select private.refresh_expired_organization_statuses();'
    );
  end if;
end;
$$;

select private.refresh_expired_organization_statuses();

comment on column public.organizations.inactive_since is
  'Start of the seven-day web payment grace period after a tenant period expires.';

comment on function private.refresh_expired_organization_statuses() is
  'Moves expired trial/active tenants to inactive, then suspends them after seven days unless a web payment review is pending.';

commit;
