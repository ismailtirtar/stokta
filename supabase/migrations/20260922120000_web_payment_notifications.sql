begin;

create table public.web_payment_settings (
  id smallint primary key default 1 check (id = 1),
  recipient_name text not null check (char_length(trim(recipient_name)) between 2 and 120),
  bank_name text not null check (char_length(trim(bank_name)) between 2 and 120),
  iban text not null check (iban ~ '^TR[0-9]{24}$'),
  amount_cents integer not null check (amount_cents between 100 and 100000000),
  currency text not null default 'TRY' check (currency = 'TRY'),
  is_enabled boolean not null default false,
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now()
);

create index web_payment_settings_updated_by_idx
  on public.web_payment_settings (updated_by)
  where updated_by is not null;

create table public.web_payment_notifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete restrict,
  submitted_by uuid not null references public.profiles(id) on delete restrict,
  sender_name text not null check (char_length(trim(sender_name)) between 2 and 120),
  amount_cents integer not null check (amount_cents between 100 and 100000000),
  currency text not null default 'TRY' check (currency = 'TRY'),
  paid_at date not null,
  bank_reference text check (
    bank_reference is null or char_length(trim(bank_reference)) between 1 and 100
  ),
  payment_reference text not null check (payment_reference ~ '^STK-[0-9A-F]{10}$'),
  note text check (note is null or char_length(trim(note)) between 1 and 300),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected')),
  reviewed_by uuid references public.profiles(id) on delete set null,
  reviewed_at timestamptz,
  rejection_reason text check (
    rejection_reason is null or char_length(trim(rejection_reason)) between 3 and 300
  ),
  activated_until timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint web_payment_notifications_review_state_check check (
    (status = 'pending'
      and reviewed_by is null
      and reviewed_at is null
      and rejection_reason is null
      and activated_until is null)
    or
    (status = 'approved'
      and reviewed_by is not null
      and reviewed_at is not null
      and rejection_reason is null
      and activated_until is not null)
    or
    (status = 'rejected'
      and reviewed_by is not null
      and reviewed_at is not null
      and rejection_reason is not null
      and activated_until is null)
  )
);

create unique index web_payment_one_pending_per_organization
  on public.web_payment_notifications (organization_id)
  where status = 'pending';

create index web_payment_notifications_organization_created_idx
  on public.web_payment_notifications (organization_id, created_at desc);

create index web_payment_notifications_status_created_idx
  on public.web_payment_notifications (status, created_at desc);

create index web_payment_notifications_submitted_by_idx
  on public.web_payment_notifications (submitted_by);

create index web_payment_notifications_reviewed_by_idx
  on public.web_payment_notifications (reviewed_by)
  where reviewed_by is not null;

create or replace function public.web_payment_reference(p_organization_id uuid)
returns text
language sql
immutable
strict
security invoker
set search_path = ''
as $$
  select 'STK-' || upper(substring(replace(p_organization_id::text, '-', '') from 1 for 10));
$$;

alter table public.web_payment_settings enable row level security;
alter table public.web_payment_notifications enable row level security;

create policy web_payment_settings_select_enabled_for_active_admins
on public.web_payment_settings
for select
to authenticated
using (
  is_enabled
  and exists (
    select 1
    from public.profiles
    where id = (select auth.uid())
      and role = 'admin'
      and is_active
      and not must_change_password
  )
);

create policy web_payment_notifications_select_own_organization
on public.web_payment_notifications
for select
to authenticated
using (
  organization_id = (
    select organization_id
    from public.profiles
    where id = (select auth.uid())
      and role = 'admin'
      and is_active
      and not must_change_password
  )
);

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
      and not (
        subscription_status = 'active'
        and (current_period_end is null or current_period_end > now())
      )
  )
);

create or replace function private.service_review_web_payment_notification(
  p_notification_id uuid,
  p_decision text,
  p_reviewer_id uuid,
  p_rejection_reason text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_notification public.web_payment_notifications;
  current_organization public.organizations;
  normalized_reason text := nullif(trim(coalesce(p_rejection_reason, '')), '');
  activation_base timestamptz;
  activation_end timestamptz;
begin
  if not exists (
    select 1
    from public.profiles
    where id = p_reviewer_id
      and is_platform_operator
      and is_active
      and not must_change_password
  ) then
    raise exception 'Yetkili platform operatörü bulunamadı';
  end if;

  if p_decision not in ('approved', 'rejected') then
    raise exception 'Geçersiz ödeme kararı';
  end if;

  if p_decision = 'approved' and normalized_reason is not null then
    raise exception 'Onaylanan bildirimde ret nedeni bulunamaz';
  end if;

  if p_decision = 'rejected'
     and (normalized_reason is null or char_length(normalized_reason) not between 3 and 300) then
    raise exception 'Ret nedeni 3-300 karakter olmalı';
  end if;

  select * into current_notification
  from public.web_payment_notifications
  where id = p_notification_id
  for update;

  if current_notification.id is null then
    raise exception 'Ödeme bildirimi bulunamadı';
  end if;

  if current_notification.status <> 'pending' then
    raise exception 'Ödeme bildirimi daha önce sonuçlandırılmış';
  end if;

  if p_decision = 'rejected' then
    update public.web_payment_notifications
    set status = 'rejected',
        reviewed_by = p_reviewer_id,
        reviewed_at = now(),
        rejection_reason = normalized_reason,
        updated_at = now()
    where id = current_notification.id;

    return jsonb_build_object(
      'notification_id', current_notification.id,
      'organization_id', current_notification.organization_id,
      'status', 'rejected'
    );
  end if;

  select * into current_organization
  from public.organizations
  where id = current_notification.organization_id
  for update;

  if current_organization.id is null then
    raise exception 'İşletme bulunamadı';
  end if;

  if current_organization.subscription_status = 'suspended' then
    raise exception 'Askıya alınmış işletme ödeme ile etkinleştirilemez';
  end if;

  activation_base := greatest(
    now(),
    coalesce(current_organization.current_period_end, '-infinity'::timestamptz),
    coalesce(current_organization.trial_ends_at, '-infinity'::timestamptz)
  );
  activation_end := activation_base + interval '30 days';

  update public.organizations
  set subscription_status = 'active',
      trial_ends_at = null,
      current_period_end = activation_end,
      updated_at = now()
  where id = current_notification.organization_id;

  update public.web_payment_notifications
  set status = 'approved',
      reviewed_by = p_reviewer_id,
      reviewed_at = now(),
      rejection_reason = null,
      activated_until = activation_end,
      updated_at = now()
  where id = current_notification.id;

  return jsonb_build_object(
    'notification_id', current_notification.id,
    'organization_id', current_notification.organization_id,
    'status', 'approved',
    'activated_until', activation_end
  );
end;
$$;

create or replace function public.service_review_web_payment_notification(
  p_notification_id uuid,
  p_decision text,
  p_reviewer_id uuid,
  p_rejection_reason text default null
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.service_review_web_payment_notification(
    p_notification_id,
    p_decision,
    p_reviewer_id,
    p_rejection_reason
  );
$$;

revoke all on table public.web_payment_settings from public, anon, authenticated;
revoke all on table public.web_payment_notifications from public, anon, authenticated;

grant select on table public.web_payment_settings to authenticated;
grant select on table public.web_payment_notifications to authenticated;
grant insert (
  organization_id,
  submitted_by,
  sender_name,
  amount_cents,
  currency,
  paid_at,
  bank_reference,
  payment_reference,
  note
) on table public.web_payment_notifications to authenticated;

grant select, insert, update, delete on table public.web_payment_settings to service_role;
grant select, insert, update, delete on table public.web_payment_notifications to service_role;

revoke all on function public.web_payment_reference(uuid) from public, anon;
grant execute on function public.web_payment_reference(uuid) to authenticated, service_role;

revoke all on function private.service_review_web_payment_notification(uuid, text, uuid, text)
  from public, anon, authenticated;
grant usage on schema private to service_role;
grant execute on function private.service_review_web_payment_notification(uuid, text, uuid, text)
  to service_role;

revoke all on function public.service_review_web_payment_notification(uuid, text, uuid, text)
  from public, anon, authenticated;
grant execute on function public.service_review_web_payment_notification(uuid, text, uuid, text)
  to service_role;

comment on table public.web_payment_settings is
  'Singleton IBAN and price configuration for manually reviewed web payments.';

comment on table public.web_payment_notifications is
  'Tenant payment notices reviewed manually by a verified platform operator.';

comment on function private.service_review_web_payment_notification(uuid, text, uuid, text) is
  'Atomically rejects a pending notice or approves it and extends the tenant period by 30 days.';

comment on function public.service_review_web_payment_notification(uuid, text, uuid, text) is
  'Service-role-only invoker wrapper for the private atomic web payment review function.';

commit;
