-- Serialize platform subscription administration in the database. Authorization,
-- compare-and-swap, mutation, receipt and audit now commit as one transaction.

begin;

set local statement_timeout = '30s';
set local lock_timeout = '10s';

do $$
begin
  if to_regclass('public.security_audit_events') is null
     or to_regclass('private.inventory_command_receipts') is null
     or to_regprocedure('public.service_has_live_session(uuid,uuid)') is null then
    raise exception
      'Platform reliability migration requires account security and inventory reliability';
  end if;
end;
$$;

alter table public.organizations
  add column if not exists subscription_revision bigint not null default 0,
  add column if not exists administratively_suspended_at timestamptz,
  add column if not exists administratively_suspended_by uuid,
  add column if not exists administrative_suspension_reason text,
  add column if not exists platform_entitlement_until timestamptz,
  add column if not exists platform_entitlement_by uuid,
  add column if not exists platform_entitlement_reason text;

alter table public.organizations
  add constraint organizations_subscription_revision_check
    check (subscription_revision >= 0),
  add constraint organizations_administrative_suspension_shape_check check (
    (
      administratively_suspended_at is null
      and administratively_suspended_by is null
      and administrative_suspension_reason is null
    )
    or (
      administratively_suspended_at is not null
      and administrative_suspension_reason is not null
      and char_length(administrative_suspension_reason) between 1 and 500
      and subscription_status = 'suspended'
    )
  ),
  add constraint organizations_administratively_suspended_by_fkey
    foreign key (administratively_suspended_by)
    references auth.users(id) on delete set null,
  add constraint organizations_platform_entitlement_shape_check check (
    (
      platform_entitlement_until is null
      and platform_entitlement_by is null
      and platform_entitlement_reason is null
    )
    or (
      platform_entitlement_until is not null
      and platform_entitlement_reason is not null
      and char_length(platform_entitlement_reason) between 1 and 500
    )
  ),
  add constraint organizations_platform_entitlement_by_fkey
    foreign key (platform_entitlement_by)
    references auth.users(id) on delete set null;

create index if not exists organizations_created_id_desc_idx
  on public.organizations (created_at desc, id desc);
create index if not exists organizations_administratively_suspended_by_idx
  on public.organizations (administratively_suspended_by)
  where administratively_suspended_by is not null;
create index if not exists organizations_platform_entitlement_until_idx
  on public.organizations (platform_entitlement_until)
  where platform_entitlement_until is not null;
create index if not exists profiles_active_organization_idx
  on public.profiles (organization_id)
  where is_active;

-- Install the CAS revision invariant before the later Google Play lifecycle
-- migration is applied. Both legacy and v2 billing writers are thereby part of
-- the same revision stream throughout a sequential rollout.
create or replace function private.enforce_subscription_revision()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  materially_changed boolean;
begin
  materially_changed :=
    new.subscription_status is distinct from old.subscription_status
    or new.trial_ends_at is distinct from old.trial_ends_at
    or new.current_period_end is distinct from old.current_period_end
    or new.max_members is distinct from old.max_members
    or new.max_products is distinct from old.max_products
    or new.administratively_suspended_at
       is distinct from old.administratively_suspended_at
    or new.administratively_suspended_by
       is distinct from old.administratively_suspended_by
    or new.administrative_suspension_reason
       is distinct from old.administrative_suspension_reason
    or new.platform_entitlement_until
       is distinct from old.platform_entitlement_until
    or new.platform_entitlement_by
       is distinct from old.platform_entitlement_by
    or new.platform_entitlement_reason
       is distinct from old.platform_entitlement_reason;

  if materially_changed then
    if new.subscription_revision = old.subscription_revision then
      new.subscription_revision := old.subscription_revision + 1;
    elsif new.subscription_revision <> old.subscription_revision + 1 then
      raise exception 'Abonelik revizyonu tam olarak bir artırılmalıdır';
    end if;
  elsif new.subscription_revision <> old.subscription_revision then
    raise exception 'Abonelik revizyonu maddi değişiklik olmadan artırılamaz';
  end if;
  return new;
end;
$$;

drop trigger if exists enforce_subscription_revision on public.organizations;
create trigger enforce_subscription_revision
before update on public.organizations
for each row execute function private.enforce_subscription_revision();

create table private.platform_admin_command_receipts (
  actor_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  organization_id uuid not null
    references public.organizations(id) on delete cascade,
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  response jsonb,
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  primary key (actor_id, request_id),
  constraint platform_admin_receipts_completion_check check (
    (response is null and completed_at is null)
    or (response is not null and completed_at is not null)
  )
);

create index platform_admin_receipts_organization_idx
  on private.platform_admin_command_receipts (organization_id, created_at desc);

alter table private.platform_admin_command_receipts enable row level security;
alter table private.platform_admin_command_receipts force row level security;
revoke all on table private.platform_admin_command_receipts
  from public, anon, authenticated, service_role;

-- Shared write fence. The immediately preceding auth reliability migration
-- creates the table/helper before any caller becomes reachable; this override
-- preserves its contract. A fence stays authoritative until explicit finalize/abort;
-- its expires_at is operational metadata, never an automatic write-reopening
-- switch. Locking the organization first serializes with fence installation.
create or replace function private.assert_organization_not_deleting(
  p_organization_id uuid
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if p_organization_id is null then
    raise exception 'İşletme gerekli' using errcode = '22023';
  end if;

  perform 1
  from public.organizations o
  where o.id = p_organization_id
  for update;
  if not found then
    raise exception 'İşletme bulunamadı' using errcode = '42501';
  end if;

  if to_regclass('private.organization_deletion_fences') is null then
    raise exception 'İşletme silme koruması hazır değil' using errcode = '55000';
  end if;

  if exists (
    select 1
    from private.organization_deletion_fences f
    where f.organization_id = p_organization_id
  ) then
    raise exception 'İşletme silme işlemi devam ediyor' using errcode = '55000';
  end if;
end;
$$;

create or replace function private.require_locked_service_platform_operator(
  p_actor_id uuid,
  p_session_id uuid
)
returns public.profiles
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  actor_organization_id uuid;
  actor public.profiles;
begin
  if p_actor_id is null or p_session_id is null then
    raise exception 'Geçerli platform oturumu gerekli';
  end if;

  -- Account deletion locks organization before profile. Read the immutable
  -- tenant key first and follow that same order so a platform command cannot
  -- deadlock deletion of the operator's own organization.
  select p.organization_id into actor_organization_id
  from public.profiles p
  where p.id = p_actor_id;
  if actor_organization_id is null then
    raise exception 'Bu işlem yalnızca etkin platform yöneticisine açıktır';
  end if;

  perform 1
  from public.organizations o
  where o.id = actor_organization_id
  for update;
  if not found then
    raise exception 'Platform yöneticisinin işletmesi bulunamadı';
  end if;

  select * into actor
  from public.profiles p
  where p.id = p_actor_id
    and p.organization_id = actor_organization_id
  for update;

  if actor.id is null
     or not actor.is_active
     or actor.must_change_password
     or not actor.is_platform_operator then
    raise exception 'Bu işlem yalnızca etkin platform yöneticisine açıktır';
  end if;

  -- KEY SHARE conflicts with session deletion, so authorization cannot be
  -- revoked between this check and the transaction's privileged mutation.
  perform 1
  from auth.sessions s
  where s.id = p_session_id
    and s.user_id = p_actor_id
  for key share;

  if not found then
    raise exception 'Platform oturumu sona erdi';
  end if;

  return actor;
end;
$$;

create or replace function public.service_list_platform_businesses(
  p_actor_id uuid,
  p_session_id uuid,
  p_before_created_at timestamptz default null,
  p_before_id uuid default null,
  p_limit integer default 101
)
returns table (
  id uuid,
  name text,
  slug text,
  subscription_status text,
  trial_ends_at timestamptz,
  current_period_end timestamptz,
  max_members integer,
  max_products integer,
  member_count bigint,
  product_count bigint,
  platform_entitlement_until timestamptz,
  platform_entitlement_reason text,
  subscription_revision bigint,
  created_at timestamptz
)
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform private.require_locked_service_platform_operator(p_actor_id, p_session_id);

  if p_limit is null or p_limit not between 1 and 101 then
    raise exception 'Sayfa boyutu 1-101 arasında olmalı';
  end if;
  if (p_before_created_at is null) <> (p_before_id is null) then
    raise exception 'İşletme sayfalama imleci eksik';
  end if;

  return query
  select
    o.id,
    o.name,
    o.slug,
    o.subscription_status,
    o.trial_ends_at,
    o.current_period_end,
    o.max_members,
    o.max_products,
    (select count(*) from public.profiles p
      where p.organization_id = o.id and p.is_active),
    (select count(*) from public.products p
      where p.organization_id = o.id and p.active),
    o.platform_entitlement_until,
    o.platform_entitlement_reason,
    o.subscription_revision,
    o.created_at
  from public.organizations o
  where p_before_created_at is null
     or (o.created_at, o.id) < (p_before_created_at, p_before_id)
  order by o.created_at desc, o.id desc
  limit p_limit;
end;
$$;

create or replace function public.service_update_platform_subscription(
  p_actor_id uuid,
  p_session_id uuid,
  p_request_id uuid,
  p_organization_id uuid,
  p_expected_revision bigint,
  p_status text,
  p_period_days integer,
  p_max_members integer,
  p_max_products integer,
  p_reason text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  actor public.profiles;
  organization public.organizations;
  updated_organization public.organizations;
  receipt private.platform_admin_command_receipts;
  normalized_status text := lower(trim(coalesce(p_status, '')));
  normalized_reason text := trim(coalesce(p_reason, ''));
  request_hash text;
  result_payload jsonb;
  inserted boolean;
  active_member_count bigint;
  active_product_count bigint;
  allowed boolean;
  next_platform_entitlement_until timestamptz;
begin
  if p_request_id is null or p_organization_id is null then
    raise exception 'İstek ve işletme kimliği gerekli';
  end if;
  if p_expected_revision is null or p_expected_revision < 0 then
    raise exception 'Geçerli işletme revizyonu gerekli';
  end if;
  if normalized_status not in ('active', 'suspended') then
    raise exception 'Platform işlemi yalnız etkinleştirme veya askıya alma olabilir';
  end if;
  if p_period_days is null or p_period_days not between 1 and 3660 then
    raise exception 'Dönem 1-3660 gün arasında olmalı';
  end if;
  if p_max_members is null or p_max_members not between 1 and 10000
     or p_max_products is null or p_max_products not between 1 and 1000000 then
    raise exception 'İşletme limitleri geçersiz';
  end if;
  if char_length(normalized_reason) not between 1 and 500 then
    raise exception 'İşlem gerekçesi 1-500 karakter olmalı';
  end if;

  -- Platform operators may live in different tenants and target each other.
  -- Serialize the low-volume cross-tenant mutation surface before taking any
  -- organization/profile row lock, preventing reciprocal A->B / B->A ABBA.
  perform pg_catalog.pg_advisory_xact_lock(7346501135020481::bigint);

  actor := private.require_locked_service_platform_operator(p_actor_id, p_session_id);

  select * into organization
  from public.organizations o
  where o.id = p_organization_id
  for update;

  if organization.id is null then
    raise exception 'İşletme bulunamadı';
  end if;
  perform private.assert_organization_not_deleting(organization.id);

  request_hash := private.inventory_request_hash(jsonb_build_object(
    'operation', 'platform_subscription_update',
    'organization_id', p_organization_id,
    'expected_revision', p_expected_revision,
    'status', normalized_status,
    'period_days', p_period_days,
    'max_members', p_max_members,
    'max_products', p_max_products,
    'reason', normalized_reason
  ));

  insert into private.platform_admin_command_receipts (
    actor_id, request_id, organization_id, request_hash
  ) values (
    actor.id, p_request_id, organization.id, request_hash
  ) on conflict (actor_id, request_id) do nothing;
  inserted := found;

  if not inserted then
    select * into receipt
    from private.platform_admin_command_receipts r
    where r.actor_id = actor.id and r.request_id = p_request_id
    for update;

    if receipt.organization_id is distinct from organization.id
       or receipt.request_hash is distinct from request_hash then
      raise exception 'İstek kimliği farklı bir platform işlemi için kullanıldı';
    end if;
    if receipt.response is null or receipt.completed_at is null then
      raise exception 'Önceki platform işlemi tamamlanmamış görünüyor';
    end if;
    return receipt.response;
  end if;

  if organization.subscription_revision <> p_expected_revision then
    raise exception using
      errcode = '40001',
      message = 'İşletme başka bir işlemde değiştirildi; güncel veriyi yükleyin';
  end if;

  select count(*) into active_member_count
  from public.profiles p
  where p.organization_id = organization.id and p.is_active;
  select count(*) into active_product_count
  from public.products p
  where p.organization_id = organization.id and p.active;

  if p_max_members < active_member_count then
    raise exception 'Kullanıcı limiti mevcut etkin kullanıcı sayısından düşük olamaz';
  end if;
  if p_max_products < active_product_count then
    raise exception 'Ürün limiti mevcut etkin ürün sayısından düşük olamaz';
  end if;

  -- Count only new privileged commands. Exact receipt replays return above.
  allowed := public.consume_auth_rate_limit(
    'platform-business-update',
    private.inventory_request_hash(jsonb_build_object('actor_id', actor.id)),
    120,
    3600
  );
  if not allowed then
    raise exception 'Çok fazla platform işlemi denendi; daha sonra tekrar deneyin';
  end if;

  if normalized_status = 'active' then
    -- Extend from the same authoritative base for both fields. In particular,
    -- an existing longer Google Play period must not make the displayed period
    -- longer than the actual administrative entitlement overlay.
    next_platform_entitlement_until := greatest(
      coalesce(organization.current_period_end, '-infinity'::timestamptz),
      coalesce(organization.platform_entitlement_until, '-infinity'::timestamptz),
      clock_timestamp()
    ) + make_interval(days => p_period_days);

    update public.organizations
    set subscription_status = 'active',
        trial_ends_at = null,
        current_period_end = next_platform_entitlement_until,
        max_members = p_max_members,
        max_products = p_max_products,
        platform_entitlement_until = next_platform_entitlement_until,
        platform_entitlement_by = actor.id,
        platform_entitlement_reason = normalized_reason,
        administratively_suspended_at = null,
        administratively_suspended_by = null,
        administrative_suspension_reason = null,
        subscription_revision = subscription_revision + 1,
        updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
    where id = organization.id
      and subscription_revision = p_expected_revision
    returning * into updated_organization;
  else
    update public.organizations
    set subscription_status = 'suspended',
        -- Preserve entitlement/trial dates; suspension is an administrative
        -- overlay and must not destroy billing evidence.
        max_members = p_max_members,
        max_products = p_max_products,
        administratively_suspended_at = clock_timestamp(),
        administratively_suspended_by = actor.id,
        administrative_suspension_reason = normalized_reason,
        subscription_revision = subscription_revision + 1,
        updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
    where id = organization.id
      and subscription_revision = p_expected_revision
    returning * into updated_organization;
  end if;

  if updated_organization.id is null then
    raise exception using
      errcode = '40001',
      message = 'İşletme eşzamanlı olarak değiştirildi';
  end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    organization.id,
    actor.id,
    organization.created_by,
    'organization.subscription_updated',
    jsonb_build_object(
      'request_id', p_request_id,
      'reason', normalized_reason,
      'before', jsonb_build_object(
        'status', organization.subscription_status,
        'trial_ends_at', organization.trial_ends_at,
        'current_period_end', organization.current_period_end,
        'max_members', organization.max_members,
        'max_products', organization.max_products,
        'platform_entitlement_until', organization.platform_entitlement_until,
        'platform_entitlement_reason', organization.platform_entitlement_reason,
        'revision', organization.subscription_revision
      ),
      'after', jsonb_build_object(
        'status', updated_organization.subscription_status,
        'trial_ends_at', updated_organization.trial_ends_at,
        'current_period_end', updated_organization.current_period_end,
        'max_members', updated_organization.max_members,
        'max_products', updated_organization.max_products,
        'platform_entitlement_until', updated_organization.platform_entitlement_until,
        'platform_entitlement_reason', updated_organization.platform_entitlement_reason,
        'revision', updated_organization.subscription_revision
      )
    )
  );

  result_payload := jsonb_build_object(
    'organization', jsonb_build_object(
      'id', updated_organization.id,
      'name', updated_organization.name,
      'slug', updated_organization.slug,
      'subscription_status', updated_organization.subscription_status,
      'trial_ends_at', updated_organization.trial_ends_at,
      'current_period_end', updated_organization.current_period_end,
      'max_members', updated_organization.max_members,
      'max_products', updated_organization.max_products,
      'platform_entitlement_until', updated_organization.platform_entitlement_until,
      'platform_entitlement_reason', updated_organization.platform_entitlement_reason,
      'subscription_revision', updated_organization.subscription_revision
    ),
    'request_id', p_request_id
  );

  update private.platform_admin_command_receipts as receipts
  set response = result_payload,
      completed_at = clock_timestamp()
  where receipts.actor_id = actor.id
    and receipts.request_id = p_request_id
    and receipts.response is null
    and receipts.completed_at is null;

  if not found then
    raise exception 'Platform işlem sonucu güvenli biçimde kaydedilemedi';
  end if;

  return result_payload;
end;
$$;

revoke all on function private.enforce_subscription_revision()
  from public, anon, authenticated, service_role;
revoke all on function private.require_locked_service_platform_operator(uuid, uuid)
  from public, anon, authenticated, service_role;
revoke all on function private.assert_organization_not_deleting(uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.service_list_platform_businesses(
  uuid, uuid, timestamptz, uuid, integer
) from public, anon, authenticated, service_role;
revoke all on function public.service_update_platform_subscription(
  uuid, uuid, uuid, uuid, bigint, text, integer, integer, integer, text
) from public, anon, authenticated, service_role;

grant execute on function public.service_list_platform_businesses(
  uuid, uuid, timestamptz, uuid, integer
) to service_role;
grant execute on function public.service_update_platform_subscription(
  uuid, uuid, uuid, uuid, bigint, text, integer, integer, integer, text
) to service_role;

comment on function public.service_list_platform_businesses(
  uuid, uuid, timestamptz, uuid, integer
) is 'Service-only bounded platform organization page with database-side exact counts and locked actor/session authorization.';
comment on function public.service_update_platform_subscription(
  uuid, uuid, uuid, uuid, bigint, text, integer, integer, integer, text
) is 'Service-only atomic platform subscription command with actor/session binding, idempotency, revision CAS and mandatory audit.';

commit;
