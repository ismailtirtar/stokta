-- Server-verified Google Play subscription state. Purchase tokens never enter
-- an exposed schema: only their SHA-256 digests are retained for ownership and
-- idempotency. The public wrapper is callable exclusively by service_role.

begin;

set local statement_timeout = '30s';

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

do $$
begin
  if not exists (
    select 1
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'extensions'
      and p.proname = 'digest'
  ) then
    raise exception 'pgcrypto digest fonksiyonu extensions şemasında bulunamadı';
  end if;
end;
$$;

create table private.google_play_subscriptions (
  purchase_token_hash text primary key
    check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  organization_id uuid not null,
  purchaser_user_id uuid not null,
  product_id text not null check (product_id = 'stokdas_pro'),
  base_plan_id text not null check (base_plan_id = 'monthly'),
  subscription_state text not null check (
    subscription_state in (
      'SUBSCRIPTION_STATE_PENDING',
      'SUBSCRIPTION_STATE_ACTIVE',
      'SUBSCRIPTION_STATE_PAUSED',
      'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
      'SUBSCRIPTION_STATE_ON_HOLD',
      'SUBSCRIPTION_STATE_CANCELED',
      'SUBSCRIPTION_STATE_EXPIRED',
      'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
    )
  ),
  acknowledgement_state text not null check (
    acknowledgement_state in (
      'ACKNOWLEDGEMENT_STATE_PENDING',
      'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
    )
  ),
  source_verified_at timestamptz not null,
  expiry_time timestamptz,
  auto_renew_enabled boolean,
  is_test_purchase boolean not null default false,
  latest_order_id_hash text
    check (latest_order_id_hash is null or latest_order_id_hash ~ '^[a-f0-9]{64}$'),
  external_account_id_hash text not null
    check (external_account_id_hash ~ '^[a-f0-9]{64}$'),
  external_profile_id_hash text not null
    check (external_profile_id_hash ~ '^[a-f0-9]{64}$'),
  entitled boolean not null,
  acknowledged_at timestamptz,
  first_verified_at timestamptz not null default now(),
  last_verified_at timestamptz not null default now(),
  verification_count bigint not null default 1 check (verification_count > 0),
  constraint google_play_subscriptions_profile_organization_fkey
    foreign key (purchaser_user_id, organization_id)
    references public.profiles(id, organization_id) on delete cascade,
  constraint google_play_subscriptions_organization_fkey
    foreign key (organization_id)
    references public.organizations(id) on delete cascade,
  constraint google_play_subscriptions_owner_key
    unique (purchase_token_hash, organization_id, purchaser_user_id),
  constraint google_play_subscriptions_entitled_expiry_check
    check (not entitled or expiry_time is not null)
);

create index google_play_subscriptions_organization_verified_idx
  on private.google_play_subscriptions (organization_id, last_verified_at desc);
create index google_play_subscriptions_purchaser_verified_idx
  on private.google_play_subscriptions (purchaser_user_id, last_verified_at desc);
create index google_play_subscriptions_purchaser_organization_idx
  on private.google_play_subscriptions (purchaser_user_id, organization_id);

-- One authoritative Google Play entitlement per organization. Historical or
-- superseded purchase tokens stay in the ledger without being able to shorten
-- a newer entitlement.
create table private.google_play_entitlements (
  organization_id uuid primary key
    references public.organizations(id) on delete cascade,
  current_purchase_token_hash text not null,
  purchaser_user_id uuid not null,
  product_id text not null check (product_id = 'stokdas_pro'),
  base_plan_id text not null check (base_plan_id = 'monthly'),
  subscription_state text not null check (
    subscription_state in (
      'SUBSCRIPTION_STATE_PENDING',
      'SUBSCRIPTION_STATE_ACTIVE',
      'SUBSCRIPTION_STATE_PAUSED',
      'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
      'SUBSCRIPTION_STATE_ON_HOLD',
      'SUBSCRIPTION_STATE_CANCELED',
      'SUBSCRIPTION_STATE_EXPIRED',
      'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
    )
  ),
  entitled boolean not null,
  current_period_end timestamptz,
  updated_at timestamptz not null default now(),
  constraint google_play_entitlements_profile_organization_fkey
    foreign key (purchaser_user_id, organization_id)
    references public.profiles(id, organization_id) on delete cascade,
  constraint google_play_entitlements_subscription_owner_fkey
    foreign key (current_purchase_token_hash, organization_id, purchaser_user_id)
    references private.google_play_subscriptions(
      purchase_token_hash, organization_id, purchaser_user_id
    ) on delete cascade,
  constraint google_play_entitlements_entitled_expiry_check
    check (not entitled or current_period_end is not null)
);

create index google_play_entitlements_token_idx
  on private.google_play_entitlements (current_purchase_token_hash);
create index google_play_entitlements_purchaser_organization_idx
  on private.google_play_entitlements (purchaser_user_id, organization_id);
create index google_play_entitlements_subscription_owner_idx
  on private.google_play_entitlements (
    current_purchase_token_hash, organization_id, purchaser_user_id
  );

-- Deduplicated verification history provides an audit trail without allowing
-- repeated client retries to grow the table indefinitely.
create table private.google_play_subscription_events (
  id bigint generated always as identity primary key,
  purchase_token_hash text not null,
  organization_id uuid not null
    references public.organizations(id) on delete cascade,
  purchaser_user_id uuid not null,
  result_fingerprint text not null check (result_fingerprint ~ '^[a-f0-9]{64}$'),
  subscription_state text not null check (
    subscription_state in (
      'SUBSCRIPTION_STATE_PENDING',
      'SUBSCRIPTION_STATE_ACTIVE',
      'SUBSCRIPTION_STATE_PAUSED',
      'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
      'SUBSCRIPTION_STATE_ON_HOLD',
      'SUBSCRIPTION_STATE_CANCELED',
      'SUBSCRIPTION_STATE_EXPIRED',
      'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
    )
  ),
  acknowledgement_state text not null check (
    acknowledgement_state in (
      'ACKNOWLEDGEMENT_STATE_PENDING',
      'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
    )
  ),
  source_verified_at timestamptz not null,
  expiry_time timestamptz,
  entitled boolean not null,
  verified_at timestamptz not null default now(),
  constraint google_play_subscription_events_profile_organization_fkey
    foreign key (purchaser_user_id, organization_id)
    references public.profiles(id, organization_id) on delete cascade,
  constraint google_play_subscription_events_subscription_owner_fkey
    foreign key (purchase_token_hash, organization_id, purchaser_user_id)
    references private.google_play_subscriptions(
      purchase_token_hash, organization_id, purchaser_user_id
    ) on delete cascade,
  constraint google_play_subscription_events_result_key
    unique (purchase_token_hash, result_fingerprint)
);

create index google_play_subscription_events_organization_verified_idx
  on private.google_play_subscription_events (organization_id, verified_at desc);
create index google_play_subscription_events_purchaser_organization_idx
  on private.google_play_subscription_events (purchaser_user_id, organization_id);
create index google_play_subscription_events_subscription_owner_idx
  on private.google_play_subscription_events (
    purchase_token_hash, organization_id, purchaser_user_id
  );

alter table private.google_play_subscriptions enable row level security;
alter table private.google_play_subscriptions force row level security;
alter table private.google_play_entitlements enable row level security;
alter table private.google_play_entitlements force row level security;
alter table private.google_play_subscription_events enable row level security;
alter table private.google_play_subscription_events force row level security;

revoke all on table private.google_play_subscriptions
  from public, anon, authenticated, service_role;
revoke all on table private.google_play_entitlements
  from public, anon, authenticated, service_role;
revoke all on table private.google_play_subscription_events
  from public, anon, authenticated, service_role;
revoke all on sequence private.google_play_subscription_events_id_seq
  from public, anon, authenticated, service_role;

create or replace function public.service_record_google_play_subscription(
  p_purchase_token_hash text,
  p_user_id uuid,
  p_organization_id uuid,
  p_product_id text,
  p_base_plan_id text,
  p_subscription_state text,
  p_acknowledgement_state text,
  p_activate_entitlement boolean,
  p_google_verified_at timestamptz,
  p_expiry_time timestamptz,
  p_auto_renew_enabled boolean,
  p_is_test_purchase boolean,
  p_latest_order_id_hash text,
  p_external_account_id_hash text,
  p_external_profile_id_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller public.profiles;
  existing_subscription private.google_play_subscriptions;
  current_entitlement private.google_play_entitlements;
  derived_entitled boolean;
  computed_result_fingerprint text;
  next_status text;
  organization_status text;
  organization_period_end timestamptz;
  should_replace_entitlement boolean := false;
  inserted_subscription boolean := false;
  incoming_is_stale boolean := false;
  effective_acknowledgement_state text;
  effective_activate_entitlement boolean;
  organization_entitled boolean;
begin
  if p_purchase_token_hash is null
     or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_user_id is null
     or p_organization_id is null then
    raise exception 'Geçersiz Google Play doğrulama isteği' using errcode = '22023';
  end if;

  if p_product_id is distinct from 'stokdas_pro'
     or p_base_plan_id is distinct from 'monthly' then
    raise exception 'Desteklenmeyen Google Play aboneliği' using errcode = '22023';
  end if;

  if p_subscription_state is null or p_subscription_state not in (
    'SUBSCRIPTION_STATE_PENDING',
    'SUBSCRIPTION_STATE_ACTIVE',
    'SUBSCRIPTION_STATE_PAUSED',
    'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
    'SUBSCRIPTION_STATE_ON_HOLD',
    'SUBSCRIPTION_STATE_CANCELED',
    'SUBSCRIPTION_STATE_EXPIRED',
    'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
  ) then
    raise exception 'Geçersiz Google Play abonelik durumu' using errcode = '22023';
  end if;

  if p_acknowledgement_state is null or p_acknowledgement_state not in (
    'ACKNOWLEDGEMENT_STATE_PENDING',
    'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
  ) then
    raise exception 'Geçersiz Google Play onay durumu' using errcode = '22023';
  end if;

  if p_activate_entitlement is null then
    raise exception 'Geçersiz Google Play etkinleştirme durumu' using errcode = '22023';
  end if;

  if p_google_verified_at is null
     or p_google_verified_at < now() - interval '15 minutes'
     or p_google_verified_at > now() + interval '1 minute' then
    raise exception 'Geçersiz Google Play doğrulama zamanı' using errcode = '22023';
  end if;

  if p_latest_order_id_hash is not null
     and p_latest_order_id_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'Geçersiz Google Play sipariş özeti' using errcode = '22023';
  end if;

  if p_external_account_id_hash is null
     or p_external_account_id_hash !~ '^[a-f0-9]{64}$'
     or p_external_profile_id_hash is null
     or p_external_profile_id_hash !~ '^[a-f0-9]{64}$'
     or p_external_account_id_hash <> encode(
       extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'),
       'hex'
     )
     or p_external_profile_id_hash <> encode(
       extensions.digest(convert_to(p_organization_id::text, 'UTF8'), 'sha256'),
       'hex'
     ) then
    raise exception 'Google Play satın alma kimliği eşleşmiyor' using errcode = '22023';
  end if;

  select * into caller
  from public.profiles p
  where p.id = p_user_id
    and p.organization_id = p_organization_id
    and p.role = 'admin'
    and p.is_active
    and not p.must_change_password
  for share;

  if caller.id is null then
    raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501';
  end if;

  if p_subscription_state in (
       'SUBSCRIPTION_STATE_ACTIVE',
       'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
       'SUBSCRIPTION_STATE_CANCELED'
     ) and p_expiry_time is null then
    raise exception 'Google Play abonelik bitiş zamanı eksik' using errcode = '22023';
  end if;

  derived_entitled := p_subscription_state in (
    'SUBSCRIPTION_STATE_ACTIVE',
    'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
    'SUBSCRIPTION_STATE_CANCELED'
  )
    and coalesce(p_expiry_time, '-infinity'::timestamptz) > now()
    and p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
    and p_activate_entitlement;

  insert into private.google_play_subscriptions (
    purchase_token_hash,
    organization_id,
    purchaser_user_id,
    product_id,
    base_plan_id,
    subscription_state,
    acknowledgement_state,
    source_verified_at,
    expiry_time,
    auto_renew_enabled,
    is_test_purchase,
    latest_order_id_hash,
    external_account_id_hash,
    external_profile_id_hash,
    entitled,
    acknowledged_at
  ) values (
    p_purchase_token_hash,
    p_organization_id,
    p_user_id,
    p_product_id,
    p_base_plan_id,
    p_subscription_state,
    p_acknowledgement_state,
    p_google_verified_at,
    p_expiry_time,
    p_auto_renew_enabled,
    coalesce(p_is_test_purchase, false),
    p_latest_order_id_hash,
    p_external_account_id_hash,
    p_external_profile_id_hash,
    derived_entitled,
    case when p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
      then now() else null end
  )
  on conflict (purchase_token_hash) do nothing
  returning * into existing_subscription;

  inserted_subscription := found;

  if not inserted_subscription then
    select * into existing_subscription
    from private.google_play_subscriptions s
    where s.purchase_token_hash = p_purchase_token_hash
    for update;
  end if;

  if existing_subscription.purchase_token_hash is null then
    raise exception 'Google Play satın alma kaydı oluşturulamadı';
  end if;

  if existing_subscription.organization_id <> p_organization_id
     or existing_subscription.purchaser_user_id <> p_user_id then
    raise exception 'Google Play satın alma başka bir hesaba bağlı' using errcode = '23505';
  end if;

  incoming_is_stale := not inserted_subscription
    and p_google_verified_at < existing_subscription.source_verified_at;

  effective_acknowledgement_state := case
    when existing_subscription.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
      or p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
    then 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
    else 'ACKNOWLEDGEMENT_STATE_PENDING'
  end;
  effective_activate_entitlement := p_activate_entitlement
    or existing_subscription.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED';
  derived_entitled := p_subscription_state in (
    'SUBSCRIPTION_STATE_ACTIVE',
    'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
    'SUBSCRIPTION_STATE_CANCELED'
  )
    and coalesce(p_expiry_time, '-infinity'::timestamptz) > now()
    and effective_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
    and effective_activate_entitlement;

  if incoming_is_stale then
    -- An earlier Google response may finish after a newer concurrent request.
    -- It can advance acknowledgement, but it cannot roll entitlement state or
    -- expiry backwards.
    update private.google_play_subscriptions
    set acknowledgement_state = case
          when acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
            or p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
          then 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
          else acknowledgement_state
        end,
        acknowledged_at = case
          when p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
            then coalesce(acknowledged_at, now())
          else acknowledged_at
        end,
        last_verified_at = now(),
        verification_count = verification_count + 1
    where purchase_token_hash = p_purchase_token_hash;
  else
    update private.google_play_subscriptions
    set subscription_state = p_subscription_state,
        acknowledgement_state = case
          when acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
            or p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
          then 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
          else p_acknowledgement_state
        end,
        source_verified_at = p_google_verified_at,
        expiry_time = p_expiry_time,
        auto_renew_enabled = p_auto_renew_enabled,
        is_test_purchase = coalesce(p_is_test_purchase, false),
        latest_order_id_hash = p_latest_order_id_hash,
        external_account_id_hash = p_external_account_id_hash,
        external_profile_id_hash = p_external_profile_id_hash,
        entitled = derived_entitled,
        acknowledged_at = case
          when p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
            then coalesce(acknowledged_at, now())
          else acknowledged_at
        end,
        last_verified_at = now(),
        verification_count = verification_count + case
          when inserted_subscription then 0 else 1 end
    where purchase_token_hash = p_purchase_token_hash;
  end if;

  computed_result_fingerprint := encode(
    extensions.digest(
      convert_to(
        concat_ws(
          '|',
          p_purchase_token_hash,
          p_subscription_state,
          p_acknowledgement_state,
          p_activate_entitlement::text,
          coalesce(extract(epoch from p_expiry_time)::text, ''),
          coalesce(p_auto_renew_enabled::text, ''),
          coalesce(p_is_test_purchase, false)::text,
          coalesce(p_latest_order_id_hash, '')
        ),
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  );

  insert into private.google_play_subscription_events (
    purchase_token_hash,
    organization_id,
    purchaser_user_id,
    result_fingerprint,
    subscription_state,
    acknowledgement_state,
    source_verified_at,
    expiry_time,
    entitled
  ) values (
    p_purchase_token_hash,
    p_organization_id,
    p_user_id,
    computed_result_fingerprint,
    p_subscription_state,
    p_acknowledgement_state,
    p_google_verified_at,
    p_expiry_time,
    derived_entitled
  )
  on conflict on constraint google_play_subscription_events_result_key do nothing;

  if not incoming_is_stale and derived_entitled then
    insert into private.google_play_entitlements (
      organization_id,
      current_purchase_token_hash,
      purchaser_user_id,
      product_id,
      base_plan_id,
      subscription_state,
      entitled,
      current_period_end
    ) values (
      p_organization_id,
      p_purchase_token_hash,
      p_user_id,
      p_product_id,
      p_base_plan_id,
      p_subscription_state,
      true,
      p_expiry_time
    )
    on conflict (organization_id) do nothing;

    select * into current_entitlement
    from private.google_play_entitlements e
    where e.organization_id = p_organization_id
    for update;

    should_replace_entitlement :=
      current_entitlement.current_purchase_token_hash = p_purchase_token_hash
      or not current_entitlement.entitled
      or current_entitlement.current_period_end is null
      or p_expiry_time > current_entitlement.current_period_end
      or (
        p_expiry_time = current_entitlement.current_period_end
        and p_purchase_token_hash > current_entitlement.current_purchase_token_hash
      );

    if should_replace_entitlement then
      update private.google_play_entitlements
      set current_purchase_token_hash = p_purchase_token_hash,
          purchaser_user_id = p_user_id,
          product_id = p_product_id,
          base_plan_id = p_base_plan_id,
          subscription_state = p_subscription_state,
          entitled = true,
          current_period_end = p_expiry_time,
          updated_at = now()
      where organization_id = p_organization_id;

      update public.organizations
      set subscription_status = case
            when subscription_status = 'suspended' then 'suspended'
            else 'active'
          end,
          trial_ends_at = null,
          current_period_end = p_expiry_time,
          updated_at = now()
      where id = p_organization_id;
    end if;
  elsif not incoming_is_stale then
    select * into current_entitlement
    from private.google_play_entitlements e
    where e.organization_id = p_organization_id
    for update;

    if current_entitlement.current_purchase_token_hash = p_purchase_token_hash then
      next_status := case
        when p_subscription_state = 'SUBSCRIPTION_STATE_ON_HOLD' then 'past_due'
        when p_subscription_state = 'SUBSCRIPTION_STATE_PAUSED' then 'past_due'
        when p_subscription_state = 'SUBSCRIPTION_STATE_PENDING' then 'past_due'
        else 'canceled'
      end;

      update private.google_play_entitlements
      set subscription_state = p_subscription_state,
          entitled = false,
          current_period_end = p_expiry_time,
          updated_at = now()
      where organization_id = p_organization_id;

      update public.organizations
      set subscription_status = case
            when subscription_status = 'suspended' then 'suspended'
            else next_status
          end,
          current_period_end = p_expiry_time,
          updated_at = now()
      where id = p_organization_id;
    end if;
  end if;

  select o.subscription_status, o.current_period_end
    into organization_status, organization_period_end
  from public.organizations o
  where o.id = p_organization_id;

  if organization_status is null then
    raise exception 'İşletme bulunamadı';
  end if;

  select coalesce(
      e.entitled
        and organization_status <> 'suspended'
        and coalesce(e.current_period_end, '-infinity'::timestamptz) > now(),
      false
    )
    into organization_entitled
  from private.google_play_entitlements e
  where e.organization_id = p_organization_id;
  organization_entitled := coalesce(organization_entitled, false);

  return jsonb_build_object(
    'entitled', organization_entitled,
    'subscriptionStatus', organization_status,
    'currentPeriodEnd', organization_period_end
  );
end;
$$;

revoke all on function public.service_record_google_play_subscription(
  text, uuid, uuid, text, text, text, text, boolean, timestamptz,
  timestamptz, boolean, boolean, text, text, text
) from public, anon, authenticated, service_role;
grant execute on function public.service_record_google_play_subscription(
  text, uuid, uuid, text, text, text, text, boolean, timestamptz,
  timestamptz, boolean, boolean, text, text, text
) to service_role;

comment on function public.service_record_google_play_subscription(
  text, uuid, uuid, text, text, text, text, boolean, timestamptz,
  timestamptz, boolean, boolean, text, text, text
) is
  'Records a server-verified Google Play subscription atomically. Service role only; accepts token hashes, never raw purchase tokens.';

create or replace function public.service_google_play_subscription_requires_cancellation(
  p_organization_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.google_play_entitlements e
    join private.google_play_subscriptions s
      on s.purchase_token_hash = e.current_purchase_token_hash
      and s.organization_id = e.organization_id
      and s.purchaser_user_id = e.purchaser_user_id
    where e.organization_id = p_organization_id
      and s.auto_renew_enabled is true
      and s.subscription_state not in (
        'SUBSCRIPTION_STATE_EXPIRED',
        'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
      )
  );
$$;

revoke all on function public.service_google_play_subscription_requires_cancellation(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_google_play_subscription_requires_cancellation(uuid)
  to service_role;

comment on function public.service_google_play_subscription_requires_cancellation(uuid) is
  'Prevents tenant deletion while the authoritative Google Play subscription can still auto-renew. Service role only.';

commit;
