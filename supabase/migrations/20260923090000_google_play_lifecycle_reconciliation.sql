-- Additive Google Play lifecycle storage. The deployed mobile request and the
-- public service_record_google_play_subscription signature remain unchanged.
begin;
set local statement_timeout = '30s';

create table private.google_play_token_vault (
  purchase_token_hash text primary key
    references private.google_play_subscriptions(purchase_token_hash) on delete cascade,
  token_ciphertext text not null,
  token_nonce text not null,
  key_version integer not null check (key_version = 1),
  reconcile_after timestamptz not null default now(),
  failure_count integer not null default 0 check (failure_count >= 0),
  last_success_at timestamptz,
  updated_at timestamptz not null default now()
);
create index google_play_token_vault_due_idx
  on private.google_play_token_vault (reconcile_after);

create table private.google_play_observation_leases (
  purchase_token_hash text primary key check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  generation bigint not null default 0 check (generation >= 0),
  lease_id uuid,
  expires_at timestamptz,
  updated_at timestamptz not null default now()
);

-- A Google-signed replacement is bound to the prior token's immutable ledger
-- owner by the observation RPC. Hash fences survive individual ledger-row
-- deletion; they disappear only with the owning profile/organization.
create table private.google_play_token_replacements (
  old_token_hash text primary key check (old_token_hash ~ '^[a-f0-9]{64}$'),
  new_token_hash text not null unique check (new_token_hash ~ '^[a-f0-9]{64}$'),
  purchaser_user_id uuid not null,
  organization_id uuid not null,
  predecessor_kind text not null check (predecessor_kind in ('linked', 'expired')),
  activated_at timestamptz,
  created_at timestamptz not null default now(),
  check (old_token_hash <> new_token_hash),
  foreign key (purchaser_user_id, organization_id)
    references public.profiles (id, organization_id)
    on delete cascade,
  foreign key (organization_id) references public.organizations (id)
    on delete cascade
);

-- A canceled PENDING predecessor can be replaced by a later valid sibling.
-- The abandoned token remains fenced if its ledger row is deleted separately.
create table private.google_play_abandoned_tokens (
  purchase_token_hash text primary key check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  purchaser_user_id uuid not null,
  organization_id uuid not null,
  abandoned_at timestamptz not null default now(),
  foreign key (purchaser_user_id, organization_id)
    references public.profiles (id, organization_id) on delete cascade,
  foreign key (organization_id) references public.organizations (id)
    on delete cascade
);

create table private.google_play_voided_orders (
  purchase_token_hash text not null check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  order_id_hash text not null check (order_id_hash ~ '^[a-f0-9]{64}$'),
  event_time timestamptz not null,
  received_at timestamptz not null default now(),
  primary key (purchase_token_hash, order_id_hash)
);

create table private.google_play_void_scan_state (
  singleton boolean primary key default true check (singleton),
  start_time_ms bigint not null,
  page_token text,
  last_completed_at timestamptz,
  updated_at timestamptz not null default now()
);
insert into private.google_play_void_scan_state(singleton, start_time_ms)
values (true, (extract(epoch from now() - interval '29 days') * 1000)::bigint);

alter table private.google_play_token_vault enable row level security;
alter table private.google_play_token_vault force row level security;
alter table private.google_play_observation_leases enable row level security;
alter table private.google_play_observation_leases force row level security;
alter table private.google_play_token_replacements enable row level security;
alter table private.google_play_token_replacements force row level security;
alter table private.google_play_abandoned_tokens enable row level security;
alter table private.google_play_abandoned_tokens force row level security;
alter table private.google_play_voided_orders enable row level security;
alter table private.google_play_voided_orders force row level security;
alter table private.google_play_void_scan_state enable row level security;
alter table private.google_play_void_scan_state force row level security;
revoke all on table private.google_play_token_vault,
  private.google_play_observation_leases,
  private.google_play_token_replacements,
  private.google_play_abandoned_tokens,
  private.google_play_voided_orders,
  private.google_play_void_scan_state
  from public, anon, authenticated, service_role;

create function public.service_claim_google_play_observation(p_token_hash text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare claimed private.google_play_observation_leases;
begin
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'Geçersiz satın alma özeti' using errcode = '22023';
  end if;
  insert into private.google_play_observation_leases
    (purchase_token_hash, generation, lease_id, expires_at)
  values (p_token_hash, 1, pg_catalog.gen_random_uuid(), now() + interval '90 seconds')
  on conflict (purchase_token_hash) do update
  set generation = private.google_play_observation_leases.generation + 1,
      lease_id = pg_catalog.gen_random_uuid(),
      expires_at = now() + interval '90 seconds',
      updated_at = now()
  where private.google_play_observation_leases.expires_at is null
     or private.google_play_observation_leases.expires_at <= now()
  returning * into claimed;
  if claimed.purchase_token_hash is null then return null; end if;
  return jsonb_build_object('leaseId', claimed.lease_id,
    'generation', claimed.generation);
end;
$$;

create function public.service_release_google_play_observation(
  p_token_hash text, p_lease_id uuid
) returns boolean language plpgsql security definer set search_path = '' as $$
begin
  update private.google_play_observation_leases
  set lease_id = null, expires_at = null, updated_at = now()
  where purchase_token_hash = p_token_hash and lease_id = p_lease_id;
  return found;
end;
$$;

create function public.service_get_google_play_owner(p_token_hash text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare subscription private.google_play_subscriptions;
begin
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'Geçersiz satın alma özeti' using errcode = '22023';
  end if;
  select * into subscription from private.google_play_subscriptions
  where purchase_token_hash = p_token_hash;
  if subscription.purchase_token_hash is null then return null; end if;
  return jsonb_build_object(
    'userId', subscription.purchaser_user_id,
    'organizationId', subscription.organization_id,
    'accountHash', subscription.external_account_id_hash,
    'profileHash', subscription.external_profile_id_hash,
    'abandoned', exists (
      select 1 from private.google_play_abandoned_tokens a
      where a.purchase_token_hash = p_token_hash
    )
  );
end;
$$;

-- Keep the old public RPC identity for already-deployed Edge code. The core is
-- moved to an unexposed schema and every caller passes through the void fence.
alter function public.service_record_google_play_subscription(
  text, uuid, uuid, text, text, text, text, boolean, timestamptz,
  timestamptz, boolean, boolean, text, text, text
) rename to service_record_google_play_subscription_core;
alter function public.service_record_google_play_subscription_core(
  text, uuid, uuid, text, text, text, text, boolean, timestamptz,
  timestamptz, boolean, boolean, text, text, text
) set schema private;
revoke all on function private.service_record_google_play_subscription_core(
  text, uuid, uuid, text, text, text, text, boolean, timestamptz,
  timestamptz, boolean, boolean, text, text, text
) from public, anon, authenticated, service_role;

-- The original RPC requires the purchasing administrator to remain active
-- forever. Renewals and HOLD after a team administrator leaves must still be
-- recorded. Existing token ownership is checked again by the core under its
-- row lock; only a FIRST purchase still needs an active administrator.
do $$
declare definition text;
declare old_guard text := 'if caller.id is null then';
declare new_guard text := $guard$if caller.id is null and not exists (
    select 1 from private.google_play_subscriptions s
    where s.purchase_token_hash = p_purchase_token_hash
      and s.purchaser_user_id = p_user_id
      and s.organization_id = p_organization_id
  ) and not exists (
    select 1 from private.google_play_token_replacements r
    where r.new_token_hash = p_purchase_token_hash
      and r.purchaser_user_id = p_user_id
      and r.organization_id = p_organization_id
  ) then$guard$;
begin
  select pg_catalog.pg_get_functiondef(
    'private.service_record_google_play_subscription_core(text,uuid,uuid,text,text,text,text,boolean,timestamptz,timestamptz,boolean,boolean,text,text,text)'::regprocedure
  ) into definition;
  if definition is null
     or pg_catalog.length(definition) - pg_catalog.length(
       pg_catalog.replace(definition, old_guard, '')
     ) <> pg_catalog.length(old_guard) then
    raise exception 'Unexpected Google Play core owner guard; stop migration';
  end if;
  execute pg_catalog.replace(definition, old_guard, new_guard);
end;
$$;

create function public.service_record_google_play_subscription(
  p_purchase_token_hash text, p_user_id uuid, p_organization_id uuid,
  p_product_id text, p_base_plan_id text, p_subscription_state text,
  p_acknowledgement_state text, p_activate_entitlement boolean,
  p_google_verified_at timestamptz, p_expiry_time timestamptz,
  p_auto_renew_enabled boolean, p_is_test_purchase boolean,
  p_latest_order_id_hash text, p_external_account_id_hash text,
  p_external_profile_id_hash text
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare result jsonb;
declare web_until timestamptz;
declare organization_status text;
declare organization_period_end timestamptz;
declare play_entitled boolean;
declare refunded_current_order boolean := false;
begin
  -- A permanently replaced token is a no-op. Lock its ledger row first so a
  -- concurrent new-token activation cannot commit between this check and the
  -- old core grant. Never let the core temporarily promote this token over an
  -- unrelated, valid subscription in the same organization.
  perform 1 from private.google_play_subscriptions s
  where s.purchase_token_hash = p_purchase_token_hash for update;
  if exists (
    select 1 from private.google_play_token_replacements r
    where r.old_token_hash = p_purchase_token_hash
      and r.activated_at is not null
  ) or exists (
    select 1 from private.google_play_abandoned_tokens a
    where a.purchase_token_hash = p_purchase_token_hash
  ) then
    select jsonb_build_object(
      'entitled', coalesce(e.entitled and e.current_period_end > now()
        and o.subscription_status <> 'suspended', false),
      'subscriptionStatus', o.subscription_status,
      'currentPeriodEnd', o.current_period_end
    ) into result
    from public.organizations o
    left join private.google_play_entitlements e on e.organization_id = o.id
    where o.id = p_organization_id;
    return result;
  end if;
  result := private.service_record_google_play_subscription_core(
    p_purchase_token_hash, p_user_id, p_organization_id,
    p_product_id, p_base_plan_id, p_subscription_state,
    p_acknowledgement_state, p_activate_entitlement,
    p_google_verified_at, p_expiry_time, p_auto_renew_enabled,
    p_is_test_purchase, p_latest_order_id_hash,
    p_external_account_id_hash, p_external_profile_id_hash
  );

  -- A successful GET can still show ACTIVE after a refund. Until the voided
  -- orders sweep is complete and recent, roll back any Play grant from the
  -- core (including calls through the old public RPC).
  if exists (
    select 1 from private.google_play_entitlements e
    where e.organization_id = p_organization_id
      and e.current_purchase_token_hash = p_purchase_token_hash
      and e.entitled and e.current_period_end > now()
  ) and not exists (
    select 1 from private.google_play_void_scan_state v
    where v.singleton = true and v.page_token is null
      and v.last_completed_at > now() - interval '15 minutes'
  ) then
    raise exception 'Google Play refund scan is not current' using errcode = '55000';
  end if;

  -- Serialize against an operator approving an IBAN payment. Read the paid
  -- period only after taking the same organization lock as the reviewer RPC.
  perform 1 from public.organizations where id = p_organization_id for update;

  select max(activated_until) into web_until
  from public.web_payment_notifications
  where organization_id = p_organization_id and status = 'approved'
    and activated_until > now();

  -- The core may observe an active resource even after a refund. Fence the
  -- exact last paid order in the SAME transaction before any grant commits.
  if exists (
    select 1
    from private.google_play_voided_orders v
    join private.google_play_subscriptions s
      on s.purchase_token_hash = v.purchase_token_hash
    where v.purchase_token_hash = p_purchase_token_hash
      and (v.order_id_hash = s.latest_order_id_hash
        or s.latest_order_id_hash is null)
  ) then
    update private.google_play_subscriptions set entitled = false
    where purchase_token_hash = p_purchase_token_hash;
    update private.google_play_entitlements set entitled = false, updated_at = now()
    where current_purchase_token_hash = p_purchase_token_hash;
    if found then
      refunded_current_order := true;
      update public.organizations
      set subscription_status = case
            when subscription_status = 'suspended' then 'suspended'
            when web_until > now() then 'active' else 'past_due' end,
          current_period_end = case when web_until > now()
            then web_until else now() end,
          updated_at = now()
      where id = p_organization_id;
    end if;
  end if;

  -- Google reconciliation must not shorten an approved IBAN payment period.
  if web_until > now() and not refunded_current_order then
    update public.organizations
    set subscription_status = case when subscription_status = 'suspended'
        then 'suspended' else 'active' end,
        current_period_end = greatest(coalesce(current_period_end, web_until), web_until),
        updated_at = now()
    where id = p_organization_id
      and (subscription_status <> 'active' or current_period_end < web_until);
  end if;

  select subscription_status, current_period_end
    into organization_status, organization_period_end
  from public.organizations where id = p_organization_id;
  select coalesce(e.entitled and organization_status <> 'suspended'
      and e.current_period_end > now(), false)
    into play_entitled
  from private.google_play_entitlements e where e.organization_id = p_organization_id;
  return jsonb_build_object('entitled', coalesce(play_entitled, false),
    'subscriptionStatus', organization_status,
    'currentPeriodEnd', organization_period_end);
end;
$$;

create function public.service_record_google_play_observation(
  p_lease_id uuid, p_generation bigint, p_observation jsonb,
  p_token_ciphertext text, p_token_nonce text
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare token_hash text := p_observation->>'purchaseTokenHash';
declare predecessor_hash text := p_observation->>'predecessorTokenHash';
declare claimed_predecessor_hash text := p_observation->>'predecessorTokenHash';
declare predecessor_kind text := p_observation->>'predecessorKind';
declare lease private.google_play_observation_leases;
declare predecessor private.google_play_subscriptions;
declare successor private.google_play_subscriptions;
declare replacement private.google_play_token_replacements;
declare prior_replacement private.google_play_token_replacements;
declare abandoned private.google_play_subscriptions;
declare web_until timestamptz;
declare result jsonb;
begin
  if p_observation is null or jsonb_typeof(p_observation) <> 'object'
     or token_hash is null or token_hash !~ '^[a-f0-9]{64}$'
     or p_token_ciphertext is null or length(p_token_ciphertext) not between 24 and 8192
     or p_token_ciphertext !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_token_nonce is null or length(p_token_nonce) not between 16 and 32
     or p_token_nonce !~ '^[A-Za-z0-9+/]+={0,2}$'
     or (predecessor_hash is not null and (
       predecessor_hash !~ '^[a-f0-9]{64}$' or predecessor_hash = token_hash
       or predecessor_kind is null
       or predecessor_kind not in ('linked', 'expired')
     )) or (predecessor_hash is null and predecessor_kind is not null) then
    raise exception 'Geçersiz Google Play gözlemi' using errcode = '22023';
  end if;
  select * into lease from private.google_play_observation_leases
  where purchase_token_hash = token_hash for update;
  if lease.lease_id is distinct from p_lease_id
     or lease.generation is distinct from p_generation
     or lease.expires_at <= now() then
    raise exception 'Google Play gözlem süresi doldu' using errcode = '55P03';
  end if;
  -- Serialize an in-flight observation with a sibling rebind. The rebind
  -- locks the old pending ledger row before writing the permanent abandoned
  -- fence; a request that started before that fence must check again here.
  perform 1 from private.google_play_subscriptions
  where purchase_token_hash = token_hash for update;
  perform 1 from private.google_play_abandoned_tokens
  where purchase_token_hash = token_hash for update;
  if found then
    raise exception 'Terk edilmiş Google Play satın alımı'
      using errcode = '23505';
  end if;
  if predecessor_hash is null then
    select r.old_token_hash into predecessor_hash
    from private.google_play_token_replacements r
    where r.new_token_hash = token_hash;
  end if;
  if predecessor_hash is not null then
    select * into predecessor from private.google_play_subscriptions
    where purchase_token_hash = predecessor_hash for update;
    if predecessor.purchase_token_hash is null
      or predecessor.purchaser_user_id is distinct from
        (p_observation->>'userId')::uuid
      or predecessor.organization_id is distinct from
        (p_observation->>'organizationId')::uuid
      or predecessor.external_account_id_hash is distinct from
        p_observation->>'accountHash'
      or predecessor.external_profile_id_hash is distinct from
        p_observation->>'profileHash' then
      raise exception 'Önceki satın alma sahibi eşleşmiyor' using errcode = '23505';
    end if;
    if claimed_predecessor_hash is not null then
      select * into prior_replacement
      from private.google_play_token_replacements
      where old_token_hash = predecessor_hash for update;
      if prior_replacement.old_token_hash is not null
         and prior_replacement.new_token_hash <> token_hash then
        select * into abandoned from private.google_play_subscriptions
        where purchase_token_hash = prior_replacement.new_token_hash for update;
        -- Rebind only a sibling that never became a paid entitlement and was
        -- conclusively canceled (or expired without any successful order).
        -- Retain its hash in a permanent fence so a late Publisher response
        -- cannot later revive it, including after a direct ledger-row delete.
        if prior_replacement.activated_at is not null
           or prior_replacement.purchaser_user_id <> predecessor.purchaser_user_id
           or prior_replacement.organization_id <> predecessor.organization_id
           or abandoned.purchase_token_hash is null
           or (abandoned.purchase_token_hash is not null and (
             abandoned.entitled
             or abandoned.acknowledgement_state <> 'ACKNOWLEDGEMENT_STATE_PENDING'
             or abandoned.latest_order_id_hash is not null
             or abandoned.subscription_state not in (
               'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED',
               'SUBSCRIPTION_STATE_EXPIRED'
             )
           ))
           or exists (
             select 1 from private.google_play_entitlements e
             where e.current_purchase_token_hash = prior_replacement.new_token_hash
           )
           or exists (
             select 1 from private.google_play_token_replacements r
             where r.old_token_hash = prior_replacement.new_token_hash
           ) then
          raise exception 'Bekleyen Google Play aboneliği değiştirilemez'
            using errcode = '23505';
        end if;
        insert into private.google_play_abandoned_tokens
          (purchase_token_hash, purchaser_user_id, organization_id)
        values (prior_replacement.new_token_hash,
          predecessor.purchaser_user_id, predecessor.organization_id);
        delete from private.google_play_token_replacements
        where old_token_hash = predecessor_hash;
      end if;
      insert into private.google_play_token_replacements
        (old_token_hash, new_token_hash, purchaser_user_id, organization_id,
         predecessor_kind)
      values (predecessor_hash, token_hash, predecessor.purchaser_user_id,
        predecessor.organization_id, predecessor_kind)
      on conflict (old_token_hash) do nothing;
    end if;
  end if;
  select * into replacement from private.google_play_token_replacements
  where new_token_hash = token_hash for update;
  if claimed_predecessor_hash is not null and (
      replacement.old_token_hash is distinct from predecessor_hash
      or replacement.predecessor_kind is distinct from predecessor_kind
    ) then
    raise exception 'Google Play abonelik bağlantısı değişti' using errcode = '23505';
  end if;
  if replacement.new_token_hash is not null and (
      replacement.purchaser_user_id is distinct from
        (p_observation->>'userId')::uuid
      or replacement.organization_id is distinct from
        (p_observation->>'organizationId')::uuid
    ) then
    raise exception 'Google Play abonelik sahibi değişti' using errcode = '23505';
  end if;
  result := public.service_record_google_play_subscription(
    token_hash, (p_observation->>'userId')::uuid,
    (p_observation->>'organizationId')::uuid,
    p_observation->>'productId', p_observation->>'basePlanId',
    p_observation->>'subscriptionState',
    p_observation->>'acknowledgementState',
    (p_observation->>'activateEntitlement')::boolean,
    (p_observation->>'verifiedAt')::timestamptz,
    (p_observation->>'expiryTime')::timestamptz,
    (p_observation->>'autoRenewEnabled')::boolean,
    (p_observation->>'isTestPurchase')::boolean,
    p_observation->>'latestOrderIdHash',
    p_observation->>'accountHash', p_observation->>'profileHash'
  );
  if replacement.new_token_hash is not null then
    select * into successor from private.google_play_subscriptions
    where purchase_token_hash = token_hash for update;
    -- A linked PENDING transaction leaves the old entitlement intact. Once
    -- Google reports a completed (non-PENDING) replacement, the old token is
    -- invalid even if the new purchase still awaits acknowledgement; that
    -- brief interval is intentionally fail-closed. An out-of-app predecessor
    -- is already expired, but a pending new purchase must remain replaceable
    -- if Google later cancels it without any successful order.
    if replacement.activated_at is not null
       or successor.subscription_state in (
         'SUBSCRIPTION_STATE_ACTIVE',
         'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
         'SUBSCRIPTION_STATE_CANCELED',
         'SUBSCRIPTION_STATE_ON_HOLD',
         'SUBSCRIPTION_STATE_PAUSED'
       )
       or (successor.subscription_state = 'SUBSCRIPTION_STATE_EXPIRED'
         and (successor.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
           or successor.latest_order_id_hash is not null)) then
      -- The core's grant gate only sees a new token if its expiry won the
      -- existing entitlement comparison. A forced replacement must satisfy
      -- the identical recent refund-sweep gate before moving the pointer.
      if successor.entitled and successor.expiry_time > now() and not exists (
        select 1 from private.google_play_void_scan_state v
        where v.singleton = true and v.page_token is null
          and v.last_completed_at > now() - interval '15 minutes'
      ) then
        raise exception 'Google Play refund scan is not current' using errcode = '55000';
      end if;
      update private.google_play_token_replacements
      set activated_at = coalesce(activated_at, now())
      where old_token_hash = replacement.old_token_hash;
      update private.google_play_subscriptions set entitled = false
      where purchase_token_hash = replacement.old_token_hash;
      update private.google_play_entitlements e
      set current_purchase_token_hash = successor.purchase_token_hash,
          purchaser_user_id = successor.purchaser_user_id,
          subscription_state = successor.subscription_state,
          entitled = successor.entitled and successor.expiry_time > now(),
          current_period_end = successor.expiry_time,
          updated_at = now()
      where e.organization_id = successor.organization_id
        and e.current_purchase_token_hash in (
          replacement.old_token_hash, successor.purchase_token_hash
        );
      if found then
        perform 1 from public.organizations
        where id = successor.organization_id for update;
        select max(activated_until) into web_until
        from public.web_payment_notifications
        where organization_id = successor.organization_id and status = 'approved'
          and activated_until > now();
        update public.organizations
        set subscription_status = case
              when subscription_status = 'suspended' then 'suspended'
              when successor.entitled and successor.expiry_time > now() then 'active'
              when web_until > now() then 'active' else 'past_due' end,
            current_period_end = case
              when successor.entitled and successor.expiry_time > now()
                then greatest(successor.expiry_time, coalesce(web_until,
                  successor.expiry_time))
              when web_until > now() then web_until
              else coalesce(successor.expiry_time, now()) end,
            updated_at = now()
        where id = successor.organization_id;
      end if;
    end if;
  end if;
  insert into private.google_play_token_vault
    (purchase_token_hash, token_ciphertext, token_nonce, key_version,
     reconcile_after, failure_count, last_success_at, updated_at)
  values (token_hash, p_token_ciphertext, p_token_nonce, 1,
    now() + interval '6 hours', 0, now(), now())
  on conflict (purchase_token_hash) do update
  set token_ciphertext = excluded.token_ciphertext,
      token_nonce = excluded.token_nonce,
      key_version = 1,
      reconcile_after = excluded.reconcile_after,
      failure_count = 0, last_success_at = now(), updated_at = now();
  select jsonb_build_object(
    'entitled', coalesce(e.entitled and e.current_period_end > now()
      and o.subscription_status <> 'suspended', false),
    'subscriptionStatus', o.subscription_status,
    'currentPeriodEnd', o.current_period_end
  ) into result
  from public.organizations o
  left join private.google_play_entitlements e on e.organization_id = o.id
  where o.id = (p_observation->>'organizationId')::uuid;
  return result;
end;
$$;

create function public.service_record_google_play_void(
  p_token_hash text, p_order_hash text, p_event_time timestamptz
) returns boolean language plpgsql security definer set search_path = '' as $$
declare subscription private.google_play_subscriptions;
declare web_until timestamptz;
begin
  if p_token_hash is null or p_token_hash !~ '^[a-f0-9]{64}$'
    or p_order_hash is null or p_order_hash !~ '^[a-f0-9]{64}$'
    or p_event_time is null or p_event_time > now() + interval '1 day' then
    raise exception 'Geçersiz iade bildirimi' using errcode = '22023';
  end if;
  select * into subscription from private.google_play_subscriptions
  where purchase_token_hash = p_token_hash for update;
  insert into private.google_play_voided_orders
    (purchase_token_hash, order_id_hash, event_time)
  values (p_token_hash, p_order_hash, p_event_time)
  on conflict (purchase_token_hash, order_id_hash) do nothing;
  if subscription.purchase_token_hash is null
     or subscription.latest_order_id_hash is distinct from p_order_hash then
    return false;
  end if;
  update private.google_play_subscriptions set entitled = false
  where purchase_token_hash = p_token_hash;
  update private.google_play_entitlements set entitled = false, updated_at = now()
  where current_purchase_token_hash = p_token_hash;
  if found then
    -- Match the core's subscription -> entitlement -> organization lock order.
    perform 1 from public.organizations
    where id = subscription.organization_id for update;
    select max(activated_until) into web_until from public.web_payment_notifications
    where organization_id = subscription.organization_id and status = 'approved'
      and activated_until > now();
    update public.organizations
    set subscription_status = case
          when subscription_status = 'suspended' then 'suspended'
          when web_until > now() then 'active' else 'past_due' end,
        current_period_end = case when web_until > now()
          then web_until else now() end,
        updated_at = now()
    where id = subscription.organization_id;
    return true;
  end if;
  return false;
end;
$$;

create function public.service_disable_google_play_token(
  p_token_hash text, p_user_id uuid, p_organization_id uuid
) returns boolean language plpgsql security definer set search_path = '' as $$
declare subscription private.google_play_subscriptions;
declare web_until timestamptz;
begin
  select * into subscription from private.google_play_subscriptions
  where purchase_token_hash = p_token_hash for update;
  if subscription.purchase_token_hash is null
     or subscription.purchaser_user_id <> p_user_id
     or subscription.organization_id <> p_organization_id then
    return false;
  end if;
  update private.google_play_subscriptions set entitled = false
  where purchase_token_hash = p_token_hash;
  update private.google_play_entitlements set entitled = false, updated_at = now()
  where current_purchase_token_hash = p_token_hash;
  if found then
    perform 1 from public.organizations
    where id = subscription.organization_id for update;
    select max(activated_until) into web_until from public.web_payment_notifications
    where organization_id = subscription.organization_id and status = 'approved'
      and activated_until > now();
    update public.organizations
    set subscription_status = case
          when subscription_status = 'suspended' then 'suspended'
          when web_until > now() then 'active' else 'past_due' end,
        current_period_end = case when web_until > now()
          then web_until else now() end,
        updated_at = now()
    where id = p_organization_id;
  end if;
  return true;
end;
$$;

create function public.service_claim_due_google_play_tokens(p_limit integer default 5)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare item record;
declare claimed jsonb;
declare jobs jsonb := '[]'::jsonb;
begin
  if p_limit is null or p_limit not between 1 and 10 then
    raise exception 'Geçersiz iş sınırı' using errcode = '22023';
  end if;
  for item in
    select v.purchase_token_hash, v.token_ciphertext, v.token_nonce,
      v.key_version, s.purchaser_user_id, s.organization_id
    from private.google_play_token_vault v
    join private.google_play_subscriptions s using (purchase_token_hash)
    where v.reconcile_after <= now()
      and not exists (
        select 1 from private.google_play_abandoned_tokens a
        where a.purchase_token_hash = v.purchase_token_hash
      )
    order by v.reconcile_after, v.purchase_token_hash
    limit p_limit * 3
  loop
    claimed := public.service_claim_google_play_observation(item.purchase_token_hash);
    if claimed is not null then
      update private.google_play_token_vault
      set reconcile_after = now() + interval '5 minutes', updated_at = now()
      where purchase_token_hash = item.purchase_token_hash;
      jobs := jobs || jsonb_build_array(jsonb_build_object(
        'purchaseTokenHash', item.purchase_token_hash,
        'tokenCiphertext', item.token_ciphertext,
        'tokenNonce', item.token_nonce,
        'keyVersion', item.key_version,
        'userId', item.purchaser_user_id,
        'organizationId', item.organization_id,
        'leaseId', claimed->>'leaseId',
        'generation', (claimed->>'generation')::bigint
      ));
      exit when jsonb_array_length(jobs) >= p_limit;
    end if;
  end loop;
  return jobs;
end;
$$;

create function public.service_defer_google_play_token(
  p_token_hash text, p_lease_id uuid, p_deterministic boolean default false
) returns boolean language plpgsql security definer set search_path = '' as $$
declare failures integer;
begin
  perform 1 from private.google_play_observation_leases
  where purchase_token_hash = p_token_hash and lease_id = p_lease_id for update;
  if not found then return false; end if;
  update private.google_play_token_vault
  set failure_count = failure_count + 1,
      reconcile_after = now() + case
        when p_deterministic then interval '24 hours'
        else make_interval(mins => least(360, (power(2, least(failure_count, 5)) * 5)::integer))
      end,
      updated_at = now()
  where purchase_token_hash = p_token_hash
  returning failure_count into failures;
  perform public.service_release_google_play_observation(p_token_hash, p_lease_id);
  return failures is not null;
end;
$$;

create function public.service_get_google_play_void_cursor()
returns jsonb language plpgsql security definer set search_path = '' as $$
declare state private.google_play_void_scan_state;
begin
  select * into state from private.google_play_void_scan_state where singleton = true;
  return jsonb_build_object('startTimeMillis', state.start_time_ms,
    'pageToken', state.page_token,
    'lastCompletedAt', state.last_completed_at);
end;
$$;

create function public.service_advance_google_play_void_cursor(
  p_expected_start bigint, p_expected_page text, p_next_page text
) returns boolean language plpgsql security definer set search_path = '' as $$
begin
  if p_next_page is not null and length(p_next_page) > 4096 then
    raise exception 'Geçersiz sayfa imleci' using errcode = '22023';
  end if;
  update private.google_play_void_scan_state
  set page_token = p_next_page,
      start_time_ms = case when p_next_page is null
        then (extract(epoch from now() - interval '2 days') * 1000)::bigint
        else start_time_ms end,
      last_completed_at = case when p_next_page is null then now()
        else last_completed_at end,
      updated_at = now()
  where singleton = true and start_time_ms = p_expected_start
    and page_token is not distinct from p_expected_page;
  return found;
end;
$$;

create function public.service_reset_google_play_void_cursor(
  p_expected_start bigint, p_expected_page text
) returns boolean language plpgsql security definer set search_path = '' as $$
begin
  update private.google_play_void_scan_state
  set start_time_ms = (extract(epoch from now() - interval '29 days') * 1000)::bigint,
      page_token = null, last_completed_at = null, updated_at = now()
  where singleton = true and start_time_ms = p_expected_start
    and page_token is not distinct from p_expected_page;
  return found;
end;
$$;

create function public.service_google_play_lifecycle_health()
returns jsonb language plpgsql security definer set search_path = '' as $$
declare vault_count bigint;
declare unvaulted_count bigint;
declare overdue_count bigint;
declare failed_count bigint;
declare last_void_scan timestamptz;
begin
  select count(*) into vault_count from private.google_play_token_vault;
  select count(*) into unvaulted_count from private.google_play_subscriptions s
  where not exists (select 1 from private.google_play_token_vault v
    where v.purchase_token_hash = s.purchase_token_hash);
  select count(*), count(*) filter (where failure_count > 0)
  into overdue_count, failed_count from private.google_play_token_vault
  where reconcile_after <= now();
  select last_completed_at into last_void_scan from private.google_play_void_scan_state;
  return jsonb_build_object('vaultCount', vault_count,
    'unvaultedCount', unvaulted_count,
    'overdueCount', overdue_count,
    'failedDueCount', failed_count,
    'voidLastCompletedAt', last_void_scan);
end;
$$;

revoke all on function public.service_claim_google_play_observation(text),
  public.service_release_google_play_observation(text,uuid),
  public.service_get_google_play_owner(text),
  public.service_record_google_play_subscription(
    text,uuid,uuid,text,text,text,text,boolean,timestamptz,
    timestamptz,boolean,boolean,text,text,text),
  public.service_record_google_play_observation(uuid,bigint,jsonb,text,text),
  public.service_record_google_play_void(text,text,timestamptz),
  public.service_disable_google_play_token(text,uuid,uuid),
  public.service_claim_due_google_play_tokens(integer),
  public.service_defer_google_play_token(text,uuid,boolean),
  public.service_get_google_play_void_cursor(),
  public.service_advance_google_play_void_cursor(bigint,text,text),
  public.service_reset_google_play_void_cursor(bigint,text),
  public.service_google_play_lifecycle_health()
from public, anon, authenticated, service_role;

grant execute on function public.service_claim_google_play_observation(text),
  public.service_release_google_play_observation(text,uuid),
  public.service_get_google_play_owner(text),
  public.service_record_google_play_subscription(
    text,uuid,uuid,text,text,text,text,boolean,timestamptz,
    timestamptz,boolean,boolean,text,text,text),
  public.service_record_google_play_observation(uuid,bigint,jsonb,text,text),
  public.service_record_google_play_void(text,text,timestamptz),
  public.service_disable_google_play_token(text,uuid,uuid),
  public.service_claim_due_google_play_tokens(integer),
  public.service_defer_google_play_token(text,uuid,boolean),
  public.service_get_google_play_void_cursor(),
  public.service_advance_google_play_void_cursor(bigint,text,text),
  public.service_reset_google_play_void_cursor(bigint,text),
  public.service_google_play_lifecycle_health()
to service_role;

notify pgrst, 'reload schema';
commit;
