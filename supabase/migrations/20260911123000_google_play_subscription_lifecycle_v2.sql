-- Google Play subscription lifecycle v2.
--
-- Security model:
-- * raw purchase tokens never enter an exposed schema and are AES-GCM encrypted
--   by Edge Functions before storage;
-- * every private table is FORCE RLS with no policy and no Data API grants;
-- * all service entry points are SECURITY DEFINER, validate every argument,
--   use a blank search_path, and are executable only by service_role;
-- * Publisher GETs are serialized by a durable token-hash lease carrying a
--   globally monotonic generation. This prevents a delayed response from
--   acknowledging or restoring an older lifecycle state.

begin;
set local statement_timeout = '60s';

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create sequence if not exists private.google_play_subscription_observation_generation_seq;

create table if not exists private.google_play_subscription_observation_leases (
  purchase_token_hash text primary key check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  generation bigint not null unique check (generation > 0),
  lease_id uuid not null unique,
  started_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  check (expires_at > started_at and expires_at <= started_at + interval '2 minutes')
);

create table if not exists private.google_play_purchase_intents (
  id uuid primary key default extensions.gen_random_uuid(),
  organization_id uuid not null,
  purchaser_user_id uuid not null,
  product_id text not null default 'stokdas_pro' check (product_id = 'stokdas_pro'),
  base_plan_id text not null default 'monthly' check (base_plan_id = 'monthly'),
  expected_account_id_hash text not null check (expected_account_id_hash ~ '^[a-f0-9]{64}$'),
  expected_profile_id_hash text not null check (expected_profile_id_hash ~ '^[a-f0-9]{64}$'),
  status text not null default 'active' check (status in ('active','pending','consumed','closed','expired')),
  bound_purchase_token_hash text check (
    bound_purchase_token_hash is null or bound_purchase_token_hash ~ '^[a-f0-9]{64}$'
  ),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  closed_reason text check (closed_reason is null or length(closed_reason) between 1 and 64),
  constraint google_play_purchase_intents_profile_org_fk
    foreign key (purchaser_user_id, organization_id)
    references public.profiles(id, organization_id) on delete restrict,
  constraint google_play_purchase_intents_org_fk
    foreign key (organization_id) references public.organizations(id) on delete restrict,
  check (expires_at = created_at + interval '7 days'),
  check ((status = 'consumed') = (consumed_at is not null)),
  check (status <> 'active' or bound_purchase_token_hash is null)
);

create unique index if not exists google_play_purchase_intents_one_open_org_idx
  on private.google_play_purchase_intents (organization_id)
  where status in ('active','pending');
create index if not exists google_play_purchase_intents_expiry_idx
  on private.google_play_purchase_intents (expires_at)
  where status in ('active','pending');

create table if not exists private.google_play_observation_claim_contexts (
  lease_id uuid primary key,
  purchase_token_hash text not null check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  organization_id uuid not null,
  purchaser_user_id uuid not null,
  mode text not null check (mode in ('intent','restore')),
  created_at timestamptz not null default clock_timestamp(),
  constraint google_play_claim_context_lease_fk
    foreign key (lease_id) references private.google_play_subscription_observation_leases(lease_id)
    on delete cascade,
  constraint google_play_claim_context_profile_org_fk
    foreign key (purchaser_user_id, organization_id)
    references public.profiles(id, organization_id) on delete restrict
);
create index if not exists google_play_claim_context_org_idx
  on private.google_play_observation_claim_contexts (organization_id, purchase_token_hash);

create table if not exists private.google_play_token_vault (
  purchase_token_hash text primary key check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  token_ciphertext text not null check (length(token_ciphertext) between 16 and 8192),
  token_nonce text not null check (length(token_nonce) between 16 and 64),
  key_version integer not null check (key_version > 0),
  organization_id uuid,
  purchaser_user_id uuid,
  retention_class text not null default 'normal'
    check (retention_class in ('normal','quarantine','deletion_proof')),
  first_stored_at timestamptz not null default clock_timestamp(),
  last_stored_at timestamptz not null default clock_timestamp(),
  purge_after timestamptz not null,
  check ((organization_id is null) = (purchaser_user_id is null)),
  check (purge_after > first_stored_at),
  check (
    (retention_class = 'normal' and purge_after <= last_stored_at + interval '60 days')
    or (retention_class = 'quarantine' and purge_after <= first_stored_at + interval '30 days')
    or (retention_class = 'deletion_proof' and purge_after <= first_stored_at + interval '120 days')
  )
);

create index if not exists google_play_token_vault_owner_idx
  on private.google_play_token_vault (organization_id, purchaser_user_id)
  where organization_id is not null;
create index if not exists google_play_token_vault_purge_idx
  on private.google_play_token_vault (purge_after);

create table if not exists private.google_play_subscription_quarantine (
  purchase_token_hash text primary key check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  reason text not null check (reason in (
    'unknown_token','incomplete_identity','identity_mismatch','divergent_observation',
    'expired_unbound','poison_notification','deleted_owner','linked_owner_unknown','voided_order'
  )),
  first_seen_at timestamptz not null default clock_timestamp(),
  last_seen_at timestamptz not null default clock_timestamp(),
  observation_count bigint not null default 1 check (observation_count > 0),
  last_generation bigint check (last_generation is null or last_generation > 0),
  lifecycle_fingerprint text check (
    lifecycle_fingerprint is null or lifecycle_fingerprint ~ '^[a-f0-9]{64}$'
  ),
  release_after timestamptz not null,
  check (release_after > first_seen_at and release_after <= first_seen_at + interval '30 days')
);

create table if not exists private.google_play_deleted_token_tombstones (
  purchase_token_hash text primary key check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  former_organization_hash text not null check (former_organization_hash ~ '^[a-f0-9]{64}$'),
  former_user_hash text not null check (former_user_hash ~ '^[a-f0-9]{64}$'),
  developer_stop_verified_at timestamptz,
  purchase_start_time timestamptz,
  last_subscription_state text not null,
  last_expiry_time timestamptz,
  ciphertext_purge_deadline timestamptz not null,
  created_at timestamptz not null default clock_timestamp(),
  purge_after timestamptz not null,
  check (purge_after > created_at and purge_after <= created_at + interval '120 days')
);
alter table private.google_play_deleted_token_tombstones
  add column if not exists ciphertext_purge_deadline timestamptz;

create table if not exists private.google_play_deleted_identity_tombstones (
  external_account_id_hash text not null check (external_account_id_hash ~ '^[a-f0-9]{64}$'),
  external_profile_id_hash text not null check (external_profile_id_hash ~ '^[a-f0-9]{64}$'),
  deleted_at timestamptz not null,
  purge_after timestamptz not null,
  primary key (external_account_id_hash, external_profile_id_hash),
  check (purge_after > deleted_at and purge_after <= deleted_at + interval '120 days')
);

create table if not exists private.google_play_voided_orders (
  purchase_token_hash text not null check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  order_id_hash text not null check (order_id_hash ~ '^[a-f0-9]{64}$'),
  voided_at timestamptz not null,
  first_seen_at timestamptz not null default clock_timestamp(),
  purge_after timestamptz not null,
  primary key (purchase_token_hash, order_id_hash),
  check (purge_after > first_seen_at and purge_after <= first_seen_at + interval '120 days')
);
create index if not exists google_play_voided_orders_purge_idx
  on private.google_play_voided_orders (purge_after);

create table if not exists private.google_play_notification_receipts (
  message_id text primary key check (length(message_id) between 1 and 256),
  notification_kind text not null check (notification_kind in ('subscription','voided')),
  payload_fingerprint text not null check (payload_fingerprint ~ '^[a-f0-9]{64}$'),
  received_at timestamptz not null default clock_timestamp(),
  purge_after timestamptz not null,
  check (purge_after > received_at and purge_after <= received_at + interval '120 days')
);

create table if not exists private.google_play_rtdn_inbox (
  message_id text primary key check (length(message_id) between 1 and 256),
  purchase_token_hash text not null check (purchase_token_hash ~ '^[a-f0-9]{64}$'),
  notification_type integer not null check (notification_type between 1 and 22),
  event_time timestamptz not null,
  received_at timestamptz not null default clock_timestamp(),
  next_attempt_at timestamptz not null default clock_timestamp(),
  attempt_count integer not null default 0 check (attempt_count between 0 and 1000),
  deterministic_failure_count integer not null default 0
    check (deterministic_failure_count between 0 and 3),
  state text not null default 'pending' check (state in ('pending','processing','completed','quarantined')),
  lease_id uuid,
  lease_expires_at timestamptz,
  last_error_code text check (last_error_code is null or length(last_error_code) between 1 and 64),
  completed_at timestamptz,
  check ((lease_id is null) = (lease_expires_at is null)),
  check ((state in ('completed','quarantined')) = (completed_at is not null))
);

create index if not exists google_play_rtdn_due_idx
  on private.google_play_rtdn_inbox (next_attempt_at, received_at, message_id)
  where state in ('pending','processing');
create index if not exists google_play_rtdn_token_idx
  on private.google_play_rtdn_inbox (purchase_token_hash, received_at desc);

create table if not exists private.google_play_reconcile_state (
  singleton boolean primary key default true check (singleton),
  voided_start_time_ms bigint not null default 0 check (voided_start_time_ms >= 0),
  voided_page_token text check (voided_page_token is null or length(voided_page_token) <= 4096),
  voided_scan_started_at_ms bigint check (
    voided_scan_started_at_ms is null or voided_scan_started_at_ms >= 0
  ),
  updated_at timestamptz not null default clock_timestamp()
);
alter table private.google_play_reconcile_state
  add column if not exists voided_scan_started_at_ms bigint;
insert into private.google_play_reconcile_state(singleton) values (true) on conflict do nothing;

create table if not exists private.account_deletion_request_receipts (
  request_id uuid primary key,
  subject_user_hash text not null check (subject_user_hash ~ '^[a-f0-9]{64}$'),
  organization_id uuid not null,
  scope text not null check (scope in ('account','organization')),
  state text not null check (state in ('processing','completed')),
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  purge_after timestamptz not null,
  check ((state = 'completed') = (completed_at is not null)),
  check (purge_after > created_at and purge_after <= created_at + interval '30 days')
);
create unique index if not exists account_deletion_one_processing_subject_idx
  on private.account_deletion_request_receipts (subject_user_hash)
  where state = 'processing';

create table if not exists private.organization_deletion_fences (
  organization_id uuid primary key,
  request_id uuid not null unique,
  initiator_user_id uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  billing_finalized_at timestamptz,
  check (expires_at > created_at and expires_at <= created_at + interval '30 days')
);
alter table private.organization_deletion_fences
  add column if not exists billing_finalized_at timestamptz;

create table if not exists private.account_auth_cleanup_jobs (
  user_id uuid primary key,
  request_id uuid not null,
  state text not null default 'pending' check (state in ('pending','processing','completed','quarantined')),
  attempt_count integer not null default 0 check (attempt_count between 0 and 1000),
  next_attempt_at timestamptz not null default clock_timestamp(),
  lease_id uuid,
  lease_expires_at timestamptz,
  last_error_code text check (last_error_code is null or length(last_error_code) between 1 and 64),
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  check ((lease_id is null) = (lease_expires_at is null)),
  check ((state in ('completed','quarantined')) = (completed_at is not null))
);
create index if not exists account_auth_cleanup_due_idx
  on private.account_auth_cleanup_jobs (next_attempt_at, created_at, user_id)
  where state in ('pending','processing');

alter table private.google_play_subscriptions
  add column if not exists last_observation_generation bigint not null default 0,
  add column if not exists last_lifecycle_fingerprint text,
  add column if not exists linked_purchase_token_hash text,
  add column if not exists developer_stop_verified_at timestamptz,
  add column if not exists terminal_observed_at timestamptz,
  add column if not exists last_voided_order_id_hash text,
  add column if not exists last_voided_at timestamptz,
  add column if not exists reconcile_after timestamptz not null default clock_timestamp(),
  add column if not exists reconcile_failure_count integer not null default 0;

alter table private.google_play_subscriptions
  drop constraint if exists google_play_subscriptions_last_observation_generation_check,
  add constraint google_play_subscriptions_last_observation_generation_check
    check (last_observation_generation >= 0),
  drop constraint if exists google_play_subscriptions_last_lifecycle_fingerprint_check,
  add constraint google_play_subscriptions_last_lifecycle_fingerprint_check
    check (last_lifecycle_fingerprint is null or last_lifecycle_fingerprint ~ '^[a-f0-9]{64}$'),
  drop constraint if exists google_play_subscriptions_linked_token_hash_check,
  add constraint google_play_subscriptions_linked_token_hash_check
    check (linked_purchase_token_hash is null or linked_purchase_token_hash ~ '^[a-f0-9]{64}$'),
  drop constraint if exists google_play_subscriptions_voided_order_hash_check,
  add constraint google_play_subscriptions_voided_order_hash_check
    check (last_voided_order_id_hash is null or last_voided_order_id_hash ~ '^[a-f0-9]{64}$'),
  drop constraint if exists google_play_subscriptions_void_pair_check,
  add constraint google_play_subscriptions_void_pair_check
    check ((last_voided_order_id_hash is null) = (last_voided_at is null)),
  drop constraint if exists google_play_subscriptions_reconcile_failure_count_check,
  add constraint google_play_subscriptions_reconcile_failure_count_check
    check (reconcile_failure_count between 0 and 1000);
create index if not exists google_play_subscriptions_reconcile_due_idx
  on private.google_play_subscriptions (reconcile_after, last_verified_at, purchase_token_hash);

alter table private.google_play_subscription_observation_leases enable row level security;
alter table private.google_play_subscription_observation_leases force row level security;
alter table private.google_play_purchase_intents enable row level security;
alter table private.google_play_purchase_intents force row level security;
alter table private.google_play_observation_claim_contexts enable row level security;
alter table private.google_play_observation_claim_contexts force row level security;
alter table private.google_play_token_vault enable row level security;
alter table private.google_play_token_vault force row level security;
alter table private.google_play_subscription_quarantine enable row level security;
alter table private.google_play_subscription_quarantine force row level security;
alter table private.google_play_deleted_token_tombstones enable row level security;
alter table private.google_play_deleted_token_tombstones force row level security;
alter table private.google_play_deleted_identity_tombstones enable row level security;
alter table private.google_play_deleted_identity_tombstones force row level security;
alter table private.google_play_voided_orders enable row level security;
alter table private.google_play_voided_orders force row level security;
alter table private.google_play_notification_receipts enable row level security;
alter table private.google_play_notification_receipts force row level security;
alter table private.google_play_rtdn_inbox enable row level security;
alter table private.google_play_rtdn_inbox force row level security;
alter table private.google_play_reconcile_state enable row level security;
alter table private.google_play_reconcile_state force row level security;
alter table private.account_deletion_request_receipts enable row level security;
alter table private.account_deletion_request_receipts force row level security;
alter table private.organization_deletion_fences enable row level security;
alter table private.organization_deletion_fences force row level security;
alter table private.account_auth_cleanup_jobs enable row level security;
alter table private.account_auth_cleanup_jobs force row level security;

revoke all on table private.google_play_subscription_observation_leases from public, anon, authenticated, service_role;
revoke all on table private.google_play_purchase_intents from public, anon, authenticated, service_role;
revoke all on table private.google_play_observation_claim_contexts from public, anon, authenticated, service_role;
revoke all on table private.google_play_token_vault from public, anon, authenticated, service_role;
revoke all on table private.google_play_subscription_quarantine from public, anon, authenticated, service_role;
revoke all on table private.google_play_deleted_token_tombstones from public, anon, authenticated, service_role;
revoke all on table private.google_play_deleted_identity_tombstones from public, anon, authenticated, service_role;
revoke all on table private.google_play_voided_orders from public, anon, authenticated, service_role;
revoke all on table private.google_play_notification_receipts from public, anon, authenticated, service_role;
revoke all on table private.google_play_rtdn_inbox from public, anon, authenticated, service_role;
revoke all on table private.google_play_reconcile_state from public, anon, authenticated, service_role;
revoke all on table private.account_deletion_request_receipts from public, anon, authenticated, service_role;
revoke all on table private.organization_deletion_fences from public, anon, authenticated, service_role;
revoke all on table private.account_auth_cleanup_jobs from public, anon, authenticated, service_role;
revoke all on sequence private.google_play_subscription_observation_generation_seq from public, anon, authenticated, service_role;

comment on table private.google_play_subscription_observation_leases is
  'Service-only, policy-free FORCE RLS table. Hash/opaque lease only; never exposed through Data API.';
comment on table private.google_play_token_vault is
  'Service-only encrypted Google Play token vault. Edge AES-GCM ciphertext only; bounded retention.';
comment on table private.google_play_rtdn_inbox is
  'Service-only RTDN inbox with bounded retries and durable poison-message quarantine.';
comment on table private.google_play_notification_receipts is
  'Service-only Pub/Sub message-id collision ledger; rejects divergent duplicate payloads.';

create or replace function public.service_begin_google_play_purchase_intent(
  p_user_id uuid,
  p_organization_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_intent private.google_play_purchase_intents;
  v_account_hash text;
  v_profile_hash text;
begin
  if p_user_id is null or p_organization_id is null then
    raise exception 'Geçersiz satın alma niyeti' using errcode = '22023';
  end if;

  perform 1 from public.organizations o where o.id = p_organization_id for update;
  if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
  perform 1
  from public.profiles p
  where p.id = p_user_id
    and p.organization_id = p_organization_id
    and p.role = 'admin'
    and p.is_active
    and not p.must_change_password
  for update;
  if not found then
    raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501';
  end if;
  if exists (
    select 1 from private.organization_deletion_fences f
    where f.organization_id = p_organization_id
  ) then
    raise exception 'İşletme silme işlemi devam ediyor' using errcode = '55000';
  end if;

  update private.google_play_purchase_intents
  set status = 'expired', closed_reason = 'timeout'
  where organization_id = p_organization_id
    and status in ('active','pending')
    and expires_at <= v_now;

  select * into v_intent
  from private.google_play_purchase_intents i
  where i.organization_id = p_organization_id
    and i.purchaser_user_id = p_user_id
    and i.status in ('active','pending')
    and i.expires_at > v_now
  for update;

  v_account_hash := encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex');
  v_profile_hash := encode(extensions.digest(convert_to(p_organization_id::text, 'UTF8'), 'sha256'), 'hex');

  if v_intent.id is null then
    insert into private.google_play_purchase_intents (
      organization_id, purchaser_user_id, expected_account_id_hash,
      expected_profile_id_hash, created_at, expires_at
    ) values (
      p_organization_id, p_user_id, v_account_hash, v_profile_hash,
      v_now, v_now + interval '7 days'
    ) returning * into v_intent;
  end if;

  return jsonb_build_object(
    'purchaseIntentId', v_intent.id,
    'obfuscatedAccountId', v_intent.expected_account_id_hash,
    'obfuscatedProfileId', v_intent.expected_profile_id_hash,
    'expiresAt', v_intent.expires_at
  );
end;
$$;

create or replace function public.service_claim_google_play_observation(
  p_purchase_token_hash text,
  p_mode text,
  p_user_id uuid default null,
  p_organization_id uuid default null,
  p_purchase_intent_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_intent private.google_play_purchase_intents;
  v_subscription private.google_play_subscriptions;
  v_lease private.google_play_subscription_observation_leases;
  v_generation bigint;
  v_lease_id uuid := extensions.gen_random_uuid();
  v_ownership text := 'neutral';
  v_expected_account text;
  v_expected_profile text;
begin
  if p_purchase_token_hash is null or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_mode is null or p_mode not in ('intent','restore','rtdn','reconcile','deletion') then
    raise exception 'Geçersiz Google Play gözlem isteği' using errcode = '22023';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_purchase_token_hash, 0));

  if p_mode in ('intent','restore') then
    if p_user_id is null or p_organization_id is null then
      raise exception 'Google Play gözlem sahibi eksik' using errcode = '22023';
    end if;
    perform 1 from public.organizations o where o.id = p_organization_id for update;
    if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
    perform 1
    from public.profiles p
    where p.id = p_user_id and p.organization_id = p_organization_id
      and p.role = 'admin' and p.is_active and not p.must_change_password
    for share;
    if not found then
      raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501';
    end if;
    if p_mode <> 'deletion' and exists (
      select 1 from private.organization_deletion_fences f
      where f.organization_id = p_organization_id
    ) then
      raise exception 'İşletme silme işlemi devam ediyor' using errcode = '55000';
    end if;
  elsif p_user_id is not null or p_organization_id is not null or p_purchase_intent_id is not null then
    raise exception 'Servis gözleminde istemci sahibi kullanılamaz' using errcode = '22023';
  end if;

  if p_mode = 'intent' then
    if p_purchase_intent_id is null then
      raise exception 'Satın alma niyeti gerekli' using errcode = '22023';
    end if;
    select * into v_intent
    from private.google_play_purchase_intents i
    where i.id = p_purchase_intent_id
      and i.organization_id = p_organization_id
      and i.purchaser_user_id = p_user_id
    for update;
    if v_intent.id is null
       or not (
         (v_intent.status in ('active','pending') and v_intent.expires_at > v_now)
         or (v_intent.status = 'consumed'
           and v_intent.bound_purchase_token_hash = p_purchase_token_hash)
       ) then
      raise exception 'Satın alma niyeti geçersiz veya süresi dolmuş' using errcode = '22023';
    end if;
    if v_intent.bound_purchase_token_hash is not null
       and v_intent.bound_purchase_token_hash <> p_purchase_token_hash then
      raise exception 'Satın alma niyeti başka bir tokena bağlı' using errcode = '23505';
    end if;
    select * into v_subscription
    from private.google_play_subscriptions s
    where s.purchase_token_hash = p_purchase_token_hash
    for update;
    if v_subscription.purchase_token_hash is not null and (
      v_subscription.organization_id <> p_organization_id
      or v_subscription.purchaser_user_id <> p_user_id
    ) then
      raise exception 'Google Play satın alma başka bir hesaba bağlı' using errcode = '23505';
    end if;
    if v_intent.status = 'active' then
      update private.google_play_purchase_intents set status = 'pending' where id = v_intent.id;
    end if;
    v_ownership := case when v_intent.status = 'consumed' then 'known' else 'intent' end;
    v_expected_account := v_intent.expected_account_id_hash;
    v_expected_profile := v_intent.expected_profile_id_hash;
  else
    select * into v_subscription
    from private.google_play_subscriptions s
    where s.purchase_token_hash = p_purchase_token_hash
    for update;
    if v_subscription.purchase_token_hash is not null then
      if p_mode = 'restore' and (
        v_subscription.organization_id is distinct from p_organization_id
        or v_subscription.purchaser_user_id is distinct from p_user_id
      ) then
        raise exception 'Google Play satın alma başka bir hesaba bağlı' using errcode = '23505';
      end if;
      v_ownership := 'known';
      v_expected_account := v_subscription.external_account_id_hash;
      v_expected_profile := v_subscription.external_profile_id_hash;
      perform 1 from public.organizations o where o.id = v_subscription.organization_id for update;
      if p_mode <> 'deletion' and exists (
        select 1 from private.organization_deletion_fences f
        where f.organization_id = v_subscription.organization_id
      ) then
        raise exception 'İşletme silme işlemi devam ediyor' using errcode = '55000';
      end if;
    elsif p_mode = 'deletion' then
      raise exception 'Silme doğrulaması için token kasası bulunamadı' using errcode = '55000';
    elsif p_mode = 'restore' then
      -- Unknown restore claims remain owner-neutral in the lease, but carry
      -- the caller's expected Google identifiers. Ownership can only be
      -- created after an exact, currently-entitled Publisher response.
      v_expected_account := encode(
        extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex'
      );
      v_expected_profile := encode(
        extensions.digest(convert_to(p_organization_id::text, 'UTF8'), 'sha256'), 'hex'
      );
    end if;
  end if;

  select * into v_lease
  from private.google_play_subscription_observation_leases l
  where l.purchase_token_hash = p_purchase_token_hash
  for update;
  if v_lease.purchase_token_hash is not null and v_lease.expires_at > v_now then
    raise exception 'Google Play gözlemi halen işleniyor' using errcode = '55P03';
  end if;
  if v_lease.purchase_token_hash is not null then
    delete from private.google_play_subscription_observation_leases
    where purchase_token_hash = p_purchase_token_hash;
  end if;

  v_generation := nextval('private.google_play_subscription_observation_generation_seq'::regclass);
  insert into private.google_play_subscription_observation_leases (
    purchase_token_hash, generation, lease_id, started_at, expires_at
  ) values (
    p_purchase_token_hash, v_generation, v_lease_id, v_now, v_now + interval '2 minutes'
  );
  if p_mode in ('intent','restore') then
    insert into private.google_play_observation_claim_contexts (
      lease_id, purchase_token_hash, organization_id, purchaser_user_id, mode, created_at
    ) values (
      v_lease_id, p_purchase_token_hash, p_organization_id, p_user_id, p_mode, v_now
    );
  end if;

  return jsonb_build_object(
    'leaseId', v_lease_id,
    'generation', v_generation,
    'ownership', v_ownership,
    'expectedAccountIdHash', v_expected_account,
    'expectedProfileIdHash', v_expected_profile
  );
end;
$$;

create or replace function public.service_release_google_play_observation(
  p_purchase_token_hash text,
  p_lease_id uuid,
  p_generation bigint
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_purchase_token_hash is null or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_lease_id is null or p_generation is null or p_generation <= 0 then
    raise exception 'Geçersiz Google Play gözlem kilidi' using errcode = '22023';
  end if;
  delete from private.google_play_subscription_observation_leases
  where purchase_token_hash = p_purchase_token_hash
    and lease_id = p_lease_id
    and generation = p_generation;
  return found;
end;
$$;

create or replace function private.quarantine_google_play_observation(
  p_purchase_token_hash text,
  p_reason text,
  p_generation bigint,
  p_lifecycle_fingerprint text,
  p_token_ciphertext text,
  p_token_nonce text,
  p_token_key_version integer
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
begin
  insert into private.google_play_subscription_quarantine (
    purchase_token_hash, reason, first_seen_at, last_seen_at,
    observation_count, last_generation, lifecycle_fingerprint, release_after
  ) values (
    p_purchase_token_hash, p_reason, v_now, v_now, 1, p_generation,
    p_lifecycle_fingerprint, v_now + interval '30 days'
  )
  on conflict (purchase_token_hash) do update
  set reason = excluded.reason,
      last_seen_at = excluded.last_seen_at,
      observation_count = private.google_play_subscription_quarantine.observation_count + 1,
      last_generation = nullif(greatest(
        coalesce(private.google_play_subscription_quarantine.last_generation, 0),
        coalesce(excluded.last_generation, 0)
      ), 0),
      lifecycle_fingerprint = excluded.lifecycle_fingerprint,
      release_after = least(
        private.google_play_subscription_quarantine.first_seen_at + interval '30 days',
        excluded.release_after
      );

  insert into private.google_play_token_vault (
    purchase_token_hash, token_ciphertext, token_nonce, key_version,
    retention_class, first_stored_at, last_stored_at, purge_after
  ) values (
    p_purchase_token_hash, p_token_ciphertext, p_token_nonce, p_token_key_version,
    'quarantine', v_now, v_now, v_now + interval '30 days'
  )
  on conflict (purchase_token_hash) do update
  set token_ciphertext = excluded.token_ciphertext,
      token_nonce = excluded.token_nonce,
      key_version = excluded.key_version,
      last_stored_at = excluded.last_stored_at,
      retention_class = case
        when private.google_play_token_vault.retention_class = 'deletion_proof'
          then 'deletion_proof'
        else 'quarantine'
      end,
      purge_after = case
        when private.google_play_token_vault.retention_class = 'deletion_proof'
          then private.google_play_token_vault.purge_after
        else least(
          private.google_play_token_vault.first_stored_at + interval '30 days',
          excluded.purge_after
        )
      end;
end;
$$;

revoke all on function private.quarantine_google_play_observation(
  text,text,bigint,text,text,text,integer
) from public, anon, authenticated, service_role;

create or replace function public.service_record_google_play_observation_v2(
  p_purchase_token_hash text,
  p_lease_id uuid,
  p_generation bigint,
  p_mode text,
  p_user_id uuid,
  p_organization_id uuid,
  p_purchase_intent_id uuid,
  p_identity_state text,
  p_external_account_id_hash text,
  p_external_profile_id_hash text,
  p_linked_purchase_token_hash text,
  p_purchase_start_time timestamptz,
  p_subscription_state text,
  p_acknowledgement_state text,
  p_source_verified_at timestamptz,
  p_expiry_time timestamptz,
  p_auto_renew_enabled boolean,
  p_is_test_purchase boolean,
  p_latest_order_id_hash text,
  p_lifecycle_fingerprint text,
  p_token_ciphertext text,
  p_token_nonce text,
  p_token_key_version integer
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_lease private.google_play_subscription_observation_leases;
  v_existing private.google_play_subscriptions;
  v_linked private.google_play_subscriptions;
  v_intent private.google_play_purchase_intents;
  v_entitlement private.google_play_entitlements;
  v_owner_user uuid;
  v_owner_org uuid;
  v_expected_account text;
  v_expected_profile text;
  v_identity_valid boolean := false;
  v_google_entitled boolean;
  v_order_not_voided boolean := true;
  v_derived_entitled boolean := false;
  v_prior_exact boolean := false;
  v_ack_allowed boolean := false;
  v_repeat boolean := false;
  v_disposition text := 'applied';
  v_status text;
  v_period_end timestamptz;
  v_org_entitled boolean := false;
  v_quarantine_reason text;
  v_candidate_org uuid;
  v_lock_hash text;
  v_is_superseded boolean := false;
  v_deleted_identity boolean := false;
begin
  if p_purchase_token_hash is null or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_lease_id is null or p_generation is null or p_generation <= 0
     or p_mode is null or p_mode not in ('intent','restore','rtdn','reconcile','deletion')
     or p_identity_state is null or p_identity_state not in ('exact','incomplete','mismatch','unclaimed')
     or p_subscription_state is null or p_subscription_state not in (
       'SUBSCRIPTION_STATE_PENDING','SUBSCRIPTION_STATE_ACTIVE','SUBSCRIPTION_STATE_PAUSED',
       'SUBSCRIPTION_STATE_IN_GRACE_PERIOD','SUBSCRIPTION_STATE_ON_HOLD',
       'SUBSCRIPTION_STATE_CANCELED','SUBSCRIPTION_STATE_EXPIRED',
       'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
     )
     or p_acknowledgement_state is null or p_acknowledgement_state not in (
       'ACKNOWLEDGEMENT_STATE_PENDING','ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
     )
     or p_source_verified_at is null
     or p_source_verified_at < v_now - interval '15 minutes'
     or p_source_verified_at > v_now + interval '1 minute'
     or p_is_test_purchase is null
     or p_lifecycle_fingerprint is null or p_lifecycle_fingerprint !~ '^[a-f0-9]{64}$'
     or p_token_ciphertext is null or length(p_token_ciphertext) not between 16 and 8192
     or p_token_nonce is null or length(p_token_nonce) not between 16 and 64
     or p_token_key_version is null or p_token_key_version <= 0
     or (p_latest_order_id_hash is not null and p_latest_order_id_hash !~ '^[a-f0-9]{64}$')
     or (p_linked_purchase_token_hash is not null and p_linked_purchase_token_hash !~ '^[a-f0-9]{64}$')
     or (p_purchase_start_time is not null and p_purchase_start_time > v_now + interval '10 minutes')
     or (p_external_account_id_hash is not null and p_external_account_id_hash !~ '^[a-f0-9]{64}$')
     or (p_external_profile_id_hash is not null and p_external_profile_id_hash !~ '^[a-f0-9]{64}$')
     or ((p_external_account_id_hash is null) <> (p_external_profile_id_hash is null)) then
    raise exception 'Geçersiz Google Play gözlem sonucu' using errcode = '22023';
  end if;

  for v_lock_hash in
    select distinct u.hash_value
    from unnest(array[p_purchase_token_hash, p_linked_purchase_token_hash]) as u(hash_value)
    where u.hash_value is not null order by u.hash_value
  loop
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_lock_hash, 0));
  end loop;

  select * into v_lease
  from private.google_play_subscription_observation_leases l
  where l.purchase_token_hash = p_purchase_token_hash
  for update;
  if v_lease.purchase_token_hash is null
     or v_lease.lease_id is distinct from p_lease_id
     or v_lease.generation is distinct from p_generation
     or v_lease.expires_at <= v_now then
    raise exception 'Google Play gözlem kilidi artık geçerli değil' using errcode = '55P03';
  end if;

  select * into v_existing
  from private.google_play_subscriptions s
  where s.purchase_token_hash = p_purchase_token_hash
  for update;

  if p_mode = 'intent' then
    if p_user_id is null or p_organization_id is null or p_purchase_intent_id is null then
      raise exception 'Satın alma niyeti eksik' using errcode = '22023';
    end if;
    perform 1 from public.organizations o where o.id = p_organization_id for update;
    if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
    perform 1 from public.profiles p
    where p.id = p_user_id and p.organization_id = p_organization_id
      and p.role = 'admin' and p.is_active and not p.must_change_password
    for update;
    if not found then raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501'; end if;
    select * into v_intent
    from private.google_play_purchase_intents i
    where i.id = p_purchase_intent_id
      and i.organization_id = p_organization_id
      and i.purchaser_user_id = p_user_id
    for update;
    if v_intent.id is null
       or not (
         (v_intent.status in ('active','pending') and v_intent.expires_at > v_now)
         or (v_intent.status = 'consumed'
           and v_intent.bound_purchase_token_hash = p_purchase_token_hash)
       ) then
      raise exception 'Satın alma niyeti geçersiz veya süresi dolmuş' using errcode = '22023';
    end if;
    if v_intent.bound_purchase_token_hash is not null
       and v_intent.bound_purchase_token_hash <> p_purchase_token_hash then
      raise exception 'Satın alma niyeti başka bir tokena bağlı' using errcode = '23505';
    end if;
    if v_existing.purchase_token_hash is not null and (
      v_existing.organization_id <> p_organization_id
      or v_existing.purchaser_user_id <> p_user_id
    ) then
      raise exception 'Google Play satın alma başka bir hesaba bağlı' using errcode = '23505';
    end if;
    v_owner_user := p_user_id;
    v_owner_org := p_organization_id;
    v_expected_account := v_intent.expected_account_id_hash;
    v_expected_profile := v_intent.expected_profile_id_hash;
  elsif v_existing.purchase_token_hash is not null then
    v_owner_user := v_existing.purchaser_user_id;
    v_owner_org := v_existing.organization_id;
    v_expected_account := v_existing.external_account_id_hash;
    v_expected_profile := v_existing.external_profile_id_hash;
    perform 1 from public.organizations o where o.id = v_owner_org for update;
    if p_mode = 'restore' and (
      p_user_id is distinct from v_owner_user or p_organization_id is distinct from v_owner_org
    ) then
      raise exception 'Google Play satın alma başka bir hesaba bağlı' using errcode = '23505';
    end if;
  elsif p_linked_purchase_token_hash is not null then
    select * into v_linked
    from private.google_play_subscriptions s
    where s.purchase_token_hash = p_linked_purchase_token_hash
    for update;
    if v_linked.purchase_token_hash is not null then
      if p_mode = 'restore' and (
        p_user_id is distinct from v_linked.purchaser_user_id
        or p_organization_id is distinct from v_linked.organization_id
      ) then
        raise exception 'Google Play satın alma başka bir hesaba bağlı' using errcode = '23505';
      end if;
      v_owner_user := v_linked.purchaser_user_id;
      v_owner_org := v_linked.organization_id;
      v_expected_account := v_linked.external_account_id_hash;
      v_expected_profile := v_linked.external_profile_id_hash;
      perform 1 from public.organizations o where o.id = v_owner_org for update;
    end if;
  elsif p_mode in ('rtdn','reconcile')
        and p_external_account_id_hash is not null
        and p_external_profile_id_hash is not null then
    select i.organization_id into v_candidate_org
    from private.google_play_purchase_intents i
    where i.expected_account_id_hash = p_external_account_id_hash
      and i.expected_profile_id_hash = p_external_profile_id_hash
      and i.status in ('active','pending') and i.expires_at > v_now
    limit 1;
    if v_candidate_org is not null then
      perform 1 from public.organizations o where o.id = v_candidate_org for update;
      select * into v_intent
      from private.google_play_purchase_intents i
      where i.organization_id = v_candidate_org
        and i.expected_account_id_hash = p_external_account_id_hash
        and i.expected_profile_id_hash = p_external_profile_id_hash
        and i.status in ('active','pending') and i.expires_at > v_now
      for update;
      if v_intent.id is not null and (
        v_intent.bound_purchase_token_hash is null
        or v_intent.bound_purchase_token_hash = p_purchase_token_hash
      ) then
        v_owner_user := v_intent.purchaser_user_id;
        v_owner_org := v_intent.organization_id;
        v_expected_account := v_intent.expected_account_id_hash;
        v_expected_profile := v_intent.expected_profile_id_hash;
      end if;
    end if;
  elsif p_mode = 'restore' and p_user_id is not null and p_organization_id is not null then
    v_owner_user := p_user_id;
    v_owner_org := p_organization_id;
    v_expected_account := encode(
      extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex'
    );
    v_expected_profile := encode(
      extensions.digest(convert_to(p_organization_id::text, 'UTF8'), 'sha256'), 'hex'
    );
    perform 1 from public.organizations o where o.id = v_owner_org for update;
  end if;

  if p_linked_purchase_token_hash is not null then
    if p_linked_purchase_token_hash = p_purchase_token_hash then
      raise exception 'Google Play tokenı kendisine bağlanamaz' using errcode = '22023';
    end if;
    select * into v_linked from private.google_play_subscriptions s
    where s.purchase_token_hash = p_linked_purchase_token_hash for update;
    if exists (
      with recursive chain(token_hash, parent_hash, depth) as (
        select s.purchase_token_hash, s.linked_purchase_token_hash, 1
        from private.google_play_subscriptions s
        where s.purchase_token_hash = p_linked_purchase_token_hash
        union all
        select s.purchase_token_hash, s.linked_purchase_token_hash, c.depth + 1
        from chain c
        join private.google_play_subscriptions s on s.purchase_token_hash = c.parent_hash
        where c.depth < 100
      )
      select 1 from chain where token_hash = p_purchase_token_hash
    ) then
      raise exception 'Google Play token bağlantı döngüsü' using errcode = '22023';
    end if;
    if v_linked.purchase_token_hash is null then
      -- A locally unseen predecessor must not erase an owner established by an
      -- exact current intent/restore or atomically-correlated RTDN identity.
      -- If the predecessor appears later, the owner comparison below fences a
      -- cross-account chain before either token can replace entitlement.
      if v_owner_user is null
         or p_external_account_id_hash is distinct from v_expected_account
         or p_external_profile_id_hash is distinct from v_expected_profile
         or p_identity_state = 'mismatch' then
        v_owner_user := null;
        v_owner_org := null;
      end if;
    elsif v_owner_user is null then
      v_owner_user := v_linked.purchaser_user_id;
      v_owner_org := v_linked.organization_id;
      v_expected_account := v_linked.external_account_id_hash;
      v_expected_profile := v_linked.external_profile_id_hash;
      perform 1 from public.organizations o where o.id = v_owner_org for update;
    elsif v_linked.purchaser_user_id <> v_owner_user
       or v_linked.organization_id <> v_owner_org then
      raise exception 'Bağlantılı Google Play satın alma sahibi eşleşmiyor' using errcode = '23505';
    end if;
  end if;

  if v_owner_user is null
     and p_external_account_id_hash is not null
     and p_external_profile_id_hash is not null then
    v_deleted_identity := exists (
      select 1 from private.google_play_deleted_identity_tombstones d
      where d.external_account_id_hash = p_external_account_id_hash
        and d.external_profile_id_hash = p_external_profile_id_hash
        and d.purge_after > v_now
    );
    if v_deleted_identity then
      insert into private.google_play_deleted_token_tombstones (
        purchase_token_hash, former_organization_hash, former_user_hash,
        developer_stop_verified_at, purchase_start_time, last_subscription_state,
        last_expiry_time, ciphertext_purge_deadline, created_at, purge_after
      ) values (
        p_purchase_token_hash, p_external_profile_id_hash, p_external_account_id_hash,
        null, p_purchase_start_time, p_subscription_state, p_expiry_time,
        v_now + interval '30 days', v_now, v_now + interval '120 days'
      ) on conflict (purchase_token_hash) do update
      set last_subscription_state = excluded.last_subscription_state,
          last_expiry_time = excluded.last_expiry_time,
          purchase_start_time = coalesce(
            private.google_play_deleted_token_tombstones.purchase_start_time,
            excluded.purchase_start_time
          ),
          ciphertext_purge_deadline = least(
            private.google_play_deleted_token_tombstones.ciphertext_purge_deadline,
            excluded.ciphertext_purge_deadline
          );
    end if;
  end if;

  v_identity_valid := v_owner_user is not null
    and p_external_account_id_hash is not distinct from v_expected_account
    and p_external_profile_id_hash is not distinct from v_expected_profile
    and p_identity_state <> 'mismatch';

  if v_owner_org is not null and p_mode <> 'deletion' and exists (
    select 1 from private.organization_deletion_fences f
    where f.organization_id = v_owner_org
  ) then
    raise exception 'İşletme silme işlemi devam ediyor' using errcode = '55000';
  end if;

  -- The explicit intent is authoritative only after Google's concrete
  -- identifiers match. An arbitrary token hash is never bound before this.
  if p_mode = 'intent' and p_identity_state <> 'exact' then
    v_identity_valid := false;
  end if;

  v_google_entitled := p_subscription_state in (
      'SUBSCRIPTION_STATE_ACTIVE','SUBSCRIPTION_STATE_IN_GRACE_PERIOD','SUBSCRIPTION_STATE_CANCELED'
    ) and coalesce(p_expiry_time, '-infinity'::timestamptz) > v_now
    and p_latest_order_id_hash is not null;

  v_order_not_voided := not exists (
    select 1 from private.google_play_voided_orders vo
    where vo.purchase_token_hash = p_purchase_token_hash
      and (
        p_latest_order_id_hash is null
        or vo.order_id_hash = p_latest_order_id_hash
      )
  );

  if v_identity_valid and v_google_entitled and v_order_not_voided and v_intent.id is not null then
    update private.google_play_purchase_intents
    set bound_purchase_token_hash = p_purchase_token_hash, status = 'pending'
    where id = v_intent.id
      and status in ('active','pending')
      and (bound_purchase_token_hash is null or bound_purchase_token_hash = p_purchase_token_hash);
    if not found and v_intent.status <> 'consumed' then
      raise exception 'Satın alma niyeti token eşleşmesi değişti' using errcode = '23505';
    end if;
  end if;

  if not v_identity_valid then
    v_quarantine_reason := case
      when p_identity_state = 'mismatch' then 'identity_mismatch'
      when p_identity_state = 'incomplete' then 'incomplete_identity'
      when v_deleted_identity then 'deleted_owner'
      when p_linked_purchase_token_hash is not null then 'linked_owner_unknown'
      else 'unknown_token'
    end;
    perform private.quarantine_google_play_observation(
      p_purchase_token_hash, v_quarantine_reason, p_generation,
      p_lifecycle_fingerprint, p_token_ciphertext, p_token_nonce, p_token_key_version
    );
    if v_existing.purchase_token_hash is not null then
      update private.google_play_subscriptions
      set entitled = false, last_verified_at = v_now
      where purchase_token_hash = p_purchase_token_hash;
      update private.google_play_entitlements
      set entitled = false, updated_at = v_now
      where current_purchase_token_hash = p_purchase_token_hash;
      if found then
        update public.organizations o
        set subscription_status = case
              when o.administratively_suspended_at is not null then 'suspended'
              when o.platform_entitlement_until > v_now then 'active'
              else 'past_due'
            end,
            current_period_end = case
              when o.platform_entitlement_until > v_now
                then greatest(coalesce(o.current_period_end, '-infinity'::timestamptz), o.platform_entitlement_until)
              else o.current_period_end
            end,
            updated_at = v_now
        where o.id = v_existing.organization_id;
      end if;
    end if;
    if p_mode = 'intent' and p_identity_state = 'mismatch' then
      update private.google_play_purchase_intents
      set status = 'closed', closed_reason = 'identity_mismatch'
      where id = p_purchase_intent_id and status in ('active','pending');
    end if;
    v_disposition := 'quarantined';
  elsif not v_order_not_voided then
    perform private.quarantine_google_play_observation(
      p_purchase_token_hash, 'voided_order', p_generation,
      p_lifecycle_fingerprint, p_token_ciphertext, p_token_nonce, p_token_key_version
    );
    v_disposition := 'quarantined';
  elsif v_existing.purchase_token_hash is null
        and not v_google_entitled
        and p_mode <> 'deletion' then
    -- An expired/unentitled external identity cannot bootstrap ownership or
    -- occupy a user's token namespace.
    perform private.quarantine_google_play_observation(
      p_purchase_token_hash, 'expired_unbound', p_generation,
      p_lifecycle_fingerprint, p_token_ciphertext, p_token_nonce, p_token_key_version
    );
    v_disposition := 'quarantined';
  else
    if v_existing.purchase_token_hash is not null
       and v_existing.last_observation_generation > p_generation then
      v_disposition := 'stale';
    elsif v_existing.purchase_token_hash is not null
       and v_existing.last_observation_generation = p_generation
       and v_existing.last_lifecycle_fingerprint is distinct from p_lifecycle_fingerprint then
      perform private.quarantine_google_play_observation(
        p_purchase_token_hash, 'divergent_observation', p_generation,
        p_lifecycle_fingerprint, p_token_ciphertext, p_token_nonce, p_token_key_version
      );
      update private.google_play_subscriptions
      set entitled = false, auto_renew_enabled = false, last_verified_at = v_now
      where purchase_token_hash = p_purchase_token_hash;
      update private.google_play_entitlements
      set entitled = false, subscription_state = p_subscription_state, updated_at = v_now
      where current_purchase_token_hash = p_purchase_token_hash;
      if found then
        update public.organizations o
        set subscription_status = case
              when o.administratively_suspended_at is not null then 'suspended'
              when o.platform_entitlement_until > v_now then 'active'
              else 'past_due'
            end,
            current_period_end = case
              when o.platform_entitlement_until > v_now
                then greatest(coalesce(o.current_period_end, '-infinity'::timestamptz), o.platform_entitlement_until)
              else o.current_period_end
            end,
            updated_at = v_now
        where o.id = v_owner_org;
      end if;
      v_disposition := 'quarantined';
    else
      v_prior_exact := v_existing.purchase_token_hash is not null
        and v_existing.last_observation_generation > 0
        and v_existing.last_observation_generation < p_generation
        and v_existing.last_lifecycle_fingerprint is not distinct from p_lifecycle_fingerprint
        and v_existing.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_PENDING';

      insert into private.google_play_subscriptions (
        purchase_token_hash, organization_id, purchaser_user_id, product_id, base_plan_id,
        subscription_state, acknowledgement_state, source_verified_at, expiry_time,
        auto_renew_enabled, is_test_purchase, latest_order_id_hash,
        external_account_id_hash, external_profile_id_hash, entitled, acknowledged_at,
        first_verified_at, last_verified_at, verification_count,
        last_observation_generation, last_lifecycle_fingerprint, linked_purchase_token_hash,
        terminal_observed_at, developer_stop_verified_at, reconcile_after, reconcile_failure_count
      ) values (
        p_purchase_token_hash, v_owner_org, v_owner_user, 'stokdas_pro', 'monthly',
        p_subscription_state, p_acknowledgement_state, p_source_verified_at, p_expiry_time,
        p_auto_renew_enabled, p_is_test_purchase, p_latest_order_id_hash,
        v_expected_account, v_expected_profile, false,
        case when p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED' then v_now end,
        v_now, v_now, 1, p_generation, p_lifecycle_fingerprint,
        p_linked_purchase_token_hash,
        case when p_subscription_state in ('SUBSCRIPTION_STATE_EXPIRED','SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED')
          then v_now end,
        case when p_mode = 'deletion' and p_auto_renew_enabled is false then v_now end
        , v_now + case
            when p_subscription_state in ('SUBSCRIPTION_STATE_EXPIRED','SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED')
              then interval '24 hours'
            else interval '6 hours'
          end,
        0
      )
      on conflict (purchase_token_hash) do update
      set subscription_state = excluded.subscription_state,
          acknowledgement_state = case
            when private.google_play_subscriptions.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
              then 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
            else excluded.acknowledgement_state
          end,
          source_verified_at = greatest(private.google_play_subscriptions.source_verified_at, excluded.source_verified_at),
          expiry_time = excluded.expiry_time,
          auto_renew_enabled = excluded.auto_renew_enabled,
          is_test_purchase = excluded.is_test_purchase,
          latest_order_id_hash = coalesce(excluded.latest_order_id_hash, private.google_play_subscriptions.latest_order_id_hash),
          linked_purchase_token_hash = coalesce(excluded.linked_purchase_token_hash, private.google_play_subscriptions.linked_purchase_token_hash),
          acknowledged_at = case
            when excluded.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
              then coalesce(private.google_play_subscriptions.acknowledged_at, v_now)
            else private.google_play_subscriptions.acknowledged_at
          end,
          last_verified_at = v_now,
          verification_count = private.google_play_subscriptions.verification_count + 1,
          last_observation_generation = greatest(
            private.google_play_subscriptions.last_observation_generation,
            excluded.last_observation_generation
          ),
          last_lifecycle_fingerprint = case
            when excluded.last_observation_generation >= private.google_play_subscriptions.last_observation_generation
              then excluded.last_lifecycle_fingerprint
            else private.google_play_subscriptions.last_lifecycle_fingerprint
          end,
          terminal_observed_at = case
            when excluded.subscription_state in ('SUBSCRIPTION_STATE_EXPIRED','SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED')
              then coalesce(private.google_play_subscriptions.terminal_observed_at, v_now)
            else null
          end,
          developer_stop_verified_at = case
            when p_mode = 'deletion' and excluded.auto_renew_enabled is false then v_now
            else private.google_play_subscriptions.developer_stop_verified_at
          end,
          reconcile_after = excluded.reconcile_after,
          reconcile_failure_count = 0;

      select * into v_existing
      from private.google_play_subscriptions s
      where s.purchase_token_hash = p_purchase_token_hash
      for update;

      v_order_not_voided := not exists (
        select 1 from private.google_play_voided_orders vo
        where vo.purchase_token_hash = p_purchase_token_hash
          and (
            p_latest_order_id_hash is null
            or vo.order_id_hash = p_latest_order_id_hash
          )
      );
      v_is_superseded := exists (
        select 1 from private.google_play_subscriptions child
        where child.linked_purchase_token_hash = p_purchase_token_hash
          and child.organization_id = v_owner_org
          and child.purchaser_user_id = v_owner_user
      );

      v_ack_allowed := p_mode <> 'deletion'
        and p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_PENDING'
        and v_google_entitled and v_order_not_voided and v_prior_exact
        and v_lease.expires_at > v_now + interval '30 seconds';
      v_repeat := p_mode <> 'deletion'
        and p_acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_PENDING'
        and v_google_entitled and v_order_not_voided and not v_prior_exact;
      v_derived_entitled := v_google_entitled
        and v_order_not_voided
        and not v_is_superseded
        and v_existing.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED';

      update private.google_play_subscriptions
      set entitled = v_derived_entitled
      where purchase_token_hash = p_purchase_token_hash;

      insert into private.google_play_token_vault (
        purchase_token_hash, token_ciphertext, token_nonce, key_version,
        organization_id, purchaser_user_id, retention_class,
        first_stored_at, last_stored_at, purge_after
      ) values (
        p_purchase_token_hash, p_token_ciphertext, p_token_nonce, p_token_key_version,
        v_owner_org, v_owner_user, 'normal', v_now, v_now,
        case when v_existing.terminal_observed_at is not null
          then v_existing.terminal_observed_at + interval '60 days'
          else v_now + interval '60 days' end
      )
      on conflict (purchase_token_hash) do update
      set token_ciphertext = excluded.token_ciphertext,
          token_nonce = excluded.token_nonce,
          key_version = excluded.key_version,
          organization_id = excluded.organization_id,
          purchaser_user_id = excluded.purchaser_user_id,
          retention_class = 'normal',
          last_stored_at = v_now,
          purge_after = case
            when v_existing.terminal_observed_at is not null then least(
              private.google_play_token_vault.purge_after,
              v_existing.terminal_observed_at + interval '60 days'
            )
            else v_now + interval '60 days'
          end;

      delete from private.google_play_subscription_quarantine
      where purchase_token_hash = p_purchase_token_hash;

      if v_derived_entitled then
        insert into private.google_play_entitlements (
          organization_id, current_purchase_token_hash, purchaser_user_id,
          product_id, base_plan_id, subscription_state, entitled, current_period_end, updated_at
        ) values (
          v_owner_org, p_purchase_token_hash, v_owner_user, 'stokdas_pro', 'monthly',
          p_subscription_state, true, p_expiry_time, v_now
        )
        on conflict (organization_id) do update
        set current_purchase_token_hash = excluded.current_purchase_token_hash,
            purchaser_user_id = excluded.purchaser_user_id,
            subscription_state = excluded.subscription_state,
            entitled = true,
            current_period_end = excluded.current_period_end,
            updated_at = v_now
        where private.google_play_entitlements.current_purchase_token_hash = p_purchase_token_hash
           or p_linked_purchase_token_hash = private.google_play_entitlements.current_purchase_token_hash
           or not private.google_play_entitlements.entitled
           or private.google_play_entitlements.current_period_end is null
           or excluded.current_period_end > private.google_play_entitlements.current_period_end;

        update public.organizations o
        set subscription_status = case
              when o.administratively_suspended_at is not null then 'suspended'
              else 'active'
            end,
            trial_ends_at = null,
            current_period_end = greatest(
              coalesce(o.current_period_end, '-infinity'::timestamptz),
              p_expiry_time,
              coalesce(o.platform_entitlement_until, '-infinity'::timestamptz)
            ),
            updated_at = v_now
        where o.id = v_owner_org;
      else
        select * into v_entitlement
        from private.google_play_entitlements e
        where e.organization_id = v_owner_org
        for update;
        if v_entitlement.current_purchase_token_hash = p_purchase_token_hash then
          update private.google_play_entitlements
          set subscription_state = p_subscription_state,
              entitled = false,
              current_period_end = p_expiry_time,
              updated_at = v_now
          where organization_id = v_owner_org;
          update public.organizations o
          set subscription_status = case
                when o.administratively_suspended_at is not null then 'suspended'
                when o.platform_entitlement_until > v_now then 'active'
                when p_subscription_state in ('SUBSCRIPTION_STATE_ON_HOLD','SUBSCRIPTION_STATE_PAUSED','SUBSCRIPTION_STATE_PENDING') then 'past_due'
                else 'canceled'
              end,
              current_period_end = case
                when o.platform_entitlement_until > v_now
                  then greatest(coalesce(p_expiry_time, '-infinity'::timestamptz), o.platform_entitlement_until)
                else p_expiry_time
              end,
              updated_at = v_now
          where o.id = v_owner_org;
        end if;
      end if;

      if v_intent.id is null and v_owner_org is not null then
        select * into v_intent
        from private.google_play_purchase_intents i
        where i.organization_id = v_owner_org
          and i.purchaser_user_id = v_owner_user
          and i.bound_purchase_token_hash = p_purchase_token_hash
          and i.status = 'pending'
        for update;
      end if;
      if v_intent.id is not null
         and v_existing.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED'
         and v_derived_entitled and v_order_not_voided then
        update private.google_play_purchase_intents
        set status = 'consumed', bound_purchase_token_hash = p_purchase_token_hash,
            consumed_at = v_now, closed_reason = null
        where id = v_intent.id and status in ('active','pending');
      end if;
    end if;
  end if;

  if v_owner_org is not null then
    select o.subscription_status, o.current_period_end
      into v_status, v_period_end
    from public.organizations o where o.id = v_owner_org;
    select coalesce(e.entitled and coalesce(e.current_period_end, '-infinity'::timestamptz) > v_now, false)
      into v_org_entitled
    from private.google_play_entitlements e where e.organization_id = v_owner_org;
    v_org_entitled := coalesce(v_org_entitled, false) and v_status <> 'suspended';
  else
    v_status := 'canceled';
    v_period_end := null;
  end if;

  return jsonb_build_object(
    'entitled', v_org_entitled,
    'subscriptionStatus', coalesce(v_status, 'canceled'),
    'currentPeriodEnd', v_period_end,
    'acknowledged', coalesce(v_existing.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED', false),
    'ackAllowed', v_ack_allowed,
    'repeatObservation', v_repeat,
    'disposition', v_disposition,
    'intentConsumed', case when p_mode = 'intent' then exists (
      select 1 from private.google_play_purchase_intents i
      where i.id = p_purchase_intent_id and i.status = 'consumed'
        and i.bound_purchase_token_hash = p_purchase_token_hash
    ) else false end,
    'intentClosed', case when p_mode = 'intent' then exists (
      select 1 from private.google_play_purchase_intents i
      where i.id = p_purchase_intent_id and i.status in ('closed','expired')
    ) else false end,
    'deletedOwnerDetected', v_deleted_identity
  );
end;
$$;

create or replace function public.service_enqueue_google_play_rtdn(
  p_message_id text,
  p_purchase_token_hash text,
  p_notification_type integer,
  p_event_time timestamptz,
  p_token_ciphertext text,
  p_token_nonce text,
  p_token_key_version integer
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_state text;
  v_deleted boolean;
  v_payload_fingerprint text;
  v_existing_fingerprint text;
  v_existing_kind text;
  v_tombstone_deadline timestamptz;
  v_ciphertext_deadline timestamptz;
begin
  if p_message_id is null or length(p_message_id) not between 1 and 256
     or p_purchase_token_hash is null or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_notification_type is null or p_notification_type not between 1 and 22
     or p_event_time is null or p_event_time < v_now - interval '120 days'
     or p_event_time > v_now + interval '10 minutes'
     or p_token_ciphertext is null or length(p_token_ciphertext) not between 16 and 8192
     or p_token_nonce is null or length(p_token_nonce) not between 16 and 64
     or p_token_key_version is null or p_token_key_version <= 0 then
    raise exception 'Geçersiz RTDN bildirimi' using errcode = '22023';
  end if;

  v_payload_fingerprint := encode(extensions.digest(convert_to(
    pg_catalog.concat_ws('|', 'subscription', p_purchase_token_hash,
      p_notification_type::text, p_event_time::text), 'UTF8'
  ), 'sha256'), 'hex');
  insert into private.google_play_notification_receipts (
    message_id, notification_kind, payload_fingerprint, received_at, purge_after
  ) values (
    p_message_id, 'subscription', v_payload_fingerprint, v_now, v_now + interval '120 days'
  ) on conflict (message_id) do nothing;
  select r.notification_kind, r.payload_fingerprint
    into v_existing_kind, v_existing_fingerprint
  from private.google_play_notification_receipts r
  where r.message_id = p_message_id for update;
  if v_existing_kind is distinct from 'subscription'
     or v_existing_fingerprint is distinct from v_payload_fingerprint then
    raise exception 'Pub/Sub mesaj kimliği farklı içerikle yeniden kullanıldı' using errcode = '23505';
  end if;

  select t.purge_after, coalesce(
      t.ciphertext_purge_deadline,
      least(t.created_at + interval '120 days', v_now + interval '30 days')
    )
    into v_tombstone_deadline, v_ciphertext_deadline
  from private.google_play_deleted_token_tombstones t
  where t.purchase_token_hash = p_purchase_token_hash and t.purge_after > v_now;
  v_deleted := v_tombstone_deadline is not null;

  if v_deleted and v_ciphertext_deadline <= v_now then
    insert into private.google_play_rtdn_inbox (
      message_id, purchase_token_hash, notification_type, event_time,
      received_at, next_attempt_at, state, completed_at
    ) values (
      p_message_id, p_purchase_token_hash, p_notification_type, p_event_time,
      v_now, v_now, 'completed', v_now
    ) on conflict (message_id) do nothing;
    return jsonb_build_object('accepted', true, 'state', 'completed', 'deletedOwner', true);
  end if;

  insert into private.google_play_token_vault (
    purchase_token_hash, token_ciphertext, token_nonce, key_version,
    retention_class, first_stored_at, last_stored_at, purge_after
  ) values (
    p_purchase_token_hash, p_token_ciphertext, p_token_nonce, p_token_key_version,
    case when v_deleted then 'deletion_proof' else 'quarantine' end,
    v_now, v_now,
    case when v_deleted then least(v_now + interval '30 days', v_ciphertext_deadline)
      else v_now + interval '30 days' end
  )
  on conflict (purchase_token_hash) do update
  set token_ciphertext = excluded.token_ciphertext,
      token_nonce = excluded.token_nonce,
      key_version = excluded.key_version,
      last_stored_at = v_now,
      retention_class = case
        when v_deleted then 'deletion_proof'
        else private.google_play_token_vault.retention_class
      end,
      purge_after = least(
        case
          when v_deleted then v_ciphertext_deadline
          when private.google_play_token_vault.retention_class = 'deletion_proof'
            then private.google_play_token_vault.first_stored_at + interval '120 days'
          when private.google_play_token_vault.retention_class = 'quarantine'
            then private.google_play_token_vault.first_stored_at + interval '30 days'
          else v_now + interval '60 days'
        end,
        case
          when private.google_play_token_vault.retention_class = 'normal'
            then v_now + interval '60 days'
          else v_now + interval '30 days'
        end
      );

  insert into private.google_play_rtdn_inbox (
    message_id, purchase_token_hash, notification_type, event_time,
    received_at, next_attempt_at, state
  ) values (
    p_message_id, p_purchase_token_hash, p_notification_type, p_event_time,
    v_now, v_now, 'pending'
  ) on conflict (message_id) do nothing;

  select state into v_state from private.google_play_rtdn_inbox where message_id = p_message_id;
  return jsonb_build_object('accepted', true, 'state', v_state, 'deletedOwner', v_deleted);
end;
$$;

create or replace function public.service_record_google_play_voided_notification(
  p_message_id text,
  p_purchase_token_hash text,
  p_order_id_hash text,
  p_event_time timestamptz,
  p_token_ciphertext text,
  p_token_nonce text,
  p_token_key_version integer
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_sub private.google_play_subscriptions;
  v_deleted boolean;
  v_payload_fingerprint text;
  v_existing_fingerprint text;
  v_existing_kind text;
  v_current_entitlement_count integer;
  v_tombstone_deadline timestamptz;
  v_ciphertext_deadline timestamptz;
begin
  if p_message_id is null or length(p_message_id) not between 1 and 256
     or p_purchase_token_hash is null or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_order_id_hash is null or p_order_id_hash !~ '^[a-f0-9]{64}$'
     or p_event_time is null or p_event_time < v_now - interval '120 days'
     or p_event_time > v_now + interval '10 minutes'
     or p_token_ciphertext is null or length(p_token_ciphertext) not between 16 and 8192
     or p_token_nonce is null or length(p_token_nonce) not between 16 and 64
     or p_token_key_version is null or p_token_key_version <= 0 then
    raise exception 'Geçersiz voided purchase bildirimi' using errcode = '22023';
  end if;
  v_payload_fingerprint := encode(extensions.digest(convert_to(
    pg_catalog.concat_ws('|', 'voided', p_purchase_token_hash,
      p_order_id_hash, p_event_time::text), 'UTF8'
  ), 'sha256'), 'hex');
  insert into private.google_play_notification_receipts (
    message_id, notification_kind, payload_fingerprint, received_at, purge_after
  ) values (
    p_message_id, 'voided', v_payload_fingerprint, v_now, v_now + interval '120 days'
  ) on conflict (message_id) do nothing;
  select r.notification_kind, r.payload_fingerprint
    into v_existing_kind, v_existing_fingerprint
  from private.google_play_notification_receipts r
  where r.message_id = p_message_id for update;
  if v_existing_kind is distinct from 'voided'
     or v_existing_fingerprint is distinct from v_payload_fingerprint then
    raise exception 'Pub/Sub mesaj kimliği farklı içerikle yeniden kullanıldı' using errcode = '23505';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_purchase_token_hash, 0));
  insert into private.google_play_voided_orders (
    purchase_token_hash, order_id_hash, voided_at, first_seen_at, purge_after
  ) values (
    p_purchase_token_hash, p_order_id_hash, p_event_time, v_now, v_now + interval '120 days'
  ) on conflict (purchase_token_hash, order_id_hash) do update
    set voided_at = greatest(private.google_play_voided_orders.voided_at, excluded.voided_at),
        purge_after = least(
          private.google_play_voided_orders.first_seen_at + interval '120 days',
          greatest(private.google_play_voided_orders.purge_after, excluded.purge_after)
        );
  select * into v_sub from private.google_play_subscriptions s
  where s.purchase_token_hash = p_purchase_token_hash for update;
  select t.purge_after, coalesce(
      t.ciphertext_purge_deadline,
      least(t.created_at + interval '120 days', v_now + interval '30 days')
    )
    into v_tombstone_deadline, v_ciphertext_deadline
  from private.google_play_deleted_token_tombstones t
  where t.purchase_token_hash = p_purchase_token_hash and t.purge_after > v_now;
  v_deleted := v_tombstone_deadline is not null;

  if v_sub.purchase_token_hash is not null then
    perform 1 from public.organizations o where o.id = v_sub.organization_id for update;
    if v_sub.latest_order_id_hash is not distinct from p_order_id_hash
       and (v_sub.last_voided_at is null or p_event_time >= v_sub.last_voided_at) then
      update private.google_play_subscriptions
      set last_voided_order_id_hash = p_order_id_hash,
          last_voided_at = p_event_time,
          entitled = false,
          last_verified_at = v_now
      where purchase_token_hash = p_purchase_token_hash;
      update private.google_play_entitlements
      set entitled = false, subscription_state = 'SUBSCRIPTION_STATE_CANCELED', updated_at = v_now
      where current_purchase_token_hash = p_purchase_token_hash;
      get diagnostics v_current_entitlement_count = row_count;
      if v_current_entitlement_count > 0 then
        update public.organizations o
        set subscription_status = case
              when o.administratively_suspended_at is not null then 'suspended'
              when o.platform_entitlement_until > v_now then 'active'
              else 'canceled'
            end,
            current_period_end = case
              when o.platform_entitlement_until > v_now
                then greatest(coalesce(o.current_period_end, '-infinity'::timestamptz), o.platform_entitlement_until)
              else o.current_period_end
            end,
            updated_at = v_now
        where o.id = v_sub.organization_id;
      end if;
    end if;
  elsif not v_deleted then
    perform private.quarantine_google_play_observation(
      p_purchase_token_hash, 'unknown_token', null, p_order_id_hash,
      p_token_ciphertext, p_token_nonce, p_token_key_version
    );
  end if;

  if v_deleted and v_ciphertext_deadline <= v_now then
    return jsonb_build_object(
      'knownOwner', v_sub.purchase_token_hash is not null,
      'deletedOwner', true
    );
  end if;

  insert into private.google_play_token_vault (
    purchase_token_hash, token_ciphertext, token_nonce, key_version,
    organization_id, purchaser_user_id, retention_class,
    first_stored_at, last_stored_at, purge_after
  ) values (
    p_purchase_token_hash, p_token_ciphertext, p_token_nonce, p_token_key_version,
    v_sub.organization_id, v_sub.purchaser_user_id,
    case when v_deleted then 'deletion_proof' when v_sub.purchase_token_hash is null then 'quarantine' else 'normal' end,
    v_now, v_now, case
      when v_deleted then least(v_now + interval '30 days', v_ciphertext_deadline)
      when v_sub.purchase_token_hash is null then v_now + interval '30 days'
      else v_now + interval '60 days'
    end
  ) on conflict (purchase_token_hash) do update
  set token_ciphertext = excluded.token_ciphertext,
      token_nonce = excluded.token_nonce,
      key_version = excluded.key_version,
      last_stored_at = v_now,
      purge_after = least(
        case when v_deleted then v_ciphertext_deadline
          when private.google_play_token_vault.retention_class in ('quarantine','deletion_proof')
          then private.google_play_token_vault.first_stored_at +
            case when private.google_play_token_vault.retention_class = 'quarantine' then interval '30 days' else interval '120 days' end
          else v_now + interval '60 days' end,
        case when private.google_play_token_vault.retention_class = 'normal' then v_now + interval '60 days' else v_now + interval '30 days' end
      );

  return jsonb_build_object(
    'knownOwner', v_sub.purchase_token_hash is not null,
    'deletedOwner', v_deleted
  );
end;
$$;

create or replace function public.service_claim_due_google_play_rtdn(p_limit integer default 10)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_rows jsonb;
begin
  if p_limit is null or p_limit not between 1 and 50 then
    raise exception 'Geçersiz RTDN iş sayısı' using errcode = '22023';
  end if;

  update private.google_play_rtdn_inbox
  set state = 'pending', lease_id = null, lease_expires_at = null,
      next_attempt_at = least(next_attempt_at, v_now)
  where state = 'processing' and lease_expires_at <= v_now;

  update private.google_play_rtdn_inbox i
  set state = 'quarantined', completed_at = v_now, next_attempt_at = v_now,
      last_error_code = 'TOKEN_VAULT_MISSING', lease_id = null, lease_expires_at = null,
      deterministic_failure_count = 3
  where i.state in ('pending','processing')
    and not exists (
      select 1 from private.google_play_token_vault v
      where v.purchase_token_hash = i.purchase_token_hash and v.purge_after > v_now
    );

  with due as (
    select i.message_id
    from private.google_play_rtdn_inbox i
    where i.state = 'pending' and i.next_attempt_at <= v_now
      and i.attempt_count < 1000 and i.deterministic_failure_count < 3
      and not exists (
        select 1 from private.google_play_rtdn_inbox active
        where active.purchase_token_hash = i.purchase_token_hash
          and active.state = 'processing' and active.lease_expires_at > v_now
      )
      and not exists (
        select 1 from private.google_play_rtdn_inbox earlier
        where earlier.purchase_token_hash = i.purchase_token_hash
          and earlier.state = 'pending' and earlier.next_attempt_at <= v_now
          and earlier.attempt_count < 1000 and earlier.deterministic_failure_count < 3
          and (earlier.next_attempt_at, earlier.received_at, earlier.message_id)
            < (i.next_attempt_at, i.received_at, i.message_id)
      )
    order by i.next_attempt_at, i.received_at, i.message_id
    for update skip locked
    limit p_limit
  ), claimed as (
    update private.google_play_rtdn_inbox i
    set state = 'processing', attempt_count = i.attempt_count + 1,
        lease_id = extensions.gen_random_uuid(), lease_expires_at = v_now + interval '2 minutes'
    from due
    where i.message_id = due.message_id
    returning i.*
  )
  select coalesce(jsonb_agg(jsonb_build_object(
    'messageId', c.message_id,
    'purchaseTokenHash', c.purchase_token_hash,
    'notificationType', c.notification_type,
    'eventTime', c.event_time,
    'attemptCount', c.attempt_count,
    'leaseId', c.lease_id,
    'tokenCiphertext', v.token_ciphertext,
    'tokenNonce', v.token_nonce,
    'tokenKeyVersion', v.key_version,
    'deletedOwner', t.purchase_token_hash is not null
  ) order by c.next_attempt_at, c.received_at, c.message_id), '[]'::jsonb)
  into v_rows
  from claimed c
  join private.google_play_token_vault v on v.purchase_token_hash = c.purchase_token_hash
  left join private.google_play_deleted_token_tombstones t
    on t.purchase_token_hash = c.purchase_token_hash;

  return v_rows;
end;
$$;

create or replace function public.service_finish_google_play_rtdn(
  p_message_id text,
  p_lease_id uuid,
  p_outcome text,
  p_error_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_row private.google_play_rtdn_inbox;
  v_final_state text;
begin
  if p_message_id is null or length(p_message_id) not between 1 and 256
     or p_lease_id is null
     or p_outcome is null or p_outcome not in ('success','transient','deterministic')
     or (p_error_code is not null and length(p_error_code) not between 1 and 64) then
    raise exception 'Geçersiz RTDN tamamlama isteği' using errcode = '22023';
  end if;
  select * into v_row from private.google_play_rtdn_inbox i
  where i.message_id = p_message_id for update;
  if v_row.message_id is null or v_row.state <> 'processing'
     or v_row.lease_id is distinct from p_lease_id then
    raise exception 'RTDN iş kilidi geçersiz' using errcode = '55P03';
  end if;

  if p_outcome = 'success' then
    v_final_state := 'completed';
    update private.google_play_rtdn_inbox
    set state = 'completed', completed_at = v_now, next_attempt_at = v_now,
        last_error_code = null, lease_expires_at = v_now
    where message_id = p_message_id;
    if exists (
      select 1 from private.google_play_deleted_token_tombstones t
      where t.purchase_token_hash = v_row.purchase_token_hash
    ) then
      update private.google_play_deleted_token_tombstones
      set developer_stop_verified_at = v_now
      where purchase_token_hash = v_row.purchase_token_hash;
      update private.google_play_rtdn_inbox
      set state = 'completed', completed_at = coalesce(completed_at, v_now),
          next_attempt_at = v_now,
          lease_expires_at = case when lease_id is null then null else v_now end,
          last_error_code = null
      where purchase_token_hash = v_row.purchase_token_hash
        and state in ('pending','processing');
      delete from private.google_play_token_vault
      where purchase_token_hash = v_row.purchase_token_hash;
    end if;
  elsif p_outcome = 'deterministic' and v_row.deterministic_failure_count >= 2 then
    v_final_state := 'quarantined';
    update private.google_play_rtdn_inbox
    set state = 'quarantined', completed_at = v_now, next_attempt_at = v_now,
        last_error_code = coalesce(p_error_code, 'DETERMINISTIC'), lease_expires_at = v_now,
        deterministic_failure_count = 3
    where message_id = p_message_id;
    insert into private.google_play_subscription_quarantine (
      purchase_token_hash, reason, first_seen_at, last_seen_at,
      observation_count, release_after
    ) values (
      v_row.purchase_token_hash, 'poison_notification', v_now, v_now, 1, v_now + interval '30 days'
    ) on conflict (purchase_token_hash) do update
      set reason = 'poison_notification', last_seen_at = v_now,
          observation_count = private.google_play_subscription_quarantine.observation_count + 1;
  else
    v_final_state := 'pending';
    update private.google_play_rtdn_inbox
    set state = 'pending',
        next_attempt_at = v_now + make_interval(
          secs => least(1800, (30 * power(2, least(greatest(0, attempt_count - 1), 6)))::integer)
        ),
        last_error_code = coalesce(p_error_code, upper(p_outcome)),
        deterministic_failure_count = case
          when p_outcome = 'deterministic' then deterministic_failure_count + 1
          else deterministic_failure_count
        end,
        lease_id = null, lease_expires_at = null
    where message_id = p_message_id;
  end if;
  return jsonb_build_object('state', v_final_state, 'attemptCount', v_row.attempt_count);
end;
$$;

create or replace function public.service_list_google_play_reconcile_tokens(p_limit integer default 50)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare v_result jsonb; v_now timestamptz := clock_timestamp();
begin
  if p_limit is null or p_limit not between 1 and 200 then
    raise exception 'Geçersiz uzlaştırma iş sayısı' using errcode = '22023';
  end if;
  with due as (
    select s.purchase_token_hash
    from private.google_play_subscriptions s
    join private.google_play_token_vault v
      on v.purchase_token_hash = s.purchase_token_hash and v.purge_after > v_now
    where s.reconcile_after <= v_now
      and (s.terminal_observed_at is null
        or s.terminal_observed_at > v_now - interval '60 days')
    order by s.reconcile_after, s.last_verified_at, s.purchase_token_hash
    for update of s skip locked
    limit p_limit
  ), claimed as (
    update private.google_play_subscriptions s
    set reconcile_after = v_now + interval '2 minutes'
    from due where s.purchase_token_hash = due.purchase_token_hash
    returning s.purchase_token_hash, s.last_verified_at
  )
  select coalesce(jsonb_agg(jsonb_build_object(
    'purchaseTokenHash', c.purchase_token_hash,
    'tokenCiphertext', v.token_ciphertext,
    'tokenNonce', v.token_nonce,
    'tokenKeyVersion', v.key_version
  ) order by c.last_verified_at, c.purchase_token_hash), '[]'::jsonb)
  into v_result
  from claimed c
  join private.google_play_token_vault v
    on v.purchase_token_hash = c.purchase_token_hash and v.purge_after > v_now;
  return v_result;
end;
$$;

create or replace function public.service_defer_google_play_reconcile(
  p_purchase_token_hash text,
  p_transient boolean
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp();
begin
  if p_purchase_token_hash is null or p_purchase_token_hash !~ '^[a-f0-9]{64}$'
     or p_transient is null then
    raise exception 'Geçersiz uzlaştırma sonucu' using errcode = '22023';
  end if;
  update private.google_play_subscriptions
  set reconcile_failure_count = least(1000, reconcile_failure_count + 1),
      reconcile_after = v_now + make_interval(secs => case
        when p_transient then least(21600, 60 * (power(2, least(reconcile_failure_count, 8)))::integer)
        else least(86400, 900 * (power(2, least(reconcile_failure_count, 6)))::integer)
      end)
  where purchase_token_hash = p_purchase_token_hash;
  return found;
end;
$$;

create or replace function public.service_get_google_play_voided_cursor()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_state private.google_play_reconcile_state;
  v_now_ms bigint := (extract(epoch from clock_timestamp()) * 1000)::bigint;
begin
  select * into v_state from private.google_play_reconcile_state where singleton for update;
  if v_state.voided_page_token is null and v_state.voided_scan_started_at_ms is null then
    update private.google_play_reconcile_state
    set voided_scan_started_at_ms = v_now_ms, updated_at = clock_timestamp()
    where singleton;
    v_state.voided_scan_started_at_ms := v_now_ms;
  end if;
  return jsonb_build_object(
    'startTimeMillis', greatest(
      v_state.voided_start_time_ms,
      (extract(epoch from clock_timestamp() - interval '30 days') * 1000)::bigint
    ),
    'pageToken', v_state.voided_page_token,
    'scanStartedAtMillis', v_state.voided_scan_started_at_ms
  );
end;
$$;

create or replace function public.service_advance_google_play_voided_cursor(
  p_expected_page_token text,
  p_next_page_token text,
  p_scan_completed_at_ms bigint
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare v_scan_started_at_ms bigint;
begin
  if (p_expected_page_token is not null and length(p_expected_page_token) > 4096)
     or (p_next_page_token is not null and length(p_next_page_token) > 4096)
     or p_scan_completed_at_ms is null or p_scan_completed_at_ms < 0
     or p_scan_completed_at_ms > (extract(epoch from clock_timestamp() + interval '10 minutes') * 1000)::bigint then
    raise exception 'Geçersiz iade imleci' using errcode = '22023';
  end if;
  select s.voided_scan_started_at_ms into v_scan_started_at_ms
  from private.google_play_reconcile_state s
  where s.singleton and s.voided_page_token is not distinct from p_expected_page_token
  for update;
  if v_scan_started_at_ms is null or p_scan_completed_at_ms < v_scan_started_at_ms then
    raise exception 'İade taraması başlangıcı bulunamadı' using errcode = '55000';
  end if;
  update private.google_play_reconcile_state
  set voided_page_token = p_next_page_token,
      voided_start_time_ms = case when p_next_page_token is null
        then greatest(
          voided_start_time_ms,
          v_scan_started_at_ms - 300000
        ) else voided_start_time_ms end,
      voided_scan_started_at_ms = case when p_next_page_token is null
        then null else v_scan_started_at_ms end,
      updated_at = clock_timestamp()
  where singleton and voided_page_token is not distinct from p_expected_page_token;
  return found;
end;
$$;

create or replace function public.service_reset_google_play_voided_cursor(p_expected_page_token text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  update private.google_play_reconcile_state
  set voided_page_token = null,
      voided_scan_started_at_ms = null,
      updated_at = clock_timestamp()
  where singleton and voided_page_token is not distinct from p_expected_page_token;
  return found;
end;
$$;

create or replace function public.service_prepare_google_play_organization_deletion(
  p_request_id uuid,
  p_user_id uuid,
  p_organization_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_hash text;
  v_tokens jsonb;
  v_missing integer;
  v_busy boolean;
  v_ready boolean;
begin
  if p_request_id is null or p_user_id is null or p_organization_id is null then
    raise exception 'Geçersiz işletme silme kontrolü' using errcode = '22023';
  end if;

  -- Token advisory locks are taken in lexical order before the organization
  -- row. Observation writers take the same token lock before tenant locks.
  for v_hash in
    select s.purchase_token_hash
    from private.google_play_subscriptions s
    where s.organization_id = p_organization_id
    order by s.purchase_token_hash
  loop
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_hash, 0));
  end loop;

  perform 1 from public.organizations o where o.id = p_organization_id for update;
  if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
  perform 1 from public.profiles p
  where p.id = p_user_id and p.organization_id = p_organization_id
    and p.role = 'admin' and p.is_active and not p.must_change_password
  for update;
  if not found then raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501'; end if;
  if not exists (
    select 1 from private.organization_deletion_fences f
    where f.organization_id = p_organization_id
      and f.request_id = p_request_id and f.initiator_user_id = p_user_id
  ) then
    raise exception 'İşletme silme kilidi bulunamadı' using errcode = '55000';
  end if;

  update private.google_play_purchase_intents
  set status = 'expired', closed_reason = 'timeout'
  where organization_id = p_organization_id
    and status in ('active','pending') and expires_at <= v_now;

  if exists (
    select 1 from private.google_play_purchase_intents i
    where i.organization_id = p_organization_id and i.status in ('active','pending')
  ) then
    return jsonb_build_object(
      'ready', false, 'busy', true, 'missingToken', false,
      'reason', 'PURCHASE_INTENT_IN_PROGRESS', 'tokens', '[]'::jsonb
    );
  end if;

  v_busy := exists (
    select 1
    from private.google_play_subscription_observation_leases l
    join private.google_play_subscriptions s on s.purchase_token_hash = l.purchase_token_hash
    where s.organization_id = p_organization_id and l.expires_at > v_now
  ) or exists (
    select 1
    from private.google_play_observation_claim_contexts c
    join private.google_play_subscription_observation_leases l on l.lease_id = c.lease_id
    where c.organization_id = p_organization_id and l.expires_at > v_now
  ) or exists (
    select 1
    from private.google_play_rtdn_inbox i
    join private.google_play_subscriptions s on s.purchase_token_hash = i.purchase_token_hash
    where s.organization_id = p_organization_id and i.state in ('pending','processing')
  );
  if v_busy then
    return jsonb_build_object(
      'ready', false, 'busy', true, 'missingToken', false,
      'reason', 'SUBSCRIPTION_SYNC_IN_PROGRESS', 'tokens', '[]'::jsonb
    );
  end if;

  select count(*) filter (where v.purchase_token_hash is null),
         coalesce(jsonb_agg(jsonb_build_object(
           'purchaseTokenHash', s.purchase_token_hash,
           'tokenCiphertext', v.token_ciphertext,
           'tokenNonce', v.token_nonce,
           'tokenKeyVersion', v.key_version,
           'needsStop', coalesce(s.auto_renew_enabled, true)
             or s.developer_stop_verified_at is null,
           'subscriptionState', s.subscription_state
         ) order by s.purchase_token_hash) filter (where v.purchase_token_hash is not null), '[]'::jsonb)
    into v_missing, v_tokens
  from private.google_play_subscriptions s
  left join private.google_play_token_vault v
    on v.purchase_token_hash = s.purchase_token_hash and v.purge_after > v_now
  where s.organization_id = p_organization_id
    and (
      coalesce(s.auto_renew_enabled, true)
      or s.developer_stop_verified_at is null
      or s.subscription_state not in (
        'SUBSCRIPTION_STATE_EXPIRED','SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
      )
    );

  v_missing := coalesce(v_missing, 0);
  v_ready := v_missing = 0 and not exists (
    select 1 from private.google_play_subscriptions s
    where s.organization_id = p_organization_id
      and (
        coalesce(s.auto_renew_enabled, true)
        or s.developer_stop_verified_at is null
      )
  );
  return jsonb_build_object(
    'ready', v_ready,
    'busy', false,
    'missingToken', v_missing > 0,
    'reason', case
      when v_missing > 0 then 'RESTORE_PURCHASES_REQUIRED'
      when v_ready then null
      else 'DEVELOPER_STOP_REQUIRED'
    end,
    'tokens', v_tokens
  );
end;
$$;

create or replace function public.service_finalize_google_play_organization_deletion(
  p_request_id uuid,
  p_user_id uuid,
  p_organization_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_hash text;
  v_original timestamptz;
begin
  if p_request_id is null or p_user_id is null or p_organization_id is null then
    raise exception 'Geçersiz işletme silme isteği' using errcode = '22023';
  end if;
  for v_hash in
    select s.purchase_token_hash from private.google_play_subscriptions s
    where s.organization_id = p_organization_id order by s.purchase_token_hash
  loop
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_hash, 0));
  end loop;

  perform 1 from public.organizations o where o.id = p_organization_id for update;
  if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
  perform 1 from public.profiles p
  where p.id = p_user_id and p.organization_id = p_organization_id
    and p.role = 'admin' and p.is_active and not p.must_change_password
  for update;
  if not found then raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501'; end if;
  if not exists (
    select 1 from private.organization_deletion_fences f
    where f.organization_id = p_organization_id
      and f.request_id = p_request_id and f.initiator_user_id = p_user_id
  ) then
    raise exception 'İşletme silme kilidi bulunamadı' using errcode = '55000';
  end if;

  delete from private.google_play_subscription_observation_leases
  where expires_at <= v_now;

  if exists (
    select 1 from private.google_play_purchase_intents i
    where i.organization_id = p_organization_id and i.status in ('active','pending')
  ) or exists (
    select 1 from private.google_play_subscription_observation_leases l
    join private.google_play_subscriptions s on s.purchase_token_hash = l.purchase_token_hash
    where s.organization_id = p_organization_id and l.expires_at > v_now
  ) or exists (
    select 1
    from private.google_play_observation_claim_contexts c
    join private.google_play_subscription_observation_leases l on l.lease_id = c.lease_id
    where c.organization_id = p_organization_id and l.expires_at > v_now
  ) or exists (
    select 1 from private.google_play_subscriptions s
    left join private.google_play_token_vault v on v.purchase_token_hash = s.purchase_token_hash
    where s.organization_id = p_organization_id
      and (
        coalesce(s.auto_renew_enabled, true)
        or s.developer_stop_verified_at is null
      )
  ) then
    raise exception 'Google Play silme kanıtı tamamlanmadı' using errcode = '55000';
  end if;

  insert into private.google_play_deleted_identity_tombstones (
    external_account_id_hash, external_profile_id_hash, deleted_at, purge_after
  )
  select distinct s.external_account_id_hash, s.external_profile_id_hash,
    v_now, v_now + interval '120 days'
  from private.google_play_subscriptions s
  where s.organization_id = p_organization_id
  union
  select
    encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex'),
    encode(extensions.digest(convert_to(p_organization_id::text, 'UTF8'), 'sha256'), 'hex'),
    v_now, v_now + interval '120 days'
  on conflict (external_account_id_hash, external_profile_id_hash) do update
  set deleted_at = least(private.google_play_deleted_identity_tombstones.deleted_at, excluded.deleted_at),
      purge_after = least(
        private.google_play_deleted_identity_tombstones.deleted_at + interval '120 days',
        greatest(private.google_play_deleted_identity_tombstones.purge_after, excluded.purge_after)
      );

  insert into private.google_play_deleted_token_tombstones (
    purchase_token_hash, former_organization_hash, former_user_hash,
    developer_stop_verified_at, last_subscription_state, last_expiry_time,
    ciphertext_purge_deadline, created_at, purge_after
  )
  select s.purchase_token_hash,
    encode(extensions.digest(convert_to(s.organization_id::text, 'UTF8'), 'sha256'), 'hex'),
    encode(extensions.digest(convert_to(s.purchaser_user_id::text, 'UTF8'), 'sha256'), 'hex'),
    s.developer_stop_verified_at, s.subscription_state, s.expiry_time,
    least(coalesce(v.first_stored_at + interval '120 days', v_now), v_now + interval '30 days'),
    v_now, v_now + interval '120 days'
  from private.google_play_subscriptions s
  left join private.google_play_token_vault v
    on v.purchase_token_hash = s.purchase_token_hash
  where s.organization_id = p_organization_id
  on conflict (purchase_token_hash) do update
  set developer_stop_verified_at = greatest(
        private.google_play_deleted_token_tombstones.developer_stop_verified_at,
        excluded.developer_stop_verified_at
      ),
      last_subscription_state = excluded.last_subscription_state,
      last_expiry_time = excluded.last_expiry_time,
      ciphertext_purge_deadline = least(
        coalesce(private.google_play_deleted_token_tombstones.ciphertext_purge_deadline,
          excluded.ciphertext_purge_deadline),
        excluded.ciphertext_purge_deadline
      ),
      purge_after = least(
        private.google_play_deleted_token_tombstones.created_at + interval '120 days',
        excluded.purge_after
      );

  -- Post-deletion ciphertext is held no longer than 30 days and never beyond
  -- 120 days from the first time this token entered the vault.
  update private.google_play_token_vault v
  set organization_id = null,
      purchaser_user_id = null,
      retention_class = 'deletion_proof',
      last_stored_at = v_now,
      purge_after = least(v.first_stored_at + interval '120 days', v_now + interval '30 days')
  where v.organization_id = p_organization_id;
  delete from private.google_play_token_vault
  where organization_id is null and retention_class = 'deletion_proof' and purge_after <= v_now;

  delete from private.google_play_purchase_intents
  where organization_id = p_organization_id;

  update private.organization_deletion_fences
  set billing_finalized_at = coalesce(billing_finalized_at, v_now)
  where organization_id = p_organization_id and request_id = p_request_id
    and initiator_user_id = p_user_id;

  return true;
end;
$$;

create or replace function public.service_purge_google_play_lifecycle_data()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_leases bigint;
  v_vault bigint;
  v_quarantine bigint;
  v_tombstones bigint;
  v_inbox bigint;
  v_receipts bigint;
  v_voided bigint;
  v_auth_jobs bigint;
  v_id_tombstones bigint;
  v_terminal_ledgers bigint;
begin
  delete from private.google_play_subscription_observation_leases where expires_at <= v_now;
  get diagnostics v_leases = row_count;
  update private.google_play_rtdn_inbox i
  set state = 'quarantined', completed_at = v_now, next_attempt_at = v_now,
      deterministic_failure_count = 3, last_error_code = 'RETENTION_DEADLINE',
      lease_id = null, lease_expires_at = null
  where i.state in ('pending','processing') and exists (
    select 1 from private.google_play_token_vault v
    where v.purchase_token_hash = i.purchase_token_hash and v.purge_after <= v_now
  );
  delete from private.google_play_entitlements e
  using private.google_play_subscriptions s
  where e.current_purchase_token_hash = s.purchase_token_hash
    and not e.entitled
    and s.terminal_observed_at <= v_now - interval '60 days';
  delete from private.google_play_subscriptions s
  where s.terminal_observed_at <= v_now - interval '60 days'
    and not exists (
      select 1 from private.google_play_entitlements e
      where e.current_purchase_token_hash = s.purchase_token_hash
    )
    and not exists (
      select 1 from private.google_play_rtdn_inbox i
      where i.purchase_token_hash = s.purchase_token_hash
        and i.state in ('pending','processing')
    );
  get diagnostics v_terminal_ledgers = row_count;
  delete from private.google_play_token_vault where purge_after <= v_now;
  get diagnostics v_vault = row_count;
  delete from private.google_play_subscription_quarantine where release_after <= v_now;
  get diagnostics v_quarantine = row_count;
  delete from private.google_play_deleted_token_tombstones where purge_after <= v_now;
  get diagnostics v_tombstones = row_count;
  delete from private.google_play_deleted_identity_tombstones where purge_after <= v_now;
  get diagnostics v_id_tombstones = row_count;
  delete from private.google_play_voided_orders where purge_after <= v_now;
  get diagnostics v_voided = row_count;
  delete from private.google_play_notification_receipts where purge_after <= v_now;
  delete from private.google_play_rtdn_inbox
  where state in ('completed','quarantined') and completed_at < v_now - interval '60 days';
  get diagnostics v_inbox = row_count;
  -- A processing saga is a durable fence. Only an explicit authenticated abort
  -- or a successful finalize may remove it; wall-clock expiry cannot reopen
  -- writes while the same deletion request is still resumable.
  delete from private.account_deletion_request_receipts
  where state = 'completed' and purge_after <= v_now;
  get diagnostics v_receipts = row_count;
  -- Do not silently forget an Auth identity that could not be deleted. Failed
  -- jobs remain observable for operator repair; only proven success is purged.
  delete from private.account_auth_cleanup_jobs
  where state = 'completed' and completed_at < v_now - interval '30 days';
  get diagnostics v_auth_jobs = row_count;
  return jsonb_build_object(
    'leases', v_leases, 'vault', v_vault, 'quarantine', v_quarantine,
    'tombstones', v_tombstones, 'identityTombstones', v_id_tombstones,
    'voidedOrders', v_voided,
    'terminalLedgers', v_terminal_ledgers, 'inbox', v_inbox,
    'deletionReceipts', v_receipts, 'authCleanupJobs', v_auth_jobs
  );
end;
$$;

create or replace function public.service_begin_account_deletion_request(
  p_request_id uuid,
  p_user_id uuid,
  p_scope text,
  p_organization_id uuid default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_receipt private.account_deletion_request_receipts;
  v_now timestamptz := clock_timestamp();
  v_profile_organization_id uuid;
begin
  if p_request_id is null or p_user_id is null
     or p_scope is null or p_scope not in ('account','organization')
     or (p_scope = 'organization') <> (p_organization_id is not null) then
    raise exception 'Geçersiz hesap silme isteği' using errcode = '22023';
  end if;
  if p_scope = 'organization' then
    perform 1 from public.organizations o where o.id = p_organization_id for update;
    if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
    perform 1 from public.profiles p
    where p.id = p_user_id and p.organization_id = p_organization_id
      and p.role = 'admin' and p.is_active and not p.must_change_password
    for update;
    if not found then
      raise exception 'Yetkili işletme yöneticisi bulunamadı' using errcode = '42501';
    end if;
  else
    select p.organization_id into v_profile_organization_id
    from public.profiles p where p.id = p_user_id;
    if v_profile_organization_id is null then
      raise exception 'Etkin üye bulunamadı' using errcode = '42501';
    end if;
    perform 1 from public.organizations o where o.id = v_profile_organization_id for update;
    if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
    perform 1 from public.profiles p
    where p.id = p_user_id and p.organization_id = v_profile_organization_id
      and p.role = 'member' and p.is_active and not p.must_change_password
    for update;
    if not found then raise exception 'Etkin üye bulunamadı' using errcode = '42501'; end if;
  end if;
  v_hash := encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex');
  select * into v_receipt from private.account_deletion_request_receipts r
  where r.subject_user_hash = v_hash and r.state = 'processing'
  for update;
  if v_receipt.request_id is not null then
    if v_receipt.scope <> p_scope
       or v_receipt.organization_id <> coalesce(p_organization_id, v_profile_organization_id) then
      raise exception 'Başka kapsamda hesap silme işlemi devam ediyor' using errcode = '23505';
    end if;
    return jsonb_build_object(
      'requestId', v_receipt.request_id, 'state', v_receipt.state,
      'scope', v_receipt.scope, 'organizationId', v_receipt.organization_id
    );
  end if;
  insert into private.account_deletion_request_receipts (
    request_id, subject_user_hash, organization_id, scope, state, created_at, purge_after
  ) values (
    p_request_id, v_hash, coalesce(p_organization_id, v_profile_organization_id),
    p_scope, 'processing', v_now, v_now + interval '30 days'
  )
  on conflict (request_id) do nothing;
  select * into v_receipt from private.account_deletion_request_receipts r
  where r.request_id = p_request_id for update;
  if v_receipt.subject_user_hash <> v_hash or v_receipt.scope <> p_scope
     or v_receipt.organization_id <> coalesce(p_organization_id, v_profile_organization_id) then
    raise exception 'Silme istek kimliği başka bir işleme ait' using errcode = '23505';
  end if;
  if p_scope = 'organization' then
    insert into private.organization_deletion_fences (
      organization_id, request_id, initiator_user_id, created_at, expires_at
    ) values (
      p_organization_id, p_request_id, p_user_id, v_now, v_now + interval '30 days'
    ) on conflict (organization_id) do nothing;
    if not exists (
      select 1 from private.organization_deletion_fences f
      where f.organization_id = p_organization_id
        and f.request_id = p_request_id and f.initiator_user_id = p_user_id
    ) then
      raise exception 'İşletme başka bir silme isteğiyle kilitli' using errcode = '55P03';
    end if;
  end if;
  return jsonb_build_object(
    'requestId', v_receipt.request_id, 'state', v_receipt.state,
    'scope', v_receipt.scope, 'organizationId', v_receipt.organization_id
  );
end;
$$;

create or replace function public.service_complete_account_deletion_request(
  p_request_id uuid,
  p_user_id uuid,
  p_scope text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash text;
begin
  if p_request_id is null or p_user_id is null
     or p_scope is null or p_scope not in ('account','organization') then
    raise exception 'Geçersiz hesap silme isteği' using errcode = '22023';
  end if;
  v_hash := encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex');
  update private.account_deletion_request_receipts
  set state = 'completed', completed_at = coalesce(completed_at, clock_timestamp())
  where request_id = p_request_id and subject_user_hash = v_hash and scope = p_scope;
  if not found then raise exception 'Silme isteği bulunamadı' using errcode = '42501'; end if;
  return true;
end;
$$;

create or replace function public.service_get_account_deletion_receipt(
  p_request_id uuid,
  p_user_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((
    select jsonb_build_object(
      'state', r.state, 'scope', r.scope, 'organizationId', r.organization_id
    )
    from private.account_deletion_request_receipts r
    where r.request_id = p_request_id
      and r.subject_user_hash = encode(
        extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex'
      )
      and (r.state = 'processing' or r.purge_after > clock_timestamp())
  ), '{}'::jsonb);
$$;

create or replace function public.service_find_active_account_deletion_request(
  p_user_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((
    select jsonb_build_object(
      'requestId', r.request_id,
      'state', r.state,
      'scope', r.scope,
      'organizationId', r.organization_id
    )
    from private.account_deletion_request_receipts r
    where r.subject_user_hash = encode(
      extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex'
    ) and (r.state = 'processing' or r.purge_after > clock_timestamp())
    order by (r.state = 'processing') desc, r.completed_at desc nulls last,
      r.created_at desc, r.request_id
    limit 1
  ), '{}'::jsonb);
$$;

create or replace function public.service_erase_organization_after_billing_finalize(
  p_request_id uuid,
  p_user_id uuid,
  p_organization_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_ids uuid[];
  v_user_id uuid;
  v_hash text;
begin
  if p_request_id is null or p_user_id is null or p_organization_id is null then
    raise exception 'Geçersiz işletme silme isteği' using errcode = '22023';
  end if;
  perform 1 from public.organizations o where o.id = p_organization_id for update;
  if not found then raise exception 'İşletme bulunamadı' using errcode = '42501'; end if;
  perform 1 from public.profiles p
  where p.organization_id = p_organization_id
  order by p.id
  for update;
  if not exists (
    select 1 from private.organization_deletion_fences f
    where f.organization_id = p_organization_id and f.request_id = p_request_id
      and f.initiator_user_id = p_user_id and f.billing_finalized_at is not null
  ) then raise exception 'İşletme silme kilidi bulunamadı' using errcode = '55000'; end if;
  v_hash := encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex');
  if not exists (
    select 1 from private.account_deletion_request_receipts r
    where r.request_id = p_request_id and r.subject_user_hash = v_hash
      and r.scope = 'organization' and r.state = 'processing'
  ) then raise exception 'İşletme silme makbuzu bulunamadı' using errcode = '55000'; end if;
  if exists (
    select 1 from private.google_play_purchase_intents i where i.organization_id = p_organization_id
  ) or exists (
    select 1 from private.google_play_token_vault v where v.organization_id = p_organization_id
  ) then raise exception 'Google Play silme sonlandırması tamamlanmadı' using errcode = '55000'; end if;

  perform 1 from public.pending_registration_intents i
  where i.organization_id = p_organization_id for update;
  perform 1 from public.pending_recovery_email_intents i
  where i.organization_id = p_organization_id for update;

  select array_agg(distinct ids.id) into v_user_ids
  from (
    select p.id from public.profiles p where p.organization_id = p_organization_id
    union all
    select r.auth_user_id from public.pending_account_registrations r
      where r.organization_id = p_organization_id
    union all
    select r.verification_user_id from public.pending_recovery_email_verifications r
      where r.organization_id = p_organization_id and r.verification_kind = 'temporary_signup'
    union all
    select i.auth_user_id from public.pending_registration_intents i
      where i.organization_id = p_organization_id and i.auth_user_id is not null
    union all
    select u.id
    from public.pending_registration_intents i
    join auth.users u
      on u.raw_user_meta_data ->> 'stokta_registration_request_id' = i.request_id::text
    where i.organization_id = p_organization_id
    union all
    select i.verification_user_id from public.pending_recovery_email_intents i
      where i.organization_id = p_organization_id
        and i.verification_kind = 'temporary_signup'
        and i.verification_user_id is not null
    union all
    select u.id
    from public.pending_recovery_email_intents i
    join auth.users u
      on u.raw_user_meta_data ->> 'stokta_recovery_request_id' = i.request_id::text
    where i.organization_id = p_organization_id
  ) ids;

  foreach v_user_id in array coalesce(v_user_ids, array[]::uuid[]) loop
    insert into private.account_auth_cleanup_jobs (
      user_id, request_id, state, attempt_count, next_attempt_at, created_at
    ) values (v_user_id, p_request_id, 'pending', 0, clock_timestamp(), clock_timestamp())
    on conflict (user_id) do update
      set request_id = excluded.request_id,
          state = case when private.account_auth_cleanup_jobs.state = 'completed' then 'completed' else 'pending' end,
          next_attempt_at = least(private.account_auth_cleanup_jobs.next_attempt_at, excluded.next_attempt_at),
          lease_id = null, lease_expires_at = null;
  end loop;

  -- Session invalidation commits atomically with the data erasure and durable
  -- Auth cleanup queue. External Auth deletion is deliberately asynchronous.
  delete from auth.sessions where user_id = any(coalesce(v_user_ids, array[]::uuid[]));

  delete from public.stock_movements where organization_id = p_organization_id;
  delete from public.products where organization_id = p_organization_id;
  delete from public.pending_recovery_email_intents where organization_id = p_organization_id;
  delete from public.pending_registration_intents where organization_id = p_organization_id;
  update public.profiles set created_by = null where organization_id = p_organization_id;
  delete from public.profiles where organization_id = p_organization_id;
  delete from public.organizations where id = p_organization_id;

  update private.account_deletion_request_receipts
  set state = 'completed', completed_at = clock_timestamp()
  where request_id = p_request_id and state = 'processing';
  delete from private.organization_deletion_fences
  where organization_id = p_organization_id and request_id = p_request_id;

  return jsonb_build_object('authUsersQueued', coalesce(array_length(v_user_ids, 1), 0));
end;
$$;

create or replace function public.service_abort_account_deletion_request(
  p_request_id uuid,
  p_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_fence private.organization_deletion_fences;
  v_receipt private.account_deletion_request_receipts;
begin
  if p_request_id is null or p_user_id is null then
    raise exception 'Geçersiz silme isteği' using errcode = '22023';
  end if;
  v_hash := encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex');
  select * into v_receipt from private.account_deletion_request_receipts r
  where r.request_id = p_request_id and r.subject_user_hash = v_hash;
  if v_receipt.request_id is null or v_receipt.state <> 'processing' then return false; end if;

  -- Global tenant lock order is organization -> profiles -> receipt/fence.
  -- The unlocked receipt read is revalidated after acquiring those locks.
  perform 1 from public.organizations o where o.id = v_receipt.organization_id for update;
  perform 1 from public.profiles p
  where p.id = p_user_id and p.organization_id = v_receipt.organization_id for update;
  select * into v_receipt from private.account_deletion_request_receipts r
  where r.request_id = p_request_id and r.subject_user_hash = v_hash for update;
  if v_receipt.request_id is null or v_receipt.state <> 'processing' then return false; end if;

  if v_receipt.scope = 'organization' then
    select * into v_fence from private.organization_deletion_fences f
    where f.request_id = p_request_id and f.initiator_user_id = p_user_id
      and f.organization_id = v_receipt.organization_id
    for update;
    if v_fence.organization_id is null then
      raise exception 'İşletme silme kilidi bulunamadı' using errcode = '55000';
    end if;
    if v_fence.billing_finalized_at is not null then
      raise exception 'Google Play sonlandırmasından sonra silme isteği iptal edilemez'
        using errcode = '55000';
    end if;
    delete from private.organization_deletion_fences
    where organization_id = v_receipt.organization_id and request_id = p_request_id
      and initiator_user_id = p_user_id and billing_finalized_at is null;
  end if;
  delete from private.account_deletion_request_receipts
  where request_id = p_request_id and subject_user_hash = v_hash and state = 'processing';
  return found;
end;
$$;

create or replace function public.service_finalize_member_account_deletion(
  p_request_id uuid,
  p_user_id uuid,
  p_organization_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_admin_id uuid;
  v_hash text;
  v_pending_auth_user uuid;
  v_receipt private.account_deletion_request_receipts;
begin
  if p_request_id is null or p_user_id is null or p_organization_id is null then
    raise exception 'Geçersiz üye silme isteği' using errcode = '22023';
  end if;
  perform 1 from public.organizations o where o.id = p_organization_id for update;
  perform 1 from public.profiles p
  where p.id = p_user_id and p.organization_id = p_organization_id
    and p.role = 'member' and p.is_active and not p.must_change_password
  for update;
  if not found then raise exception 'Etkin üye bulunamadı' using errcode = '42501'; end if;
  select p.id into v_admin_id from public.profiles p
  where p.organization_id = p_organization_id and p.role = 'admin' and p.is_active
  order by p.id limit 1 for update;
  if v_admin_id is null then raise exception 'Verileri devralacak yönetici bulunamadı' using errcode = '55000'; end if;
  v_hash := encode(extensions.digest(convert_to(p_user_id::text, 'UTF8'), 'sha256'), 'hex');
  select * into v_receipt from private.account_deletion_request_receipts r
  where r.request_id = p_request_id and r.subject_user_hash = v_hash
    and r.organization_id = p_organization_id and r.scope = 'account'
  for update;
  if v_receipt.request_id is null or v_receipt.state <> 'processing' then
    raise exception 'Üye silme makbuzu bulunamadı' using errcode = '55000';
  end if;

  perform 1 from public.pending_registration_intents i
  where i.created_by = p_user_id
  for update;
  perform 1 from public.pending_recovery_email_intents i
  where i.target_user_id = p_user_id
  for update;
  for v_pending_auth_user in
    select distinct candidates.auth_user_id
    from (
      select i.auth_user_id
      from public.pending_registration_intents i
      where i.created_by = p_user_id and i.auth_user_id is not null
      union all
      select u.id
      from public.pending_registration_intents i
      join auth.users u
        on u.raw_user_meta_data ->> 'stokta_registration_request_id' = i.request_id::text
      where i.created_by = p_user_id
      union all
      select i.verification_user_id
      from public.pending_recovery_email_intents i
      where i.target_user_id = p_user_id
        and i.verification_kind = 'temporary_signup'
        and i.verification_user_id is not null
      union all
      select u.id
      from public.pending_recovery_email_intents i
      join auth.users u
        on u.raw_user_meta_data ->> 'stokta_recovery_request_id' = i.request_id::text
      where i.target_user_id = p_user_id
    ) candidates
  loop
    insert into private.account_auth_cleanup_jobs (
      user_id, request_id, state, attempt_count, next_attempt_at, created_at
    ) values (v_pending_auth_user, p_request_id, 'pending', 0, clock_timestamp(), clock_timestamp())
    on conflict (user_id) do update
      set request_id = excluded.request_id, state = 'pending', next_attempt_at = excluded.next_attempt_at,
          lease_id = null, lease_expires_at = null;
  end loop;
  delete from public.pending_recovery_email_intents where target_user_id = p_user_id;
  delete from public.pending_registration_intents where created_by = p_user_id;

  update public.stock_movements
  set actor_id = null, actor_name = 'Silinmiş kullanıcı'
  where actor_id = p_user_id;
  update public.products set created_by = v_admin_id
  where organization_id = p_organization_id and created_by = p_user_id;
  update public.profiles set created_by = v_admin_id
  where organization_id = p_organization_id and created_by = p_user_id;
  insert into private.account_auth_cleanup_jobs (
    user_id, request_id, state, attempt_count, next_attempt_at, created_at
  ) values (p_user_id, p_request_id, 'pending', 0, clock_timestamp(), clock_timestamp())
  on conflict (user_id) do update
    set request_id = excluded.request_id, state = 'pending',
        next_attempt_at = excluded.next_attempt_at, lease_id = null, lease_expires_at = null;
  delete from auth.sessions where user_id = p_user_id;
  delete from public.profiles where id = p_user_id and organization_id = p_organization_id;
  update private.account_deletion_request_receipts
  set state = 'completed', completed_at = clock_timestamp()
  where request_id = p_request_id and state = 'processing';
  if not found then raise exception 'Üye silme makbuzu güncellenemedi' using errcode = '55000'; end if;
  return true;
end;
$$;

create or replace function public.service_claim_account_auth_cleanup(p_limit integer default 20)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp(); v_result jsonb;
begin
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'Geçersiz Auth temizleme iş sayısı' using errcode = '22023';
  end if;
  update private.account_auth_cleanup_jobs
  set state = 'pending', lease_id = null, lease_expires_at = null,
      next_attempt_at = least(next_attempt_at, v_now)
  where state = 'processing' and lease_expires_at <= v_now;
  with due as (
    select j.user_id from private.account_auth_cleanup_jobs j
    where j.state = 'pending' and j.next_attempt_at <= v_now and j.attempt_count < 1000
    order by j.next_attempt_at, j.created_at, j.user_id
    for update skip locked limit p_limit
  ), claimed as (
    update private.account_auth_cleanup_jobs j
    set state = 'processing', attempt_count = j.attempt_count + 1,
        lease_id = extensions.gen_random_uuid(), lease_expires_at = v_now + interval '2 minutes'
    from due where j.user_id = due.user_id returning j.*
  )
  select coalesce(jsonb_agg(jsonb_build_object(
    'userId', c.user_id, 'requestId', c.request_id,
    'leaseId', c.lease_id, 'attemptCount', c.attempt_count
  ) order by c.created_at, c.user_id), '[]'::jsonb) into v_result from claimed c;
  return v_result;
end;
$$;

create or replace function public.service_finish_account_auth_cleanup(
  p_user_id uuid,
  p_lease_id uuid,
  p_success boolean,
  p_error_code text default null
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare v_job private.account_auth_cleanup_jobs; v_now timestamptz := clock_timestamp();
begin
  if p_user_id is null or p_lease_id is null or p_success is null
     or (p_error_code is not null and length(p_error_code) not between 1 and 64) then
    raise exception 'Geçersiz Auth temizleme sonucu' using errcode = '22023';
  end if;
  select * into v_job from private.account_auth_cleanup_jobs j
  where j.user_id = p_user_id for update;
  if v_job.user_id is null or v_job.state <> 'processing' or v_job.lease_id <> p_lease_id then
    raise exception 'Auth temizleme kilidi geçersiz' using errcode = '55P03';
  end if;
  if p_success then
    update private.account_auth_cleanup_jobs
    set state = 'completed', completed_at = v_now, next_attempt_at = v_now,
        last_error_code = null, lease_expires_at = v_now
    where user_id = p_user_id;
  else
    update private.account_auth_cleanup_jobs
    set state = case when attempt_count >= 1000 then 'quarantined' else 'pending' end,
        completed_at = case when attempt_count >= 1000 then v_now else null end,
        next_attempt_at = v_now + make_interval(
          secs => least(21600, (60 * power(2, least(greatest(0, attempt_count - 1), 8)))::integer)
        ),
        last_error_code = coalesce(p_error_code, 'AUTH_DELETE_FAILED'),
        lease_id = case when attempt_count >= 1000 then lease_id else null end,
        lease_expires_at = case when attempt_count >= 1000 then v_now else null end
    where user_id = p_user_id;
  end if;
  return true;
end;
$$;

create or replace function public.service_release_organization_deletion_fence(
  p_request_id uuid,
  p_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_request_id is null or p_user_id is null then
    raise exception 'Geçersiz silme kilidi' using errcode = '22023';
  end if;
  -- Compatibility stub: releasing only a fence could orphan a processing
  -- receipt. Call service_abort_account_deletion_request so both records move
  -- atomically and finalized billing proof cannot be reopened.
  return public.service_abort_account_deletion_request(p_request_id, p_user_id);
end;
$$;

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
    select 1 from private.google_play_purchase_intents i
    where i.organization_id = p_organization_id
      and i.status in ('active','pending') and i.expires_at > clock_timestamp()
  ) or exists (
    select 1
    from private.google_play_subscriptions s
    left join private.google_play_token_vault v on v.purchase_token_hash = s.purchase_token_hash
    where s.organization_id = p_organization_id
      and (
        v.purchase_token_hash is null
        or v.purge_after <= clock_timestamp()
        or coalesce(s.auto_renew_enabled, true)
        or s.developer_stop_verified_at is null
      )
  ) or exists (
    select 1
    from private.google_play_subscription_observation_leases l
    join private.google_play_subscriptions s on s.purchase_token_hash = l.purchase_token_hash
    where s.organization_id = p_organization_id and l.expires_at > clock_timestamp()
  );
$$;

create or replace function public.service_google_play_lifecycle_health()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'rtdnPending', (select count(*) from private.google_play_rtdn_inbox i
      where i.state in ('pending','processing')),
    'rtdnOldestSeconds', coalesce((select extract(epoch from
      (statement_timestamp() - min(i.received_at)))::bigint
      from private.google_play_rtdn_inbox i where i.state in ('pending','processing')), 0),
    'rtdnQuarantined', (select count(*) from private.google_play_rtdn_inbox i
      where i.state = 'quarantined'),
    'observationExpiredLeases', (select count(*)
      from private.google_play_subscription_observation_leases l
      where l.expires_at <= statement_timestamp()),
    'deletionsProcessing', (select count(*) from private.account_deletion_request_receipts r
      where r.state = 'processing'),
    'authCleanupPending', (select count(*) from private.account_auth_cleanup_jobs j
      where j.state in ('pending','processing')),
    'authCleanupOldestSeconds', coalesce((select extract(epoch from
      (statement_timestamp() - min(j.created_at)))::bigint
      from private.account_auth_cleanup_jobs j where j.state in ('pending','processing')), 0),
    'authCleanupQuarantined', (select count(*) from private.account_auth_cleanup_jobs j
      where j.state = 'quarantined')
  );
$$;

revoke all on function public.service_begin_google_play_purchase_intent(uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_begin_google_play_purchase_intent(uuid,uuid) to service_role;
revoke all on function public.service_claim_google_play_observation(text,text,uuid,uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_claim_google_play_observation(text,text,uuid,uuid,uuid) to service_role;
revoke all on function public.service_release_google_play_observation(text,uuid,bigint)
  from public, anon, authenticated, service_role;
grant execute on function public.service_release_google_play_observation(text,uuid,bigint) to service_role;
revoke all on function public.service_record_google_play_observation_v2(
  text,uuid,bigint,text,uuid,uuid,uuid,text,text,text,text,timestamptz,text,text,timestamptz,
  timestamptz,boolean,boolean,text,text,text,text,integer
) from public, anon, authenticated, service_role;
grant execute on function public.service_record_google_play_observation_v2(
  text,uuid,bigint,text,uuid,uuid,uuid,text,text,text,text,timestamptz,text,text,timestamptz,
  timestamptz,boolean,boolean,text,text,text,text,integer
) to service_role;
revoke all on function public.service_enqueue_google_play_rtdn(text,text,integer,timestamptz,text,text,integer)
  from public, anon, authenticated, service_role;
grant execute on function public.service_enqueue_google_play_rtdn(text,text,integer,timestamptz,text,text,integer)
  to service_role;
revoke all on function public.service_record_google_play_voided_notification(text,text,text,timestamptz,text,text,integer)
  from public, anon, authenticated, service_role;
grant execute on function public.service_record_google_play_voided_notification(text,text,text,timestamptz,text,text,integer)
  to service_role;
revoke all on function public.service_claim_due_google_play_rtdn(integer)
  from public, anon, authenticated, service_role;
grant execute on function public.service_claim_due_google_play_rtdn(integer) to service_role;
revoke all on function public.service_finish_google_play_rtdn(text,uuid,text,text)
  from public, anon, authenticated, service_role;
grant execute on function public.service_finish_google_play_rtdn(text,uuid,text,text) to service_role;
revoke all on function public.service_list_google_play_reconcile_tokens(integer)
  from public, anon, authenticated, service_role;
grant execute on function public.service_list_google_play_reconcile_tokens(integer) to service_role;
revoke all on function public.service_defer_google_play_reconcile(text,boolean)
  from public, anon, authenticated, service_role;
grant execute on function public.service_defer_google_play_reconcile(text,boolean) to service_role;
revoke all on function public.service_get_google_play_voided_cursor()
  from public, anon, authenticated, service_role;
grant execute on function public.service_get_google_play_voided_cursor() to service_role;
revoke all on function public.service_advance_google_play_voided_cursor(text,text,bigint)
  from public, anon, authenticated, service_role;
grant execute on function public.service_advance_google_play_voided_cursor(text,text,bigint) to service_role;
revoke all on function public.service_reset_google_play_voided_cursor(text)
  from public, anon, authenticated, service_role;
grant execute on function public.service_reset_google_play_voided_cursor(text) to service_role;
revoke all on function public.service_prepare_google_play_organization_deletion(uuid,uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_prepare_google_play_organization_deletion(uuid,uuid,uuid) to service_role;
revoke all on function public.service_finalize_google_play_organization_deletion(uuid,uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_finalize_google_play_organization_deletion(uuid,uuid,uuid) to service_role;
revoke all on function public.service_purge_google_play_lifecycle_data()
  from public, anon, authenticated, service_role;
grant execute on function public.service_purge_google_play_lifecycle_data() to service_role;
revoke all on function public.service_begin_account_deletion_request(uuid,uuid,text,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_begin_account_deletion_request(uuid,uuid,text,uuid) to service_role;
revoke all on function public.service_complete_account_deletion_request(uuid,uuid,text)
  from public, anon, authenticated, service_role;
comment on function public.service_complete_account_deletion_request(uuid,uuid,text) is
  'Retired fail-closed surface. Only atomic member/org erasers may complete deletion receipts.';
revoke all on function public.service_get_account_deletion_receipt(uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_get_account_deletion_receipt(uuid,uuid) to service_role;
revoke all on function public.service_find_active_account_deletion_request(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_find_active_account_deletion_request(uuid) to service_role;
revoke all on function public.service_erase_organization_after_billing_finalize(uuid,uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_erase_organization_after_billing_finalize(uuid,uuid,uuid) to service_role;
revoke all on function public.service_abort_account_deletion_request(uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_abort_account_deletion_request(uuid,uuid) to service_role;
revoke all on function public.service_finalize_member_account_deletion(uuid,uuid,uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_finalize_member_account_deletion(uuid,uuid,uuid) to service_role;
revoke all on function public.service_claim_account_auth_cleanup(integer)
  from public, anon, authenticated, service_role;
grant execute on function public.service_claim_account_auth_cleanup(integer) to service_role;
revoke all on function public.service_finish_account_auth_cleanup(uuid,uuid,boolean,text)
  from public, anon, authenticated, service_role;
grant execute on function public.service_finish_account_auth_cleanup(uuid,uuid,boolean,text) to service_role;
revoke all on function public.service_release_organization_deletion_fence(uuid,uuid)
  from public, anon, authenticated, service_role;
comment on function public.service_release_organization_deletion_fence(uuid,uuid) is
  'Retired compatibility surface; no API role has EXECUTE. Use atomic abort before billing finalize.';
revoke all on function public.service_google_play_subscription_requires_cancellation(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_google_play_subscription_requires_cancellation(uuid) to service_role;
revoke all on function public.service_google_play_lifecycle_health()
  from public, anon, authenticated, service_role;
grant execute on function public.service_google_play_lifecycle_health() to service_role;

-- Retire the v1 write surface. Leaving EXECUTE for service_role would let a
-- stale worker bypass observation generations and deletion fences.
revoke all on function public.service_record_google_play_subscription(
  text,uuid,uuid,text,text,text,text,boolean,timestamptz,timestamptz,
  boolean,boolean,text,text,text
) from public, anon, authenticated, service_role;
comment on function public.service_record_google_play_subscription(
  text,uuid,uuid,text,text,text,text,boolean,timestamptz,timestamptz,
  boolean,boolean,text,text,text
) is 'RETIRED by lifecycle v2; no role has EXECUTE. Use observation-generation RPCs.';

comment on function public.service_claim_google_play_observation(text,text,uuid,uuid,uuid) is
  'Claims a two-minute, token-hash-only Publisher observation lease with a globally monotonic generation.';
comment on function public.service_record_google_play_observation_v2(
  text,uuid,bigint,text,uuid,uuid,uuid,text,text,text,text,timestamptz,text,text,timestamptz,
  timestamptz,boolean,boolean,text,text,text,text,integer
) is 'Applies only an exact active observation generation; lower/divergent responses cannot grant or ACK.';

commit;
