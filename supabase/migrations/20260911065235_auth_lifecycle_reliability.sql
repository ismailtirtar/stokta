-- Harden authentication/account lifecycle operations around external GoTrue
-- calls.  All state transitions below are service-only, tenant-bound and
-- retryable without storing raw OTPs, passwords or bearer tickets.

begin;

set local statement_timeout = '30s';
set local lock_timeout = '10s';

do $$
begin
  if to_regclass('public.profiles') is null
     or to_regclass('public.pending_account_registrations') is null
     or to_regclass('public.pending_recovery_email_verifications') is null
     or to_regclass('public.password_reset_challenges') is null
     or to_regclass('public.security_audit_events') is null then
    raise exception 'Auth lifecycle reliability migration requires the account-security schema';
  end if;
end;
$$;

-- Establish the durable organization-deletion fence before any auth routine
-- can reference it.  The later billing migration uses CREATE IF NOT EXISTS
-- and extends this exact schema, so sequential migration/function rollout has
-- no window where tenant writes either bypass the fence or fail on a missing
-- helper.
create table if not exists private.organization_deletion_fences (
  organization_id uuid primary key,
  request_id uuid not null unique,
  initiator_user_id uuid not null,
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  billing_finalized_at timestamptz,
  check (expires_at > created_at and expires_at <= created_at + interval '30 days')
);
alter table private.organization_deletion_fences enable row level security;
alter table private.organization_deletion_fences force row level security;
revoke all on table private.organization_deletion_fences
  from public, anon, authenticated, service_role;

-- Recovery-email verification can finish before the dedicated cleanup worker
-- migration is deployed.  Create its exact durable queue schema here so a
-- retired temporary Auth identity is never forgotten in that rollout window.
create table if not exists private.account_auth_cleanup_jobs (
  user_id uuid primary key,
  request_id uuid not null,
  state text not null default 'pending'
    check (state in ('pending','processing','completed','quarantined')),
  attempt_count integer not null default 0 check (attempt_count between 0 and 1000),
  next_attempt_at timestamptz not null default clock_timestamp(),
  lease_id uuid,
  lease_expires_at timestamptz,
  last_error_code text check (
    last_error_code is null or length(last_error_code) between 1 and 64
  ),
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  check ((lease_id is null) = (lease_expires_at is null)),
  check ((state in ('completed','quarantined')) = (completed_at is not null))
);
create index if not exists account_auth_cleanup_due_idx
  on private.account_auth_cleanup_jobs (next_attempt_at, created_at, user_id)
  where state in ('pending','processing');
alter table private.account_auth_cleanup_jobs enable row level security;
alter table private.account_auth_cleanup_jobs force row level security;
revoke all on table private.account_auth_cleanup_jobs
  from public, anon, authenticated, service_role;

-- A member deletion is committed in Postgres before the external Auth delete.
-- The receipt makes response-loss retries converge, while the cleanup queue
-- guarantees that both the member identity and any temporary recovery-email
-- identity remain discoverable until GoTrue confirms deletion.
create table if not exists private.coworker_deletion_receipts (
  request_id uuid primary key,
  organization_id uuid not null,
  actor_id uuid not null,
  target_user_id uuid not null unique,
  state text not null default 'prepared'
    check (state in ('prepared','completed')),
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  check ((state = 'completed') = (completed_at is not null))
);
create index if not exists coworker_deletion_receipts_org_idx
  on private.coworker_deletion_receipts (organization_id, created_at, request_id);
alter table private.coworker_deletion_receipts enable row level security;
alter table private.coworker_deletion_receipts force row level security;
revoke all on table private.coworker_deletion_receipts
  from public, anon, authenticated, service_role;

create or replace function private.assert_organization_not_deleting(
  p_organization_id uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_organization_id is null then
    raise exception 'İşletme kimliği gerekli' using errcode = '22023';
  end if;
  perform 1 from public.organizations
  where id = p_organization_id
  for update;
  if not found then
    raise exception 'İşletme bulunamadı' using errcode = '42501';
  end if;
  if exists (
    select 1 from private.organization_deletion_fences
    where organization_id = p_organization_id
  ) then
    raise exception 'İşletme silme işlemi devam ediyor' using errcode = '55000';
  end if;
end;
$$;
revoke all on function private.assert_organization_not_deleting(uuid)
  from public, anon, authenticated, service_role;

-- An expired registration is first claimed in Postgres.  The claiming request
-- may then delete the unverified Auth identity without racing a concurrent
-- registration finalizer into deleting a newly-live profile.
alter table public.pending_account_registrations
  add column if not exists cleanup_claimed_at timestamptz,
  add column if not exists request_id uuid;

update public.pending_account_registrations
set request_id = gen_random_uuid()
where request_id is null;

alter table public.pending_account_registrations
  alter column request_id set not null;

create unique index if not exists pending_account_registrations_request_id_idx
  on public.pending_account_registrations (request_id);

-- A request receipt is committed before calling GoTrue signUp.  The request ID
-- is also written into Auth user_metadata, allowing a retry to rediscover the
-- exact unconfirmed identity if the Edge invocation dies between systems.
create table if not exists public.pending_registration_intents (
  request_id uuid primary key,
  registration_kind text not null
    check (registration_kind in ('business_admin', 'coworker')),
  username text not null check (
    username = lower(username)
    and username ~ '^[a-z0-9][a-z0-9._-]{2,31}$'
  ),
  email text not null check (
    email = lower(email)
    and char_length(email) between 5 and 254
    and email !~ '@stokta[.]invalid$'
  ),
  display_name text not null check (char_length(display_name) between 1 and 80),
  organization_name text,
  organization_slug text,
  organization_id uuid references public.organizations(id) on delete restrict,
  created_by uuid references public.profiles(id) on delete restrict,
  requested_session_id uuid,
  ugc_terms_version text,
  auth_user_id uuid unique,
  cleanup_claimed_at timestamptz,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  constraint pending_registration_intents_expiry check (expires_at > created_at),
  constraint pending_registration_intents_shape check (
    (
      registration_kind = 'business_admin'
      and organization_name is not null
      and char_length(organization_name) between 2 and 100
      and organization_slug is not null
      and organization_slug ~ '^[a-z0-9][a-z0-9-]{2,47}$'
      and organization_id is null
      and created_by is null
      and requested_session_id is null
      and ugc_terms_version is not null
    )
    or (
      registration_kind = 'coworker'
      and organization_name is null
      and organization_slug is null
      and organization_id is not null
      and created_by is not null
      and requested_session_id is not null
      and ugc_terms_version is null
    )
  )
);

create unique index if not exists pending_registration_intents_email_idx
  on public.pending_registration_intents (email);
create unique index if not exists pending_registration_intents_username_idx
  on public.pending_registration_intents (username);
create index if not exists pending_registration_intents_expiry_idx
  on public.pending_registration_intents (expires_at);
alter table public.pending_registration_intents enable row level security;
revoke all on table public.pending_registration_intents from public, anon, authenticated;
grant select, insert, update, delete on table public.pending_registration_intents to service_role;

comment on column public.pending_account_registrations.cleanup_claimed_at is
  'Set under a row/Auth lock before an expired unverified identity is removed through the Admin API.';

-- Password reset tickets are opaque 256-bit values returned once to the
-- client.  Only a service-peppered SHA-256 digest is stored.  A short claim
-- lease bridges the non-transactional Auth Admin password update and makes an
-- identical HTTP retry safe.
alter table public.password_reset_challenges
  add column if not exists claim_hash text,
  add column if not exists claimed_at timestamptz,
  add column if not exists claim_expires_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'password_reset_claim_hash_format'
      and conrelid = 'public.password_reset_challenges'::regclass
  ) then
    alter table public.password_reset_challenges
      add constraint password_reset_claim_hash_format check (
        claim_hash is null or claim_hash ~ '^[a-f0-9]{64}$'
      );
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'password_reset_claim_shape'
      and conrelid = 'public.password_reset_challenges'::regclass
  ) then
    alter table public.password_reset_challenges
      add constraint password_reset_claim_shape check (
        (
          claim_hash is null
          and claimed_at is null
          and claim_expires_at is null
        )
        or (
          claim_hash is not null
          and claimed_at is not null
          and claim_expires_at is not null
          and claim_expires_at > claimed_at
          and claim_expires_at <= expires_at
        )
      );
  end if;
end;
$$;

-- Collapse any legacy duplicate open challenges before enforcing one current
-- ticket per identity.  Consumed audit rows are intentionally unaffected.
with ranked as (
  select ticket_hash,
         row_number() over (
           partition by user_id
           order by created_at desc, ticket_hash desc
         ) as ordinal
  from public.password_reset_challenges
  where consumed_at is null
)
delete from public.password_reset_challenges challenge
using ranked
where ranked.ticket_hash = challenge.ticket_hash
  and ranked.ordinal > 1;

create unique index if not exists password_reset_one_open_per_user_idx
  on public.password_reset_challenges (user_id)
  where consumed_at is null;

-- Recovery-email verification also uses a service-peppered digest of the OTP,
-- never the OTP itself.  The prepared marker allows an identical request to
-- resume after the OTP was consumed but before the cross-service update ended.
alter table public.pending_recovery_email_verifications
  add column if not exists request_id uuid,
  add column if not exists attempt_hash text,
  add column if not exists claim_expires_at timestamptz,
  add column if not exists prepared_at timestamptz;

update public.pending_recovery_email_verifications
set request_id = gen_random_uuid()
where request_id is null;
alter table public.pending_recovery_email_verifications
  alter column request_id set not null;
create unique index if not exists pending_recovery_email_request_id_idx
  on public.pending_recovery_email_verifications (request_id);

create table if not exists public.pending_recovery_email_intents (
  request_id uuid primary key,
  target_user_id uuid not null unique references auth.users(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete restrict,
  email text not null unique check (
    email = lower(email)
    and char_length(email) between 5 and 254
    and email !~ '@stokta[.]invalid$'
  ),
  requested_session_id uuid not null,
  verification_kind text not null check (
    verification_kind in ('temporary_signup', 'existing_identity')
  ),
  verification_user_id uuid unique,
  cleanup_claimed_at timestamptz,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 minutes'),
  check (expires_at > created_at),
  check (
    (verification_kind = 'existing_identity' and verification_user_id = target_user_id)
    or verification_kind = 'temporary_signup'
  )
);
create index if not exists pending_recovery_email_intents_expiry_idx
  on public.pending_recovery_email_intents (expires_at);
alter table public.pending_recovery_email_intents enable row level security;
revoke all on table public.pending_recovery_email_intents from public, anon, authenticated;
grant select, insert, update, delete on table public.pending_recovery_email_intents to service_role;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'pending_recovery_attempt_hash_format'
      and conrelid = 'public.pending_recovery_email_verifications'::regclass
  ) then
    alter table public.pending_recovery_email_verifications
      add constraint pending_recovery_attempt_hash_format check (
        attempt_hash is null or attempt_hash ~ '^[a-f0-9]{64}$'
      );
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'pending_recovery_claim_shape'
      and conrelid = 'public.pending_recovery_email_verifications'::regclass
  ) then
    alter table public.pending_recovery_email_verifications
      add constraint pending_recovery_claim_shape check (
        (attempt_hash is null and claim_expires_at is null and prepared_at is null)
        or (
          attempt_hash is not null
          and claim_expires_at is not null
          and claim_expires_at <= expires_at
          and (prepared_at is null or prepared_at <= expires_at)
        )
      );
  end if;
end;
$$;

-- Public is an exposed schema, but these tables are deliberately service-only:
-- RLS remains enabled and no end-user policy exists by design.
alter table public.auth_rate_limits enable row level security;
alter table public.password_reset_challenges enable row level security;
alter table public.pending_account_registrations enable row level security;
alter table public.pending_recovery_email_verifications enable row level security;
revoke all on table public.auth_rate_limits from public, anon, authenticated;
revoke all on table public.password_reset_challenges from public, anon, authenticated;
revoke all on table public.pending_account_registrations from public, anon, authenticated;
revoke all on table public.pending_recovery_email_verifications from public, anon, authenticated;
grant select, insert, update, delete on table public.auth_rate_limits to service_role;
grant select, insert, update, delete on table public.password_reset_challenges to service_role;
grant select, insert, update, delete on table public.pending_account_registrations to service_role;
grant select, insert, update, delete on table public.pending_recovery_email_verifications to service_role;

create or replace function public.service_issue_password_reset(
  p_ticket_hash text,
  p_user_id uuid,
  p_organization_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  locked_profile public.profiles;
begin
  if p_ticket_hash is null or p_ticket_hash !~ '^[a-f0-9]{64}$'
     or p_user_id is null or p_organization_id is null then
    return false;
  end if;

  perform private.assert_organization_not_deleting(p_organization_id);

  select * into locked_profile
  from public.profiles
  where id = p_user_id
    and organization_id = p_organization_id
    and is_active
    and recovery_email_verified_at is not null
  for update;

  if locked_profile.id is null then
    return false;
  end if;

  perform 1 from auth.users
  where id = p_user_id
  for update;
  if not found then
    return false;
  end if;

  delete from public.password_reset_challenges
  where user_id = p_user_id;

  insert into public.password_reset_challenges (
    ticket_hash, user_id, organization_id, expires_at
  ) values (
    p_ticket_hash, p_user_id, p_organization_id, now() + interval '10 minutes'
  );

  delete from public.password_reset_challenges
  where expires_at < now() - interval '1 day';

  return true;
end;
$$;

drop function if exists public.service_claim_password_reset(text);

create or replace function public.service_claim_password_reset(
  p_ticket_hash text,
  p_claim_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  challenge public.password_reset_challenges;
  locked_profile public.profiles;
  lease_end timestamptz;
  pre_organization_id uuid;
begin
  if p_ticket_hash is null or p_ticket_hash !~ '^[a-f0-9]{64}$'
     or p_claim_hash is null or p_claim_hash !~ '^[a-f0-9]{64}$' then
    return null;
  end if;

  select organization_id into pre_organization_id
  from public.password_reset_challenges
  where ticket_hash = p_ticket_hash;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into challenge
  from public.password_reset_challenges
  where ticket_hash = p_ticket_hash
  for update;

  if challenge.ticket_hash is not null
     and challenge.consumed_at is not null
     and challenge.claim_hash = p_claim_hash then
    return jsonb_build_object(
      'userId', challenge.user_id,
      'organizationId', challenge.organization_id,
      'completed', true
    );
  end if;

  if challenge.ticket_hash is null
     or challenge.consumed_at is not null
     or challenge.expires_at <= now() then
    return null;
  end if;
  if challenge.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  select * into locked_profile
  from public.profiles
  where id = challenge.user_id
    and organization_id = challenge.organization_id
    and is_active
  for update;
  if locked_profile.id is null then
    return null;
  end if;

  perform 1 from auth.users where id = challenge.user_id for update;
  if not found then
    return null;
  end if;

  if challenge.claim_hash is not null
     and challenge.claim_expires_at > now()
     and challenge.claim_hash <> p_claim_hash then
    return null;
  end if;

  -- There is no fencing token accepted by the Auth Admin password endpoint.
  -- Therefore a different password attempt must never overtake an in-flight
  -- writer; only the identical deterministic claim may retry until the ticket
  -- itself expires (or an explicit API failure releases it).
  lease_end := challenge.expires_at;
  update public.password_reset_challenges
  set claim_hash = p_claim_hash,
      claimed_at = case
        when claim_hash = p_claim_hash then coalesce(claimed_at, now())
        else now()
      end,
      claim_expires_at = lease_end
  where ticket_hash = p_ticket_hash;

  return jsonb_build_object(
    'userId', challenge.user_id,
    'organizationId', challenge.organization_id,
    'completed', false
  );
end;
$$;

create or replace function public.service_release_password_reset_claim(
  p_ticket_hash text,
  p_claim_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  changed integer;
begin
  update public.password_reset_challenges
  set claim_hash = null,
      claimed_at = null,
      claim_expires_at = null
  where ticket_hash = p_ticket_hash
    and claim_hash = p_claim_hash
    and consumed_at is null;
  get diagnostics changed = row_count;
  return changed = 1;
end;
$$;

create or replace function public.service_finish_password_reset(
  p_ticket_hash text,
  p_claim_hash text,
  p_user_id uuid,
  p_ip_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  challenge public.password_reset_challenges;
  locked_profile public.profiles;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.password_reset_challenges
  where ticket_hash = p_ticket_hash;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into challenge
  from public.password_reset_challenges
  where ticket_hash = p_ticket_hash
  for update;

  if p_ip_hash is not null and p_ip_hash !~ '^[a-f0-9]{64}$' then
    return false;
  end if;

  if challenge.ticket_hash is null
     or challenge.user_id <> p_user_id
     or challenge.consumed_at is not null
     or challenge.expires_at <= now()
     or challenge.claim_hash <> p_claim_hash
     or challenge.organization_id is distinct from pre_organization_id then
    return false;
  end if;

  select * into locked_profile
  from public.profiles
  where id = challenge.user_id
    and organization_id = challenge.organization_id
    and is_active
  for update;
  if locked_profile.id is null then
    return false;
  end if;

  perform 1 from auth.users where id = challenge.user_id for update;
  if not found then
    return false;
  end if;

  update public.password_reset_challenges
  set consumed_at = now()
  where ticket_hash = challenge.ticket_hash;

  delete from public.password_reset_challenges
  where user_id = challenge.user_id
    and ticket_hash <> challenge.ticket_hash;

  update public.profiles
  set must_change_password = false
  where id = challenge.user_id;

  delete from auth.sessions where user_id = challenge.user_id;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, ip_hash
  ) values (
    challenge.organization_id, challenge.user_id,
    challenge.user_id, 'password.reset_completed', p_ip_hash
  );

  return true;
end;
$$;

-- Reserve the exact payload before the external Auth sign-up.  A retry can
-- then rediscover and bind only the identity carrying the same unguessable
-- request ID in Auth user_metadata.
create or replace function public.service_begin_registration_intent(
  p_request_id uuid,
  p_registration_kind text,
  p_username text,
  p_email text,
  p_display_name text,
  p_organization_name text,
  p_organization_slug text,
  p_organization_id uuid,
  p_created_by uuid,
  p_requested_session_id uuid,
  p_ugc_terms_version text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_registration_intents;
  conflicting_intent public.pending_registration_intents;
  pending public.pending_account_registrations;
  conflicting_pending public.pending_account_registrations;
  caller public.profiles;
  organization public.organizations;
  reserved_seats integer;
begin
  if p_request_id is null
     or p_registration_kind not in ('business_admin', 'coworker')
     or p_username is null
     or p_username !~ '^[a-z0-9][a-z0-9._-]{2,31}$'
     or p_email is null
     or p_email <> lower(p_email)
     or p_email ~ '@stokta[.]invalid$'
     or char_length(p_email) not between 5 and 254
     or p_display_name is null
     or char_length(p_display_name) not between 1 and 80 then
    raise exception 'Geçersiz kayıt niyeti' using errcode = '22023';
  end if;

  -- Organization deletion takes the tenant row first. Match that global lock
  -- order before locking any child request row.
  if p_registration_kind = 'coworker' then
    if p_organization_id is null then
      raise exception 'Çalışan kayıt niyeti doğrulanamadı' using errcode = '22023';
    end if;
    perform private.assert_organization_not_deleting(p_organization_id);
  end if;

  select * into pending
  from public.pending_account_registrations
  where request_id = p_request_id
  for update;
  if pending.id is not null then
    if pending.registration_kind is distinct from p_registration_kind
       or pending.username is distinct from p_username
       or pending.email is distinct from p_email
       or pending.display_name is distinct from p_display_name
       or pending.organization_name is distinct from p_organization_name
       or pending.organization_slug is distinct from p_organization_slug
       or pending.organization_id is distinct from p_organization_id
       or pending.created_by is distinct from p_created_by
       or pending.ugc_terms_version is distinct from p_ugc_terms_version then
      raise exception 'İstek kimliği farklı bir kayıt için kullanılmış'
        using errcode = '23505';
    end if;
    return jsonb_build_object(
      'state', 'pending', 'requestId', pending.request_id,
      'authUserId', pending.auth_user_id,
      'acceptedAt', pending.ugc_terms_accepted_at,
      'organizationSlug', pending.organization_slug
    );
  end if;

  select * into intent
  from public.pending_registration_intents
  where request_id = p_request_id
  for update;
  if intent.request_id is not null then
    if intent.registration_kind is distinct from p_registration_kind
       or intent.username is distinct from p_username
       or intent.email is distinct from p_email
       or intent.display_name is distinct from p_display_name
       or intent.organization_name is distinct from p_organization_name
       or intent.organization_slug is distinct from p_organization_slug
       or intent.organization_id is distinct from p_organization_id
       or intent.created_by is distinct from p_created_by
       or intent.requested_session_id is distinct from p_requested_session_id
       or intent.ugc_terms_version is distinct from p_ugc_terms_version then
      raise exception 'İstek kimliği farklı bir kayıt için kullanılmış'
        using errcode = '23505';
    end if;
    if intent.cleanup_claimed_at is not null or intent.expires_at <= now() then
      return jsonb_build_object(
        'state', 'cleanup_required', 'requestId', intent.request_id,
        'authUserId', intent.auth_user_id
      );
    end if;
    return jsonb_build_object(
      'state', case when intent.auth_user_id is null then 'reserved' else 'bound' end,
      'requestId', intent.request_id,
      'authUserId', intent.auth_user_id,
      'acceptedAt', intent.created_at,
      'organizationSlug', intent.organization_slug
    );
  end if;

  -- Mobile processes can disappear after the durable reservation or pending
  -- row commits.  A new client-generated UUID may therefore represent the
  -- same exact operation.  Return the canonical receipt instead of leaving
  -- the username/e-mail unusable for the reservation lifetime.  The generated
  -- business slug is deliberately not compared because it contains that UUID;
  -- the committed canonical slug is returned to the Edge worker instead.
  select * into conflicting_pending
  from public.pending_account_registrations candidate
  where candidate.username = p_username or candidate.email = p_email
  order by candidate.created_at, candidate.request_id
  limit 1
  for update;
  if conflicting_pending.id is not null
     and conflicting_pending.expires_at > now()
     and conflicting_pending.cleanup_claimed_at is null then
    if conflicting_pending.registration_kind is not distinct from p_registration_kind
       and conflicting_pending.username is not distinct from p_username
       and conflicting_pending.email is not distinct from p_email
       and conflicting_pending.display_name is not distinct from p_display_name
       and conflicting_pending.organization_name is not distinct from p_organization_name
       and conflicting_pending.organization_id is not distinct from p_organization_id
       and conflicting_pending.created_by is not distinct from p_created_by
       and conflicting_pending.ugc_terms_version is not distinct from p_ugc_terms_version then
      return jsonb_build_object(
        'state', 'pending', 'requestId', conflicting_pending.request_id,
        'authUserId', conflicting_pending.auth_user_id,
        'acceptedAt', conflicting_pending.ugc_terms_accepted_at,
        'organizationSlug', conflicting_pending.organization_slug
      );
    end if;
    raise exception 'Kullanıcı adı veya e-posta için kayıt zaten bekleniyor'
      using errcode = '23505';
  end if;

  -- A different expired request may still own the unique username/e-mail
  -- reservation.  Ask the Edge worker to run the fenced cleanup first.
  select * into conflicting_intent
  from public.pending_registration_intents candidate
  where (candidate.username = p_username or candidate.email = p_email)
  order by candidate.created_at, candidate.request_id
  limit 1
  for update;
  if conflicting_intent.request_id is not null then
    if conflicting_intent.expires_at > now()
       and conflicting_intent.cleanup_claimed_at is null then
      if conflicting_intent.registration_kind is not distinct from p_registration_kind
         and conflicting_intent.username is not distinct from p_username
         and conflicting_intent.email is not distinct from p_email
         and conflicting_intent.display_name is not distinct from p_display_name
         and conflicting_intent.organization_name is not distinct from p_organization_name
         and conflicting_intent.organization_id is not distinct from p_organization_id
         and conflicting_intent.created_by is not distinct from p_created_by
         and conflicting_intent.requested_session_id is not distinct from p_requested_session_id
         and conflicting_intent.ugc_terms_version is not distinct from p_ugc_terms_version then
        return jsonb_build_object(
          'state', case when conflicting_intent.auth_user_id is null
            then 'reserved' else 'bound' end,
          'requestId', conflicting_intent.request_id,
          'authUserId', conflicting_intent.auth_user_id,
          'acceptedAt', conflicting_intent.created_at,
          'organizationSlug', conflicting_intent.organization_slug
        );
      end if;
      raise exception 'Kullanıcı adı veya e-posta için kayıt zaten bekleniyor'
        using errcode = '23505';
    end if;
    if conflicting_intent.auth_user_id is null then
      delete from public.pending_registration_intents
      where request_id = conflicting_intent.request_id;
    else
      return jsonb_build_object(
        'state', 'cleanup_required',
        'requestId', conflicting_intent.request_id,
        'authUserId', conflicting_intent.auth_user_id
      );
    end if;
  end if;

  if exists (
    select 1 from public.profiles profile where profile.username = p_username
  ) or exists (
    select 1 from public.pending_account_registrations registration
    where registration.username = p_username or registration.email = p_email
  ) then
    raise exception 'Kullanıcı adı veya e-posta kullanılıyor' using errcode = '23505';
  end if;

  if p_registration_kind = 'business_admin' then
    if p_organization_name is null
       or char_length(p_organization_name) not between 2 and 100
       or p_organization_slug is null
       or p_organization_slug !~ '^[a-z0-9][a-z0-9-]{2,47}$'
       or p_organization_id is not null
       or p_created_by is not null
       or p_requested_session_id is not null
       or p_ugc_terms_version is distinct from private.current_ugc_terms_version()
       or exists (
         select 1 from public.organizations existing
         where existing.slug = p_organization_slug
       ) then
      raise exception 'İşletme kayıt niyeti doğrulanamadı' using errcode = '22023';
    end if;
  else
    if p_organization_name is not null
       or p_organization_slug is not null
       or p_organization_id is null
       or p_created_by is null
       or p_requested_session_id is null
       or p_ugc_terms_version is not null then
      raise exception 'Çalışan kayıt niyeti doğrulanamadı' using errcode = '22023';
    end if;

    select * into organization
    from public.organizations
    where id = p_organization_id
    for update;
    select * into caller
    from public.profiles
    where id = p_created_by
      and organization_id = p_organization_id
      and role = 'admin'
      and is_active
      and not must_change_password
    for update;
    perform 1 from auth.sessions
    where id = p_requested_session_id and user_id = p_created_by
    for update;

    if organization.id is null or caller.id is null or not found then
      raise exception 'Çalışan kaydını oluşturan yönetici artık yetkili değil'
        using errcode = '42501';
    end if;
    if caller.ugc_terms_accepted_at is null
       or caller.ugc_terms_version is distinct from private.current_ugc_terms_version() then
      raise exception 'Yönetici güncel kullanıcı içeriği şartlarını kabul etmedi'
        using errcode = '42501';
    end if;
    if organization.subscription_status = 'trial'
       and coalesce(organization.trial_ends_at, '-infinity'::timestamptz) <= now() then
      raise exception 'Deneme süresi sona erdi' using errcode = '42501';
    end if;
    if organization.subscription_status = 'active'
       and organization.current_period_end is not null
       and organization.current_period_end <= now() then
      raise exception 'Kiralama dönemi sona erdi' using errcode = '42501';
    end if;
    if organization.subscription_status not in ('trial', 'active') then
      raise exception 'İşletme hesabı yeni çalışan eklemeye açık değil'
        using errcode = '42501';
    end if;

    select
      (select count(*) from public.profiles profile
       where profile.organization_id = organization.id and profile.is_active)
      +
      (select count(*) from public.pending_account_registrations registration
       where registration.organization_id = organization.id
         and registration.registration_kind = 'coworker'
         and registration.expires_at > now()
         and registration.cleanup_claimed_at is null)
      +
      (select count(*) from public.pending_registration_intents reservation
       where reservation.organization_id = organization.id
         and reservation.registration_kind = 'coworker'
         and reservation.expires_at > now()
         and reservation.cleanup_claimed_at is null)
    into reserved_seats;
    if reserved_seats >= organization.max_members then
      raise exception 'Kullanıcı limitine ulaşıldı (%)', organization.max_members
        using errcode = '23505';
    end if;
  end if;

  insert into public.pending_registration_intents (
    request_id, registration_kind, username, email, display_name,
    organization_name, organization_slug, organization_id, created_by,
    requested_session_id, ugc_terms_version
  ) values (
    p_request_id, p_registration_kind, p_username, p_email, p_display_name,
    p_organization_name, p_organization_slug, p_organization_id, p_created_by,
    p_requested_session_id, p_ugc_terms_version
  )
  returning * into intent;

  return jsonb_build_object(
    'state', 'reserved', 'requestId', intent.request_id,
    'authUserId', null, 'acceptedAt', intent.created_at,
    'organizationSlug', intent.organization_slug
  );
end;
$$;

create or replace function public.service_bind_registration_identity(
  p_request_id uuid,
  p_auth_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_registration_intents;
  auth_user auth.users;
  pre_kind text;
  pre_organization_id uuid;
begin
  select registration_kind, organization_id
    into pre_kind, pre_organization_id
  from public.pending_registration_intents
  where request_id = p_request_id;
  if pre_kind = 'coworker' then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_registration_intents
  where request_id = p_request_id for update;
  if intent.request_id is null
     or intent.cleanup_claimed_at is not null
     or intent.expires_at <= now() then
    return null;
  end if;
  if intent.auth_user_id is not null and intent.auth_user_id <> p_auth_user_id then
    return null;
  end if;
  if intent.registration_kind is distinct from pre_kind
     or intent.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  select * into auth_user from auth.users
  where id = p_auth_user_id for update;
  if auth_user.id is null
     or lower(auth_user.email) is distinct from intent.email
     or auth_user.created_at < intent.created_at - interval '1 minute'
     or auth_user.created_at > intent.expires_at
     or auth_user.raw_user_meta_data ->> 'stokta_registration_request_id'
          is distinct from p_request_id::text
     or (
       intent.registration_kind = 'coworker'
       and auth_user.raw_user_meta_data ->> 'organization_id'
         is distinct from intent.organization_id::text
     )
     or exists (select 1 from public.profiles where id = p_auth_user_id) then
    return null;
  end if;

  update public.pending_registration_intents
  set auth_user_id = p_auth_user_id
  where request_id = p_request_id and auth_user_id is null;

  return jsonb_build_object(
    'authUserId', auth_user.id,
    'emailConfirmed', auth_user.email_confirmed_at is not null,
    'createdAt', auth_user.created_at
  );
end;
$$;

create or replace function public.service_recover_registration_identity(
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_registration_intents;
  auth_user auth.users;
  pre_kind text;
  pre_organization_id uuid;
begin
  select registration_kind, organization_id
    into pre_kind, pre_organization_id
  from public.pending_registration_intents
  where request_id = p_request_id;
  if pre_kind = 'coworker' then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_registration_intents
  where request_id = p_request_id for update;
  if intent.request_id is null
     or intent.cleanup_claimed_at is not null
     or intent.expires_at <= now() then
    return null;
  end if;
  if intent.registration_kind is distinct from pre_kind
     or intent.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  if intent.auth_user_id is not null then
    select * into auth_user from auth.users
    where id = intent.auth_user_id for update;
  else
    select * into auth_user
    from auth.users candidate
    where lower(candidate.email) = intent.email
      and candidate.created_at >= intent.created_at - interval '1 minute'
      and candidate.created_at <= intent.expires_at
      and candidate.raw_user_meta_data ->> 'stokta_registration_request_id'
          = p_request_id::text
      and not exists (select 1 from public.profiles where id = candidate.id)
    order by candidate.created_at desc, candidate.id
    limit 1
    for update;
  end if;

  if auth_user.id is null
     or lower(auth_user.email) is distinct from intent.email
     or auth_user.raw_user_meta_data ->> 'stokta_registration_request_id'
          is distinct from p_request_id::text
     or (
       intent.registration_kind = 'coworker'
       and auth_user.raw_user_meta_data ->> 'organization_id'
         is distinct from intent.organization_id::text
     )
     or exists (select 1 from public.profiles where id = auth_user.id) then
    return null;
  end if;

  update public.pending_registration_intents
  set auth_user_id = auth_user.id
  where request_id = p_request_id and auth_user_id is null;

  return jsonb_build_object(
    'authUserId', auth_user.id,
    'emailConfirmed', auth_user.email_confirmed_at is not null,
    'createdAt', auth_user.created_at
  );
end;
$$;

create or replace function public.service_claim_registration_intent_cleanup(
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_registration_intents;
  auth_user auth.users;
  pre_kind text;
  pre_organization_id uuid;
begin
  select registration_kind, organization_id
    into pre_kind, pre_organization_id
  from public.pending_registration_intents
  where request_id = p_request_id;
  if pre_kind = 'coworker' then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_registration_intents
  where request_id = p_request_id for update;
  if intent.request_id is null then
    return jsonb_build_object('finished', true);
  end if;
  if intent.registration_kind is distinct from pre_kind
     or intent.organization_id is distinct from pre_organization_id then
    return null;
  end if;
  if exists (
    select 1 from public.pending_account_registrations
    where request_id = p_request_id
  ) then
    return null;
  end if;
  if intent.auth_user_id is null then
    delete from public.pending_registration_intents where request_id = p_request_id;
    return jsonb_build_object('finished', true);
  end if;

  select * into auth_user from auth.users
  where id = intent.auth_user_id for update;
  if auth_user.id is null then
    delete from public.pending_registration_intents where request_id = p_request_id;
    return jsonb_build_object('finished', true);
  end if;
  if exists (select 1 from public.profiles where id = intent.auth_user_id)
     or lower(auth_user.email) is distinct from intent.email
     or auth_user.raw_user_meta_data ->> 'stokta_registration_request_id'
          is distinct from p_request_id::text then
    return null;
  end if;

  update public.pending_registration_intents
  set cleanup_claimed_at = coalesce(cleanup_claimed_at, now())
  where request_id = p_request_id;
  return jsonb_build_object(
    'finished', false, 'userId', intent.auth_user_id,
    'email', intent.email
  );
end;
$$;

create or replace function public.service_finish_registration_intent_cleanup(
  p_request_id uuid,
  p_auth_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_registration_intents;
  pre_kind text;
  pre_organization_id uuid;
begin
  select registration_kind, organization_id
    into pre_kind, pre_organization_id
  from public.pending_registration_intents
  where request_id = p_request_id;
  if pre_kind = 'coworker' then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_registration_intents
  where request_id = p_request_id for update;
  if intent.request_id is null then
    return true;
  end if;
  if intent.registration_kind is distinct from pre_kind
     or intent.organization_id is distinct from pre_organization_id then
    return false;
  end if;
  if intent.auth_user_id is distinct from p_auth_user_id
     or intent.cleanup_claimed_at is null
     or exists (select 1 from auth.users where id = p_auth_user_id)
     or exists (select 1 from public.profiles where id = p_auth_user_id) then
    return false;
  end if;
  delete from public.pending_registration_intents where request_id = p_request_id;
  return true;
end;
$$;

create or replace function public.service_claim_expired_pending_registration(
  p_auth_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  pending public.pending_account_registrations;
  auth_user auth.users;
  pre_kind text;
  pre_organization_id uuid;
begin
  if p_auth_user_id is null then
    return null;
  end if;

  select registration_kind, organization_id
    into pre_kind, pre_organization_id
  from public.pending_account_registrations
  where auth_user_id = p_auth_user_id;
  if pre_kind = 'coworker' then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into pending
  from public.pending_account_registrations
  where auth_user_id = p_auth_user_id
  for update;

  if pending.id is null or pending.expires_at > now() then
    return null;
  end if;
  if pending.registration_kind is distinct from pre_kind
     or pending.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  if exists (select 1 from public.profiles where id = p_auth_user_id) then
    delete from public.pending_account_registrations where id = pending.id;
    return null;
  end if;

  select *
    into auth_user
  from auth.users
  where id = p_auth_user_id
  for update;

  if auth_user.id is null then
    delete from public.pending_account_registrations where id = pending.id;
    return null;
  end if;

  -- Never ask the Admin API to delete an identity unless both independent
  -- records agree that it is this exact unfinalized registration.
  if auth_user.raw_app_meta_data ->> 'stokta_pending_registration'
       is distinct from pending.registration_kind
     or auth_user.raw_app_meta_data ->> 'username'
       is distinct from pending.username
     or auth_user.raw_app_meta_data ->> 'stokta_registration_request_id'
       is distinct from pending.request_id::text
     or auth_user.raw_user_meta_data ->> 'stokta_registration_request_id'
       is distinct from pending.request_id::text then
    delete from public.pending_account_registrations where id = pending.id;
    return null;
  end if;

  update public.pending_account_registrations
  set cleanup_claimed_at = now()
  where id = pending.id;

  return jsonb_build_object(
    'claimed', true,
    'userId', pending.auth_user_id,
    'registrationKind', pending.registration_kind
  );
end;
$$;

create or replace function public.service_store_pending_registration(
  p_auth_user_id uuid,
  p_request_id uuid,
  p_registration_kind text,
  p_username text,
  p_email text,
  p_display_name text,
  p_organization_name text,
  p_organization_slug text,
  p_organization_id uuid,
  p_created_by uuid,
  p_ugc_terms_version text,
  p_ugc_terms_accepted_at timestamptz
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  auth_user auth.users;
  intent public.pending_registration_intents;
  existing_pending public.pending_account_registrations;
  caller public.profiles;
  organization public.organizations;
  pending_id uuid;
  reserved_seats integer;
begin
  if p_auth_user_id is null
     or p_request_id is null
     or p_registration_kind not in ('business_admin', 'coworker')
     or p_username is null
     or p_username !~ '^[a-z0-9][a-z0-9._-]{2,31}$'
     or p_email is null
     or p_email <> lower(p_email)
     or p_email ~ '@stokta[.]invalid$'
     or char_length(p_email) not between 5 and 254
     or p_display_name is null
     or char_length(p_display_name) not between 1 and 80 then
    raise exception 'Geçersiz kayıt bilgileri';
  end if;

  if p_registration_kind = 'coworker' then
    if p_organization_id is null then
      raise exception 'Çalışan kaydı tenant bilgileriyle eşleşmiyor';
    end if;
    perform private.assert_organization_not_deleting(p_organization_id);
  end if;

  select * into existing_pending
  from public.pending_account_registrations
  where request_id = p_request_id
  for update;
  if existing_pending.id is not null then
    if existing_pending.auth_user_id is distinct from p_auth_user_id
       or existing_pending.registration_kind is distinct from p_registration_kind
       or existing_pending.username is distinct from p_username
       or existing_pending.email is distinct from p_email
       or existing_pending.display_name is distinct from p_display_name
       or existing_pending.organization_name is distinct from p_organization_name
       or existing_pending.organization_slug is distinct from p_organization_slug
       or existing_pending.organization_id is distinct from p_organization_id
       or existing_pending.created_by is distinct from p_created_by
       or existing_pending.ugc_terms_version is distinct from p_ugc_terms_version then
      raise exception 'İstek kimliği farklı bir kayıt için kullanılmış'
        using errcode = '23505';
    end if;
    return existing_pending.id;
  end if;

  select * into intent
  from public.pending_registration_intents
  where request_id = p_request_id
  for update;
  if intent.request_id is null
     or intent.cleanup_claimed_at is not null
     or intent.expires_at <= now()
     or intent.auth_user_id is distinct from p_auth_user_id
     or intent.registration_kind is distinct from p_registration_kind
     or intent.username is distinct from p_username
     or intent.email is distinct from p_email
     or intent.display_name is distinct from p_display_name
     or intent.organization_name is distinct from p_organization_name
     or intent.organization_slug is distinct from p_organization_slug
     or intent.organization_id is distinct from p_organization_id
     or intent.created_by is distinct from p_created_by
     or intent.ugc_terms_version is distinct from p_ugc_terms_version then
    raise exception 'Kayıt niyeti bulunamadı veya bilgiler eşleşmiyor'
      using errcode = '55000';
  end if;

  select * into auth_user
  from auth.users
  where id = p_auth_user_id
  for update;

  if auth_user.id is null
     or lower(auth_user.email) <> p_email
     or auth_user.email_confirmed_at is not null
     or auth_user.created_at < intent.created_at - interval '1 minute'
     or auth_user.created_at > intent.expires_at
     or coalesce(auth_user.raw_app_meta_data ->> 'stokta_pending_registration', '')
        <> p_registration_kind
     or coalesce(auth_user.raw_app_meta_data ->> 'username', '') <> p_username
     or auth_user.raw_app_meta_data ->> 'stokta_registration_request_id'
          is distinct from p_request_id::text
     or auth_user.raw_user_meta_data ->> 'stokta_registration_request_id'
          is distinct from p_request_id::text then
    raise exception 'Bekleyen Auth kimliği kayıt bilgileriyle eşleşmiyor';
  end if;

  if exists (select 1 from public.profiles where id = p_auth_user_id) then
    raise exception 'Auth kimliği zaten etkin bir profile bağlı';
  end if;

  if p_registration_kind = 'business_admin' then
    if p_organization_name is null
       or char_length(p_organization_name) not between 2 and 100
       or p_organization_slug is null
       or p_organization_slug !~ '^[a-z0-9][a-z0-9-]{2,47}$'
       or p_organization_id is not null
       or p_created_by is not null
       or p_ugc_terms_version is distinct from private.current_ugc_terms_version()
       or p_ugc_terms_accepted_at is null
       or p_ugc_terms_accepted_at > now() + interval '1 minute' then
      raise exception 'İşletme kaydı şartları doğrulanamadı';
    end if;
  else
    if p_organization_name is not null
       or p_organization_slug is not null
       or p_organization_id is null
       or p_created_by is null
       or p_ugc_terms_version is not null
       or p_ugc_terms_accepted_at is not null
       or auth_user.raw_app_meta_data ->> 'organization_id'
          is distinct from p_organization_id::text
       or auth_user.raw_app_meta_data ->> 'created_by'
          is distinct from p_created_by::text then
      raise exception 'Çalışan kaydı tenant bilgileriyle eşleşmiyor';
    end if;

    select * into organization
    from public.organizations
    where id = p_organization_id
    for update;
    select * into caller
    from public.profiles
    where id = p_created_by
      and organization_id = p_organization_id
      and role = 'admin'
      and is_active
      and not must_change_password
    for update;

    if organization.id is null or caller.id is null then
      raise exception 'Çalışan kaydını oluşturan yönetici artık yetkili değil';
    end if;
    if caller.ugc_terms_accepted_at is null
       or caller.ugc_terms_version is distinct from private.current_ugc_terms_version() then
      raise exception 'Yönetici güncel kullanıcı içeriği şartlarını kabul etmedi';
    end if;
    if organization.subscription_status = 'trial'
       and coalesce(organization.trial_ends_at, '-infinity'::timestamptz) <= now() then
      raise exception 'Deneme süresi sona erdi';
    end if;
    if organization.subscription_status = 'active'
       and organization.current_period_end is not null
       and organization.current_period_end <= now() then
      raise exception 'Kiralama dönemi sona erdi';
    end if;
    if organization.subscription_status not in ('trial', 'active') then
      raise exception 'İşletme hesabı yeni çalışan eklemeye açık değil';
    end if;

    select
      (select count(*) from public.profiles p
       where p.organization_id = organization.id and p.is_active)
      +
      (select count(*) from public.pending_account_registrations r
       where r.organization_id = organization.id
         and r.registration_kind = 'coworker'
         and r.expires_at > now()
         and r.cleanup_claimed_at is null)
      +
      (select count(*) from public.pending_registration_intents reservation
       where reservation.organization_id = organization.id
         and reservation.registration_kind = 'coworker'
         and reservation.request_id <> p_request_id
         and reservation.expires_at > now()
         and reservation.cleanup_claimed_at is null)
    into reserved_seats;

    if reserved_seats >= organization.max_members then
      raise exception 'Kullanıcı limitine ulaşıldı (%).', organization.max_members;
    end if;
  end if;

  insert into public.pending_account_registrations (
    auth_user_id, request_id, registration_kind, username, email, display_name,
    organization_name, organization_slug, organization_id, created_by,
    ugc_terms_version, ugc_terms_accepted_at
  ) values (
    p_auth_user_id, p_request_id, p_registration_kind, p_username, p_email, p_display_name,
    p_organization_name, p_organization_slug, p_organization_id, p_created_by,
    p_ugc_terms_version,
    case when p_registration_kind = 'business_admin'
      then intent.created_at else null end
  )
  returning id into pending_id;

  delete from public.pending_registration_intents
  where request_id = p_request_id;

  return pending_id;
end;
$$;

create or replace function public.service_finalize_pending_registration(
  p_auth_user_id uuid,
  p_username text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  pending public.pending_account_registrations;
  existing_profile public.profiles;
  created_profile public.profiles;
  organization public.organizations;
  caller public.profiles;
  auth_user auth.users;
  active_seats integer;
  pre_kind text;
  pre_organization_id uuid;
begin
  if p_auth_user_id is null
     or p_username is null
     or p_username !~ '^[a-z0-9][a-z0-9._-]{2,31}$' then
    raise exception 'Geçersiz kayıt doğrulama bilgileri';
  end if;

  select registration_kind, organization_id
    into pre_kind, pre_organization_id
  from public.pending_account_registrations
  where auth_user_id = p_auth_user_id and username = p_username;
  if pre_kind = 'coworker' then
    perform private.assert_organization_not_deleting(pre_organization_id);
  elsif pre_kind is null then
    select organization_id into pre_organization_id
    from public.profiles
    where id = p_auth_user_id and username = p_username;
    if pre_organization_id is not null then
      perform private.assert_organization_not_deleting(pre_organization_id);
    end if;
  end if;

  select * into pending
  from public.pending_account_registrations
  where auth_user_id = p_auth_user_id
    and username = p_username
  for update;

  -- A committed response can be lost.  Reconstruct the same safe result from
  -- the profile/Auth pair instead of attempting a second insert.
  if pending.id is null then
    select * into existing_profile
    from public.profiles
    where id = p_auth_user_id and username = p_username
    for update;

    if existing_profile.id is null then
      raise exception 'Bekleyen doğrulama kaydı bulunamadı';
    end if;

    select * into auth_user from auth.users
    where id = existing_profile.id
    for update;
    select * into organization from public.organizations
    where id = existing_profile.organization_id;

    if auth_user.id is null
       or auth_user.email_confirmed_at is null
       or lower(auth_user.email) is distinct from existing_profile.recovery_email
       or organization.id is null then
      raise exception 'Tamamlanmış kayıt kimliği tutarsız';
    end if;

    return jsonb_build_object(
      'completed', true,
      'registrationKind', case when existing_profile.role = 'admin'
        then 'business_admin' else 'coworker' end,
      'organization', jsonb_build_object('id', organization.id, 'name', organization.name),
      'user', jsonb_build_object(
        'id', existing_profile.id,
        'username', existing_profile.username,
        'displayName', existing_profile.display_name,
        'mustChangePassword', existing_profile.must_change_password
      )
    );
  end if;

  if pending.registration_kind is distinct from pre_kind
     or pending.organization_id is distinct from pre_organization_id then
    raise exception 'Kayıt tenant bilgileri işlem sırasında değişti'
      using errcode = '40001';
  end if;

  if pending.cleanup_claimed_at is not null or pending.expires_at <= now() then
    raise exception 'Doğrulama isteğinin süresi doldu';
  end if;

  if pending.registration_kind = 'business_admin'
     and (pending.ugc_terms_accepted_at is null
       or pending.ugc_terms_version is distinct from private.current_ugc_terms_version()) then
    raise exception 'Güncel kullanıcı içeriği şartları kabul edilmedi';
  end if;
  if pending.ugc_terms_version is not null
     and pending.ugc_terms_version is distinct from private.current_ugc_terms_version() then
    raise exception 'Kayıt sırasında kabul edilen kullanıcı içeriği şartları artık güncel değil';
  end if;

  select * into auth_user
  from auth.users
  where id = pending.auth_user_id
  for update;

  if auth_user.id is null
     or auth_user.email_confirmed_at is null
     or lower(auth_user.email) <> pending.email
     or auth_user.raw_app_meta_data ->> 'stokta_pending_registration'
        is distinct from pending.registration_kind
     or auth_user.raw_app_meta_data ->> 'username'
        is distinct from pending.username
     or auth_user.raw_app_meta_data ->> 'stokta_registration_request_id'
        is distinct from pending.request_id::text
     or auth_user.raw_user_meta_data ->> 'stokta_registration_request_id'
        is distinct from pending.request_id::text then
    raise exception 'E-posta doğrulaması veya kayıt kimliği eşleşmedi';
  end if;

  if exists (select 1 from public.profiles where username = pending.username) then
    raise exception using errcode = '23505', message = 'Bu kullanıcı adı zaten kullanılıyor';
  end if;

  if pending.registration_kind = 'business_admin' then
    insert into public.organizations (
      name, slug, subscription_status, trial_ends_at,
      max_members, max_products, created_by
    ) values (
      pending.organization_name, pending.organization_slug, 'trial',
      now() + interval '14 days', 5, 1000, pending.auth_user_id
    ) returning * into organization;

    insert into public.profiles (
      id, organization_id, username, display_name, role, created_by,
      is_platform_operator, is_active, deactivated_at, must_change_password,
      recovery_email, recovery_email_verified_at,
      ugc_terms_version, ugc_terms_accepted_at
    ) values (
      pending.auth_user_id, organization.id, pending.username,
      pending.display_name, 'admin', null, false, true, null, false,
      pending.email, now(), pending.ugc_terms_version, pending.ugc_terms_accepted_at
    ) returning * into created_profile;
  else
    if auth_user.raw_app_meta_data ->> 'organization_id'
         is distinct from pending.organization_id::text
       or auth_user.raw_app_meta_data ->> 'created_by'
         is distinct from pending.created_by::text then
      raise exception 'Çalışan Auth kimliği tenant kaydıyla eşleşmedi';
    end if;

    select * into organization
    from public.organizations
    where id = pending.organization_id
    for update;
    select * into caller
    from public.profiles
    where id = pending.created_by
      and organization_id = pending.organization_id
      and role = 'admin'
      and is_active
      and not must_change_password
    for update;

    if organization.id is null or caller.id is null then
      raise exception 'Çalışanı oluşturan yönetici artık yetkili değil';
    end if;
    if caller.ugc_terms_accepted_at is null
       or caller.ugc_terms_version is distinct from private.current_ugc_terms_version() then
      raise exception 'Yönetici güncel kullanıcı içeriği şartlarını kabul etmedi';
    end if;
    if organization.subscription_status = 'trial'
       and coalesce(organization.trial_ends_at, '-infinity'::timestamptz) <= now() then
      raise exception 'Deneme süresi sona erdi';
    end if;
    if organization.subscription_status = 'active'
       and organization.current_period_end is not null
       and organization.current_period_end <= now() then
      raise exception 'Kiralama dönemi sona erdi';
    end if;
    if organization.subscription_status not in ('trial', 'active') then
      raise exception 'İşletme hesabı yeni çalışan eklemeye açık değil';
    end if;

    select count(*) into active_seats
    from public.profiles
    where organization_id = organization.id and is_active;
    if active_seats >= organization.max_members then
      raise exception 'Kullanıcı limitine ulaşıldı (%).', organization.max_members;
    end if;

    insert into public.profiles (
      id, organization_id, username, display_name, role, created_by,
      is_platform_operator, is_active, deactivated_at, must_change_password,
      recovery_email, recovery_email_verified_at,
      ugc_terms_version, ugc_terms_accepted_at
    ) values (
      pending.auth_user_id, organization.id, pending.username,
      pending.display_name, 'member', pending.created_by, false, true, null,
      true, pending.email, now(), pending.ugc_terms_version, pending.ugc_terms_accepted_at
    ) returning * into created_profile;
  end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    organization.id,
    case when pending.registration_kind = 'coworker'
      then pending.created_by else pending.auth_user_id end,
    pending.auth_user_id,
    case when pending.registration_kind = 'coworker'
      then 'coworker.registration_completed'
      else 'business.registration_completed' end,
    jsonb_build_object('username', pending.username)
  );

  if pending.ugc_terms_version is not null then
    insert into public.security_audit_events (
      organization_id, actor_id, subject_id, event_type, metadata
    ) values (
      organization.id, pending.auth_user_id, pending.auth_user_id,
      'ugc.terms.accepted',
      jsonb_build_object('version', pending.ugc_terms_version, 'source', 'registration')
    );
  end if;

  delete from public.pending_account_registrations where id = pending.id;

  return jsonb_build_object(
    'completed', true,
    'registrationKind', pending.registration_kind,
    'organization', jsonb_build_object(
      'id', organization.id, 'name', organization.name,
      'trialEndsAt', organization.trial_ends_at,
      'maxMembers', organization.max_members,
      'maxProducts', organization.max_products
    ),
    'user', jsonb_build_object(
      'id', created_profile.id, 'username', created_profile.username,
      'displayName', created_profile.display_name,
      'mustChangePassword', created_profile.must_change_password
    )
  );
end;
$$;

create or replace function public.service_begin_recovery_email_intent(
  p_request_id uuid,
  p_target_user_id uuid,
  p_organization_id uuid,
  p_requested_session_id uuid,
  p_email text,
  p_verification_kind text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  locked_profile public.profiles;
  target_auth auth.users;
  intent public.pending_recovery_email_intents;
  conflicting_intent public.pending_recovery_email_intents;
  pending public.pending_recovery_email_verifications;
begin
  if p_request_id is null
     or p_target_user_id is null
     or p_organization_id is null
     or p_requested_session_id is null
     or p_verification_kind not in ('temporary_signup', 'existing_identity')
     or p_email is null
     or p_email <> lower(p_email)
     or p_email ~ '@stokta[.]invalid$'
     or char_length(p_email) not between 5 and 254 then
    raise exception 'Geçersiz kurtarma e-postası niyeti' using errcode = '22023';
  end if;

  perform private.assert_organization_not_deleting(p_organization_id);
  select * into locked_profile from public.profiles
  where id = p_target_user_id
    and organization_id = p_organization_id
    and is_active
    and not must_change_password
  for update;
  perform 1 from auth.sessions
  where id = p_requested_session_id and user_id = p_target_user_id
  for update;
  select * into target_auth from auth.users
  where id = p_target_user_id for update;
  if locked_profile.id is null
     or target_auth.id is null
     or not exists (
       select 1 from auth.sessions
       where id = p_requested_session_id and user_id = p_target_user_id
     ) then
    raise exception 'Hesap veya oturum artık etkin değil' using errcode = '42501';
  end if;
  if (p_verification_kind = 'existing_identity') is distinct from (
    lower(target_auth.email) = p_email and target_auth.email_confirmed_at is not null
  ) then
    raise exception 'Kurtarma e-postası doğrulama türü eşleşmiyor'
      using errcode = '22023';
  end if;

  select * into pending from public.pending_recovery_email_verifications
  where request_id = p_request_id for update;
  if pending.target_user_id is not null then
    if pending.target_user_id is distinct from p_target_user_id
       or pending.organization_id is distinct from p_organization_id
       or pending.requested_session_id is distinct from p_requested_session_id
       or pending.email is distinct from p_email
       or pending.verification_kind is distinct from p_verification_kind then
      raise exception 'İstek kimliği farklı bir kurtarma e-postası için kullanılmış'
        using errcode = '23505';
    end if;
    return jsonb_build_object(
      'state', 'pending', 'requestId', pending.request_id,
      'verificationUserId', pending.verification_user_id,
      'verificationKind', pending.verification_kind
    );
  end if;

  select * into intent from public.pending_recovery_email_intents
  where target_user_id = p_target_user_id for update;
  if intent.request_id is not null then
    if intent.request_id = p_request_id then
      if intent.organization_id is distinct from p_organization_id
         or intent.requested_session_id is distinct from p_requested_session_id
         or intent.email is distinct from p_email
         or intent.verification_kind is distinct from p_verification_kind then
        raise exception 'İstek kimliği farklı bir kurtarma e-postası için kullanılmış'
          using errcode = '23505';
      end if;
      if intent.cleanup_claimed_at is not null or intent.expires_at <= now() then
        return jsonb_build_object(
          'state', 'cleanup_required', 'requestId', intent.request_id,
          'verificationUserId', intent.verification_user_id,
          'verificationKind', intent.verification_kind
        );
      end if;
      return jsonb_build_object(
        'state', case when intent.verification_user_id is null then 'reserved' else 'bound' end,
        'requestId', intent.request_id,
        'verificationUserId', intent.verification_user_id,
        'verificationKind', intent.verification_kind
      );
    end if;
    if intent.expires_at > now() and intent.cleanup_claimed_at is null then
      if intent.target_user_id is not distinct from p_target_user_id
         and intent.organization_id is not distinct from p_organization_id
         and intent.requested_session_id is not distinct from p_requested_session_id
         and intent.email is not distinct from p_email
         and intent.verification_kind is not distinct from p_verification_kind then
        return jsonb_build_object(
          'state', case when intent.verification_user_id is null
            then 'reserved' else 'bound' end,
          'requestId', intent.request_id,
          'verificationUserId', intent.verification_user_id,
          'verificationKind', intent.verification_kind
        );
      end if;
      raise exception 'Başka bir kurtarma e-postası doğrulaması hazırlanıyor'
        using errcode = '23505';
    end if;
    return jsonb_build_object(
      'state', 'cleanup_required', 'requestId', intent.request_id,
      'verificationUserId', intent.verification_user_id,
      'verificationKind', intent.verification_kind
    );
  end if;

  select * into conflicting_intent from public.pending_recovery_email_intents candidate
  where candidate.email = p_email
  limit 1 for update;
  if conflicting_intent.request_id is not null then
    if conflicting_intent.expires_at > now()
       and conflicting_intent.cleanup_claimed_at is null then
      if conflicting_intent.target_user_id is not distinct from p_target_user_id
         and conflicting_intent.organization_id is not distinct from p_organization_id
         and conflicting_intent.requested_session_id is not distinct from p_requested_session_id
         and conflicting_intent.email is not distinct from p_email
         and conflicting_intent.verification_kind is not distinct from p_verification_kind then
        return jsonb_build_object(
          'state', case when conflicting_intent.verification_user_id is null
            then 'reserved' else 'bound' end,
          'requestId', conflicting_intent.request_id,
          'verificationUserId', conflicting_intent.verification_user_id,
          'verificationKind', conflicting_intent.verification_kind
        );
      end if;
      raise exception 'E-posta için başka bir doğrulama hazırlanıyor'
        using errcode = '23505';
    end if;
    return jsonb_build_object(
      'state', 'cleanup_required', 'requestId', conflicting_intent.request_id,
      'verificationUserId', conflicting_intent.verification_user_id,
      'verificationKind', conflicting_intent.verification_kind
    );
  end if;

  insert into public.pending_recovery_email_intents (
    request_id, target_user_id, organization_id, email,
    requested_session_id, verification_kind, verification_user_id
  ) values (
    p_request_id, p_target_user_id, p_organization_id, p_email,
    p_requested_session_id, p_verification_kind,
    case when p_verification_kind = 'existing_identity' then p_target_user_id else null end
  ) returning * into intent;

  return jsonb_build_object(
    'state', case when intent.verification_user_id is null then 'reserved' else 'bound' end,
    'requestId', intent.request_id,
    'verificationUserId', intent.verification_user_id,
    'verificationKind', intent.verification_kind
  );
end;
$$;

create or replace function public.service_bind_recovery_email_identity(
  p_request_id uuid,
  p_verification_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_recovery_email_intents;
  verification_auth auth.users;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.pending_recovery_email_intents
  where request_id = p_request_id;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_recovery_email_intents
  where request_id = p_request_id for update;
  if intent.request_id is null
     or intent.verification_kind <> 'temporary_signup'
     or intent.cleanup_claimed_at is not null
     or intent.expires_at <= now()
     or (intent.verification_user_id is not null
         and intent.verification_user_id <> p_verification_user_id) then
    return null;
  end if;
  if intent.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  select * into verification_auth from auth.users
  where id = p_verification_user_id for update;
  if verification_auth.id is null
     or verification_auth.id = intent.target_user_id
     or lower(verification_auth.email) is distinct from intent.email
     or verification_auth.created_at < intent.created_at - interval '1 minute'
     or verification_auth.created_at > intent.expires_at
     or verification_auth.raw_user_meta_data ->> 'stokta_recovery_request_id'
          is distinct from p_request_id::text
     or verification_auth.raw_user_meta_data ->> 'target_user_id'
          is distinct from intent.target_user_id::text
     or exists (select 1 from public.profiles where id = verification_auth.id) then
    return null;
  end if;

  update public.pending_recovery_email_intents
  set verification_user_id = verification_auth.id
  where request_id = p_request_id and verification_user_id is null;
  return jsonb_build_object(
    'verificationUserId', verification_auth.id,
    'emailConfirmed', verification_auth.email_confirmed_at is not null
  );
end;
$$;

create or replace function public.service_recover_recovery_email_identity(
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_recovery_email_intents;
  verification_auth auth.users;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.pending_recovery_email_intents
  where request_id = p_request_id;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_recovery_email_intents
  where request_id = p_request_id for update;
  if intent.request_id is null
     or intent.cleanup_claimed_at is not null
     or intent.expires_at <= now() then
    return null;
  end if;
  if intent.organization_id is distinct from pre_organization_id then
    return null;
  end if;
  if intent.verification_kind = 'existing_identity' then
    return jsonb_build_object(
      'verificationUserId', intent.target_user_id, 'emailConfirmed', true
    );
  end if;

  if intent.verification_user_id is not null then
    select * into verification_auth from auth.users
    where id = intent.verification_user_id for update;
  else
    select * into verification_auth from auth.users candidate
    where lower(candidate.email) = intent.email
      and candidate.created_at >= intent.created_at - interval '1 minute'
      and candidate.created_at <= intent.expires_at
      and candidate.raw_user_meta_data ->> 'stokta_recovery_request_id'
          = p_request_id::text
      and candidate.raw_user_meta_data ->> 'target_user_id'
          = intent.target_user_id::text
      and not exists (select 1 from public.profiles where id = candidate.id)
    order by candidate.created_at desc, candidate.id
    limit 1 for update;
  end if;
  if verification_auth.id is null
     or verification_auth.id = intent.target_user_id
     or lower(verification_auth.email) is distinct from intent.email
     or verification_auth.raw_user_meta_data ->> 'stokta_recovery_request_id'
          is distinct from p_request_id::text
     or verification_auth.raw_user_meta_data ->> 'target_user_id'
          is distinct from intent.target_user_id::text
     or exists (select 1 from public.profiles where id = verification_auth.id) then
    return null;
  end if;

  update public.pending_recovery_email_intents
  set verification_user_id = verification_auth.id
  where request_id = p_request_id and verification_user_id is null;
  return jsonb_build_object(
    'verificationUserId', verification_auth.id,
    'emailConfirmed', verification_auth.email_confirmed_at is not null
  );
end;
$$;

create or replace function public.service_claim_recovery_email_intent_cleanup(
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_recovery_email_intents;
  verification_auth auth.users;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.pending_recovery_email_intents
  where request_id = p_request_id;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_recovery_email_intents
  where request_id = p_request_id for update;
  if intent.request_id is null then
    return jsonb_build_object('finished', true);
  end if;
  if intent.organization_id is distinct from pre_organization_id then
    return null;
  end if;
  if exists (
    select 1 from public.pending_recovery_email_verifications
    where request_id = p_request_id
  ) then
    return null;
  end if;
  if intent.verification_kind = 'existing_identity'
     or intent.verification_user_id is null then
    delete from public.pending_recovery_email_intents where request_id = p_request_id;
    return jsonb_build_object('finished', true);
  end if;

  select * into verification_auth from auth.users
  where id = intent.verification_user_id for update;
  if verification_auth.id is null then
    delete from public.pending_recovery_email_intents where request_id = p_request_id;
    return jsonb_build_object('finished', true);
  end if;
  if verification_auth.id = intent.target_user_id
     or lower(verification_auth.email) is distinct from intent.email
     or verification_auth.raw_user_meta_data ->> 'stokta_recovery_request_id'
          is distinct from p_request_id::text
     or verification_auth.raw_user_meta_data ->> 'target_user_id'
          is distinct from intent.target_user_id::text
     or exists (select 1 from public.profiles where id = verification_auth.id) then
    return null;
  end if;
  update public.pending_recovery_email_intents
  set cleanup_claimed_at = coalesce(cleanup_claimed_at, now())
  where request_id = p_request_id;
  return jsonb_build_object(
    'finished', false, 'userId', intent.verification_user_id,
    'targetUserId', intent.target_user_id, 'email', intent.email
  );
end;
$$;

create or replace function public.service_finish_recovery_email_intent_cleanup(
  p_request_id uuid,
  p_verification_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  intent public.pending_recovery_email_intents;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.pending_recovery_email_intents
  where request_id = p_request_id;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into intent from public.pending_recovery_email_intents
  where request_id = p_request_id for update;
  if intent.request_id is null then return true; end if;
  if intent.organization_id is distinct from pre_organization_id then return false; end if;
  if intent.verification_user_id is distinct from p_verification_user_id
     or intent.cleanup_claimed_at is null
     or exists (select 1 from auth.users where id = p_verification_user_id)
     or exists (select 1 from public.profiles where id = p_verification_user_id) then
    return false;
  end if;
  delete from public.pending_recovery_email_intents where request_id = p_request_id;
  return true;
end;
$$;

create or replace function public.service_retire_pending_recovery_email_verification(
  p_target_user_id uuid,
  p_requested_session_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  locked_profile public.profiles;
  pending public.pending_recovery_email_verifications;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.profiles
  where id = p_target_user_id and is_active;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into locked_profile
  from public.profiles
  where id = p_target_user_id and is_active
  for update;
  if locked_profile.id is null then
    return null;
  end if;

  if locked_profile.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  perform 1 from auth.sessions
  where id = p_requested_session_id and user_id = p_target_user_id
  for update;
  if not found then
    return null;
  end if;

  select * into pending
  from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id
  for update;
  if pending.target_user_id is null then
    return jsonb_build_object('retired', false);
  end if;
  if pending.prepared_at is not null and pending.expires_at > now() then
    raise exception 'Hazırlanmış e-posta doğrulaması değiştirilemez';
  end if;

  delete from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id;

  return jsonb_build_object(
    'retired', true,
    'verificationUserId', pending.verification_user_id,
    'verificationKind', pending.verification_kind,
    'email', pending.email
  );
end;
$$;

drop function if exists public.service_store_recovery_email_verification(uuid, uuid, uuid, text, text);

create or replace function public.service_store_recovery_email_verification(
  p_target_user_id uuid,
  p_request_id uuid,
  p_requested_session_id uuid,
  p_verification_user_id uuid,
  p_verification_kind text,
  p_email text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  locked_profile public.profiles;
  target_auth auth.users;
  verification_auth auth.users;
  intent public.pending_recovery_email_intents;
  existing_pending public.pending_recovery_email_verifications;
  pre_organization_id uuid;
begin
  if p_target_user_id is null
     or p_request_id is null
     or p_requested_session_id is null
     or p_verification_user_id is null
     or p_verification_kind not in ('temporary_signup', 'existing_identity')
     or p_email is null
     or p_email <> lower(p_email)
     or p_email ~ '@stokta[.]invalid$'
     or char_length(p_email) not between 5 and 254 then
    return false;
  end if;

  select organization_id into pre_organization_id
  from public.pending_recovery_email_verifications
  where request_id = p_request_id;
  if pre_organization_id is null then
    select organization_id into pre_organization_id
    from public.pending_recovery_email_intents
    where request_id = p_request_id;
  end if;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into existing_pending
  from public.pending_recovery_email_verifications
  where request_id = p_request_id
  for update;
  if existing_pending.target_user_id is not null then
    return existing_pending.target_user_id = p_target_user_id
      and existing_pending.requested_session_id = p_requested_session_id
      and existing_pending.verification_user_id = p_verification_user_id
      and existing_pending.verification_kind = p_verification_kind
      and existing_pending.email = p_email
      and existing_pending.expires_at > now();
  end if;

  select * into intent from public.pending_recovery_email_intents
  where request_id = p_request_id and target_user_id = p_target_user_id
  for update;
  if intent.request_id is null
     or intent.cleanup_claimed_at is not null
     or intent.expires_at <= now()
     or intent.requested_session_id <> p_requested_session_id
     or intent.verification_user_id is distinct from p_verification_user_id
     or intent.verification_kind <> p_verification_kind
     or intent.email <> p_email then
    return false;
  end if;

  if intent.organization_id is distinct from pre_organization_id then
    return false;
  end if;

  select * into locked_profile
  from public.profiles
  where id = p_target_user_id and is_active
  for update;
  if locked_profile.id is null then
    return false;
  end if;

  perform 1 from auth.sessions
  where id = p_requested_session_id and user_id = p_target_user_id
  for update;
  if not found then
    return false;
  end if;

  select * into target_auth
  from auth.users
  where id = p_target_user_id
  for update;
  select * into verification_auth
  from auth.users
  where id = p_verification_user_id
  for update;
  if target_auth.id is null or verification_auth.id is null then
    return false;
  end if;

  if p_verification_kind = 'existing_identity' then
    if p_verification_user_id <> p_target_user_id
       or lower(target_auth.email) <> p_email
       or target_auth.email_confirmed_at is null then
      return false;
    end if;
  else
    if p_verification_user_id = p_target_user_id
       or lower(verification_auth.email) <> p_email
       or verification_auth.email_confirmed_at is not null
       or verification_auth.created_at < intent.created_at - interval '1 minute'
       or verification_auth.created_at > intent.expires_at
       or verification_auth.raw_app_meta_data ->> 'stokta_verification_only'
          is distinct from 'true'
       or verification_auth.raw_app_meta_data ->> 'target_user_id'
          is distinct from p_target_user_id::text
       or verification_auth.raw_app_meta_data ->> 'stokta_recovery_request_id'
          is distinct from p_request_id::text
       or verification_auth.raw_user_meta_data ->> 'stokta_recovery_request_id'
          is distinct from p_request_id::text
       or verification_auth.raw_user_meta_data ->> 'target_user_id'
          is distinct from p_target_user_id::text then
      return false;
    end if;
  end if;

  insert into public.pending_recovery_email_verifications (
    target_user_id, request_id, verification_user_id, verification_kind,
    organization_id, email, requested_session_id
  ) values (
    p_target_user_id, p_request_id, p_verification_user_id, p_verification_kind,
    locked_profile.organization_id, p_email, p_requested_session_id
  );

  delete from public.pending_recovery_email_intents
  where request_id = p_request_id;

  return true;
end;
$$;

create or replace function public.service_claim_recovery_email_verification(
  p_target_user_id uuid,
  p_requested_session_id uuid,
  p_attempt_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  locked_profile public.profiles;
  pending public.pending_recovery_email_verifications;
  lease_end timestamptz;
  pre_organization_id uuid;
begin
  if p_target_user_id is null
     or p_requested_session_id is null
     or p_attempt_hash is null
     or p_attempt_hash !~ '^[a-f0-9]{64}$' then
    return null;
  end if;

  select organization_id into pre_organization_id
  from public.profiles
  where id = p_target_user_id and is_active;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into locked_profile
  from public.profiles
  where id = p_target_user_id and is_active
  for update;
  if locked_profile.id is null then
    return null;
  end if;

  if locked_profile.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  perform 1 from auth.sessions
  where id = p_requested_session_id and user_id = p_target_user_id
  for update;
  if not found then
    return null;
  end if;

  select * into pending
  from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id
  for update;

  if pending.target_user_id is null
     or pending.organization_id <> locked_profile.organization_id
     or pending.requested_session_id <> p_requested_session_id
     or pending.expires_at <= now() then
    return null;
  end if;

  if pending.attempt_hash is not null
     and pending.claim_expires_at > now()
     and pending.attempt_hash <> p_attempt_hash then
    return null;
  end if;

  -- Once prepared, only the exact OTP-derived attempt may resume even after
  -- the short lease.  Before preparation, an expired attempt can be replaced.
  if pending.prepared_at is not null and pending.attempt_hash <> p_attempt_hash then
    return null;
  end if;

  lease_end := least(pending.expires_at, now() + interval '2 minutes');
  update public.pending_recovery_email_verifications
  set attempt_hash = p_attempt_hash,
      claim_expires_at = lease_end
  where target_user_id = p_target_user_id;

  return jsonb_build_object(
    'requestId', pending.request_id,
    'targetUserId', pending.target_user_id,
    'organizationId', pending.organization_id,
    'verificationUserId', pending.verification_user_id,
    'verificationKind', pending.verification_kind,
    'email', pending.email,
    'prepared', pending.prepared_at is not null
  );
end;
$$;

create or replace function public.service_release_recovery_email_verification_claim(
  p_target_user_id uuid,
  p_attempt_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  changed integer;
begin
  update public.pending_recovery_email_verifications
  set attempt_hash = null,
      claim_expires_at = null
  where target_user_id = p_target_user_id
    and attempt_hash = p_attempt_hash
    and prepared_at is null;
  get diagnostics changed = row_count;
  return changed = 1;
end;
$$;

create or replace function public.service_prepare_recovery_email_verification(
  p_target_user_id uuid,
  p_verification_user_id uuid,
  p_attempt_hash text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  pending public.pending_recovery_email_verifications;
  verification_auth auth.users;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into pending
  from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id
  for update;

  if pending.target_user_id is null
     or pending.verification_user_id <> p_verification_user_id
     or pending.attempt_hash <> p_attempt_hash
     or pending.claim_expires_at <= now()
     or pending.expires_at <= now() then
    return false;
  end if;

  if pending.organization_id is distinct from pre_organization_id then
    return false;
  end if;

  if pending.prepared_at is not null then
    return true;
  end if;

  select * into verification_auth
  from auth.users
  where id = p_verification_user_id
  for update;
  if verification_auth.id is null
     or lower(verification_auth.email) <> pending.email
     or verification_auth.email_confirmed_at is null then
    return false;
  end if;

  if pending.verification_kind = 'temporary_signup'
     and (verification_auth.raw_app_meta_data ->> 'stokta_verification_only'
            is distinct from 'true'
       or verification_auth.raw_app_meta_data ->> 'target_user_id'
            is distinct from p_target_user_id::text
       or verification_auth.raw_app_meta_data ->> 'stokta_recovery_request_id'
            is distinct from pending.request_id::text
       or verification_auth.raw_user_meta_data ->> 'stokta_recovery_request_id'
            is distinct from pending.request_id::text
       or verification_auth.raw_user_meta_data ->> 'target_user_id'
            is distinct from p_target_user_id::text) then
    return false;
  end if;
  if pending.verification_kind = 'existing_identity'
     and p_verification_user_id <> p_target_user_id then
    return false;
  end if;

  update public.pending_recovery_email_verifications
  set prepared_at = now()
  where target_user_id = p_target_user_id;
  return true;
end;
$$;

create or replace function public.service_finish_recovery_email_verification(
  p_target_user_id uuid,
  p_attempt_hash text
)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  pending public.pending_recovery_email_verifications;
  locked_profile public.profiles;
  target_auth auth.users;
  verified_at timestamptz := now();
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.profiles
  where id = p_target_user_id and is_active;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into locked_profile
  from public.profiles
  where id = p_target_user_id and is_active
  for update;
  select * into pending
  from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id
  for update;

  if locked_profile.id is null
     or pending.target_user_id is null
     or pending.organization_id <> locked_profile.organization_id
     or pending.attempt_hash <> p_attempt_hash
     or pending.prepared_at is null
     or pending.expires_at <= now() then
    return null;
  end if;

  if locked_profile.organization_id is distinct from pre_organization_id then
    return null;
  end if;

  select * into target_auth
  from auth.users
  where id = p_target_user_id
  for update;
  if target_auth.id is null
     or lower(target_auth.email) <> pending.email
     or target_auth.email_confirmed_at is null then
    return null;
  end if;

  update public.profiles
  set recovery_email = pending.email,
      recovery_email_verified_at = verified_at
  where id = p_target_user_id;

  if pending.verification_kind = 'temporary_signup' then
    insert into private.account_auth_cleanup_jobs (
      user_id, request_id, state, next_attempt_at
    ) values (
      pending.verification_user_id, pending.request_id, 'pending', clock_timestamp()
    )
    on conflict (user_id) do nothing;
  end if;

  delete from auth.sessions where user_id = p_target_user_id;
  delete from public.pending_recovery_email_verifications
  where target_user_id = p_target_user_id;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type,
    metadata
  ) values (
    locked_profile.organization_id, p_target_user_id, p_target_user_id,
    'recovery_email.verified',
    jsonb_build_object('verificationKind', pending.verification_kind)
  );

  return verified_at;
end;
$$;

-- Coworker administration uses the same tenant-first lock order as the
-- durable organization-deletion saga.  These definitions replace legacy
-- routines that trusted an Edge precheck but did not fence concurrent erase.
create or replace function public.service_require_member_password_change(
  p_admin_id uuid,
  p_member_id uuid,
  p_session_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  pre_organization_id uuid;
  caller public.profiles;
  target public.profiles;
begin
  if p_session_id is null then
    raise exception 'Yönetici oturumu gerekli' using errcode = '42501';
  end if;
  select organization_id into pre_organization_id
  from public.profiles where id = p_admin_id;
  if pre_organization_id is null then
    raise exception 'Yetkisiz şifre yenileme isteği' using errcode = '42501';
  end if;
  perform private.assert_organization_not_deleting(pre_organization_id);

  select * into caller from public.profiles
  where id = p_admin_id
    and organization_id = pre_organization_id
    and role = 'admin' and is_active and not must_change_password
  for update;
  if caller.id is null then
    raise exception 'Yetkisiz çalışan şifre yenileme isteği' using errcode = '42501';
  end if;
  perform 1 from auth.sessions
  where id = p_session_id and user_id = p_admin_id
  for key share;
  if not found then
    raise exception 'Yönetici oturumu sona erdi' using errcode = '42501';
  end if;
  select * into target from public.profiles
  where id = p_member_id
    and organization_id = pre_organization_id
    and role = 'member'
  for update;
  if target.id is null then
    raise exception 'Yetkisiz çalışan şifre yenileme isteği' using errcode = '42501';
  end if;

  update public.profiles set must_change_password = true where id = target.id;
  delete from auth.sessions where user_id = target.id;
  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    pre_organization_id, caller.id, target.id, 'coworker.password_reset',
    jsonb_build_object('username', target.username)
  );
  return true;
end;
$$;

create or replace function public.service_set_member_active(
  p_admin_id uuid,
  p_member_id uuid,
  p_is_active boolean,
  p_session_id uuid
)
returns public.profiles
language plpgsql
security definer
set search_path = ''
as $$
declare
  pre_organization_id uuid;
  caller public.profiles;
  organization public.organizations;
  target public.profiles;
  active_seats integer;
  updated_profile public.profiles;
begin
  if p_session_id is null or p_is_active is null then
    raise exception 'Yönetici oturumu ve çalışan durumu gerekli'
      using errcode = '22023';
  end if;
  select organization_id into pre_organization_id
  from public.profiles where id = p_admin_id;
  if pre_organization_id is null then
    raise exception 'Yetkisiz çalışan yönetimi isteği' using errcode = '42501';
  end if;
  perform private.assert_organization_not_deleting(pre_organization_id);

  select * into organization from public.organizations
  where id = pre_organization_id for update;
  select * into caller from public.profiles
  where id = p_admin_id
    and organization_id = pre_organization_id
    and role = 'admin' and is_active and not must_change_password
  for update;
  if caller.id is null then
    raise exception 'Yetkisiz çalışan yönetimi isteği' using errcode = '42501';
  end if;
  perform 1 from auth.sessions
  where id = p_session_id and user_id = p_admin_id
  for key share;
  if not found then
    raise exception 'Yönetici oturumu sona erdi' using errcode = '42501';
  end if;
  select * into target from public.profiles
  where id = p_member_id
    and organization_id = pre_organization_id
    and role = 'member'
  for update;
  if organization.id is null or target.id is null then
    raise exception 'Yetkisiz çalışan yönetimi isteği' using errcode = '42501';
  end if;
  if target.is_active = p_is_active then return target; end if;

  if p_is_active then
    if organization.subscription_status = 'trial'
       and coalesce(organization.trial_ends_at, '-infinity'::timestamptz) <= now() then
      raise exception 'Deneme süresi sona erdi' using errcode = '42501';
    end if;
    if organization.subscription_status = 'active'
       and organization.current_period_end is not null
       and organization.current_period_end <= now() then
      raise exception 'Kiralama dönemi sona erdi' using errcode = '42501';
    end if;
    if organization.subscription_status not in ('trial', 'active') then
      raise exception 'İşletme hesabı çalışan etkinleştirmeye açık değil'
        using errcode = '42501';
    end if;
    select count(*) into active_seats from public.profiles
    where organization_id = pre_organization_id and is_active;
    if active_seats >= organization.max_members then
      raise exception 'Kullanıcı limitine ulaşıldı (%)', organization.max_members
        using errcode = '23505';
    end if;
  end if;

  update public.profiles
  set is_active = p_is_active,
      deactivated_at = case when p_is_active then null else now() end
  where id = target.id returning * into updated_profile;
  if not p_is_active then delete from auth.sessions where user_id = target.id; end if;
  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    pre_organization_id, caller.id, target.id,
    case when p_is_active then 'coworker.activated' else 'coworker.deactivated' end,
    jsonb_build_object('username', target.username)
  );
  return updated_profile;
end;
$$;

create or replace function public.service_prepare_member_deletion(
  p_admin_id uuid,
  p_member_id uuid,
  p_session_id uuid,
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  pre_organization_id uuid;
  caller public.profiles;
  target public.profiles;
  receipt private.coworker_deletion_receipts;
begin
  if p_session_id is null or p_request_id is null then
    raise exception 'Yönetici oturumu ve silme istek kimliği gerekli'
      using errcode = '22023';
  end if;
  select organization_id into pre_organization_id
  from public.profiles where id = p_admin_id;
  if pre_organization_id is null then
    raise exception 'Yetkisiz çalışan silme isteği' using errcode = '42501';
  end if;
  perform private.assert_organization_not_deleting(pre_organization_id);

  select * into caller from public.profiles
  where id = p_admin_id
    and organization_id = pre_organization_id
    and role = 'admin' and is_active and not must_change_password
  for update;
  if caller.id is null then
    raise exception 'Yetkisiz çalışan silme isteği' using errcode = '42501';
  end if;
  perform 1 from auth.sessions
  where id = p_session_id and user_id = p_admin_id
  for key share;
  if not found then
    raise exception 'Yönetici oturumu sona erdi' using errcode = '42501';
  end if;

  select * into receipt from private.coworker_deletion_receipts
  where target_user_id = p_member_id
  for update;
  if receipt.request_id is not null then
    if receipt.organization_id is distinct from pre_organization_id then
      raise exception 'Yetkisiz çalışan silme isteği' using errcode = '42501';
    end if;
    return jsonb_build_object(
      'requestId', receipt.request_id,
      'targetUserId', receipt.target_user_id,
      'state', receipt.state
    );
  end if;

  select * into target from public.profiles
  where id = p_member_id
    and organization_id = pre_organization_id
    and role = 'member'
  for update;
  if target.id is null then
    raise exception 'Yetkisiz çalışan silme isteği' using errcode = '42501';
  end if;

  -- The target row serializes two first-time deletion requests. Recheck the
  -- receipt after taking it so both requests converge on one canonical UUID.
  select * into receipt from private.coworker_deletion_receipts
  where target_user_id = p_member_id
  for update;
  if receipt.request_id is not null then
    return jsonb_build_object(
      'requestId', receipt.request_id,
      'targetUserId', receipt.target_user_id,
      'state', receipt.state
    );
  end if;
  if exists (
    select 1 from private.coworker_deletion_receipts
    where request_id = p_request_id and target_user_id <> p_member_id
  ) then
    raise exception 'Silme istek kimliği farklı bir çalışan için kullanılmış'
      using errcode = '23505';
  end if;

  insert into private.coworker_deletion_receipts (
    request_id, organization_id, actor_id, target_user_id
  ) values (
    p_request_id, pre_organization_id, p_admin_id, p_member_id
  ) returning * into receipt;

  insert into private.account_auth_cleanup_jobs (
    user_id, request_id, state, next_attempt_at
  ) values (
    target.id, receipt.request_id, 'pending', clock_timestamp()
  ) on conflict (user_id) do nothing;

  -- Preserve every temporary recovery identity before target/profile cascades
  -- can remove the only database reference. The metadata join also recovers a
  -- GoTrue sign-up created immediately before an Edge invocation crashed.
  with temporary_identities as (
    select pending.verification_user_id as user_id, pending.request_id
    from public.pending_recovery_email_verifications pending
    where pending.target_user_id = target.id
      and pending.verification_kind = 'temporary_signup'
      and pending.verification_user_id <> target.id
    union
    select intent.verification_user_id, intent.request_id
    from public.pending_recovery_email_intents intent
    where intent.target_user_id = target.id
      and intent.verification_kind = 'temporary_signup'
      and intent.verification_user_id is not null
      and intent.verification_user_id <> target.id
    union
    select candidate.id, intent.request_id
    from public.pending_recovery_email_intents intent
    join auth.users candidate
      on candidate.raw_user_meta_data ->> 'stokta_recovery_request_id'
           = intent.request_id::text
     and candidate.raw_user_meta_data ->> 'target_user_id' = target.id::text
     and lower(candidate.email) = intent.email
    where intent.target_user_id = target.id
      and intent.verification_kind = 'temporary_signup'
      and candidate.id <> target.id
      and not exists (select 1 from public.profiles p where p.id = candidate.id)
  )
  insert into private.account_auth_cleanup_jobs (
    user_id, request_id, state, next_attempt_at
  )
  select user_id, request_id, 'pending', clock_timestamp()
  from temporary_identities
  where user_id is not null
  on conflict (user_id) do nothing;

  update public.stock_movements
  set actor_id = null, actor_name = 'Silinmiş kullanıcı'
  where organization_id = pre_organization_id and actor_id = target.id;
  update public.products set created_by = caller.id
  where organization_id = pre_organization_id and created_by = target.id;
  update public.profiles set created_by = caller.id
  where organization_id = pre_organization_id and created_by = target.id;
  update public.profiles
  set is_active = false,
      deactivated_at = coalesce(deactivated_at, now()),
      must_change_password = true
  where id = target.id;
  delete from auth.sessions where user_id = target.id;
  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    pre_organization_id, caller.id, target.id, 'coworker.deletion_prepared',
    jsonb_build_object('username', target.username, 'requestId', receipt.request_id)
  );
  return jsonb_build_object(
    'requestId', receipt.request_id,
    'targetUserId', target.id,
    'state', receipt.state
  );
end;
$$;

create or replace function public.service_complete_member_deletion(
  p_admin_id uuid,
  p_member_id uuid,
  p_session_id uuid,
  p_request_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  pre_organization_id uuid;
  caller public.profiles;
  receipt private.coworker_deletion_receipts;
begin
  select organization_id into pre_organization_id
  from public.profiles where id = p_admin_id;
  if pre_organization_id is null then
    raise exception 'Yetkisiz çalışan silme isteği' using errcode = '42501';
  end if;
  perform private.assert_organization_not_deleting(pre_organization_id);
  select * into caller from public.profiles
  where id = p_admin_id
    and organization_id = pre_organization_id
    and role = 'admin' and is_active and not must_change_password
  for update;
  if caller.id is null then
    raise exception 'Yetkisiz çalışan silme isteği' using errcode = '42501';
  end if;
  perform 1 from auth.sessions
  where id = p_session_id and user_id = p_admin_id
  for key share;
  if not found then
    raise exception 'Yönetici oturumu sona erdi' using errcode = '42501';
  end if;
  select * into receipt from private.coworker_deletion_receipts
  where target_user_id = p_member_id
  for update;
  if receipt.request_id is null
     or receipt.organization_id is distinct from pre_organization_id
     or receipt.request_id is distinct from p_request_id then
    return false;
  end if;
  update private.coworker_deletion_receipts
  set state = 'completed', completed_at = coalesce(completed_at, clock_timestamp())
  where request_id = receipt.request_id;
  delete from public.profiles
  where id = p_member_id
    and organization_id = pre_organization_id
    and role = 'member'
    and not is_active;
  return true;
end;
$$;

-- Revocation is idempotent for a missing session, but fails closed if the same
-- session UUID belongs to another user.
create or replace function public.service_revoke_session(
  p_user_id uuid,
  p_session_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  session_owner uuid;
begin
  if p_user_id is null or p_session_id is null then
    return false;
  end if;

  select user_id into session_owner
  from auth.sessions
  where id = p_session_id
  for update;
  if not found then
    return true;
  end if;
  if session_owner <> p_user_id then
    return false;
  end if;

  delete from auth.sessions where id = p_session_id;
  return true;
end;
$$;

create or replace function public.service_complete_password_change(p_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  locked_profile public.profiles;
  pre_organization_id uuid;
begin
  select organization_id into pre_organization_id
  from public.profiles
  where id = p_user_id and is_active;
  if pre_organization_id is not null then
    perform private.assert_organization_not_deleting(pre_organization_id);
  end if;

  select * into locked_profile
  from public.profiles
  where id = p_user_id and is_active
  for update;
  if locked_profile.id is null then
    raise exception 'Etkin kullanıcı profili bulunamadı';
  end if;

  if locked_profile.organization_id is distinct from pre_organization_id then
    raise exception 'Hesap tenant bilgileri işlem sırasında değişti'
      using errcode = '40001';
  end if;

  perform 1 from auth.users where id = p_user_id for update;
  if not found then
    raise exception 'Auth kimliği bulunamadı';
  end if;

  update public.profiles
  set must_change_password = false
  where id = p_user_id;
  delete from auth.sessions where user_id = p_user_id;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type
  ) values (
    locked_profile.organization_id, p_user_id, p_user_id, 'password.changed'
  );
  return true;
end;
$$;

-- SECURITY DEFINER functions in an exposed schema receive PUBLIC EXECUTE by
-- default.  Revoke it explicitly; only the backend service client may bridge
-- Auth and application state.
revoke all on function public.service_issue_password_reset(text, uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_claim_password_reset(text, text)
  from public, anon, authenticated;
revoke all on function public.service_release_password_reset_claim(text, text)
  from public, anon, authenticated;
revoke all on function public.service_finish_password_reset(text, text, uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_claim_expired_pending_registration(uuid)
  from public, anon, authenticated;
revoke all on function public.service_begin_registration_intent(
  uuid, text, text, text, text, text, text, uuid, uuid, uuid, text
) from public, anon, authenticated;
revoke all on function public.service_bind_registration_identity(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_recover_registration_identity(uuid)
  from public, anon, authenticated;
revoke all on function public.service_claim_registration_intent_cleanup(uuid)
  from public, anon, authenticated;
revoke all on function public.service_finish_registration_intent_cleanup(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_store_pending_registration(
  uuid, uuid, text, text, text, text, text, text, uuid, uuid, text, timestamptz
) from public, anon, authenticated;
revoke all on function public.service_finalize_pending_registration(uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_retire_pending_recovery_email_verification(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_begin_recovery_email_intent(uuid, uuid, uuid, uuid, text, text)
  from public, anon, authenticated;
revoke all on function public.service_bind_recovery_email_identity(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_recover_recovery_email_identity(uuid)
  from public, anon, authenticated;
revoke all on function public.service_claim_recovery_email_intent_cleanup(uuid)
  from public, anon, authenticated;
revoke all on function public.service_finish_recovery_email_intent_cleanup(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_store_recovery_email_verification(uuid, uuid, uuid, uuid, text, text)
  from public, anon, authenticated;
revoke all on function public.service_claim_recovery_email_verification(uuid, uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_release_recovery_email_verification_claim(uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_prepare_recovery_email_verification(uuid, uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_finish_recovery_email_verification(uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_mark_recovery_email_verified(uuid, text)
  from public, anon, authenticated, service_role;
revoke all on function public.service_revoke_session(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_complete_password_change(uuid)
  from public, anon, authenticated;
revoke all on function public.service_require_member_password_change(uuid, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.service_set_member_active(uuid, uuid, boolean)
  from public, anon, authenticated, service_role;
revoke all on function public.service_prepare_member_deletion(uuid, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.service_require_member_password_change(uuid, uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_set_member_active(uuid, uuid, boolean, uuid)
  from public, anon, authenticated;
revoke all on function public.service_prepare_member_deletion(uuid, uuid, uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_complete_member_deletion(uuid, uuid, uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_create_member_profile(uuid, uuid, text, text, uuid)
  from public, anon, authenticated, service_role;

grant execute on function public.service_issue_password_reset(text, uuid, uuid)
  to service_role;
grant execute on function public.service_claim_password_reset(text, text)
  to service_role;
grant execute on function public.service_release_password_reset_claim(text, text)
  to service_role;
grant execute on function public.service_finish_password_reset(text, text, uuid, text)
  to service_role;
grant execute on function public.service_claim_expired_pending_registration(uuid)
  to service_role;
grant execute on function public.service_begin_registration_intent(
  uuid, text, text, text, text, text, text, uuid, uuid, uuid, text
) to service_role;
grant execute on function public.service_bind_registration_identity(uuid, uuid)
  to service_role;
grant execute on function public.service_recover_registration_identity(uuid)
  to service_role;
grant execute on function public.service_claim_registration_intent_cleanup(uuid)
  to service_role;
grant execute on function public.service_finish_registration_intent_cleanup(uuid, uuid)
  to service_role;
grant execute on function public.service_store_pending_registration(
  uuid, uuid, text, text, text, text, text, text, uuid, uuid, text, timestamptz
) to service_role;
grant execute on function public.service_finalize_pending_registration(uuid, text)
  to service_role;
grant execute on function public.service_retire_pending_recovery_email_verification(uuid, uuid)
  to service_role;
grant execute on function public.service_begin_recovery_email_intent(uuid, uuid, uuid, uuid, text, text)
  to service_role;
grant execute on function public.service_bind_recovery_email_identity(uuid, uuid)
  to service_role;
grant execute on function public.service_recover_recovery_email_identity(uuid)
  to service_role;
grant execute on function public.service_claim_recovery_email_intent_cleanup(uuid)
  to service_role;
grant execute on function public.service_finish_recovery_email_intent_cleanup(uuid, uuid)
  to service_role;
grant execute on function public.service_store_recovery_email_verification(uuid, uuid, uuid, uuid, text, text)
  to service_role;
grant execute on function public.service_claim_recovery_email_verification(uuid, uuid, text)
  to service_role;
grant execute on function public.service_release_recovery_email_verification_claim(uuid, text)
  to service_role;
grant execute on function public.service_prepare_recovery_email_verification(uuid, uuid, text)
  to service_role;
grant execute on function public.service_finish_recovery_email_verification(uuid, text)
  to service_role;
grant execute on function public.service_revoke_session(uuid, uuid)
  to service_role;
grant execute on function public.service_complete_password_change(uuid)
  to service_role;
grant execute on function public.service_require_member_password_change(uuid, uuid, uuid)
  to service_role;
grant execute on function public.service_set_member_active(uuid, uuid, boolean, uuid)
  to service_role;
grant execute on function public.service_prepare_member_deletion(uuid, uuid, uuid, uuid)
  to service_role;
grant execute on function public.service_complete_member_deletion(uuid, uuid, uuid, uuid)
  to service_role;

comment on function public.service_issue_password_reset(text, uuid, uuid) is
  'Atomically replaces a user reset ticket with a service-peppered digest.';
comment on function public.service_claim_password_reset(text, text) is
  'Leases a reset ticket to one deterministic retry identity before the external Auth update.';
comment on function public.service_finish_password_reset(text, text, uuid, text) is
  'Atomically consumes a claimed reset ticket, unlocks the profile and revokes all sessions.';
comment on function public.service_begin_registration_intent(
  uuid, text, text, text, text, text, text, uuid, uuid, uuid, text
) is 'Commits an idempotent registration payload and tenant/seat reservation before external Auth sign-up.';
comment on function public.service_recover_registration_identity(uuid) is
  'Recovers only the fresh unprofiled Auth identity carrying the exact registration request UUID.';
comment on function public.service_begin_recovery_email_intent(uuid, uuid, uuid, uuid, text, text) is
  'Commits the exact recovery-email payload before creating an isolated Auth verification identity.';
comment on function public.service_finalize_pending_registration(uuid, text) is
  'Finalizes an email-confirmed registration under pending/Auth/tenant locks with an idempotent result.';
comment on function public.service_finish_recovery_email_verification(uuid, text) is
  'Commits a prepared recovery-email change only after the target Auth identity matches the verified address.';
comment on table public.pending_registration_intents is
  'Service-only, policy-free RLS request receipts committed before external Auth registration calls.';
comment on table public.pending_recovery_email_intents is
  'Service-only, policy-free RLS request receipts committed before isolated recovery-email Auth sign-up.';
comment on table private.organization_deletion_fences is
  'Durable service-only tenant write fence; rows remain authoritative until explicit deletion abort/finalization.';
comment on table private.coworker_deletion_receipts is
  'Service-only idempotency receipts for fence-first member deletion and durable Auth cleanup.';

commit;
