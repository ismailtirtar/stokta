-- Product-grade account security, verified-email onboarding and tenant-scoped
-- coworker lifecycle management. Pending and audit data are service-role only.

begin;

set local statement_timeout = '30s';

create index if not exists signup_rate_limits_updated_at_idx
  on public.signup_rate_limits (updated_at);

create or replace function public.consume_signup_rate_limit(p_key_hash text)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  current_attempts integer;
begin
  if p_key_hash is null or p_key_hash !~ '^[a-f0-9]{64}$' then
    return false;
  end if;

  insert into public.signup_rate_limits as limits (
    key_hash, window_started_at, attempts, updated_at
  ) values (p_key_hash, now(), 1, now())
  on conflict (key_hash) do update
  set window_started_at = case
        when limits.window_started_at <= now() - interval '1 hour' then now()
        else limits.window_started_at
      end,
      attempts = case
        when limits.window_started_at <= now() - interval '1 hour' then 1
        else limits.attempts + 1
      end,
      updated_at = now()
  returning attempts into current_attempts;

  if random() < 0.01 then
    delete from public.signup_rate_limits
    where updated_at < now() - interval '24 hours';
  end if;

  return current_attempts <= 5;
end;
$$;

alter table public.profiles add column if not exists is_active boolean not null default true;
alter table public.profiles add column if not exists deactivated_at timestamptz;
alter table public.profiles add column if not exists must_change_password boolean not null default false;
alter table public.profiles add column if not exists recovery_email text;
alter table public.profiles add column if not exists recovery_email_verified_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'profiles_recovery_email_normalized_check'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_recovery_email_normalized_check check (
        recovery_email is null
        or (
          recovery_email = lower(recovery_email)
          and char_length(recovery_email) between 5 and 254
          and recovery_email !~ '@stokta[.]invalid$'
        )
      );
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'profiles_activation_state_check'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_activation_state_check check (
        (is_active and deactivated_at is null)
        or (not is_active and deactivated_at is not null)
      );
  end if;
end;
$$;

create index if not exists profiles_organization_members_active_idx
  on public.profiles (organization_id, is_active, created_at, id)
  where role = 'member';

create unique index if not exists profiles_recovery_email_unique_idx
  on public.profiles (recovery_email)
  where recovery_email is not null;

-- Existing accounts with a real, already-confirmed Auth address can use it
-- immediately. Legacy username-only @stokta.invalid accounts stay unverified
-- until the owner proves control of a real address through the OTP flow.
update public.profiles p
set recovery_email = lower(u.email),
    recovery_email_verified_at = u.email_confirmed_at
from auth.users u
where u.id = p.id
  and u.email_confirmed_at is not null
  and u.email is not null
  and lower(u.email) !~ '@stokta[.]invalid$';

-- A deleted Auth identity must not leave a tenant profile able to satisfy RLS.
-- All application references are prepared/anonymized before Admin API deletion.
alter table public.profiles drop constraint if exists profiles_id_fkey;
alter table public.profiles
  add constraint profiles_id_fkey
  foreign key (id) references auth.users(id) on delete cascade;

create table if not exists public.auth_rate_limits (
  scope text not null,
  key_hash text not null,
  window_started_at timestamptz not null default now(),
  attempts integer not null default 1 check (attempts between 1 and 1000000),
  updated_at timestamptz not null default now(),
  primary key (scope, key_hash),
  constraint auth_rate_limits_scope_format check (
    scope ~ '^[a-z0-9][a-z0-9:_-]{1,63}$'
  ),
  constraint auth_rate_limits_key_hash_format check (key_hash ~ '^[a-f0-9]{64}$')
);

create index if not exists auth_rate_limits_updated_at_idx
  on public.auth_rate_limits (updated_at);

alter table public.auth_rate_limits enable row level security;
revoke all on table public.auth_rate_limits from public, anon, authenticated;
grant select, insert, update, delete on table public.auth_rate_limits to service_role;

create or replace function public.consume_auth_rate_limit(
  p_scope text,
  p_key_hash text,
  p_max_attempts integer,
  p_window_seconds integer
)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  current_attempts integer;
begin
  if p_scope is null
     or p_scope !~ '^[a-z0-9][a-z0-9:_-]{1,63}$'
     or p_key_hash is null
     or p_key_hash !~ '^[a-f0-9]{64}$'
     or p_max_attempts is null
     or p_max_attempts not between 1 and 10000
     or p_window_seconds is null
     or p_window_seconds not between 60 and 86400 then
    return false;
  end if;

  insert into public.auth_rate_limits as limits (
    scope, key_hash, window_started_at, attempts, updated_at
  ) values (p_scope, p_key_hash, now(), 1, now())
  on conflict (scope, key_hash) do update
  set window_started_at = case
        when limits.window_started_at <= now() - make_interval(secs => p_window_seconds)
          then now()
        else limits.window_started_at
      end,
      attempts = case
        when limits.window_started_at <= now() - make_interval(secs => p_window_seconds)
          then 1
        else limits.attempts + 1
      end,
      updated_at = now()
  returning attempts into current_attempts;

  if random() < 0.01 then
    delete from public.auth_rate_limits
    where updated_at < now() - interval '7 days';
  end if;

  return current_attempts <= p_max_attempts;
end;
$$;

create or replace function public.clear_auth_rate_limit(p_scope text, p_key_hash text)
returns void
language sql
security invoker
set search_path = ''
as $$
  delete from public.auth_rate_limits
  where scope = p_scope and key_hash = p_key_hash;
$$;

revoke all on function public.consume_auth_rate_limit(text, text, integer, integer)
  from public, anon, authenticated;
revoke all on function public.clear_auth_rate_limit(text, text)
  from public, anon, authenticated;
grant execute on function public.consume_auth_rate_limit(text, text, integer, integer)
  to service_role;
grant execute on function public.clear_auth_rate_limit(text, text) to service_role;

-- Passwords stay exclusively in Supabase Auth. These rows contain only the
-- non-secret data needed after an email OTP has been verified.
create table if not exists public.pending_account_registrations (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null unique references auth.users(id) on delete cascade,
  registration_kind text not null
    check (registration_kind in ('business_admin', 'coworker')),
  username text not null unique,
  email text not null unique,
  display_name text not null check (char_length(display_name) between 1 and 80),
  organization_name text,
  organization_slug text,
  organization_id uuid references public.organizations(id) on delete cascade,
  created_by uuid references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  constraint pending_registration_username_format check (
    username = lower(username)
    and username ~ '^[a-z0-9][a-z0-9._-]{2,31}$'
  ),
  constraint pending_registration_email_normalized check (
    email = lower(email)
    and char_length(email) between 5 and 254
    and email !~ '@stokta[.]invalid$'
  ),
  constraint pending_registration_slug_format check (
    organization_slug is null
    or (
      organization_slug = lower(organization_slug)
      and organization_slug ~ '^[a-z0-9][a-z0-9-]{2,47}$'
    )
  ),
  constraint pending_registration_expiry_check check (expires_at > created_at),
  constraint pending_registration_shape_check check (
    (
      registration_kind = 'business_admin'
      and organization_name is not null
      and char_length(organization_name) between 2 and 100
      and organization_slug is not null
      and organization_id is null
      and created_by is null
    )
    or (
      registration_kind = 'coworker'
      and organization_name is null
      and organization_slug is null
      and organization_id is not null
      and created_by is not null
    )
  )
);

create index if not exists pending_account_registrations_expires_idx
  on public.pending_account_registrations (expires_at);
create index if not exists pending_account_registrations_creator_idx
  on public.pending_account_registrations (created_by)
  where created_by is not null;
create index if not exists pending_account_registrations_organization_idx
  on public.pending_account_registrations (organization_id)
  where organization_id is not null;

alter table public.pending_account_registrations
  drop constraint if exists pending_account_registrations_auth_user_id_fkey;
alter table public.pending_account_registrations
  add constraint pending_account_registrations_auth_user_id_fkey
  foreign key (auth_user_id) references auth.users(id) on delete cascade;
alter table public.pending_account_registrations
  drop constraint if exists pending_account_registrations_organization_id_fkey;
alter table public.pending_account_registrations
  add constraint pending_account_registrations_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete cascade;
alter table public.pending_account_registrations
  drop constraint if exists pending_account_registrations_created_by_fkey;
alter table public.pending_account_registrations
  add constraint pending_account_registrations_created_by_fkey
  foreign key (created_by) references public.profiles(id) on delete cascade;

alter table public.pending_account_registrations enable row level security;
revoke all on table public.pending_account_registrations from public, anon, authenticated;
grant select, insert, update, delete on table public.pending_account_registrations to service_role;

-- A recovery-email change is verified on a short-lived isolated Auth user.
create table if not exists public.pending_recovery_email_verifications (
  target_user_id uuid primary key references auth.users(id) on delete cascade,
  verification_user_id uuid not null unique references auth.users(id) on delete cascade,
  verification_kind text not null
    check (verification_kind in ('temporary_signup', 'existing_identity')),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  email text not null unique,
  requested_session_id uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 minutes'),
  constraint pending_recovery_email_normalized check (
    email = lower(email)
    and char_length(email) between 5 and 254
    and email !~ '@stokta[.]invalid$'
  ),
  constraint pending_recovery_user_shape check (
    (verification_kind = 'temporary_signup' and target_user_id <> verification_user_id)
    or (verification_kind = 'existing_identity' and target_user_id = verification_user_id)
  ),
  constraint pending_recovery_expiry_check check (expires_at > created_at)
);

create index if not exists pending_recovery_email_expires_idx
  on public.pending_recovery_email_verifications (expires_at);
create index if not exists pending_recovery_email_organization_idx
  on public.pending_recovery_email_verifications (organization_id);

alter table public.pending_recovery_email_verifications
  drop constraint if exists pending_recovery_email_verifications_target_user_id_fkey;
alter table public.pending_recovery_email_verifications
  add constraint pending_recovery_email_verifications_target_user_id_fkey
  foreign key (target_user_id) references auth.users(id) on delete cascade;
alter table public.pending_recovery_email_verifications
  drop constraint if exists pending_recovery_email_verifications_verification_user_id_fkey;
alter table public.pending_recovery_email_verifications
  add constraint pending_recovery_email_verifications_verification_user_id_fkey
  foreign key (verification_user_id) references auth.users(id) on delete cascade;
alter table public.pending_recovery_email_verifications
  drop constraint if exists pending_recovery_email_verifications_organization_id_fkey;
alter table public.pending_recovery_email_verifications
  add constraint pending_recovery_email_verifications_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete cascade;

alter table public.pending_recovery_email_verifications enable row level security;
revoke all on table public.pending_recovery_email_verifications from public, anon, authenticated;
grant select, insert, update, delete on table public.pending_recovery_email_verifications to service_role;

create table if not exists public.security_audit_events (
  id bigint generated always as identity primary key,
  organization_id uuid references public.organizations(id) on delete set null,
  actor_id uuid references auth.users(id) on delete set null,
  subject_id uuid references auth.users(id) on delete set null,
  event_type text not null
    check (event_type ~ '^[a-z0-9][a-z0-9._-]{2,79}$'),
  ip_hash text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint security_audit_ip_hash_format check (
    ip_hash is null or ip_hash ~ '^[a-f0-9]{64}$'
  ),
  constraint security_audit_metadata_object check (jsonb_typeof(metadata) = 'object')
);

create index if not exists security_audit_organization_created_idx
  on public.security_audit_events (organization_id, created_at desc);
create index if not exists security_audit_subject_created_idx
  on public.security_audit_events (subject_id, created_at desc)
  where subject_id is not null;
create index if not exists security_audit_actor_created_idx
  on public.security_audit_events (actor_id, created_at desc)
  where actor_id is not null;

alter table public.security_audit_events
  drop constraint if exists security_audit_events_organization_id_fkey;
alter table public.security_audit_events
  add constraint security_audit_events_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete set null;
alter table public.security_audit_events
  drop constraint if exists security_audit_events_actor_id_fkey;
alter table public.security_audit_events
  add constraint security_audit_events_actor_id_fkey
  foreign key (actor_id) references auth.users(id) on delete set null;
alter table public.security_audit_events
  drop constraint if exists security_audit_events_subject_id_fkey;
alter table public.security_audit_events
  add constraint security_audit_events_subject_id_fkey
  foreign key (subject_id) references auth.users(id) on delete set null;

alter table public.security_audit_events enable row level security;
revoke all on table public.security_audit_events from public, anon, authenticated;
grant select, insert on table public.security_audit_events to service_role;
grant usage, select on sequence public.security_audit_events_id_seq to service_role;

-- Raw reset tickets never enter Postgres. Edge Functions store a secret-peppered
-- SHA-256 digest and expose the random ticket only once to the requesting client.
create table if not exists public.password_reset_challenges (
  ticket_hash text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '10 minutes'),
  consumed_at timestamptz,
  constraint password_reset_ticket_hash_format check (ticket_hash ~ '^[a-f0-9]{64}$'),
  constraint password_reset_expiry_check check (expires_at > created_at),
  constraint password_reset_consumed_check check (
    consumed_at is null or consumed_at >= created_at
  )
);

create index if not exists password_reset_challenges_user_active_idx
  on public.password_reset_challenges (user_id, expires_at desc)
  where consumed_at is null;
create index if not exists password_reset_challenges_expiry_idx
  on public.password_reset_challenges (expires_at);
create index if not exists password_reset_challenges_organization_idx
  on public.password_reset_challenges (organization_id);

alter table public.password_reset_challenges
  drop constraint if exists password_reset_challenges_user_id_fkey;
alter table public.password_reset_challenges
  add constraint password_reset_challenges_user_id_fkey
  foreign key (user_id) references auth.users(id) on delete cascade;
alter table public.password_reset_challenges
  drop constraint if exists password_reset_challenges_organization_id_fkey;
alter table public.password_reset_challenges
  add constraint password_reset_challenges_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete cascade;

alter table public.password_reset_challenges enable row level security;
revoke all on table public.password_reset_challenges from public, anon, authenticated;
grant select, insert, update, delete on table public.password_reset_challenges to service_role;

-- Every tenant-data decision checks that the JWT still names an Auth session.
-- Deleting auth.sessions therefore cuts access off before the JWT expires.
create or replace function private.has_live_session()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when (select auth.uid()) is null then false
    when coalesce((select auth.jwt() ->> 'session_id'), '')
         !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      then false
    else exists (
      select 1
      from auth.sessions s
      where s.id = ((select auth.jwt() ->> 'session_id'))::uuid
        and s.user_id = (select auth.uid())
    )
  end;
$$;

create or replace function private.has_active_profile()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.has_live_session()
    and exists (
      select 1
      from public.profiles p
      where p.id = (select auth.uid())
        and p.is_active
        and not p.must_change_password
    );
$$;

create or replace function private.current_organization_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.organization_id
  from public.profiles p
  where private.has_live_session()
    and p.id = (select auth.uid())
    and p.is_active
    and not p.must_change_password;
$$;

create or replace function private.require_active_profile()
returns public.profiles
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  if (select auth.uid()) is null or not private.has_live_session() then
    raise exception 'Geçerli oturum gerekli';
  end if;

  select * into current_profile
  from public.profiles
  where id = (select auth.uid())
    and is_active
    and not must_change_password;

  if current_profile.id is null then
    raise exception 'Etkin kullanıcı profili bulunamadı veya şifre değişikliği gerekli';
  end if;

  return current_profile;
end;
$$;

revoke all on function private.has_live_session() from public, anon, authenticated;
revoke all on function private.has_active_profile() from public, anon, authenticated;
revoke all on function private.current_organization_id() from public, anon;
revoke all on function private.require_active_profile() from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.has_live_session() to authenticated;
grant execute on function private.has_active_profile() to authenticated;
grant execute on function private.current_organization_id() to authenticated;

-- Service-role wrappers are also used by Edge Functions, whose database client
-- intentionally bypasses end-user RLS.
create or replace function public.service_has_live_session(
  p_user_id uuid,
  p_session_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_user_id is not null
    and p_session_id is not null
    and exists (
      select 1 from auth.sessions s
      where s.id = p_session_id and s.user_id = p_user_id
    );
$$;

create or replace function public.service_revoke_user_sessions(
  p_user_id uuid,
  p_except_session_id uuid default null
)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  removed_count integer;
begin
  if p_user_id is null then
    raise exception 'Kullanıcı gerekli';
  end if;

  delete from auth.sessions
  where user_id = p_user_id
    and (p_except_session_id is null or id <> p_except_session_id);
  get diagnostics removed_count = row_count;
  return removed_count;
end;
$$;

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
  removed_count integer;
begin
  if p_user_id is null or p_session_id is null then
    return false;
  end if;

  delete from auth.sessions
  where id = p_session_id and user_id = p_user_id;
  get diagnostics removed_count = row_count;
  return removed_count = 1;
end;
$$;

create or replace function public.service_record_security_event(
  p_event_type text,
  p_organization_id uuid default null,
  p_actor_id uuid default null,
  p_subject_id uuid default null,
  p_ip_hash text default null,
  p_metadata jsonb default '{}'::jsonb
)
returns bigint
language plpgsql
security invoker
set search_path = ''
as $$
declare
  event_id bigint;
begin
  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, ip_hash, metadata
  ) values (
    p_organization_id, p_actor_id, p_subject_id, p_event_type, p_ip_hash,
    coalesce(p_metadata, '{}'::jsonb)
  )
  returning id into event_id;
  return event_id;
end;
$$;

-- Atomically consumes a reset ticket before the Auth Admin API changes the
-- password. Concurrent/replayed requests can therefore never reuse a ticket.
create or replace function public.service_claim_password_reset(p_ticket_hash text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  challenge public.password_reset_challenges;
begin
  if p_ticket_hash is null or p_ticket_hash !~ '^[a-f0-9]{64}$' then
    return null;
  end if;

  select * into challenge
  from public.password_reset_challenges
  where ticket_hash = p_ticket_hash
    and consumed_at is null
    and expires_at > now()
  for update;

  if challenge.ticket_hash is null then
    return null;
  end if;

  update public.password_reset_challenges
  set consumed_at = now()
  where ticket_hash = challenge.ticket_hash;

  delete from public.password_reset_challenges
  where expires_at < now() - interval '1 day';

  return jsonb_build_object(
    'userId', challenge.user_id,
    'organizationId', challenge.organization_id
  );
end;
$$;

-- The database verifies Auth state before it marks an address verified.
create or replace function public.service_mark_recovery_email_verified(
  p_user_id uuid,
  p_expected_email text
)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  verified_at timestamptz := now();
  auth_email text;
  auth_confirmed_at timestamptz;
  organization_id_value uuid;
begin
  select lower(u.email), u.email_confirmed_at
    into auth_email, auth_confirmed_at
  from auth.users u
  where u.id = p_user_id;

  if auth_email is null
     or auth_confirmed_at is null
     or auth_email <> lower(coalesce(p_expected_email, ''))
     or auth_email ~ '@stokta[.]invalid$' then
    raise exception 'Doğrulanmış e-posta kimliği bulunamadı';
  end if;

  update public.profiles
  set recovery_email = auth_email,
      recovery_email_verified_at = verified_at
  where id = p_user_id
  returning organization_id into organization_id_value;

  if organization_id_value is null then
    raise exception 'Kullanıcı profili bulunamadı';
  end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type
  ) values (
    organization_id_value, p_user_id, p_user_id, 'recovery_email.verified'
  );

  return verified_at;
end;
$$;

create or replace function public.service_complete_password_change(p_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  organization_id_value uuid;
begin
  update public.profiles
  set must_change_password = false
  where id = p_user_id and is_active
  returning organization_id into organization_id_value;

  if organization_id_value is null then
    raise exception 'Etkin kullanıcı profili bulunamadı';
  end if;

  delete from auth.sessions where user_id = p_user_id;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type
  ) values (
    organization_id_value, p_user_id, p_user_id, 'password.changed'
  );

  return true;
end;
$$;

create or replace function public.service_require_member_password_change(
  p_admin_id uuid,
  p_member_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller public.profiles;
  target public.profiles;
begin
  select * into caller
  from public.profiles
  where id = p_admin_id and role = 'admin' and is_active;

  if caller.id is null then
    raise exception 'Yetkisiz şifre yenileme isteği';
  end if;

  update public.profiles
  set must_change_password = true
  where id = p_member_id
    and organization_id = caller.organization_id
    and role = 'member'
  returning * into target;

  if target.id is null then
    raise exception 'Çalışan bulunamadı';
  end if;

  delete from auth.sessions where user_id = target.id;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    caller.organization_id, caller.id, target.id, 'coworker.password_reset',
    jsonb_build_object('username', target.username)
  );

  return true;
end;
$$;

revoke all on function public.service_has_live_session(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_revoke_user_sessions(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_revoke_session(uuid, uuid)
  from public, anon, authenticated;
revoke all on function public.service_record_security_event(text, uuid, uuid, uuid, text, jsonb)
  from public, anon, authenticated;
revoke all on function public.service_claim_password_reset(text)
  from public, anon, authenticated;
revoke all on function public.service_mark_recovery_email_verified(uuid, text)
  from public, anon, authenticated;
revoke all on function public.service_complete_password_change(uuid)
  from public, anon, authenticated;
revoke all on function public.service_require_member_password_change(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.service_has_live_session(uuid, uuid) to service_role;
grant execute on function public.service_revoke_user_sessions(uuid, uuid) to service_role;
grant execute on function public.service_revoke_session(uuid, uuid) to service_role;
grant execute on function public.service_record_security_event(text, uuid, uuid, uuid, text, jsonb)
  to service_role;
grant execute on function public.service_claim_password_reset(text) to service_role;
grant execute on function public.service_mark_recovery_email_verified(uuid, text)
  to service_role;
grant execute on function public.service_complete_password_change(uuid) to service_role;
grant execute on function public.service_require_member_password_change(uuid, uuid)
  to service_role;

-- Finish an OTP-confirmed business or coworker atomically. This is SECURITY
-- DEFINER only because it must verify auth.users; every public role is revoked.
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
  active_seats integer;
  auth_email text;
  auth_confirmed_at timestamptz;
begin
  select * into pending
  from public.pending_account_registrations
  where auth_user_id = p_auth_user_id and username = p_username
  for update;

  if pending.id is null then
    select * into existing_profile
    from public.profiles
    where id = p_auth_user_id and username = p_username;

    if existing_profile.id is not null then
      select * into organization
      from public.organizations where id = existing_profile.organization_id;
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

    raise exception 'Bekleyen doğrulama kaydı bulunamadı';
  end if;

  if pending.expires_at <= now() then
    raise exception 'Doğrulama isteğinin süresi doldu';
  end if;

  select lower(u.email), u.email_confirmed_at
    into auth_email, auth_confirmed_at
  from auth.users u
  where u.id = pending.auth_user_id;

  if auth_email is null
     or auth_confirmed_at is null
     or auth_email <> pending.email then
    raise exception 'E-posta doğrulaması tamamlanmadı';
  end if;

  if exists (select 1 from public.profiles p where p.username = pending.username) then
    raise exception using errcode = '23505', message = 'Bu kullanıcı adı zaten kullanılıyor';
  end if;

  if pending.registration_kind = 'business_admin' then
    insert into public.organizations (
      name, slug, subscription_status, trial_ends_at,
      max_members, max_products, created_by
    ) values (
      pending.organization_name,
      pending.organization_slug,
      'trial',
      now() + interval '14 days',
      5,
      1000,
      pending.auth_user_id
    )
    returning * into organization;

    insert into public.profiles (
      id, organization_id, username, display_name, role, created_by,
      is_platform_operator, is_active, deactivated_at,
      must_change_password, recovery_email, recovery_email_verified_at
    ) values (
      pending.auth_user_id, organization.id, pending.username,
      pending.display_name, 'admin', null, false, true, null, false,
      pending.email, now()
    )
    returning * into created_profile;
  else
    select * into caller
    from public.profiles
    where id = pending.created_by
      and organization_id = pending.organization_id
      and role = 'admin'
      and is_active;

    if caller.id is null then
      raise exception 'Çalışanı oluşturan yönetici artık yetkili değil';
    end if;

    select * into organization
    from public.organizations
    where id = pending.organization_id
    for update;

    if organization.id is null then
      raise exception 'İşletme bulunamadı';
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
      is_platform_operator, is_active, deactivated_at,
      must_change_password, recovery_email, recovery_email_verified_at
    ) values (
      pending.auth_user_id, organization.id, pending.username,
      pending.display_name, 'member', pending.created_by, false, true, null,
      true, pending.email, now()
    )
    returning * into created_profile;
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

  delete from public.pending_account_registrations where id = pending.id;

  return jsonb_build_object(
    'completed', true,
    'registrationKind', pending.registration_kind,
    'organization', jsonb_build_object(
      'id', organization.id,
      'name', organization.name,
      'trialEndsAt', organization.trial_ends_at,
      'maxMembers', organization.max_members,
      'maxProducts', organization.max_products
    ),
    'user', jsonb_build_object(
      'id', created_profile.id,
      'username', created_profile.username,
      'displayName', created_profile.display_name,
      'mustChangePassword', created_profile.must_change_password
    )
  );
end;
$$;

revoke all on function public.service_finalize_pending_registration(uuid, text)
  from public, anon, authenticated;
grant execute on function public.service_finalize_pending_registration(uuid, text)
  to service_role;

-- Kept for backwards-compatible service callers. New invites use the pending
-- registration finalizer above and cannot reach inventory before changing the
-- manager-supplied temporary password.
create or replace function public.service_create_member_profile(
  p_member_id uuid,
  p_organization_id uuid,
  p_username text,
  p_display_name text,
  p_created_by uuid
)
returns public.profiles
language plpgsql
security invoker
set search_path = ''
as $$
declare
  caller public.profiles;
  organization public.organizations;
  active_seats integer;
  created_profile public.profiles;
begin
  select * into caller
  from public.profiles
  where id = p_created_by
    and organization_id = p_organization_id
    and role = 'admin'
    and is_active;

  if caller.id is null then
    raise exception 'Yetkisiz çalışan oluşturma isteği';
  end if;

  select * into organization
  from public.organizations
  where id = p_organization_id
  for update;

  if organization.id is null then
    raise exception 'İşletme bulunamadı';
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
  where organization_id = p_organization_id and is_active;

  if active_seats >= organization.max_members then
    raise exception 'Kullanıcı limitine ulaşıldı (%).', organization.max_members;
  end if;

  insert into public.profiles (
    id, organization_id, username, display_name, role, created_by,
    is_active, deactivated_at, must_change_password, recovery_email_verified_at
  ) values (
    p_member_id, p_organization_id, p_username, p_display_name, 'member', p_created_by,
    true, null, true, null
  )
  returning * into created_profile;

  return created_profile;
end;
$$;

create or replace function public.service_set_member_active(
  p_admin_id uuid,
  p_member_id uuid,
  p_is_active boolean
)
returns public.profiles
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller public.profiles;
  organization public.organizations;
  target public.profiles;
  active_seats integer;
  updated_profile public.profiles;
begin
  select * into caller
  from public.profiles
  where id = p_admin_id and role = 'admin' and is_active;

  if caller.id is null then
    raise exception 'Yetkisiz çalışan yönetimi isteği';
  end if;

  select * into organization
  from public.organizations
  where id = caller.organization_id
  for update;

  if organization.id is null then
    raise exception 'İşletme bulunamadı';
  end if;

  select * into target
  from public.profiles
  where id = p_member_id
    and organization_id = caller.organization_id
    and role = 'member'
  for update;

  if target.id is null then
    raise exception 'Çalışan bulunamadı';
  end if;

  if target.is_active = p_is_active then
    return target;
  end if;

  if p_is_active then
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
      raise exception 'İşletme hesabı çalışan etkinleştirmeye açık değil';
    end if;

    select count(*) into active_seats
    from public.profiles
    where organization_id = caller.organization_id and is_active;

    if active_seats >= organization.max_members then
      raise exception 'Kullanıcı limitine ulaşıldı (%).', organization.max_members;
    end if;
  end if;

  update public.profiles
  set is_active = p_is_active,
      deactivated_at = case when p_is_active then null else now() end
  where id = target.id
  returning * into updated_profile;

  if not p_is_active then
    delete from auth.sessions where user_id = target.id;
  end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    caller.organization_id, caller.id, target.id,
    case when p_is_active then 'coworker.activated' else 'coworker.deactivated' end,
    jsonb_build_object('username', target.username)
  );

  return updated_profile;
end;
$$;

create or replace function public.service_prepare_member_deletion(
  p_admin_id uuid,
  p_member_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller public.profiles;
  target public.profiles;
begin
  select * into caller
  from public.profiles
  where id = p_admin_id and role = 'admin' and is_active;

  if caller.id is null then
    raise exception 'Yetkisiz çalışan silme isteği';
  end if;

  select * into target
  from public.profiles
  where id = p_member_id
    and organization_id = caller.organization_id
    and role = 'member'
  for update;

  if target.id is null then
    raise exception 'Çalışan bulunamadı';
  end if;

  update public.stock_movements
  set actor_id = null,
      actor_name = 'Silinmiş kullanıcı'
  where organization_id = caller.organization_id
    and actor_id = target.id;

  update public.products
  set created_by = caller.id
  where organization_id = caller.organization_id
    and created_by = target.id;

  update public.profiles
  set created_by = caller.id
  where organization_id = caller.organization_id
    and created_by = target.id;

  update public.profiles
  set is_active = false,
      deactivated_at = coalesce(deactivated_at, now()),
      must_change_password = true
  where id = target.id;

  delete from auth.sessions where user_id = target.id;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    caller.organization_id, caller.id, target.id, 'coworker.deletion_prepared',
    jsonb_build_object('username', target.username)
  );

  return jsonb_build_object('id', target.id, 'username', target.username);
end;
$$;

revoke all on function public.service_create_member_profile(uuid, uuid, text, text, uuid)
  from public, anon, authenticated;
revoke all on function public.service_set_member_active(uuid, uuid, boolean)
  from public, anon, authenticated;
revoke all on function public.service_prepare_member_deletion(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.service_create_member_profile(uuid, uuid, text, text, uuid)
  to service_role;
grant execute on function public.service_set_member_active(uuid, uuid, boolean)
  to service_role;
grant execute on function public.service_prepare_member_deletion(uuid, uuid)
  to service_role;

drop policy if exists "organization members read own organization" on public.organizations;
create policy "organization members read own organization"
  on public.organizations for select to authenticated
  using (id = (select private.current_organization_id()));

drop policy if exists "authenticated profiles read" on public.profiles;
create policy "authenticated profiles read"
  on public.profiles for select to authenticated
  using (
    id = (select auth.uid())
    and (select private.has_live_session())
  );

drop policy if exists "authenticated active products read" on public.products;
create policy "authenticated active products read"
  on public.products for select to authenticated
  using (
    active
    and organization_id = (select private.current_organization_id())
  );

drop policy if exists "authenticated movements read" on public.stock_movements;
create policy "authenticated movements read"
  on public.stock_movements for select to authenticated
  using (organization_id = (select private.current_organization_id()));

commit;
