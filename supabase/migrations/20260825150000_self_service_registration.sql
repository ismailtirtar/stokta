-- Rate-limit public self-service business registrations without storing raw IP addresses.

begin;

create table public.signup_rate_limits (
  key_hash text primary key,
  window_started_at timestamptz not null default now(),
  attempts integer not null default 1 check (attempts between 1 and 1000000),
  updated_at timestamptz not null default now(),
  constraint signup_rate_limits_key_hash_format check (key_hash ~ '^[a-f0-9]{64}$')
);

alter table public.signup_rate_limits enable row level security;

revoke all on table public.signup_rate_limits from public, anon, authenticated;
grant select, insert, update, delete on table public.signup_rate_limits to service_role;

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
    key_hash,
    window_started_at,
    attempts,
    updated_at
  )
  values (p_key_hash, now(), 1, now())
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

  delete from public.signup_rate_limits
  where updated_at < now() - interval '24 hours';

  return current_attempts <= 5;
end;
$$;

revoke all on function public.consume_signup_rate_limit(text) from public, anon, authenticated;
grant execute on function public.consume_signup_rate_limit(text) to service_role;

commit;
