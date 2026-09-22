begin;

-- The platform operator manages every tenant and must be able to test stock
-- workflows in the operator's own organization without a paid tenant period.
-- UGC acceptance and the active-profile checks remain mandatory.
create or replace function private.require_writable_organization(
  p_organization_id uuid
)
returns public.organizations
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_organization public.organizations;
begin
  perform private.require_current_ugc_terms(p_organization_id);

  select * into current_organization
  from public.organizations
  where id = p_organization_id;

  if current_organization.id is null then
    raise exception 'İşletme bulunamadı';
  end if;

  if exists (
    select 1
    from public.profiles
    where id = (select auth.uid())
      and organization_id = p_organization_id
      and is_platform_operator
      and is_active
      and not must_change_password
  ) then
    return current_organization;
  end if;

  if current_organization.subscription_status = 'trial'
     and coalesce(current_organization.trial_ends_at, '-infinity'::timestamptz) <= now() then
    raise exception 'Deneme süresi sona erdi. Kiralama durumunu yenileyin';
  end if;

  if current_organization.subscription_status = 'active'
     and current_organization.current_period_end is not null
     and current_organization.current_period_end <= now() then
    raise exception 'Kiralama dönemi sona erdi. Aboneliği yenileyin';
  end if;

  if current_organization.subscription_status not in ('trial', 'active') then
    raise exception 'İşletme hesabı şu anda işlem yapmaya açık değil';
  end if;

  return current_organization;
end;
$$;

revoke all on function private.require_writable_organization(uuid)
  from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.require_writable_organization(uuid)
  to authenticated;

comment on function private.require_writable_organization(uuid) is
  'Requires accepted terms and a writable tenant period; platform operators may write only to their own organization.';

commit;
