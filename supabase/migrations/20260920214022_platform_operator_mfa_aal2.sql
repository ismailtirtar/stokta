-- Require a TOTP-verified AAL2 session only on platform-operator APIs.
-- Tenant administrators and members keep their existing AAL1 access model.

begin;

set local statement_timeout = '30s';

do $$
begin
  if to_regprocedure('private.require_active_profile()') is null
     or to_regclass('auth.sessions') is null
     or to_regclass('auth.mfa_factors') is null
     or to_regprocedure('public.list_platform_content_reports(text)') is null
     or to_regprocedure('public.moderate_platform_content_report(uuid,text,text)') is null then
    raise exception
      'Platform operator MFA migration requires the account-security and platform-moderation migrations';
  end if;
end;
$$;

create or replace function public.service_has_live_totp_aal2_session(
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
      select 1
      from auth.sessions s
      join auth.mfa_factors factor on factor.id = s.factor_id
      where s.id = p_session_id
        and s.user_id = p_user_id
        and s.aal = 'aal2'
        and factor.user_id = p_user_id
        and factor.factor_type = 'totp'
        and factor.status = 'verified'
    );
$$;

revoke all on function public.service_has_live_totp_aal2_session(uuid, uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_has_live_totp_aal2_session(uuid, uuid)
  to service_role;

create or replace function private.require_platform_operator_aal2()
returns public.profiles
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  current_profile := private.require_active_profile();

  if not current_profile.is_platform_operator then
    raise exception 'Bu işlem yalnızca platform yöneticisine açıktır';
  end if;
  if not exists (
    select 1
    from auth.sessions s
    join auth.mfa_factors factor on factor.id = s.factor_id
    where s.id = ((select auth.jwt()->>'session_id'))::uuid
      and s.user_id = current_profile.id
      and s.aal = 'aal2'
      and factor.user_id = current_profile.id
      and factor.factor_type = 'totp'
      and factor.status = 'verified'
  ) then
    raise exception using
      errcode = '42501',
      message = 'Platform yönetimi için doğrulanmış bir TOTP faktörü gerekli';
  end if;
  if coalesce((select auth.jwt()->>'aal'), 'aal1') <> 'aal2' then
    raise exception using
      errcode = '42501',
      message = 'Platform yönetimi için iki adımlı doğrulama gerekli';
  end if;
  if not exists (
    select 1
    from jsonb_array_elements(coalesce((select auth.jwt()->'amr'), '[]'::jsonb)) entry
    where case jsonb_typeof(entry)
      when 'string' then trim(both '"' from entry::text)
      else entry->>'method'
    end in ('totp', 'mfa/totp')
  ) then
    raise exception using
      errcode = '42501',
      message = 'Bu oturum TOTP ile doğrulanmalıdır';
  end if;

  return current_profile;
end;
$$;

revoke all on function private.require_platform_operator_aal2()
  from public, anon, authenticated, service_role;

create or replace function public.list_platform_content_reports(
  p_status text default 'open'
)
returns table (
  organization_id uuid,
  organization_name text,
  report_id uuid,
  created_at timestamptz,
  status text,
  target_type text,
  target_id uuid,
  target_label text,
  target_content_snapshot text,
  reason text,
  details text,
  reporter_id uuid,
  reporter_name text,
  resolution_action text,
  resolution_note text,
  resolved_at timestamptz,
  resolved_by uuid,
  resolved_by_name text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  normalized_status text := lower(trim(coalesce(p_status, 'open')));
begin
  current_profile := private.require_platform_operator_aal2();
  if normalized_status not in ('open', 'resolved', 'all') then
    raise exception 'Geçersiz şikâyet durumu';
  end if;

  return query
  select
    r.organization_id,
    o.name,
    r.id,
    r.created_at,
    r.status,
    r.target_type,
    case r.target_type
      when 'product' then r.target_product_id
      when 'movement' then r.target_movement_id
      when 'user' then r.target_user_id
    end,
    r.target_label,
    r.target_content_snapshot,
    r.reason,
    r.details,
    r.reporter_id,
    r.reporter_name,
    r.resolution_action,
    r.resolution_note,
    r.resolved_at,
    r.resolved_by,
    r.resolved_by_name
  from public.content_reports r
  join public.organizations o on o.id = r.organization_id
  where r.review_scope = 'platform'
    and r.review_subject_id is distinct from current_profile.id
    and (normalized_status = 'all' or r.status = normalized_status)
  order by r.created_at desc, r.id;
end;
$$;

comment on function public.list_platform_content_reports(text) is
  'Lists cross-organization platform-review reports only to an active AAL2 platform operator, excluding reports about that operator own content or account.';

create or replace function public.moderate_platform_content_report(
  p_report_id uuid,
  p_action text,
  p_note text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_report public.content_reports;
  target_organization public.organizations;
  normalized_action text := lower(trim(coalesce(p_action, '')));
  normalized_note text := nullif(trim(coalesce(p_note, '')), '');
  resolved_timestamp timestamptz := now();
  affected_rows integer;
begin
  current_profile := private.require_platform_operator_aal2();
  if p_report_id is null then
    raise exception 'Şikâyet kaydı gerekli';
  end if;
  if normalized_action not in (
    'dismiss',
    'remove_product',
    'redact_movement_note',
    'suspend_organization'
  ) then
    raise exception 'Geçersiz platform moderasyon işlemi';
  end if;
  if normalized_note is not null and char_length(normalized_note) > 500 then
    raise exception 'Moderasyon notu en fazla 500 karakter olabilir';
  end if;

  -- The organization is derived exclusively from the locked report. There is
  -- no caller-provided tenant selector that could create an IDOR path.
  select * into current_report
  from public.content_reports r
  where r.id = p_report_id
    and r.review_scope = 'platform'
    and r.review_subject_id is distinct from current_profile.id
    and r.status = 'open'
  for update;

  if current_report.id is null then
    raise exception 'Açık platform şikâyeti bulunamadı';
  end if;

  case normalized_action
    when 'dismiss' then
      null;

    when 'remove_product' then
      if current_report.target_type <> 'product'
         or current_report.target_product_id is null then
        raise exception 'Bu işlem yalnızca ürün şikâyetlerinde kullanılabilir';
      end if;

      update public.products
      set active = false,
          updated_at = resolved_timestamp
      where id = current_report.target_product_id
        and organization_id = current_report.organization_id;
      get diagnostics affected_rows = row_count;

      if affected_rows <> 1 then
        raise exception 'Moderasyon hedefi ürün bulunamadı';
      end if;

    when 'redact_movement_note' then
      if current_report.target_type <> 'movement'
         or current_report.target_movement_id is null then
        raise exception 'Bu işlem yalnızca stok hareketi şikâyetlerinde kullanılabilir';
      end if;

      update public.stock_movements
      set note = '[Moderasyon tarafından kaldırıldı]'
      where id = current_report.target_movement_id
        and organization_id = current_report.organization_id;
      get diagnostics affected_rows = row_count;

      if affected_rows <> 1 then
        raise exception 'Moderasyon hedefi stok hareketi bulunamadı';
      end if;

    when 'suspend_organization' then
      select * into target_organization
      from public.organizations o
      where o.id = current_report.organization_id
      for update;

      if target_organization.id is null then
        raise exception 'Moderasyon hedefi işletme bulunamadı';
      end if;

      -- Subscription suspension is deliberately reversible through the existing
      -- Platform Businesses control. Profiles and sessions remain intact so a
      -- later return to active does not strand the tenant without an admin.
      update public.organizations
      set subscription_status = 'suspended',
          updated_at = resolved_timestamp
      where id = current_report.organization_id;
      get diagnostics affected_rows = row_count;

      if affected_rows <> 1 then
        raise exception 'Moderasyon hedefi işletme değiştirildi';
      end if;
  end case;

  update public.content_reports
  set status = 'resolved',
      resolution_action = normalized_action,
      resolution_note = normalized_note,
      resolved_by = current_profile.id,
      resolved_by_name = current_profile.display_name,
      resolved_at = resolved_timestamp,
      updated_at = resolved_timestamp
  where id = current_report.id
    and review_scope = 'platform'
    and review_subject_id is distinct from current_profile.id
    and status = 'open';
  get diagnostics affected_rows = row_count;

  if affected_rows <> 1 then
    raise exception 'Şikâyet eşzamanlı olarak değiştirildi';
  end if;

  insert into public.security_audit_events (
    organization_id,
    actor_id,
    subject_id,
    event_type,
    metadata
  ) values (
    current_report.organization_id,
    current_profile.id,
    current_report.review_subject_id,
    'ugc.platform_report.resolved',
    jsonb_build_object(
      'report_id', current_report.id,
      'target_type', current_report.target_type,
      'target_id', case current_report.target_type
        when 'product' then current_report.target_product_id
        when 'movement' then current_report.target_movement_id
        when 'user' then current_report.target_user_id
      end,
      'action', normalized_action,
      'review_scope', 'platform'
    )
  );

  return jsonb_build_object(
    'report_id', current_report.id,
    'status', 'resolved',
    'action', normalized_action,
    'resolved_at', resolved_timestamp
  );
end;
$$;

comment on function public.moderate_platform_content_report(uuid, text, text) is
  'Lets an active AAL2 platform operator resolve another subject platform-review report; organization and subject are derived from the locked report.';

revoke all on function public.list_platform_content_reports(text)
  from public, anon, authenticated, service_role;
revoke all on function public.moderate_platform_content_report(uuid, text, text)
  from public, anon, authenticated, service_role;
grant execute on function public.list_platform_content_reports(text)
  to authenticated;
grant execute on function public.moderate_platform_content_report(uuid, text, text)
  to authenticated;

commit;
