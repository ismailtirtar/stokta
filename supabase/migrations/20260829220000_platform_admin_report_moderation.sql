-- Route reports about tenant administrators to a platform-only moderation queue.
-- Tenant administrators cannot see or resolve reports in that queue.

begin;

set local statement_timeout = '30s';

do $$
begin
  if to_regclass('public.content_reports') is null
     or to_regprocedure('public.report_content(text,uuid,text,text)') is null
     or to_regprocedure('public.list_content_reports(text)') is null
     or to_regprocedure('public.moderate_content_report(uuid,text,text)') is null then
    raise exception
      'Platform moderation migration requires 20260829193000_ugc_terms_and_moderation';
  end if;
end;
$$;

alter table public.content_reports
  add column review_scope text not null default 'tenant',
  add column review_subject_id uuid,
  add constraint content_reports_review_scope_check check (
    review_scope in ('tenant', 'platform')
  ),
  add constraint content_reports_platform_target_check check (
    review_scope = 'tenant'
    or (
      review_scope = 'platform'
      and target_type in ('product', 'movement', 'user')
    )
  ),
  add constraint content_reports_review_subject_scope_check check (
    review_scope = 'platform' or review_subject_id is null
  ),
  add constraint content_reports_review_subject_organization_fkey
    foreign key (review_subject_id, organization_id)
    references public.profiles(id, organization_id)
    on delete set null (review_subject_id);

comment on column public.content_reports.review_scope is
  'tenant reports are visible to the tenant admin; platform reports are visible only to platform operators.';
comment on column public.content_reports.review_subject_id is
  'Admin or platform-operator target/creator/actor used to prevent self-review; null after that profile is deleted.';

-- Reclassify any reports created in the short interval between the base UGC
-- migration and this follow-up. Admin/operator-authored content must never
-- remain in a tenant-admin queue merely because it predates this routing rule.
update public.content_reports r
set review_scope = 'platform',
    review_subject_id = creator.id,
    updated_at = now()
from public.products p
join public.profiles creator
  on creator.id = p.created_by
 and creator.organization_id = p.organization_id
where r.target_type = 'product'
  and r.target_product_id = p.id
  and r.organization_id = p.organization_id
  and (creator.role = 'admin' or creator.is_platform_operator);

update public.content_reports r
set review_scope = 'platform',
    review_subject_id = actor.id,
    updated_at = now()
from public.stock_movements m
join public.profiles actor
  on actor.id = m.actor_id
 and actor.organization_id = m.organization_id
where r.target_type = 'movement'
  and r.target_movement_id = m.id
  and r.organization_id = m.organization_id
  and (actor.role = 'admin' or actor.is_platform_operator);

update public.content_reports r
set review_scope = 'platform',
    review_subject_id = target.id,
    updated_at = now()
from public.profiles target
where r.target_type = 'user'
  and r.target_user_id = target.id
  and r.organization_id = target.organization_id
  and target.role = 'admin'
  and not target.is_platform_operator;

alter table public.content_reports
  drop constraint content_reports_resolution_action_check,
  drop constraint content_reports_resolution_target_check,
  add constraint content_reports_resolution_action_check check (
    resolution_action is null
    or resolution_action in (
      'dismiss',
      'remove_product',
      'redact_movement_note',
      'deactivate_user',
      'suspend_organization'
    )
  ),
  add constraint content_reports_resolution_target_check check (
    resolution_action is null
    or resolution_action = 'dismiss'
    or (
      resolution_action = 'remove_product'
      and target_type = 'product'
    )
    or (
      resolution_action = 'redact_movement_note'
      and target_type = 'movement'
    )
    or (
      resolution_action = 'deactivate_user'
      and review_scope = 'tenant'
      and target_type = 'user'
    )
    or (
      resolution_action = 'suspend_organization'
      and review_scope = 'platform'
      and target_type in ('product', 'movement', 'user')
    )
  );

-- A platform operator resolving another tenant report cannot satisfy the old
-- same-organization resolver FK. The Auth FK still preserves actor existence;
-- authorization is enforced inside the hardened RPCs below.
alter table public.content_reports
  drop constraint content_reports_resolver_organization_fkey,
  add constraint content_reports_resolved_by_fkey
    foreign key (resolved_by) references auth.users(id) on delete set null;

create index content_reports_platform_status_created_idx
  on public.content_reports (status, created_at desc)
  where review_scope = 'platform';

create index content_reports_review_subject_organization_idx
  on public.content_reports (review_subject_id, organization_id)
  where review_subject_id is not null;

create or replace function private.anonymize_ugc_reports_before_profile_delete()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.content_reports
  set reporter_name = 'Silinmiş kullanıcı',
      details = '',
      updated_at = now()
  where organization_id = old.organization_id
    and reporter_id = old.id;

  update public.content_reports
  set target_label = 'Silinmiş kullanıcı',
      target_content_snapshot = 'Silinmiş kullanıcı',
      updated_at = now()
  where organization_id = old.organization_id
    and target_type = 'user'
    and target_user_id = old.id;

  update public.content_reports
  set review_subject_id = null,
      updated_at = now()
  where organization_id = old.organization_id
    and review_subject_id = old.id;

  -- Platform operators can resolve reports outside their own organization, so
  -- resolver anonymization must follow the user id across every tenant.
  update public.content_reports
  set resolved_by = null,
      resolved_by_name = 'Silinmiş kullanıcı',
      resolution_note = null,
      updated_at = now()
  where resolved_by = old.id;

  update public.security_audit_events
  set metadata = metadata - 'target_id'
  where subject_id = old.id
    and event_type in (
      'ugc.content.reported',
      'ugc.report.resolved',
      'ugc.platform_report.resolved'
    );

  return old;
end;
$$;

create or replace function public.report_content(
  p_target_type text,
  p_target_id uuid,
  p_reason text,
  p_details text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  normalized_target_type text := lower(trim(coalesce(p_target_type, '')));
  normalized_reason text := lower(trim(coalesce(p_reason, '')));
  normalized_details text := trim(coalesce(p_details, ''));
  target_label text;
  target_content_snapshot text;
  target_user_role text;
  target_is_platform_operator boolean;
  target_review_subject_id uuid;
  report_review_scope text := 'tenant';
  report_id uuid;
  report_created_at timestamptz;
begin
  current_profile := private.require_active_profile();

  -- Reporting remains available when billing is read-only or acceptance is
  -- pending because it is a safety operation, not tenant content creation.
  if p_target_id is null then
    raise exception 'Şikâyet edilecek içerik gerekli';
  end if;
  if normalized_target_type not in ('product', 'movement', 'user') then
    raise exception 'Geçersiz şikâyet hedefi';
  end if;
  if normalized_reason not in ('spam', 'harassment', 'offensive', 'fraud', 'privacy', 'other') then
    raise exception 'Geçersiz şikâyet nedeni';
  end if;
  if char_length(normalized_details) > 1000 then
    raise exception 'Şikâyet açıklaması en fazla 1000 karakter olabilir';
  end if;

  case normalized_target_type
    when 'product' then
      select
        left(p.name || ' (' || p.sku || ')', 160),
        left(
          'Ürün: ' || p.name
          || '; SKU: ' || p.sku
          || '; Kategori: ' || p.category
          || '; Birim: ' || p.unit,
          1000
        ),
        creator.id,
        creator.role,
        creator.is_platform_operator
      into
        target_label,
        target_content_snapshot,
        target_review_subject_id,
        target_user_role,
        target_is_platform_operator
      from public.products p
      left join public.profiles creator
        on creator.id = p.created_by
       and creator.organization_id = p.organization_id
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.active;

      if target_user_role = 'admin' or coalesce(target_is_platform_operator, false) then
        report_review_scope := 'platform';
      else
        target_review_subject_id := null;
      end if;

    when 'movement' then
      select
        left('Stok hareketi · ' || p.name, 160),
        left(coalesce(nullif(m.note, ''), '[Not yok]'), 1000),
        actor.id,
        actor.role,
        actor.is_platform_operator
      into
        target_label,
        target_content_snapshot,
        target_review_subject_id,
        target_user_role,
        target_is_platform_operator
      from public.stock_movements m
      join public.products p
        on p.id = m.product_id
       and p.organization_id = m.organization_id
      left join public.profiles actor
        on actor.id = m.actor_id
       and actor.organization_id = m.organization_id
      where m.id = p_target_id
        and m.organization_id = current_profile.organization_id;

      if target_user_role = 'admin' or coalesce(target_is_platform_operator, false) then
        report_review_scope := 'platform';
      else
        target_review_subject_id := null;
      end if;

    when 'user' then
      if p_target_id = current_profile.id then
        raise exception 'Kendi hesabınızı şikâyet edemezsiniz';
      end if;

      select
        left(p.display_name || ' (@' || p.username || ')', 160),
        left(p.display_name || ' (@' || p.username || ')', 1000),
        p.id,
        p.role,
        p.is_platform_operator
      into
        target_label,
        target_content_snapshot,
        target_review_subject_id,
        target_user_role,
        target_is_platform_operator
      from public.profiles p
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.is_active;

      if target_user_role = 'admin' or coalesce(target_is_platform_operator, false) then
        report_review_scope := 'platform';
      else
        target_review_subject_id := null;
      end if;
  end case;

  if target_label is null or target_content_snapshot is null then
    raise exception 'Şikâyet hedefi bu işletmede bulunamadı';
  end if;

  insert into public.content_reports (
    organization_id,
    reporter_id,
    reporter_name,
    target_type,
    target_product_id,
    target_movement_id,
    target_user_id,
    target_label,
    target_content_snapshot,
    reason,
    details,
    review_scope,
    review_subject_id
  ) values (
    current_profile.organization_id,
    current_profile.id,
    current_profile.display_name,
    normalized_target_type,
    case when normalized_target_type = 'product' then p_target_id end,
    case when normalized_target_type = 'movement' then p_target_id end,
    case when normalized_target_type = 'user' then p_target_id end,
    target_label,
    target_content_snapshot,
    normalized_reason,
    normalized_details,
    report_review_scope,
    target_review_subject_id
  )
  on conflict do nothing
  returning id, created_at into report_id, report_created_at;

  if report_id is null then
    raise exception 'Bu hedef için zaten açık bir şikâyetiniz var';
  end if;

  insert into public.security_audit_events (
    organization_id,
    actor_id,
    subject_id,
    event_type,
    metadata
  ) values (
    current_profile.organization_id,
    current_profile.id,
    case
      when report_review_scope = 'platform' then target_review_subject_id
      when normalized_target_type = 'user' then p_target_id
    end,
    'ugc.content.reported',
    jsonb_build_object(
      'report_id', report_id,
      'target_type', normalized_target_type,
      'target_id', p_target_id,
      'reason', normalized_reason,
      'review_scope', report_review_scope
    )
  );

  return jsonb_build_object(
    'report_id', report_id,
    'status', 'open',
    'review_scope', report_review_scope,
    'created_at', report_created_at
  );
end;
$$;

create or replace function public.list_content_reports(p_status text default 'open')
returns table (
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
  current_profile := private.require_admin_profile();

  if normalized_status not in ('open', 'resolved', 'all') then
    raise exception 'Geçersiz şikâyet durumu';
  end if;

  return query
  select
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
  where r.organization_id = current_profile.organization_id
    and r.review_scope = 'tenant'
    and (normalized_status = 'all' or r.status = normalized_status)
  order by r.created_at desc, r.id;
end;
$$;

comment on function public.list_content_reports(text) is
  'Lists only tenant-review reports for the authenticated administrator own organization; platform-review reports are deliberately excluded.';

create or replace function public.moderate_content_report(
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
  target_profile public.profiles;
  normalized_action text := lower(trim(coalesce(p_action, '')));
  normalized_note text := nullif(trim(coalesce(p_note, '')), '');
  resolved_timestamp timestamptz := now();
  affected_rows integer;
begin
  current_profile := private.require_admin_profile();
  -- Tenant moderation is a safety operation and remains available while billing
  -- is read-only, but an administrator must have accepted the current terms.
  perform private.require_current_ugc_terms(current_profile.organization_id);

  if p_report_id is null then
    raise exception 'Şikâyet kaydı gerekli';
  end if;
  if normalized_action not in (
    'dismiss',
    'remove_product',
    'redact_movement_note',
    'deactivate_user'
  ) then
    raise exception 'Geçersiz moderasyon işlemi';
  end if;
  if normalized_note is not null and char_length(normalized_note) > 500 then
    raise exception 'Moderasyon notu en fazla 500 karakter olabilir';
  end if;

  -- Organization and scope are both server-derived predicates. A tenant admin
  -- therefore cannot probe, lock, or mutate a platform-review report by UUID.
  select * into current_report
  from public.content_reports r
  where r.id = p_report_id
    and r.organization_id = current_profile.organization_id
    and r.review_scope = 'tenant'
    and r.status = 'open'
  for update;

  if current_report.id is null then
    raise exception 'Açık şikâyet bulunamadı';
  end if;
  if current_report.target_type = 'user'
     and current_report.target_user_id = current_profile.id then
    raise exception 'Yönetici kendi hakkındaki şikâyeti çözemez';
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
        and organization_id = current_profile.organization_id;
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
        and organization_id = current_profile.organization_id;
      get diagnostics affected_rows = row_count;

      if affected_rows <> 1 then
        raise exception 'Moderasyon hedefi stok hareketi bulunamadı';
      end if;

    when 'deactivate_user' then
      if current_report.target_type <> 'user'
         or current_report.target_user_id is null then
        raise exception 'Bu işlem yalnızca kullanıcı şikâyetlerinde kullanılabilir';
      end if;

      select * into target_profile
      from public.profiles p
      where p.id = current_report.target_user_id
        and p.organization_id = current_profile.organization_id
      for update;

      if target_profile.id is null then
        raise exception 'Moderasyon hedefi kullanıcı bulunamadı';
      end if;
      if target_profile.id = current_profile.id then
        raise exception 'Yönetici kendi hesabını devre dışı bırakamaz';
      end if;
      if target_profile.role = 'admin' then
        raise exception 'İşletme yöneticisi bu işlemle devre dışı bırakılamaz';
      end if;
      if target_profile.is_platform_operator then
        raise exception 'Platform yöneticisi bu işlemle devre dışı bırakılamaz';
      end if;

      update public.profiles
      set is_active = false,
          deactivated_at = coalesce(deactivated_at, resolved_timestamp)
      where id = target_profile.id
        and organization_id = current_profile.organization_id;

      delete from auth.sessions
      where user_id = target_profile.id;
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
    and organization_id = current_profile.organization_id
    and review_scope = 'tenant'
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
    current_profile.organization_id,
    current_profile.id,
    case when current_report.target_type = 'user' then current_report.target_user_id end,
    'ugc.report.resolved',
    jsonb_build_object(
      'report_id', current_report.id,
      'target_type', current_report.target_type,
      'target_id', case current_report.target_type
        when 'product' then current_report.target_product_id
        when 'movement' then current_report.target_movement_id
        when 'user' then current_report.target_user_id
      end,
      'action', normalized_action,
      'review_scope', 'tenant'
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

comment on function public.moderate_content_report(uuid, text, text) is
  'Resolves only an authenticated administrator own-organization tenant-review report; platform-review UUIDs are indistinguishable from missing records.';

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
  current_profile := private.require_active_profile();

  if not current_profile.is_platform_operator then
    raise exception 'Bu işlem yalnızca platform yöneticisine açıktır';
  end if;
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
  'Lists cross-organization platform-review reports to an active platform operator, excluding reports about that operator own content or account.';

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
  current_profile := private.require_active_profile();

  if not current_profile.is_platform_operator then
    raise exception 'Bu işlem yalnızca platform yöneticisine açıktır';
  end if;
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
  'Lets an active platform operator resolve another subject platform-review report; organization and subject are derived from the locked report.';

create or replace function public.service_list_platform_content_reports(
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
  normalized_status text := lower(trim(coalesce(p_status, 'open')));
begin
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
    and (normalized_status = 'all' or r.status = normalized_status)
  order by r.created_at desc, r.id;
end;
$$;

comment on function public.service_list_platform_content_reports(text) is
  'Independent service-role support fallback that can inspect every platform-review report, including reports hidden from their operator subject.';

create or replace function public.service_moderate_platform_content_report(
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
  current_report public.content_reports;
  target_organization public.organizations;
  normalized_action text := lower(trim(coalesce(p_action, '')));
  normalized_note text := nullif(trim(coalesce(p_note, '')), '');
  resolved_timestamp timestamptz := now();
  support_request_id uuid := gen_random_uuid();
  affected_rows integer;
begin
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

  -- No caller organization or actor id is accepted. The trusted support worker
  -- derives the tenant and target exclusively from the locked report.
  select * into current_report
  from public.content_reports r
  where r.id = p_report_id
    and r.review_scope = 'platform'
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
      resolved_by = null,
      resolved_by_name = 'Platform destek ekibi',
      resolved_at = resolved_timestamp,
      updated_at = resolved_timestamp
  where id = current_report.id
    and review_scope = 'platform'
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
    null,
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
      'review_scope', 'platform',
      'resolution_channel', 'service_support',
      'support_request_id', support_request_id
    )
  );

  return jsonb_build_object(
    'report_id', current_report.id,
    'status', 'resolved',
    'action', normalized_action,
    'resolved_at', resolved_timestamp,
    'support_request_id', support_request_id
  );
end;
$$;

comment on function public.service_moderate_platform_content_report(uuid, text, text) is
  'Independent service-role support fallback for reports that cannot be self-reviewed by their sole platform-operator subject; audit actor_id stays null, resolver is an explicit system label, and a server-generated request id correlates the action.';

comment on table public.content_reports is
  'Service-protected, tenant-owned UGC reports exposed through scope-specific authenticated RPCs and a service-only independent support fallback.';
comment on column public.content_reports.resolution_action is
  'Scope-constrained action: tenant content moderation or platform-only administrator/organization enforcement.';

revoke all on function private.anonymize_ugc_reports_before_profile_delete()
  from public, anon, authenticated, service_role;

revoke all on function public.report_content(text, uuid, text, text)
  from public, anon, authenticated, service_role;
revoke all on function public.list_content_reports(text)
  from public, anon, authenticated, service_role;
revoke all on function public.moderate_content_report(uuid, text, text)
  from public, anon, authenticated, service_role;
revoke all on function public.list_platform_content_reports(text)
  from public, anon, authenticated, service_role;
revoke all on function public.moderate_platform_content_report(uuid, text, text)
  from public, anon, authenticated, service_role;
revoke all on function public.service_list_platform_content_reports(text)
  from public, anon, authenticated, service_role;
revoke all on function public.service_moderate_platform_content_report(uuid, text, text)
  from public, anon, authenticated, service_role;

grant execute on function public.report_content(text, uuid, text, text)
  to authenticated;
grant execute on function public.list_content_reports(text)
  to authenticated;
grant execute on function public.moderate_content_report(uuid, text, text)
  to authenticated;
grant execute on function public.list_platform_content_reports(text)
  to authenticated;
grant execute on function public.moderate_platform_content_report(uuid, text, text)
  to authenticated;
grant execute on function public.service_list_platform_content_reports(text)
  to service_role;
grant execute on function public.service_moderate_platform_content_report(uuid, text, text)
  to service_role;

commit;
