-- Require versioned UGC terms acceptance and provide tenant-isolated reporting
-- and moderation APIs without exposing moderation records directly to clients.

begin;

set local statement_timeout = '30s';

-- This repository snapshot does not contain the already-live account-security
-- migration. Fail atomically and explicitly if a target database has not
-- applied that prerequisite instead of creating RPCs with deferred runtime
-- failures or the older, weaker session checks.
do $$
begin
  if to_regclass('public.security_audit_events') is null
     or to_regclass('public.pending_account_registrations') is null
     or to_regprocedure('private.has_live_session()') is null
     or (
       select count(*)
       from pg_catalog.pg_attribute a
       where a.attrelid = 'public.profiles'::regclass
         and a.attname in ('is_active', 'deactivated_at', 'must_change_password')
         and a.attnum > 0
         and not a.attisdropped
     ) <> 3 then
    raise exception
      'UGC migration requires 20260826063358_account_security_and_coworker_management';
  end if;
end;
$$;

alter table public.pending_account_registrations
  add column ugc_terms_version text,
  add column ugc_terms_accepted_at timestamptz,
  add constraint pending_registrations_ugc_terms_acceptance_check check (
    (
      registration_kind = 'coworker'
      and ugc_terms_version is null
      and ugc_terms_accepted_at is null
    )
    or (
      ugc_terms_version is not null
      and ugc_terms_version ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}-v[1-9][0-9]*$'
      and ugc_terms_accepted_at is not null
    )
  ) not valid;

comment on column public.pending_account_registrations.ugc_terms_version is
  'UGC terms version explicitly accepted during registration; required for business administrators.';
comment on column public.pending_account_registrations.ugc_terms_accepted_at is
  'Timestamp of registration-time UGC terms acceptance; coworkers may accept after first sign-in.';
comment on constraint pending_registrations_ugc_terms_acceptance_check
  on public.pending_account_registrations is
  'Enforced for new rows; NOT VALID preserves pre-deployment pending registrations. '
  'The finalizer rejects business registrations without current acceptance.';

alter table public.profiles
  add column ugc_terms_version text,
  add column ugc_terms_accepted_at timestamptz,
  add constraint profiles_ugc_terms_acceptance_check check (
    (ugc_terms_version is null and ugc_terms_accepted_at is null)
    or (
      ugc_terms_version is not null
      and ugc_terms_version ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}-v[1-9][0-9]*$'
      and ugc_terms_accepted_at is not null
    )
  );

comment on column public.profiles.ugc_terms_version is
  'Latest version of the in-app user-generated-content terms accepted by this profile.';
comment on column public.profiles.ugc_terms_accepted_at is
  'Timestamp at which the profile accepted ugc_terms_version.';

create or replace function private.current_ugc_terms_version()
returns text
language sql
immutable
set search_path = ''
as $$
  select '2026-08-29-v1'::text;
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
  active_seats integer;
  auth_email text;
  auth_confirmed_at timestamptz;
begin
  select * into pending
  from public.pending_account_registrations
  where auth_user_id = p_auth_user_id and username = p_username
  for update;

  -- Preserve the live function idempotent response exactly for registrations
  -- that were already finalized before a retry.
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

  if pending.registration_kind = 'business_admin'
     and (
       pending.ugc_terms_accepted_at is null
       or pending.ugc_terms_version is distinct from private.current_ugc_terms_version()
     ) then
    raise exception 'Güncel kullanıcı içeriği şartları kabul edilmedi';
  end if;

  if pending.ugc_terms_version is not null
     and pending.ugc_terms_version is distinct from private.current_ugc_terms_version() then
    raise exception 'Kayıt sırasında kabul edilen kullanıcı içeriği şartları artık güncel değil';
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
      must_change_password, recovery_email, recovery_email_verified_at,
      ugc_terms_version, ugc_terms_accepted_at
    ) values (
      pending.auth_user_id, organization.id, pending.username,
      pending.display_name, 'admin', null, false, true, null, false,
      pending.email, now(), pending.ugc_terms_version, pending.ugc_terms_accepted_at
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
      must_change_password, recovery_email, recovery_email_verified_at,
      ugc_terms_version, ugc_terms_accepted_at
    ) values (
      pending.auth_user_id, organization.id, pending.username,
      pending.display_name, 'member', pending.created_by, false, true, null,
      true, pending.email, now(), pending.ugc_terms_version, pending.ugc_terms_accepted_at
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

  if pending.ugc_terms_version is not null then
    insert into public.security_audit_events (
      organization_id, actor_id, subject_id, event_type, metadata
    ) values (
      organization.id,
      pending.auth_user_id,
      pending.auth_user_id,
      'ugc.terms.accepted',
      jsonb_build_object(
        'version', pending.ugc_terms_version,
        'source', 'registration'
      )
    );
  end if;

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

comment on function public.service_finalize_pending_registration(uuid, text) is
  'Finalizes verified registrations and copies registration-time UGC acceptance evidence into the profile.';

create or replace function private.require_current_ugc_terms(p_organization_id uuid)
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

  if current_profile.organization_id <> p_organization_id then
    raise exception 'İşletme erişimi reddedildi';
  end if;

  if current_profile.ugc_terms_accepted_at is null
     or current_profile.ugc_terms_version is distinct from private.current_ugc_terms_version() then
    raise exception 'Devam etmek için güncel kullanıcı içeriği şartlarını kabul edin';
  end if;

  return current_profile;
end;
$$;

-- All normal inventory writes already call this helper. Requiring the current
-- UGC terms here makes acceptance a single, fail-closed write boundary.
create or replace function private.require_writable_organization(p_organization_id uuid)
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

-- Required for the tenant-qualified movement foreign key below. The movement
-- primary key remains unchanged.
create unique index stock_movements_id_organization_idx
  on public.stock_movements (id, organization_id);

create table public.content_reports (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null,
  reporter_id uuid,
  reporter_name text not null,
  target_type text not null,
  target_product_id uuid,
  target_movement_id uuid,
  target_user_id uuid,
  target_label text not null,
  target_content_snapshot text not null,
  reason text not null,
  details text not null default '',
  status text not null default 'open',
  resolution_action text,
  resolution_note text,
  resolved_by uuid,
  resolved_by_name text,
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint content_reports_organization_id_fkey
    foreign key (organization_id)
    references public.organizations(id) on delete cascade,
  constraint content_reports_reporter_organization_fkey
    foreign key (reporter_id, organization_id)
    references public.profiles(id, organization_id)
    on delete set null (reporter_id),
  constraint content_reports_product_organization_fkey
    foreign key (target_product_id, organization_id)
    references public.products(id, organization_id)
    on delete set null (target_product_id),
  constraint content_reports_movement_organization_fkey
    foreign key (target_movement_id, organization_id)
    references public.stock_movements(id, organization_id)
    on delete set null (target_movement_id),
  constraint content_reports_user_organization_fkey
    foreign key (target_user_id, organization_id)
    references public.profiles(id, organization_id)
    on delete set null (target_user_id),
  constraint content_reports_resolver_organization_fkey
    foreign key (resolved_by, organization_id)
    references public.profiles(id, organization_id)
    on delete set null (resolved_by),
  constraint content_reports_reporter_name_length check (
    char_length(reporter_name) between 1 and 80
  ),
  constraint content_reports_target_type_check check (
    target_type in ('product', 'movement', 'user')
  ),
  constraint content_reports_target_shape_check check (
    (
      target_type = 'product'
      and target_product_id is not null
      and target_movement_id is null
      and target_user_id is null
    )
    or (
      target_type = 'movement'
      and target_product_id is null
      and target_movement_id is not null
      and target_user_id is null
    )
    or (
      target_type = 'user'
      and target_product_id is null
      and target_movement_id is null
      and target_user_id is not null
    )
    -- A referenced target may later be deleted by the existing account-erasure
    -- flow. Its server-derived label remains available for moderation history.
    or (
      target_product_id is null
      and target_movement_id is null
      and target_user_id is null
    )
  ),
  constraint content_reports_target_label_length check (
    char_length(target_label) between 1 and 160
  ),
  constraint content_reports_target_content_snapshot_length check (
    char_length(target_content_snapshot) between 1 and 1000
  ),
  constraint content_reports_reason_check check (
    reason in ('spam', 'harassment', 'offensive', 'fraud', 'privacy', 'other')
  ),
  constraint content_reports_details_length check (char_length(details) <= 1000),
  constraint content_reports_status_check check (status in ('open', 'resolved')),
  constraint content_reports_resolution_action_check check (
    resolution_action is null
    or resolution_action in (
      'dismiss',
      'remove_product',
      'redact_movement_note',
      'deactivate_user'
    )
  ),
  constraint content_reports_resolution_target_check check (
    resolution_action is null
    or resolution_action = 'dismiss'
    or (resolution_action = 'remove_product' and target_type = 'product')
    or (resolution_action = 'redact_movement_note' and target_type = 'movement')
    or (resolution_action = 'deactivate_user' and target_type = 'user')
  ),
  constraint content_reports_resolution_note_length check (
    resolution_note is null or char_length(resolution_note) <= 500
  ),
  constraint content_reports_resolved_by_name_length check (
    resolved_by_name is null or char_length(resolved_by_name) between 1 and 80
  ),
  constraint content_reports_state_check check (
    (
      status = 'open'
      and resolution_action is null
      and resolution_note is null
      and resolved_by is null
      and resolved_by_name is null
      and resolved_at is null
    )
    or (
      status = 'resolved'
      and resolution_action is not null
      and resolved_by_name is not null
      and resolved_at is not null
    )
  )
);

comment on table public.content_reports is
  'Tenant-scoped UGC abuse reports. Clients can access records only through authenticated RPCs.';
comment on column public.content_reports.target_label is
  'Server-derived target label retained after content removal and anonymized when privacy erasure requires it.';
comment on column public.content_reports.target_content_snapshot is
  'Bounded server-derived evidence copy, modified only when a deleted user must be anonymized.';
comment on column public.content_reports.details is
  'Reporter-provided context, limited to 1000 characters.';
comment on column public.content_reports.resolution_action is
  'Moderation action applied while resolving the report.';

create index content_reports_organization_status_created_idx
  on public.content_reports (organization_id, status, created_at desc);
create index content_reports_reporter_created_idx
  on public.content_reports (reporter_id, created_at desc)
  where reporter_id is not null;
create index content_reports_product_target_idx
  on public.content_reports (target_product_id)
  where target_product_id is not null;
create index content_reports_movement_target_idx
  on public.content_reports (target_movement_id)
  where target_movement_id is not null;
create index content_reports_user_target_idx
  on public.content_reports (target_user_id)
  where target_user_id is not null;
create index content_reports_resolver_idx
  on public.content_reports (resolved_by)
  where resolved_by is not null;
create unique index content_reports_one_open_product_per_reporter_idx
  on public.content_reports (organization_id, reporter_id, target_product_id)
  where status = 'open'
    and reporter_id is not null
    and target_product_id is not null;
create unique index content_reports_one_open_movement_per_reporter_idx
  on public.content_reports (organization_id, reporter_id, target_movement_id)
  where status = 'open'
    and reporter_id is not null
    and target_movement_id is not null;
create unique index content_reports_one_open_user_per_reporter_idx
  on public.content_reports (organization_id, reporter_id, target_user_id)
  where status = 'open'
    and reporter_id is not null
    and target_user_id is not null;

alter table public.content_reports enable row level security;

revoke all on table public.content_reports
  from public, anon, authenticated, service_role;
grant select, insert, update, delete on table public.content_reports
  to service_role;

create or replace function private.anonymize_ugc_reports_before_profile_delete()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  -- Remove reporter-authored free text together with the reporter identity.
  update public.content_reports
  set reporter_name = 'Silinmiş kullanıcı',
      details = '',
      updated_at = now()
  where organization_id = old.organization_id
    and reporter_id = old.id;

  -- A user report keeps its workflow state but no deleted profile snapshot.
  update public.content_reports
  set target_label = 'Silinmiş kullanıcı',
      target_content_snapshot = 'Silinmiş kullanıcı',
      updated_at = now()
  where organization_id = old.organization_id
    and target_type = 'user'
    and target_user_id = old.id;

  update public.content_reports
  set resolved_by_name = 'Silinmiş kullanıcı',
      resolution_note = null,
      updated_at = now()
  where organization_id = old.organization_id
    and resolved_by = old.id;

  -- The audit table retains the action but not a deleted user UUID in JSON.
  update public.security_audit_events
  set metadata = metadata - 'target_id'
  where subject_id = old.id
    and event_type in ('ugc.content.reported', 'ugc.report.resolved');

  return old;
end;
$$;

create trigger before_profile_delete_anonymize_ugc_reports
before delete on public.profiles
for each row
execute function private.anonymize_ugc_reports_before_profile_delete();

comment on function private.anonymize_ugc_reports_before_profile_delete() is
  'Scrubs deleted-profile names, free text, and user target identifiers while retaining moderation state.';
comment on trigger before_profile_delete_anonymize_ugc_reports on public.profiles is
  'Keeps existing account-erasure flows compatible with retained moderation records.';

create or replace function public.get_ugc_terms_status()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_version text := private.current_ugc_terms_version();
begin
  current_profile := private.require_active_profile();

  return jsonb_build_object(
    'current_version', current_version,
    'accepted_version', current_profile.ugc_terms_version,
    'accepted_at', current_profile.ugc_terms_accepted_at,
    'accepted', current_profile.ugc_terms_accepted_at is not null
      and current_profile.ugc_terms_version = current_version
  );
end;
$$;

comment on function public.get_ugc_terms_status() is
  'Returns the server current UGC terms version and the authenticated active profile acceptance state.';

drop function if exists public.accept_current_ugc_terms();

create or replace function public.accept_current_ugc_terms(p_version text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_version text := private.current_ugc_terms_version();
  accepted_timestamp timestamptz;
begin
  current_profile := private.require_active_profile();

  if p_version is distinct from current_version then
    raise exception 'Gösterilen kullanıcı içeriği şartları artık güncel değil';
  end if;

  if current_profile.ugc_terms_version = current_version
     and current_profile.ugc_terms_accepted_at is not null then
    return jsonb_build_object(
      'accepted', true,
      'current_version', current_version,
      'accepted_version', current_profile.ugc_terms_version,
      'accepted_at', current_profile.ugc_terms_accepted_at
    );
  end if;

  accepted_timestamp := now();

  update public.profiles
  set ugc_terms_version = current_version,
      ugc_terms_accepted_at = accepted_timestamp
  where id = current_profile.id
    and organization_id = current_profile.organization_id;

  insert into public.security_audit_events (
    organization_id,
    actor_id,
    subject_id,
    event_type,
    metadata
  ) values (
    current_profile.organization_id,
    current_profile.id,
    current_profile.id,
    'ugc.terms.accepted',
    jsonb_build_object('version', current_version)
  );

  return jsonb_build_object(
    'accepted', true,
    'current_version', current_version,
    'accepted_version', current_version,
    'accepted_at', accepted_timestamp
  );
end;
$$;

comment on function public.accept_current_ugc_terms(text) is
  'Records acceptance only when the client-displayed UGC terms version matches the server current version.';

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
  report_id uuid;
  report_created_at timestamptz;
begin
  current_profile := private.require_active_profile();

  -- Reporting is a safety operation, not inventory content creation. Keep it
  -- available when a subscription is read-only or terms acceptance is pending.

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
        )
      into target_label, target_content_snapshot
      from public.products p
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.active;

    when 'movement' then
      select
        left('Stok hareketi · ' || p.name, 160),
        left(coalesce(nullif(m.note, ''), '[Not yok]'), 1000)
      into target_label, target_content_snapshot
      from public.stock_movements m
      join public.products p
        on p.id = m.product_id
       and p.organization_id = m.organization_id
      where m.id = p_target_id
        and m.organization_id = current_profile.organization_id;

    when 'user' then
      if p_target_id = current_profile.id then
        raise exception 'Kendi hesabınızı şikâyet edemezsiniz';
      end if;

      select
        left(p.display_name || ' (@' || p.username || ')', 160),
        left(p.display_name || ' (@' || p.username || ')', 1000),
        p.role,
        p.is_platform_operator
      into target_label, target_content_snapshot, target_user_role, target_is_platform_operator
      from public.profiles p
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.is_active;

      if target_user_role = 'admin' or target_is_platform_operator then
        raise exception 'İşletme yöneticisi bildirimleri platform desteğine iletilmelidir';
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
    details
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
    normalized_details
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
    case when normalized_target_type = 'user' then p_target_id end,
    'ugc.content.reported',
    jsonb_build_object(
      'report_id', report_id,
      'target_type', normalized_target_type,
      'target_id', p_target_id,
      'reason', normalized_reason
    )
  );

  return jsonb_build_object(
    'report_id', report_id,
    'status', 'open',
    'created_at', report_created_at
  );
end;
$$;

comment on function public.report_content(text, uuid, text, text) is
  'Creates a tenant-scoped UGC report after authenticating the reporter and validating the target.';

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
    and (normalized_status = 'all' or r.status = normalized_status)
  order by r.created_at desc, r.id;
end;
$$;

comment on function public.list_content_reports(text) is
  'Lists only the authenticated administrator own-organization reports, filtered by open, resolved, or all.';

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
  -- Safety moderation remains available even when billing makes normal inventory
  -- writes read-only, but the administrator must accept the current UGC terms.
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

  select * into current_report
  from public.content_reports r
  where r.id = p_report_id
    and r.organization_id = current_profile.organization_id
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

      -- Existing RLS already checks that the backing auth session still exists.
      -- Removing all sessions makes deactivation immediate for existing tokens.
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
    and organization_id = current_profile.organization_id;

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
      'action', normalized_action
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
  'Lets an authenticated own-organization administrator resolve a report and applies the selected safe action.';

revoke all on function private.current_ugc_terms_version()
  from public, anon, authenticated, service_role;
revoke all on function private.require_current_ugc_terms(uuid)
  from public, anon, authenticated, service_role;
revoke all on function private.require_writable_organization(uuid)
  from public, anon, authenticated, service_role;
revoke all on function private.anonymize_ugc_reports_before_profile_delete()
  from public, anon, authenticated, service_role;

revoke all on function public.service_finalize_pending_registration(uuid, text)
  from public, anon, authenticated, service_role;
grant execute on function public.service_finalize_pending_registration(uuid, text)
  to service_role;

revoke all on function public.get_ugc_terms_status()
  from public, anon, authenticated, service_role;
revoke all on function public.accept_current_ugc_terms(text)
  from public, anon, authenticated, service_role;
revoke all on function public.report_content(text, uuid, text, text)
  from public, anon, authenticated, service_role;
revoke all on function public.list_content_reports(text)
  from public, anon, authenticated, service_role;
revoke all on function public.moderate_content_report(uuid, text, text)
  from public, anon, authenticated, service_role;

grant execute on function public.accept_current_ugc_terms(text)
  to authenticated;
grant execute on function public.get_ugc_terms_status()
  to authenticated;
grant execute on function public.report_content(text, uuid, text, text)
  to authenticated;
grant execute on function public.list_content_reports(text)
  to authenticated;
grant execute on function public.moderate_content_report(uuid, text, text)
  to authenticated;

commit;
