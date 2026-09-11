-- Close UGC authorization races, bound report reads, make authenticated
-- moderation replay-safe and keep every public RPC as SECURITY INVOKER.

begin;

set local statement_timeout = '30s';
set local lock_timeout = '10s';

do $$
begin
  if to_regclass('private.ugc_terms_documents') is null
     or to_regclass('private.inventory_command_receipts') is null
     or to_regclass('private.platform_admin_command_receipts') is null
     or to_regprocedure('private.require_locked_inventory_profile(boolean)') is null then
    raise exception
      'UGC concurrency migration requires terms v2, inventory and platform reliability';
  end if;
end;
$$;

-- The subject may become NULL only through the profile-erasure trigger. Keeping
-- an explicit tombstone makes NULL fail closed instead of silently bypassing
-- the platform self-review exclusion.
alter table public.content_reports
  add column if not exists review_subject_deleted_at timestamptz;

update public.content_reports
set review_subject_deleted_at = coalesce(updated_at, clock_timestamp())
where review_scope = 'platform'
  and review_subject_id is null
  and review_subject_deleted_at is null;

alter table public.content_reports
  add constraint content_reports_review_subject_lifecycle_check check (
    (
      review_scope = 'tenant'
      and review_subject_id is null
      and review_subject_deleted_at is null
    )
    or (
      review_scope = 'platform'
      and (
        (review_subject_id is not null and review_subject_deleted_at is null)
        or (review_subject_id is null and review_subject_deleted_at is not null)
      )
    )
  );

-- No direct Data API path exists. All access goes through the bounded routines
-- below, including trusted support; the absence of an RLS policy is deliberate.
alter table public.content_reports force row level security;
revoke all on table public.content_reports
  from public, anon, authenticated, service_role;

create index if not exists content_reports_tenant_keyset_idx
  on public.content_reports (
    organization_id, review_scope, status, created_at desc, id desc
  );
create index if not exists content_reports_platform_keyset_idx
  on public.content_reports (status, created_at desc, id desc)
  where review_scope = 'platform';

create table private.ugc_command_receipts (
  actor_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  organization_id uuid not null
    references public.organizations(id) on delete cascade,
  command_name text not null check (
    command_name in ('report_content', 'moderate_tenant', 'moderate_platform')
  ),
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  response jsonb,
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  primary key (actor_id, request_id),
  constraint ugc_command_receipts_completion_check check (
    (response is null and completed_at is null)
    or (response is not null and completed_at is not null)
  )
);

create index ugc_command_receipts_organization_idx
  on private.ugc_command_receipts (organization_id, created_at desc);
alter table private.ugc_command_receipts enable row level security;
alter table private.ugc_command_receipts force row level security;
revoke all on table private.ugc_command_receipts
  from public, anon, authenticated, service_role;

create table private.ugc_service_command_receipts (
  request_id uuid primary key,
  organization_id uuid not null
    references public.organizations(id) on delete cascade,
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  response jsonb,
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  constraint ugc_service_receipts_completion_check check (
    (response is null and completed_at is null)
    or (response is not null and completed_at is not null)
  )
);
create index ugc_service_receipts_organization_idx
  on private.ugc_service_command_receipts (organization_id, created_at desc);
alter table private.ugc_service_command_receipts enable row level security;
alter table private.ugc_service_command_receipts force row level security;
revoke all on table private.ugc_service_command_receipts
  from public, anon, authenticated, service_role;

create or replace function private.require_locked_ugc_profile(
  p_admin_required boolean default false,
  p_platform_required boolean default false
)
returns public.profiles
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  current_profile := private.require_locked_inventory_profile(p_admin_required);
  if p_platform_required and not current_profile.is_platform_operator then
    raise exception 'Bu işlem yalnızca platform yöneticisine açıktır';
  end if;
  return current_profile;
end;
$$;

create or replace function private.claim_ugc_command(
  p_actor_id uuid,
  p_request_id uuid,
  p_organization_id uuid,
  p_command_name text,
  p_request_hash text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  inserted boolean;
  receipt private.ugc_command_receipts;
begin
  if p_request_id is null then
    raise exception 'İstek kimliği gerekli';
  end if;

  insert into private.ugc_command_receipts (
    actor_id, request_id, organization_id, command_name, request_hash
  ) values (
    p_actor_id, p_request_id, p_organization_id, p_command_name, p_request_hash
  ) on conflict (actor_id, request_id) do nothing;
  inserted := found;
  if inserted then return null; end if;

  select * into receipt
  from private.ugc_command_receipts r
  where r.actor_id = p_actor_id and r.request_id = p_request_id
  for update;

  if receipt.organization_id is distinct from p_organization_id
     or receipt.command_name is distinct from p_command_name
     or receipt.request_hash is distinct from p_request_hash then
    raise exception 'İstek kimliği farklı bir moderasyon işlemi için kullanıldı';
  end if;
  if receipt.response is null or receipt.completed_at is null then
    raise exception 'Önceki moderasyon işlemi tamamlanmamış görünüyor';
  end if;
  return receipt.response;
end;
$$;

create or replace function private.finish_ugc_command(
  p_actor_id uuid,
  p_request_id uuid,
  p_response jsonb
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if p_request_id is null then return; end if;
  update private.ugc_command_receipts as receipts
  set response = p_response,
      completed_at = clock_timestamp()
  where receipts.actor_id = p_actor_id
    and receipts.request_id = p_request_id
    and receipts.response is null
    and receipts.completed_at is null;
  if not found then
    raise exception 'Moderasyon işlem sonucu güvenli biçimde kaydedilemedi';
  end if;
end;
$$;

create or replace function private.get_ugc_terms_status_v2()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_version text := private.current_ugc_terms_version();
  current_digest text := private.current_ugc_terms_digest();
  accepted_digest text;
begin
  current_profile := private.require_active_profile();
  select a.document_digest into accepted_digest
  from private.ugc_terms_acceptances a
  where a.profile_id = current_profile.id
    and a.terms_version = current_profile.ugc_terms_version;

  return jsonb_build_object(
    'current_version', current_version,
    'current_digest', current_digest,
    'accepted_version', current_profile.ugc_terms_version,
    'accepted_digest', accepted_digest,
    'accepted_at', current_profile.ugc_terms_accepted_at,
    'accepted', current_profile.ugc_terms_accepted_at is not null
      and current_profile.ugc_terms_version = current_version
      and accepted_digest = current_digest
  );
end;
$$;

create or replace function private.accept_current_ugc_terms_v2(
  p_version text,
  p_digest text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_version text := private.current_ugc_terms_version();
  current_digest text := private.current_ugc_terms_digest();
  accepted_timestamp timestamptz;
  accepted_digest text;
begin
  current_profile := private.require_locked_ugc_profile(false, false);
  perform private.assert_organization_not_deleting(current_profile.organization_id);
  if p_version is distinct from current_version then
    raise exception 'Gösterilen kullanıcı içeriği şartları artık güncel değil';
  end if;
  if current_digest is null then
    raise exception 'Güncel kullanıcı içeriği şartı yayımlanmamış';
  end if;
  if p_digest is distinct from current_digest then
    raise exception 'Gösterilen kullanıcı içeriği metninin özeti güncel belgeyle eşleşmiyor';
  end if;

  select a.document_digest into accepted_digest
  from private.ugc_terms_acceptances a
  where a.profile_id = current_profile.id
    and a.terms_version = current_version;

  if current_profile.ugc_terms_version = current_version
     and current_profile.ugc_terms_accepted_at is not null
     and accepted_digest = current_digest then
    return jsonb_build_object(
      'accepted', true,
      'current_version', current_version,
      'current_digest', current_digest,
      'accepted_version', current_version,
      'accepted_digest', accepted_digest,
      'accepted_at', current_profile.ugc_terms_accepted_at
    );
  end if;

  accepted_timestamp := clock_timestamp();
  update public.profiles
  set ugc_terms_version = current_version,
      ugc_terms_accepted_at = accepted_timestamp
  where id = current_profile.id
    and organization_id = current_profile.organization_id;
  if not found then raise exception 'Kullanım koşulu kabulü kaydedilemedi'; end if;

  -- The profile trigger inserts the immutable acceptance in this transaction.
  select a.document_digest into accepted_digest
  from private.ugc_terms_acceptances a
  where a.profile_id = current_profile.id
    and a.terms_version = current_version;
  if accepted_digest is distinct from current_digest then
    raise exception 'Kullanım koşulu kabul kanıtı doğrulanamadı';
  end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    current_profile.organization_id,
    current_profile.id,
    current_profile.id,
    'ugc.terms.accepted',
    jsonb_build_object('version', current_version, 'digest', current_digest)
  );

  return jsonb_build_object(
    'accepted', true,
    'current_version', current_version,
    'current_digest', current_digest,
    'accepted_version', current_version,
    'accepted_digest', current_digest,
    'accepted_at', accepted_timestamp
  );
end;
$$;

create or replace function private.report_content_v2(
  p_target_type text,
  p_target_id uuid,
  p_reason text,
  p_details text,
  p_request_id uuid
)
returns jsonb
language plpgsql
volatile
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
  candidate_subject_id uuid;
  report_review_scope text := 'tenant';
  report_id uuid;
  report_created_at timestamptz;
  request_hash text;
  replay jsonb;
  result_payload jsonb;
  open_report_count integer;
  rate_allowed boolean;
begin
  current_profile := private.require_locked_ugc_profile(false, false);

  if p_target_id is null then raise exception 'Şikâyet edilecek içerik gerekli'; end if;
  if normalized_target_type not in ('product', 'movement', 'user') then
    raise exception 'Geçersiz şikâyet hedefi';
  end if;
  if normalized_reason not in ('spam', 'harassment', 'offensive', 'fraud', 'privacy', 'other') then
    raise exception 'Geçersiz şikâyet nedeni';
  end if;
  if char_length(normalized_details) > 1000 then
    raise exception 'Şikâyet açıklaması en fazla 1000 karakter olabilir';
  end if;

  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'report_content',
    'target_type', normalized_target_type,
    'target_id', p_target_id,
    'reason', normalized_reason,
    'details', normalized_details
  ));
  replay := private.claim_ugc_command(
    current_profile.id, p_request_id, current_profile.organization_id,
    'report_content', request_hash
  );
  if replay is not null then return replay; end if;

  perform private.assert_organization_not_deleting(current_profile.organization_id);

  rate_allowed := public.consume_auth_rate_limit(
    'ugc-report',
    private.inventory_request_hash(jsonb_build_object('actor_id', current_profile.id)),
    30,
    3600
  );
  if not rate_allowed then
    raise exception 'Çok fazla şikâyet gönderdiniz; daha sonra tekrar deneyin';
  end if;

  select count(*) into open_report_count
  from public.content_reports r
  where r.organization_id = current_profile.organization_id
    and r.reporter_id = current_profile.id
    and r.status = 'open';
  if open_report_count >= 50 then
    raise exception 'Açık şikâyet sınırına ulaştınız';
  end if;

  case normalized_target_type
    when 'product' then
      -- Member deletion locks the creator profile before reassigning products.
      -- Read the immutable candidate, then lock profile -> product and recheck.
      select p.created_by into candidate_subject_id
      from public.products p
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.active;
      if candidate_subject_id is not null then
        perform 1
        from public.profiles subject
        where subject.id = candidate_subject_id
          and subject.organization_id = current_profile.organization_id
        for share;
      end if;

      select
        left(p.name || ' (' || p.sku || ')', 160),
        left(
          'Ürün: ' || p.name || '; SKU: ' || p.sku
          || '; Kategori: ' || p.category || '; Birim: ' || p.unit,
          1000
        ),
        creator.id,
        creator.role,
        creator.is_platform_operator
      into target_label, target_content_snapshot, target_review_subject_id,
           target_user_role, target_is_platform_operator
      from public.products p
      left join public.profiles creator
        on creator.id = p.created_by and creator.organization_id = p.organization_id
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.active
        and p.created_by is not distinct from candidate_subject_id
      for share of p;

    when 'movement' then
      select m.actor_id into candidate_subject_id
      from public.stock_movements m
      where m.id = p_target_id
        and m.organization_id = current_profile.organization_id;
      if candidate_subject_id is not null then
        perform 1
        from public.profiles subject
        where subject.id = candidate_subject_id
          and subject.organization_id = current_profile.organization_id
        for share;
      end if;

      select
        left('Stok hareketi · ' || p.name, 160),
        left(coalesce(nullif(m.note, ''), '[Not yok]'), 1000),
        actor.id,
        actor.role,
        actor.is_platform_operator
      into target_label, target_content_snapshot, target_review_subject_id,
           target_user_role, target_is_platform_operator
      from public.stock_movements m
      join public.products p
        on p.id = m.product_id and p.organization_id = m.organization_id
      left join public.profiles actor
        on actor.id = m.actor_id and actor.organization_id = m.organization_id
      where m.id = p_target_id
        and m.organization_id = current_profile.organization_id
        and m.actor_id is not distinct from candidate_subject_id
      for share of m;

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
      into target_label, target_content_snapshot, target_review_subject_id,
           target_user_role, target_is_platform_operator
      from public.profiles p
      where p.id = p_target_id
        and p.organization_id = current_profile.organization_id
        and p.is_active
      for share;
  end case;

  if target_label is null or target_content_snapshot is null then
    raise exception 'Şikâyet hedefi bu işletmede bulunamadı';
  end if;
  if target_user_role = 'admin' or coalesce(target_is_platform_operator, false) then
    report_review_scope := 'platform';
  else
    target_review_subject_id := null;
  end if;

  insert into public.content_reports (
    organization_id, reporter_id, reporter_name, target_type,
    target_product_id, target_movement_id, target_user_id,
    target_label, target_content_snapshot, reason, details,
    review_scope, review_subject_id, review_subject_deleted_at
  ) values (
    current_profile.organization_id, current_profile.id,
    current_profile.display_name, normalized_target_type,
    case when normalized_target_type = 'product' then p_target_id end,
    case when normalized_target_type = 'movement' then p_target_id end,
    case when normalized_target_type = 'user' then p_target_id end,
    target_label, target_content_snapshot, normalized_reason, normalized_details,
    report_review_scope, target_review_subject_id, null
  )
  on conflict do nothing
  returning id, created_at into report_id, report_created_at;

  if report_id is null then
    raise exception 'Bu hedef için zaten açık bir şikâyetiniz var';
  end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
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
      'review_scope', report_review_scope,
      'request_id', p_request_id
    )
  );

  result_payload := jsonb_build_object(
    'report_id', report_id,
    'status', 'open',
    'review_scope', report_review_scope,
    'created_at', report_created_at,
    'request_id', p_request_id
  );
  perform private.finish_ugc_command(current_profile.id, p_request_id, result_payload);
  return result_payload;
end;
$$;

create or replace function private.list_content_reports_v2(
  p_status text default 'open',
  p_before_created_at timestamptz default null,
  p_before_id uuid default null,
  p_limit integer default 50
)
returns table (
  report_id uuid, created_at timestamptz, status text, target_type text,
  target_id uuid, target_label text, target_content_snapshot text,
  reason text, details text, reporter_id uuid, reporter_name text,
  resolution_action text, resolution_note text, resolved_at timestamptz,
  resolved_by uuid, resolved_by_name text
)
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  normalized_status text := lower(trim(coalesce(p_status, 'open')));
begin
  current_profile := private.require_locked_ugc_profile(true, false);
  if normalized_status not in ('open', 'resolved', 'all') then
    raise exception 'Geçersiz şikâyet durumu';
  end if;
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'Sayfa boyutu 1-100 arasında olmalı';
  end if;
  if (p_before_created_at is null) <> (p_before_id is null) then
    raise exception 'Şikâyet sayfalama imleci eksik';
  end if;

  return query
  select
    r.id, r.created_at, r.status, r.target_type,
    case r.target_type
      when 'product' then r.target_product_id
      when 'movement' then r.target_movement_id
      when 'user' then r.target_user_id
    end,
    r.target_label, r.target_content_snapshot, r.reason, r.details,
    r.reporter_id, r.reporter_name, r.resolution_action, r.resolution_note,
    r.resolved_at, r.resolved_by, r.resolved_by_name
  from public.content_reports r
  where r.organization_id = current_profile.organization_id
    and r.review_scope = 'tenant'
    and (normalized_status = 'all' or r.status = normalized_status)
    and (
      p_before_created_at is null
      or (r.created_at, r.id) < (p_before_created_at, p_before_id)
    )
  order by r.created_at desc, r.id desc
  limit p_limit;
end;
$$;

create or replace function private.list_platform_content_reports_v2(
  p_status text default 'open',
  p_before_created_at timestamptz default null,
  p_before_id uuid default null,
  p_limit integer default 50
)
returns table (
  organization_id uuid, organization_name text, report_id uuid,
  created_at timestamptz, status text, target_type text, target_id uuid,
  target_label text, target_content_snapshot text, reason text, details text,
  reporter_id uuid, reporter_name text, resolution_action text,
  resolution_note text, resolved_at timestamptz, resolved_by uuid,
  resolved_by_name text
)
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  normalized_status text := lower(trim(coalesce(p_status, 'open')));
begin
  current_profile := private.require_locked_ugc_profile(false, true);
  if normalized_status not in ('open', 'resolved', 'all') then
    raise exception 'Geçersiz şikâyet durumu';
  end if;
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'Sayfa boyutu 1-100 arasında olmalı';
  end if;
  if (p_before_created_at is null) <> (p_before_id is null) then
    raise exception 'Şikâyet sayfalama imleci eksik';
  end if;

  return query
  select
    r.organization_id, o.name, r.id, r.created_at, r.status, r.target_type,
    case r.target_type
      when 'product' then r.target_product_id
      when 'movement' then r.target_movement_id
      when 'user' then r.target_user_id
    end,
    r.target_label, r.target_content_snapshot, r.reason, r.details,
    r.reporter_id, r.reporter_name, r.resolution_action, r.resolution_note,
    r.resolved_at, r.resolved_by, r.resolved_by_name
  from public.content_reports r
  join public.organizations o on o.id = r.organization_id
  where r.review_scope = 'platform'
    and r.organization_id <> current_profile.organization_id
    and r.review_subject_id is distinct from current_profile.id
    and (normalized_status = 'all' or r.status = normalized_status)
    and (
      p_before_created_at is null
      or (r.created_at, r.id) < (p_before_created_at, p_before_id)
    )
  order by r.created_at desc, r.id desc
  limit p_limit;
end;
$$;

create or replace function private.moderate_content_report_v2(
  p_scope text,
  p_report_id uuid,
  p_action text,
  p_note text,
  p_request_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  candidate public.content_reports;
  current_report public.content_reports;
  target_profile public.profiles;
  target_product public.products;
  target_movement public.stock_movements;
  target_organization public.organizations;
  normalized_scope text := lower(trim(coalesce(p_scope, '')));
  normalized_action text := lower(trim(coalesce(p_action, '')));
  normalized_note text := nullif(trim(coalesce(p_note, '')), '');
  resolved_timestamp timestamptz := clock_timestamp();
  affected_rows integer;
  request_hash text;
  replay jsonb;
  result_payload jsonb;
begin
  if normalized_scope = 'tenant' then
    current_profile := private.require_locked_ugc_profile(true, false);
  elsif normalized_scope = 'platform' then
    -- Share one transaction lock with platform subscription administration.
    -- It must be acquired before actor/target tenant row locks so two platform
    -- operators cannot deadlock while moderating each other's organizations.
    perform pg_catalog.pg_advisory_xact_lock(7346501135020481::bigint);
    current_profile := private.require_locked_ugc_profile(false, true);
  else
    raise exception 'Geçersiz moderasyon kapsamı';
  end if;

  if current_profile.ugc_terms_accepted_at is null
     or current_profile.ugc_terms_version
        is distinct from private.current_ugc_terms_version() then
    raise exception 'Devam etmek için güncel kullanıcı içeriği şartlarını kabul edin';
  end if;
  if p_report_id is null then raise exception 'Şikâyet kaydı gerekli'; end if;
  if normalized_scope = 'tenant'
     and normalized_action not in (
       'dismiss', 'remove_product', 'redact_movement_note', 'deactivate_user'
     ) then
    raise exception 'Geçersiz moderasyon işlemi';
  end if;
  if normalized_scope = 'platform'
     and normalized_action not in (
       'dismiss', 'remove_product', 'redact_movement_note', 'suspend_organization'
     ) then
    raise exception 'Geçersiz platform moderasyon işlemi';
  end if;
  if normalized_note is not null and char_length(normalized_note) > 500 then
    raise exception 'Moderasyon notu en fazla 500 karakter olabilir';
  end if;
  if normalized_action <> 'dismiss' and normalized_note is null then
    raise exception 'Yıkıcı moderasyon işlemleri için gerekçe zorunludur';
  end if;

  select * into candidate
  from public.content_reports r
  where r.id = p_report_id
    and r.review_scope = normalized_scope
    and (
      (normalized_scope = 'tenant'
       and r.organization_id = current_profile.organization_id)
      or
      (normalized_scope = 'platform'
       and r.organization_id <> current_profile.organization_id
       and r.review_subject_id is distinct from current_profile.id)
    );
  if candidate.id is null then raise exception 'Şikâyet bulunamadı'; end if;

  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'moderate_' || normalized_scope,
    'report_id', p_report_id,
    'action', normalized_action,
    'note', normalized_note
  ));
  replay := private.claim_ugc_command(
    current_profile.id, p_request_id, candidate.organization_id,
    'moderate_' || normalized_scope, request_hash
  );
  if replay is not null then return replay; end if;

  if candidate.status <> 'open' then
    raise exception 'Açık şikâyet bulunamadı';
  end if;

  -- Tenant deletion installs the fence while holding this organization row.
  -- For platform moderation this also establishes target-org -> resource ->
  -- report lock order before any destructive change.
  perform private.assert_organization_not_deleting(current_profile.organization_id);
  perform private.assert_organization_not_deleting(candidate.organization_id);

  -- Account deletion locks profile -> product/movement -> report while it
  -- anonymizes ownership and UGC references. Take exactly the same resource
  -- order before locking the report; otherwise concurrent deletion can form a
  -- report/resource deadlock cycle.
  case normalized_action
    when 'remove_product' then
      if candidate.target_type <> 'product'
         or candidate.target_product_id is null then
        raise exception 'Bu işlem yalnızca ürün şikâyetlerinde kullanılabilir';
      end if;
      select * into target_product
      from public.products p
      where p.id = candidate.target_product_id
        and p.organization_id = candidate.organization_id
      for update;
      if target_product.id is null then
        raise exception 'Moderasyon hedefi ürün bulunamadı';
      end if;
    when 'redact_movement_note' then
      if candidate.target_type <> 'movement'
         or candidate.target_movement_id is null then
        raise exception 'Bu işlem yalnızca stok hareketi şikâyetlerinde kullanılabilir';
      end if;
      select * into target_movement
      from public.stock_movements m
      where m.id = candidate.target_movement_id
        and m.organization_id = candidate.organization_id
      for update;
      if target_movement.id is null then
        raise exception 'Moderasyon hedefi stok hareketi bulunamadı';
      end if;
    when 'deactivate_user' then
      if candidate.target_type <> 'user' or candidate.target_user_id is null then
        raise exception 'Bu işlem yalnızca kullanıcı şikâyetlerinde kullanılabilir';
      end if;
      select * into target_profile
      from public.profiles p
      where p.id = candidate.target_user_id
        and p.organization_id = current_profile.organization_id
      for update;
      if target_profile.id is null then
        raise exception 'Moderasyon hedefi kullanıcı bulunamadı';
      end if;
    when 'suspend_organization' then
      select * into target_organization
      from public.organizations o
      where o.id = candidate.organization_id
      for update;
      if target_organization.id is null then
        raise exception 'Moderasyon hedefi işletme bulunamadı';
      end if;
    else
      null;
  end case;

  select * into current_report
  from public.content_reports r
  where r.id = candidate.id
    and r.organization_id = candidate.organization_id
    and r.review_scope = normalized_scope
    and r.status = 'open'
    and r.target_type is not distinct from candidate.target_type
    and r.target_product_id is not distinct from candidate.target_product_id
    and r.target_movement_id is not distinct from candidate.target_movement_id
    and r.target_user_id is not distinct from candidate.target_user_id
    and (
      normalized_scope = 'tenant'
      or (
        r.organization_id <> current_profile.organization_id
        and r.review_subject_id is distinct from current_profile.id
      )
    )
  for update;
  if current_report.id is null then
    raise exception 'Şikâyet eşzamanlı olarak değiştirildi';
  end if;

  case normalized_action
    when 'dismiss' then
      null;
    when 'remove_product' then
      update public.products
      set active = false,
          updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
      where id = target_product.id
        and organization_id = target_product.organization_id;
      get diagnostics affected_rows = row_count;
      if affected_rows <> 1 then raise exception 'Moderasyon hedefi ürün bulunamadı'; end if;
    when 'redact_movement_note' then
      update public.stock_movements
      set note = '[Moderasyon tarafından kaldırıldı]'
      where id = target_movement.id
        and organization_id = target_movement.organization_id;
      get diagnostics affected_rows = row_count;
      if affected_rows <> 1 then raise exception 'Moderasyon hedefi stok hareketi bulunamadı'; end if;
    when 'deactivate_user' then
      if target_profile.id = current_profile.id
         or target_profile.role = 'admin'
         or target_profile.is_platform_operator then
        raise exception 'Bu kullanıcı işletme moderasyonuyla devre dışı bırakılamaz';
      end if;
      update public.profiles
      set is_active = false,
          deactivated_at = coalesce(deactivated_at, resolved_timestamp)
      where id = target_profile.id
        and organization_id = current_profile.organization_id;
      delete from auth.sessions where user_id = target_profile.id;
    when 'suspend_organization' then
      update public.organizations
      set subscription_status = 'suspended',
          administratively_suspended_at = resolved_timestamp,
          administratively_suspended_by = current_profile.id,
          administrative_suspension_reason = normalized_note,
          subscription_revision = subscription_revision + 1,
          updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
      where id = current_report.organization_id;
      get diagnostics affected_rows = row_count;
      if affected_rows <> 1 then raise exception 'Moderasyon hedefi işletme bulunamadı'; end if;
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
    and review_scope = normalized_scope
    and status = 'open';
  get diagnostics affected_rows = row_count;
  if affected_rows <> 1 then raise exception 'Şikâyet eşzamanlı olarak değiştirildi'; end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    current_report.organization_id,
    current_profile.id,
    case
      when normalized_scope = 'platform' then current_report.review_subject_id
      when current_report.target_type = 'user' then current_report.target_user_id
    end,
    case
      when normalized_scope = 'platform' then 'ugc.platform_report.resolved'
      else 'ugc.report.resolved'
    end,
    jsonb_build_object(
      'report_id', current_report.id,
      'target_type', current_report.target_type,
      'target_id', case current_report.target_type
        when 'product' then current_report.target_product_id
        when 'movement' then current_report.target_movement_id
        when 'user' then current_report.target_user_id
      end,
      'action', normalized_action,
      'reason', normalized_note,
      'review_scope', normalized_scope,
      'request_id', p_request_id
    )
  );

  result_payload := jsonb_build_object(
    'report_id', current_report.id,
    'status', 'resolved',
    'action', normalized_action,
    'resolved_at', resolved_timestamp,
    'request_id', p_request_id
  );
  perform private.finish_ugc_command(current_profile.id, p_request_id, result_payload);
  return result_payload;
end;
$$;

-- Extend erasure scrubbing with the platform-subject tombstone invariant.
create or replace function private.anonymize_ugc_reports_before_profile_delete()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.content_reports
  set reporter_name = 'Silinmiş kullanıcı', details = '', updated_at = clock_timestamp()
  where organization_id = old.organization_id and reporter_id = old.id;

  update public.content_reports
  set target_label = 'Silinmiş kullanıcı',
      target_content_snapshot = 'Silinmiş kullanıcı',
      updated_at = clock_timestamp()
  where organization_id = old.organization_id
    and target_type = 'user' and target_user_id = old.id;

  update public.content_reports
  set review_subject_id = null,
      review_subject_deleted_at = clock_timestamp(),
      updated_at = clock_timestamp()
  where organization_id = old.organization_id
    and review_scope = 'platform'
    and review_subject_id = old.id;

  update public.content_reports
  set resolved_by = null,
      resolved_by_name = 'Silinmiş kullanıcı',
      resolution_note = null,
      updated_at = clock_timestamp()
  where resolved_by = old.id;

  update public.security_audit_events
  set metadata = metadata - 'target_id'
  where subject_id = old.id
    and event_type in (
      'ugc.content.reported', 'ugc.report.resolved',
      'ugc.platform_report.resolved'
    );
  return old;
end;
$$;

-- Replace every authenticated public DEFINER RPC with an invoker wrapper over
-- a non-exposed private core. This removes the advisor warning while retaining
-- the explicit actor, session, role and tenant checks above.
drop function if exists public.get_ugc_terms_status();
drop function if exists public.accept_current_ugc_terms(text);
drop function if exists public.accept_current_ugc_terms(text, text);
drop function if exists public.report_content(text, uuid, text, text);
drop function if exists public.list_content_reports(text);
drop function if exists public.moderate_content_report(uuid, text, text);
drop function if exists public.list_platform_content_reports(text);
drop function if exists public.moderate_platform_content_report(uuid, text, text);
drop function if exists public.service_list_platform_content_reports(text);
drop function if exists public.service_moderate_platform_content_report(uuid, text, text);

create function public.get_ugc_terms_status()
returns jsonb
language sql stable security invoker set search_path = ''
as $$ select private.get_ugc_terms_status_v2(); $$;

create function public.accept_current_ugc_terms(
  p_version text,
  p_digest text
)
returns jsonb
language sql volatile security invoker set search_path = ''
as $$ select private.accept_current_ugc_terms_v2(p_version, p_digest); $$;

create function public.report_content(
  p_target_type text, p_target_id uuid, p_reason text,
  p_details text, p_request_id uuid
)
returns jsonb
language sql volatile security invoker set search_path = ''
as $$
  select private.report_content_v2(
    p_target_type, p_target_id, p_reason, p_details, p_request_id
  );
$$;

create function public.list_content_reports(
  p_status text default 'open',
  p_before_created_at timestamptz default null,
  p_before_id uuid default null,
  p_limit integer default 50
)
returns table (
  report_id uuid, created_at timestamptz, status text, target_type text,
  target_id uuid, target_label text, target_content_snapshot text,
  reason text, details text, reporter_id uuid, reporter_name text,
  resolution_action text, resolution_note text, resolved_at timestamptz,
  resolved_by uuid, resolved_by_name text
)
language sql volatile security invoker set search_path = ''
as $$
  select * from private.list_content_reports_v2(
    p_status, p_before_created_at, p_before_id, p_limit
  );
$$;

create function public.moderate_content_report(
  p_report_id uuid, p_action text, p_note text,
  p_request_id uuid
)
returns jsonb
language sql volatile security invoker set search_path = ''
as $$
  select private.moderate_content_report_v2(
    'tenant', p_report_id, p_action, p_note, p_request_id
  );
$$;

create function public.list_platform_content_reports(
  p_status text default 'open',
  p_before_created_at timestamptz default null,
  p_before_id uuid default null,
  p_limit integer default 50
)
returns table (
  organization_id uuid, organization_name text, report_id uuid,
  created_at timestamptz, status text, target_type text, target_id uuid,
  target_label text, target_content_snapshot text, reason text, details text,
  reporter_id uuid, reporter_name text, resolution_action text,
  resolution_note text, resolved_at timestamptz, resolved_by uuid,
  resolved_by_name text
)
language sql volatile security invoker set search_path = ''
as $$
  select * from private.list_platform_content_reports_v2(
    p_status, p_before_created_at, p_before_id, p_limit
  );
$$;

create function public.moderate_platform_content_report(
  p_report_id uuid, p_action text, p_note text,
  p_request_id uuid
)
returns jsonb
language sql volatile security invoker set search_path = ''
as $$
  select private.moderate_content_report_v2(
    'platform', p_report_id, p_action, p_note, p_request_id
  );
$$;

-- Independent service support remains available for reports hidden from their
-- sole platform-operator subject, but the legacy unbounded/non-idempotent
-- signatures above are retired.
create function public.service_list_platform_content_reports(
  p_status text default 'open',
  p_before_created_at timestamptz default null,
  p_before_id uuid default null,
  p_limit integer default 50
)
returns table (
  organization_id uuid, organization_name text, report_id uuid,
  created_at timestamptz, status text, target_type text, target_id uuid,
  target_label text, target_content_snapshot text, reason text, details text,
  reporter_id uuid, reporter_name text, resolution_action text,
  resolution_note text, resolved_at timestamptz, resolved_by uuid,
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
    raise exception 'Geçersiz bildirim durumu';
  end if;
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'Sayfa boyutu 1-100 arasında olmalı';
  end if;
  if (p_before_created_at is null) <> (p_before_id is null) then
    raise exception 'Bildirim sayfalama imleci eksik';
  end if;

  return query
  select
    r.organization_id, o.name, r.id, r.created_at, r.status, r.target_type,
    case r.target_type
      when 'product' then r.target_product_id
      when 'movement' then r.target_movement_id
      when 'user' then r.target_user_id
    end,
    r.target_label, r.target_content_snapshot, r.reason, r.details,
    r.reporter_id, r.reporter_name, r.resolution_action, r.resolution_note,
    r.resolved_at, r.resolved_by, r.resolved_by_name
  from public.content_reports r
  join public.organizations o on o.id = r.organization_id
  where r.review_scope = 'platform'
    and (normalized_status = 'all' or r.status = normalized_status)
    and (
      p_before_created_at is null
      or (r.created_at, r.id) < (p_before_created_at, p_before_id)
    )
  order by r.created_at desc, r.id desc
  limit p_limit;
end;
$$;

create function public.service_moderate_platform_content_report(
  p_request_id uuid,
  p_report_id uuid,
  p_action text,
  p_note text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  candidate public.content_reports;
  current_report public.content_reports;
  target_product public.products;
  target_movement public.stock_movements;
  receipt private.ugc_service_command_receipts;
  normalized_action text := lower(trim(coalesce(p_action, '')));
  normalized_note text := nullif(trim(coalesce(p_note, '')), '');
  resolved_timestamp timestamptz := clock_timestamp();
  request_hash text;
  result_payload jsonb;
  inserted boolean;
  affected_rows integer;
begin
  if p_request_id is null or p_report_id is null then
    raise exception 'İstek ve şikâyet kimliği gerekli';
  end if;
  if normalized_action not in (
    'dismiss', 'remove_product', 'redact_movement_note', 'suspend_organization'
  ) then
    raise exception 'Geçersiz platform moderasyon işlemi';
  end if;
  if normalized_note is not null and char_length(normalized_note) > 500 then
    raise exception 'Moderasyon notu en fazla 500 karakter olabilir';
  end if;
  if normalized_action <> 'dismiss' and normalized_note is null then
    raise exception 'Yıkıcı moderasyon işlemleri için gerekçe zorunludur';
  end if;

  -- Independent support uses the same global cross-tenant ordering boundary
  -- as operator moderation and subscription administration.
  perform pg_catalog.pg_advisory_xact_lock(7346501135020481::bigint);

  select * into candidate
  from public.content_reports r
  where r.id = p_report_id and r.review_scope = 'platform';
  if candidate.id is null then raise exception 'Platform şikâyeti bulunamadı'; end if;

  perform private.assert_organization_not_deleting(candidate.organization_id);
  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'service_moderate_platform',
    'report_id', p_report_id,
    'action', normalized_action,
    'note', normalized_note
  ));

  insert into private.ugc_service_command_receipts (
    request_id, organization_id, request_hash
  ) values (
    p_request_id, candidate.organization_id, request_hash
  ) on conflict (request_id) do nothing;
  inserted := found;
  if not inserted then
    select * into receipt
    from private.ugc_service_command_receipts r
    where r.request_id = p_request_id
    for update;
    if receipt.organization_id is distinct from candidate.organization_id
       or receipt.request_hash is distinct from request_hash then
      raise exception 'İstek kimliği farklı bir destek işlemi için kullanıldı';
    end if;
    if receipt.response is null or receipt.completed_at is null then
      raise exception 'Önceki destek işlemi tamamlanmamış görünüyor';
    end if;
    return receipt.response;
  end if;

  if candidate.status <> 'open' then
    raise exception 'Açık platform şikâyeti bulunamadı';
  end if;

  case normalized_action
    when 'remove_product' then
      if candidate.target_type <> 'product'
         or candidate.target_product_id is null then
        raise exception 'Bu işlem yalnızca ürün şikâyetlerinde kullanılabilir';
      end if;
      select * into target_product
      from public.products p
      where p.id = candidate.target_product_id
        and p.organization_id = candidate.organization_id
      for update;
      if target_product.id is null then
        raise exception 'Moderasyon hedefi ürün bulunamadı';
      end if;
    when 'redact_movement_note' then
      if candidate.target_type <> 'movement'
         or candidate.target_movement_id is null then
        raise exception 'Bu işlem yalnızca stok hareketi şikâyetlerinde kullanılabilir';
      end if;
      select * into target_movement
      from public.stock_movements m
      where m.id = candidate.target_movement_id
        and m.organization_id = candidate.organization_id
      for update;
      if target_movement.id is null then
        raise exception 'Moderasyon hedefi stok hareketi bulunamadı';
      end if;
    else
      null;
  end case;

  select * into current_report
  from public.content_reports r
  where r.id = candidate.id
    and r.organization_id = candidate.organization_id
    and r.review_scope = 'platform'
    and r.status = 'open'
    and r.target_type is not distinct from candidate.target_type
    and r.target_product_id is not distinct from candidate.target_product_id
    and r.target_movement_id is not distinct from candidate.target_movement_id
    and r.target_user_id is not distinct from candidate.target_user_id
  for update;
  if current_report.id is null then
    raise exception 'Şikâyet eşzamanlı olarak değiştirildi';
  end if;

  case normalized_action
    when 'dismiss' then
      null;
    when 'remove_product' then
      update public.products
      set active = false,
          updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
      where id = target_product.id
        and organization_id = target_product.organization_id;
      get diagnostics affected_rows = row_count;
      if affected_rows <> 1 then raise exception 'Moderasyon hedefi ürün bulunamadı'; end if;
    when 'redact_movement_note' then
      update public.stock_movements
      set note = '[Moderasyon tarafından kaldırıldı]'
      where id = target_movement.id
        and organization_id = target_movement.organization_id;
      get diagnostics affected_rows = row_count;
      if affected_rows <> 1 then raise exception 'Moderasyon hedefi stok hareketi bulunamadı'; end if;
    when 'suspend_organization' then
      update public.organizations
      set subscription_status = 'suspended',
          administratively_suspended_at = resolved_timestamp,
          administratively_suspended_by = null,
          administrative_suspension_reason = normalized_note,
          subscription_revision = subscription_revision + 1,
          updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
      where id = current_report.organization_id;
      get diagnostics affected_rows = row_count;
      if affected_rows <> 1 then raise exception 'Moderasyon hedefi işletme bulunamadı'; end if;
  end case;

  update public.content_reports
  set status = 'resolved',
      resolution_action = normalized_action,
      resolution_note = normalized_note,
      resolved_by = null,
      resolved_by_name = 'Stokdaş bağımsız destek',
      resolved_at = resolved_timestamp,
      updated_at = resolved_timestamp
  where id = current_report.id
    and review_scope = 'platform'
    and status = 'open';
  get diagnostics affected_rows = row_count;
  if affected_rows <> 1 then raise exception 'Şikâyet eşzamanlı olarak değiştirildi'; end if;

  insert into public.security_audit_events (
    organization_id, actor_id, subject_id, event_type, metadata
  ) values (
    current_report.organization_id, null, current_report.review_subject_id,
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
      'reason', normalized_note,
      'review_scope', 'platform',
      'resolution_channel', 'service_support',
      'request_id', p_request_id
    )
  );

  result_payload := jsonb_build_object(
    'report_id', current_report.id,
    'status', 'resolved',
    'action', normalized_action,
    'resolved_at', resolved_timestamp,
    'request_id', p_request_id
  );
  update private.ugc_service_command_receipts r
  set response = result_payload, completed_at = clock_timestamp()
  where r.request_id = p_request_id
    and r.response is null and r.completed_at is null;
  if not found then
    raise exception 'Destek işlem sonucu güvenli biçimde kaydedilemedi';
  end if;
  return result_payload;
end;
$$;

-- Bounded maintenance entry point for a scheduled service job. In-flight rows
-- are never selected; replay evidence has a documented 90/365/180-day horizon.
create or replace function public.service_purge_command_receipts(
  p_limit integer default 1000
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  inventory_count integer;
  platform_count integer;
  ugc_count integer;
  ugc_service_count integer;
begin
  if p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'Temizlik sınırı 1-5000 arasında olmalı';
  end if;

  with candidates as (
    select r.organization_id, r.actor_id, r.request_id
    from private.inventory_command_receipts r
    where r.completed_at < clock_timestamp() - interval '90 days'
      and r.response is not null
    order by r.completed_at
    for update skip locked
    limit p_limit
  )
  delete from private.inventory_command_receipts r
  using candidates c
  where r.organization_id = c.organization_id
    and r.actor_id = c.actor_id and r.request_id = c.request_id;
  get diagnostics inventory_count = row_count;

  with candidates as (
    select r.actor_id, r.request_id
    from private.platform_admin_command_receipts r
    where r.completed_at < clock_timestamp() - interval '365 days'
      and r.response is not null
    order by r.completed_at
    for update skip locked
    limit p_limit
  )
  delete from private.platform_admin_command_receipts r
  using candidates c
  where r.actor_id = c.actor_id and r.request_id = c.request_id;
  get diagnostics platform_count = row_count;

  with candidates as (
    select r.actor_id, r.request_id
    from private.ugc_command_receipts r
    where r.completed_at < clock_timestamp() - interval '180 days'
      and r.response is not null
    order by r.completed_at
    for update skip locked
    limit p_limit
  )
  delete from private.ugc_command_receipts r
  using candidates c
  where r.actor_id = c.actor_id and r.request_id = c.request_id;
  get diagnostics ugc_count = row_count;

  with candidates as (
    select r.request_id
    from private.ugc_service_command_receipts r
    where r.completed_at < clock_timestamp() - interval '365 days'
      and r.response is not null
    order by r.completed_at
    for update skip locked
    limit p_limit
  )
  delete from private.ugc_service_command_receipts r
  using candidates c
  where r.request_id = c.request_id;
  get diagnostics ugc_service_count = row_count;

  return jsonb_build_object(
    'inventory', inventory_count,
    'platform', platform_count,
    'ugc', ugc_count,
    'ugc_service', ugc_service_count
  );
end;
$$;

revoke all on function private.require_locked_ugc_profile(boolean, boolean)
  from public, anon, authenticated, service_role;
revoke all on function private.claim_ugc_command(uuid, uuid, uuid, text, text)
  from public, anon, authenticated, service_role;
revoke all on function private.finish_ugc_command(uuid, uuid, jsonb)
  from public, anon, authenticated, service_role;
revoke all on function private.anonymize_ugc_reports_before_profile_delete()
  from public, anon, authenticated, service_role;

revoke all on function private.get_ugc_terms_status_v2()
  from public, anon, authenticated, service_role;
revoke all on function private.accept_current_ugc_terms_v2(text, text)
  from public, anon, authenticated, service_role;
revoke all on function private.report_content_v2(text, uuid, text, text, uuid)
  from public, anon, authenticated, service_role;
revoke all on function private.list_content_reports_v2(text, timestamptz, uuid, integer)
  from public, anon, authenticated, service_role;
revoke all on function private.list_platform_content_reports_v2(text, timestamptz, uuid, integer)
  from public, anon, authenticated, service_role;
revoke all on function private.moderate_content_report_v2(text, uuid, text, text, uuid)
  from public, anon, authenticated, service_role;

grant execute on function private.get_ugc_terms_status_v2() to authenticated;
grant execute on function private.accept_current_ugc_terms_v2(text, text) to authenticated;
grant execute on function private.report_content_v2(text, uuid, text, text, uuid)
  to authenticated;
grant execute on function private.list_content_reports_v2(text, timestamptz, uuid, integer)
  to authenticated;
grant execute on function private.list_platform_content_reports_v2(text, timestamptz, uuid, integer)
  to authenticated;
grant execute on function private.moderate_content_report_v2(text, uuid, text, text, uuid)
  to authenticated;

revoke all on function public.get_ugc_terms_status()
  from public, anon, authenticated, service_role;
revoke all on function public.accept_current_ugc_terms(text, text)
  from public, anon, authenticated, service_role;
revoke all on function public.report_content(text, uuid, text, text, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.list_content_reports(text, timestamptz, uuid, integer)
  from public, anon, authenticated, service_role;
revoke all on function public.moderate_content_report(uuid, text, text, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.list_platform_content_reports(text, timestamptz, uuid, integer)
  from public, anon, authenticated, service_role;
revoke all on function public.moderate_platform_content_report(uuid, text, text, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.service_list_platform_content_reports(
  text, timestamptz, uuid, integer
) from public, anon, authenticated, service_role;
revoke all on function public.service_moderate_platform_content_report(
  uuid, uuid, text, text
) from public, anon, authenticated, service_role;
revoke all on function public.service_purge_command_receipts(integer)
  from public, anon, authenticated, service_role;

grant execute on function public.get_ugc_terms_status() to authenticated;
grant execute on function public.accept_current_ugc_terms(text, text) to authenticated;
grant execute on function public.report_content(text, uuid, text, text, uuid)
  to authenticated;
grant execute on function public.list_content_reports(text, timestamptz, uuid, integer)
  to authenticated;
grant execute on function public.moderate_content_report(uuid, text, text, uuid)
  to authenticated;
grant execute on function public.list_platform_content_reports(text, timestamptz, uuid, integer)
  to authenticated;
grant execute on function public.moderate_platform_content_report(uuid, text, text, uuid)
  to authenticated;
grant execute on function public.service_list_platform_content_reports(
  text, timestamptz, uuid, integer
) to service_role;
grant execute on function public.service_moderate_platform_content_report(
  uuid, uuid, text, text
) to service_role;
grant execute on function public.service_purge_command_receipts(integer)
  to service_role;

comment on table public.content_reports is
  'Service-protected UGC reports; authenticated access is only through bounded SECURITY INVOKER wrappers over actor/tenant-checked private cores.';
comment on function public.get_ugc_terms_status() is
  'Returns current and accepted UGC version plus exact immutable document digests.';
comment on function public.accept_current_ugc_terms(text, text) is
  'Requires the exact displayed version/digest, then records one immutable acceptance and audit event for that document.';
comment on function public.service_list_platform_content_reports(
  text, timestamptz, uuid, integer
) is 'Service-only bounded keyset queue for conflict-free independent platform support review.';
comment on function public.service_moderate_platform_content_report(
  uuid, uuid, text, text
) is 'Service-only independent support moderation with mandatory request id/reason, deletion fence, resource-first locks, receipt and atomic audit.';
comment on function public.service_purge_command_receipts(integer) is
  'Service-only bounded purge; schedule daily. Keeps in-flight rows and 90/365/180/365-day replay horizons.';

commit;
