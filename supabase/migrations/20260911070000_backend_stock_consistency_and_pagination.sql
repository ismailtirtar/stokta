-- Make inventory writes linearizable, replay-safe and bounded to one tenant.
-- Write RPC names remain stable, but this is an intentional minimum-client
-- contract break: every mutation now requires a request UUID and product
-- metadata writes also require an optimistic-concurrency timestamp.

begin;

set local statement_timeout = '30s';
set local lock_timeout = '10s';

do $$
begin
  if to_regclass('public.security_audit_events') is null
     or to_regprocedure('private.has_live_session()') is null
     or to_regprocedure('private.current_ugc_terms_version()') is null
     or to_regclass('private.organization_deletion_fences') is null
     or to_regprocedure('private.assert_organization_not_deleting(uuid)') is null then
    raise exception
      'Inventory reliability migration requires the account-security and UGC migrations';
  end if;
end;
$$;

-- A sequence is a stable keyset cursor even when multiple movements receive
-- the same created_at timestamp. It is ordering metadata, not a business id.
create sequence if not exists public.stock_movements_event_sequence_seq as bigint;
revoke all on sequence public.stock_movements_event_sequence_seq
  from public, anon, authenticated, service_role;
alter table public.stock_movements
  add column if not exists event_sequence bigint;

alter sequence public.stock_movements_event_sequence_seq
  owned by public.stock_movements.event_sequence;

alter table public.stock_movements
  alter column event_sequence
  set default nextval('public.stock_movements_event_sequence_seq'::regclass);

update public.stock_movements
set event_sequence = nextval('public.stock_movements_event_sequence_seq'::regclass)
where event_sequence is null;

select setval(
  'public.stock_movements_event_sequence_seq'::regclass,
  greatest(
    coalesce((select max(event_sequence) from public.stock_movements), 0),
    1
  ),
  exists (select 1 from public.stock_movements)
);

alter table public.stock_movements
  alter column event_sequence set not null;

create unique index if not exists stock_movements_event_sequence_key
  on public.stock_movements (event_sequence);
create index if not exists stock_movements_organization_sequence_idx
  on public.stock_movements (organization_id, event_sequence desc);
create index if not exists products_organization_active_name_id_idx
  on public.products (organization_id, active, name, id);

-- A fresh Supabase project does not automatically publish pre-existing tables.
-- Inventory clients use these events only as invalidation hints and re-read
-- through tenant-scoped RPCs, so primary-key replica identity is sufficient.
do $$
begin
  if exists (
    select 1 from pg_catalog.pg_publication p
    where p.pubname = 'supabase_realtime'
  ) and not exists (
    select 1 from pg_catalog.pg_publication_tables pt
    where pt.pubname = 'supabase_realtime'
      and pt.schemaname = 'public'
      and pt.tablename = 'products'
  ) then
    alter publication supabase_realtime add table public.products;
  end if;

  if exists (
    select 1 from pg_catalog.pg_publication p
    where p.pubname = 'supabase_realtime'
  ) and not exists (
    select 1 from pg_catalog.pg_publication_tables pt
    where pt.pubname = 'supabase_realtime'
      and pt.schemaname = 'public'
      and pt.tablename = 'stock_movements'
  ) then
    alter publication supabase_realtime add table public.stock_movements;
  end if;
end;
$$;

-- Keep both sides of history internally coherent. NOT VALID makes adding the
-- check safe to stage; VALIDATE scans existing rows before commit and fails the
-- whole migration rather than silently accepting corrupt legacy history.
alter table public.stock_movements
  add constraint stock_movements_arithmetic_check check (
    (type = 'in' and new_stock = previous_stock + quantity)
    or (type = 'out' and new_stock = previous_stock - quantity)
  ) not valid;
alter table public.stock_movements
  validate constraint stock_movements_arithmetic_check;

-- Actor identity must belong to the movement tenant. Preserve the organization
-- when an account is erased and only null the personal actor identifier.
alter table public.stock_movements
  drop constraint if exists stock_movements_actor_id_fkey;
alter table public.stock_movements
  add constraint stock_movements_actor_organization_fkey
  foreign key (actor_id, organization_id)
  references public.profiles(id, organization_id)
  on delete set null (actor_id);
create index if not exists stock_movements_actor_organization_idx
  on public.stock_movements (actor_id, organization_id)
  where actor_id is not null;

create table private.inventory_command_receipts (
  organization_id uuid not null
    references public.organizations(id) on delete cascade,
  actor_id uuid not null
    references auth.users(id) on delete cascade,
  request_id uuid not null,
  command_name text not null check (
    command_name in ('create_product', 'update_product', 'archive_product', 'record_movement')
  ),
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  response jsonb,
  created_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  primary key (organization_id, actor_id, request_id),
  constraint inventory_command_receipts_completion_check check (
    (response is null and completed_at is null)
    or (response is not null and completed_at is not null)
  )
);

create index inventory_command_receipts_actor_idx
  on private.inventory_command_receipts (actor_id, organization_id);
create index inventory_command_receipts_created_idx
  on private.inventory_command_receipts (created_at);

alter table private.inventory_command_receipts enable row level security;
alter table private.inventory_command_receipts force row level security;
revoke all on table private.inventory_command_receipts
  from public, anon, authenticated, service_role;

-- Lock the profile before every inventory mutation. This turns account
-- deactivation/deletion and a concurrent stock write into an ordered outcome.
create or replace function private.require_locked_inventory_profile(
  p_admin_required boolean default false
)
returns public.profiles
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_user_id uuid := (select auth.uid());
  current_session_id_text text := coalesce((select auth.jwt() ->> 'session_id'), '');
  current_session_id uuid;
  candidate_organization_id uuid;
  current_profile public.profiles;
begin
  if current_user_id is null
     or current_session_id_text
        !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    raise exception 'Geçerli oturum gerekli';
  end if;

  current_session_id := current_session_id_text::uuid;

  -- Organization deletion and billing flows lock organization before profile.
  -- Read the immutable tenant key, then take the same global lock order so a
  -- write cannot deadlock an organization-deletion fence transaction.
  select p.organization_id into candidate_organization_id
  from public.profiles p
  where p.id = current_user_id;
  if candidate_organization_id is null then
    raise exception 'Etkin kullanıcı profili bulunamadı veya şifre değişikliği gerekli';
  end if;

  perform 1
  from public.organizations o
  where o.id = candidate_organization_id
  for update;
  if not found then
    raise exception 'İşletme bulunamadı';
  end if;

  select * into current_profile
  from public.profiles p
  where p.id = current_user_id
    and p.organization_id = candidate_organization_id
  for update;

  if current_profile.id is null
     or not current_profile.is_active
     or current_profile.must_change_password then
    raise exception 'Etkin kullanıcı profili bulunamadı veya şifre değişikliği gerekli';
  end if;

  perform 1
  from auth.sessions s
  where s.id = current_session_id
    and s.user_id = current_user_id
  for key share;

  if not found then
    raise exception 'Oturum sona erdi';
  end if;

  if p_admin_required and current_profile.role <> 'admin' then
    raise exception 'Bu işlem yalnızca işletme yöneticisine açıktır';
  end if;

  return current_profile;
end;
$$;

create or replace function private.lock_writable_inventory_organization(
  p_profile public.profiles
)
returns public.organizations
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_organization public.organizations;
begin
  select * into current_organization
  from public.organizations o
  where o.id = p_profile.organization_id
  for update;

  if current_organization.id is null then
    raise exception 'İşletme bulunamadı';
  end if;

  -- Defined by the immediately following platform reliability migration. It
  -- serializes all tenant mutations with durable organization deletion.
  perform private.assert_organization_not_deleting(current_organization.id);

  if p_profile.ugc_terms_accepted_at is null
     or p_profile.ugc_terms_version
        is distinct from private.current_ugc_terms_version() then
    raise exception 'Devam etmek için güncel kullanıcı içeriği şartlarını kabul edin';
  end if;

  if current_organization.subscription_status = 'trial'
     and coalesce(current_organization.trial_ends_at, '-infinity'::timestamptz)
         <= clock_timestamp() then
    raise exception 'Deneme süresi sona erdi. Kiralama durumunu yenileyin';
  end if;

  if current_organization.subscription_status = 'active'
     and current_organization.current_period_end is not null
     and current_organization.current_period_end <= clock_timestamp() then
    raise exception 'Kiralama dönemi sona erdi. Aboneliği yenileyin';
  end if;

  if current_organization.subscription_status not in ('trial', 'active') then
    raise exception 'İşletme hesabı şu anda işlem yapmaya açık değil';
  end if;

  return current_organization;
end;
$$;

-- NULL means this is a new command. A JSON result means the same completed
-- request is being replayed. Reusing a request id with different inputs fails.
create or replace function private.claim_inventory_command(
  p_organization_id uuid,
  p_actor_id uuid,
  p_request_id uuid,
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
  receipt private.inventory_command_receipts;
begin
  if p_request_id is null then
    raise exception 'İstek kimliği gerekli';
  end if;

  insert into private.inventory_command_receipts (
    organization_id, actor_id, request_id, command_name, request_hash
  ) values (
    p_organization_id, p_actor_id, p_request_id, p_command_name, p_request_hash
  )
  on conflict (organization_id, actor_id, request_id) do nothing;
  inserted := found;

  if inserted then
    return null;
  end if;

  select * into receipt
  from private.inventory_command_receipts r
  where r.organization_id = p_organization_id
    and r.actor_id = p_actor_id
    and r.request_id = p_request_id
  for update;

  if receipt.command_name is distinct from p_command_name
     or receipt.request_hash is distinct from p_request_hash then
    raise exception 'İstek kimliği farklı bir işlem için daha önce kullanıldı';
  end if;

  if receipt.response is null or receipt.completed_at is null then
    -- A command and its receipt commit atomically, so this state can only be
    -- introduced by privileged manual tampering. Fail closed.
    raise exception 'Önceki işlem tamamlanmamış görünüyor';
  end if;

  return receipt.response;
end;
$$;

create or replace function private.finish_inventory_command(
  p_organization_id uuid,
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
declare
  affected_rows integer;
begin
  if p_request_id is null then
    return;
  end if;

  update private.inventory_command_receipts
  set response = p_response,
      completed_at = clock_timestamp()
  where organization_id = p_organization_id
    and actor_id = p_actor_id
    and request_id = p_request_id
    and response is null
    and completed_at is null;
  get diagnostics affected_rows = row_count;

  if affected_rows <> 1 then
    raise exception 'İşlem sonucu güvenli biçimde kaydedilemedi';
  end if;
end;
$$;

create or replace function private.inventory_request_hash(p_payload jsonb)
returns text
language sql
immutable
security definer
set search_path = ''
as $$
  select encode(extensions.digest(convert_to(p_payload::text, 'UTF8'), 'sha256'), 'hex');
$$;

create or replace function private.create_inventory_product_v2(
  p_name text,
  p_sku text,
  p_category text,
  p_unit text,
  p_stock numeric,
  p_min_stock numeric,
  p_request_id uuid
)
returns public.products
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_organization public.organizations;
  created_product public.products;
  replay jsonb;
  response jsonb;
  normalized_name text := trim(coalesce(p_name, ''));
  normalized_sku text := upper(trim(coalesce(p_sku, '')));
  normalized_category text := coalesce(nullif(trim(coalesce(p_category, '')), ''), 'Genel');
  normalized_unit text := lower(coalesce(nullif(trim(coalesce(p_unit, '')), ''), 'adet'));
  normalized_stock numeric := round(coalesce(p_stock, 0), 3);
  normalized_min_stock numeric := round(coalesce(p_min_stock, 0), 3);
  request_hash text;
  active_product_count integer;
begin
  current_profile := private.require_locked_inventory_profile(true);
  current_organization := private.lock_writable_inventory_organization(current_profile);

  if char_length(normalized_name) not between 1 and 100 then
    raise exception 'Ürün adı 1-100 karakter olmalı';
  end if;
  if char_length(normalized_sku) not between 1 and 40 then
    raise exception 'SKU 1-40 karakter olmalı';
  end if;
  if char_length(normalized_category) not between 1 and 60 then
    raise exception 'Kategori 1-60 karakter olmalı';
  end if;
  if char_length(normalized_unit) not between 1 and 20 then
    raise exception 'Birim 1-20 karakter olmalı';
  end if;
  if normalized_stock < 0 or normalized_min_stock < 0
     or normalized_stock > 99999999999.999
     or normalized_min_stock > 99999999999.999 then
    raise exception 'Stok değerleri geçerli aralıkta olmalı';
  end if;

  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'create_product',
    'name', normalized_name,
    'sku', normalized_sku,
    'category', normalized_category,
    'unit', normalized_unit,
    'stock', normalized_stock,
    'min_stock', normalized_min_stock
  ));
  replay := private.claim_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id,
    'create_product', request_hash
  );
  if replay is not null then
    return jsonb_populate_record(null::public.products, replay -> 'product');
  end if;

  select count(*) into active_product_count
  from public.products p
  where p.organization_id = current_profile.organization_id
    and p.active;

  if active_product_count >= current_organization.max_products then
    raise exception 'Ürün limitine ulaşıldı';
  end if;

  insert into public.products (
    organization_id, name, sku, category, unit, stock, min_stock, created_by
  ) values (
    current_profile.organization_id, normalized_name, normalized_sku,
    normalized_category, normalized_unit, normalized_stock,
    normalized_min_stock, current_profile.id
  ) returning * into created_product;

  if normalized_stock > 0 then
    insert into public.stock_movements (
      organization_id, product_id, type, quantity, previous_stock, new_stock,
      note, actor_id, actor_name
    ) values (
      current_profile.organization_id, created_product.id, 'in', normalized_stock,
      0, normalized_stock, 'İlk stok', current_profile.id,
      current_profile.display_name
    );
  end if;

  response := jsonb_build_object('product', to_jsonb(created_product));
  perform private.finish_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id, response
  );
  return created_product;
end;
$$;

create or replace function private.update_inventory_product_v2(
  p_product_id uuid,
  p_name text,
  p_sku text,
  p_category text,
  p_unit text,
  p_min_stock numeric,
  p_expected_updated_at timestamptz,
  p_request_id uuid
)
returns public.products
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_product public.products;
  updated_product public.products;
  replay jsonb;
  response jsonb;
  normalized_name text := trim(coalesce(p_name, ''));
  normalized_sku text := upper(trim(coalesce(p_sku, '')));
  normalized_category text := coalesce(nullif(trim(coalesce(p_category, '')), ''), 'Genel');
  normalized_unit text := lower(coalesce(nullif(trim(coalesce(p_unit, '')), ''), 'adet'));
  normalized_min_stock numeric := round(coalesce(p_min_stock, 0), 3);
  request_hash text;
  next_updated_at timestamptz;
begin
  if p_product_id is null then
    raise exception 'Ürün gerekli';
  end if;
  if p_expected_updated_at is null then
    raise exception 'Ürünün beklenen güncelleme zamanı gerekli';
  end if;

  current_profile := private.require_locked_inventory_profile(true);
  perform private.lock_writable_inventory_organization(current_profile);

  if char_length(normalized_name) not between 1 and 100 then
    raise exception 'Ürün adı 1-100 karakter olmalı';
  end if;
  if char_length(normalized_sku) not between 1 and 40 then
    raise exception 'SKU 1-40 karakter olmalı';
  end if;
  if char_length(normalized_category) not between 1 and 60 then
    raise exception 'Kategori 1-60 karakter olmalı';
  end if;
  if char_length(normalized_unit) not between 1 and 20 then
    raise exception 'Birim 1-20 karakter olmalı';
  end if;
  if normalized_min_stock < 0 or normalized_min_stock > 99999999999.999 then
    raise exception 'Uyarı sınırı geçerli aralıkta olmalı';
  end if;

  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'update_product',
    'product_id', p_product_id,
    'name', normalized_name,
    'sku', normalized_sku,
    'category', normalized_category,
    'unit', normalized_unit,
    'min_stock', normalized_min_stock,
    'expected_updated_at', p_expected_updated_at
  ));
  replay := private.claim_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id,
    'update_product', request_hash
  );
  if replay is not null then
    return jsonb_populate_record(null::public.products, replay -> 'product');
  end if;

  select * into current_product
  from public.products p
  where p.id = p_product_id
    and p.organization_id = current_profile.organization_id
    and p.active
  for update;

  if current_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;
  if current_product.updated_at is distinct from p_expected_updated_at then
    raise exception using
      errcode = '40001',
      message = 'Ürün başka bir oturumda değiştirildi; güncel veriyi yükleyip tekrar deneyin';
  end if;

  next_updated_at := greatest(
    clock_timestamp(), current_product.updated_at + interval '1 microsecond'
  );
  update public.products
  set name = normalized_name,
      sku = normalized_sku,
      category = normalized_category,
      unit = normalized_unit,
      min_stock = normalized_min_stock,
      updated_at = next_updated_at
  where id = current_product.id
    and organization_id = current_profile.organization_id
  returning * into updated_product;

  response := jsonb_build_object('product', to_jsonb(updated_product));
  perform private.finish_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id, response
  );
  return updated_product;
end;
$$;

create or replace function private.archive_inventory_product_v2(
  p_product_id uuid,
  p_expected_updated_at timestamptz,
  p_request_id uuid
)
returns public.products
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_product public.products;
  archived_product public.products;
  replay jsonb;
  response jsonb;
  request_hash text;
begin
  if p_product_id is null then
    raise exception 'Ürün gerekli';
  end if;
  if p_expected_updated_at is null then
    raise exception 'Ürünün beklenen güncelleme zamanı gerekli';
  end if;

  current_profile := private.require_locked_inventory_profile(true);
  perform private.lock_writable_inventory_organization(current_profile);
  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'archive_product',
    'product_id', p_product_id,
    'expected_updated_at', p_expected_updated_at
  ));
  replay := private.claim_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id,
    'archive_product', request_hash
  );
  if replay is not null then
    return jsonb_populate_record(null::public.products, replay -> 'product');
  end if;

  select * into current_product
  from public.products p
  where p.id = p_product_id
    and p.organization_id = current_profile.organization_id
    and p.active
  for update;

  if current_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;
  if current_product.updated_at is distinct from p_expected_updated_at then
    raise exception using
      errcode = '40001',
      message = 'Ürün başka bir oturumda değiştirildi; güncel veriyi yükleyip tekrar deneyin';
  end if;

  update public.products
  set active = false,
      updated_at = greatest(
        clock_timestamp(), current_product.updated_at + interval '1 microsecond'
      )
  where id = current_product.id
    and organization_id = current_profile.organization_id
  returning * into archived_product;

  response := jsonb_build_object('product', to_jsonb(archived_product));
  perform private.finish_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id, response
  );
  return archived_product;
end;
$$;

create or replace function private.record_stock_movement_v2(
  p_product_id uuid,
  p_type text,
  p_quantity numeric,
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
  current_product public.products;
  normalized_type text := lower(trim(coalesce(p_type, '')));
  normalized_quantity numeric := round(coalesce(p_quantity, 0), 3);
  normalized_note text := coalesce(p_note, '');
  next_stock numeric;
  next_updated_at timestamptz;
  movement_id uuid;
  movement_sequence bigint;
  request_hash text;
  replay jsonb;
  response jsonb;
begin
  if p_product_id is null then
    raise exception 'Ürün gerekli';
  end if;

  current_profile := private.require_locked_inventory_profile(false);
  perform private.lock_writable_inventory_organization(current_profile);

  if normalized_type not in ('in', 'out') then
    raise exception 'Geçersiz işlem türü';
  end if;
  if normalized_quantity <= 0 or normalized_quantity > 99999999999.999 then
    raise exception 'Miktar geçerli aralıkta ve sıfırdan büyük olmalı';
  end if;
  if char_length(normalized_note) > 200 then
    raise exception 'Stok hareketi notu en fazla 200 karakter olabilir';
  end if;

  request_hash := private.inventory_request_hash(jsonb_build_object(
    'command', 'record_movement',
    'product_id', p_product_id,
    'type', normalized_type,
    'quantity', normalized_quantity,
    'note', normalized_note
  ));
  replay := private.claim_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id,
    'record_movement', request_hash
  );
  if replay is not null then
    return replay;
  end if;

  select * into current_product
  from public.products p
  where p.id = p_product_id
    and p.organization_id = current_profile.organization_id
    and p.active
  for update;

  if current_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;
  if normalized_type = 'out' and normalized_quantity > current_product.stock then
    raise exception 'Stokta yalnızca % % bulunuyor', current_product.stock, current_product.unit;
  end if;

  next_stock := case
    when normalized_type = 'in' then current_product.stock + normalized_quantity
    else current_product.stock - normalized_quantity
  end;
  if next_stock > 99999999999.999 then
    raise exception 'Stok değeri desteklenen üst sınırı aşıyor';
  end if;

  next_updated_at := greatest(
    clock_timestamp(), current_product.updated_at + interval '1 microsecond'
  );
  update public.products
  set stock = round(next_stock, 3),
      updated_at = next_updated_at
  where id = current_product.id
    and organization_id = current_profile.organization_id;

  insert into public.stock_movements (
    organization_id, product_id, type, quantity, previous_stock, new_stock,
    note, actor_id, actor_name
  ) values (
    current_profile.organization_id, current_product.id, normalized_type,
    normalized_quantity, current_product.stock, round(next_stock, 3),
    normalized_note, current_profile.id, current_profile.display_name
  ) returning id, event_sequence into movement_id, movement_sequence;

  response := jsonb_build_object(
    'movement_id', movement_id,
    'event_sequence', movement_sequence,
    'product_id', current_product.id,
    'previous_stock', current_product.stock,
    'new_stock', round(next_stock, 3),
    'product_updated_at', next_updated_at
  );
  perform private.finish_inventory_command(
    current_profile.organization_id, current_profile.id, p_request_id, response
  );
  return response;
end;
$$;

-- Replace the public wrappers so the Data API sees one unambiguous overload.
-- New writes are deliberately strict: every command carries a stable UUID and
-- update/archive operations carry an optimistic-concurrency timestamp.
drop function if exists public.create_inventory_product(
  text, text, text, text, numeric, numeric
);
drop function if exists public.update_inventory_product(
  uuid, text, text, text, text, numeric
);
drop function if exists public.archive_inventory_product(uuid);
drop function if exists public.record_stock_movement(uuid, text, numeric, text);

-- The 2026-08 compatibility layer granted these private DEFINER functions to
-- authenticated. Removing the implementations closes a legacy path that
-- would otherwise bypass the new locks, receipts and optimistic checks.
drop function if exists private.create_inventory_product(
  text, text, text, text, numeric, numeric
);
drop function if exists private.update_inventory_product(
  uuid, text, text, text, text, numeric
);
drop function if exists private.archive_inventory_product(uuid);
drop function if exists private.record_stock_movement(uuid, text, numeric, text);

create function public.create_inventory_product(
  p_name text,
  p_sku text,
  p_category text,
  p_unit text,
  p_stock numeric,
  p_min_stock numeric,
  p_request_id uuid
)
returns public.products
language sql
volatile
security invoker
set search_path = ''
as $$
  select private.create_inventory_product_v2(
    p_name, p_sku, p_category, p_unit, p_stock, p_min_stock, p_request_id
  );
$$;

create function public.update_inventory_product(
  p_product_id uuid,
  p_name text,
  p_sku text,
  p_category text,
  p_unit text,
  p_min_stock numeric,
  p_expected_updated_at timestamptz,
  p_request_id uuid
)
returns public.products
language sql
volatile
security invoker
set search_path = ''
as $$
  select private.update_inventory_product_v2(
    p_product_id, p_name, p_sku, p_category, p_unit, p_min_stock,
    p_expected_updated_at, p_request_id
  );
$$;

create function public.archive_inventory_product(
  p_product_id uuid,
  p_expected_updated_at timestamptz,
  p_request_id uuid
)
returns public.products
language sql
volatile
security invoker
set search_path = ''
as $$
  select private.archive_inventory_product_v2(
    p_product_id, p_expected_updated_at, p_request_id
  );
$$;

create function public.record_stock_movement(
  p_product_id uuid,
  p_type text,
  p_quantity numeric,
  p_note text,
  p_request_id uuid
)
returns jsonb
language sql
volatile
security invoker
set search_path = ''
as $$
  select private.record_stock_movement_v2(
    p_product_id, p_type, p_quantity, p_note, p_request_id
  );
$$;

create or replace function private.list_inventory_products_v2(
  p_after_name text default null,
  p_after_id uuid default null,
  p_limit integer default 200,
  p_query text default null,
  p_only_low boolean default false
)
returns setof public.products
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  normalized_query text := lower(trim(coalesce(p_query, '')));
begin
  current_profile := private.require_active_profile();

  if p_limit is null or p_limit not between 1 and 200 then
    raise exception 'Sayfa boyutu 1-200 arasında olmalı';
  end if;
  if (p_after_name is null) <> (p_after_id is null) then
    raise exception 'Ürün sayfalama imleci eksik';
  end if;
  if char_length(normalized_query) > 100 then
    raise exception 'Ürün araması en fazla 100 karakter olabilir';
  end if;
  if p_only_low is null then
    raise exception 'Düşük stok filtresi geçersiz';
  end if;

  return query
  select p.*
  from public.products p
  where p.organization_id = current_profile.organization_id
    and p.active
    and (not p_only_low or p.stock <= p.min_stock)
    and (
      normalized_query = ''
      or strpos(
        lower(p.name || ' ' || p.sku || ' ' || p.category),
        normalized_query
      ) > 0
    )
    and (
      p_after_name is null
      or (p.name, p.id) > (p_after_name, p_after_id)
    )
  order by p.name, p.id
  limit p_limit;
end;
$$;

create or replace function private.list_stock_movements_v2(
  p_before_sequence bigint default null,
  p_limit integer default 50
)
returns table (
  id uuid,
  product_id uuid,
  type text,
  quantity numeric,
  previous_stock numeric,
  new_stock numeric,
  note text,
  actor_id uuid,
  actor_name text,
  created_at timestamptz,
  product_name text,
  product_sku text,
  product_unit text,
  event_sequence bigint
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  current_profile := private.require_active_profile();

  if p_limit is null or p_limit not between 1 and 200 then
    raise exception 'Sayfa boyutu 1-200 arasında olmalı';
  end if;
  if p_before_sequence is not null and p_before_sequence <= 0 then
    raise exception 'Stok hareketi imleci geçersiz';
  end if;

  return query
  select
    m.id, m.product_id, m.type, m.quantity, m.previous_stock, m.new_stock,
    m.note, m.actor_id, m.actor_name, m.created_at,
    p.name, p.sku, p.unit, m.event_sequence
  from public.stock_movements m
  join public.products p
    on p.id = m.product_id
   and p.organization_id = m.organization_id
  where m.organization_id = current_profile.organization_id
    and (p_before_sequence is null or m.event_sequence < p_before_sequence)
  order by m.event_sequence desc
  limit p_limit;
end;
$$;

create or replace function public.list_inventory_products(
  p_after_name text default null,
  p_after_id uuid default null,
  p_limit integer default 200,
  p_query text default null,
  p_only_low boolean default false
)
returns setof public.products
language sql
stable
security invoker
set search_path = ''
as $$
  select * from private.list_inventory_products_v2(
    p_after_name, p_after_id, p_limit, p_query, p_only_low
  );
$$;

create or replace function private.get_inventory_summary_v2()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  total_products bigint;
  low_stock_products bigint;
  critical_products bigint;
  today_movements bigint;
begin
  current_profile := private.require_active_profile();
  select
    count(*),
    count(*) filter (where p.stock <= p.min_stock),
    count(*) filter (where p.stock = 0)
  into total_products, low_stock_products, critical_products
  from public.products p
  where p.organization_id = current_profile.organization_id and p.active;

  select count(*) into today_movements
  from public.stock_movements m
  where m.organization_id = current_profile.organization_id
    and timezone('Europe/Istanbul', m.created_at)::date
      = timezone('Europe/Istanbul', clock_timestamp())::date;

  return jsonb_build_object(
    'total_products', total_products,
    'low_stock_products', low_stock_products,
    'critical_products', critical_products,
    'today_movements', today_movements
  );
end;
$$;

create or replace function public.get_inventory_summary()
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$ select private.get_inventory_summary_v2(); $$;

create or replace function public.list_stock_movements(
  p_before_sequence bigint default null,
  p_limit integer default 50
)
returns table (
  id uuid,
  product_id uuid,
  type text,
  quantity numeric,
  previous_stock numeric,
  new_stock numeric,
  note text,
  actor_id uuid,
  actor_name text,
  created_at timestamptz,
  product_name text,
  product_sku text,
  product_unit text,
  event_sequence bigint
)
language sql
stable
security invoker
set search_path = ''
as $$
  select * from private.list_stock_movements_v2(
    p_before_sequence, p_limit
  );
$$;

-- Movement facts are immutable. The only supported post-write mutations are
-- note redaction by moderation and actor anonymization during account erasure.
create or replace function private.protect_stock_movement_history()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.id is distinct from old.id
     or new.organization_id is distinct from old.organization_id
     or new.product_id is distinct from old.product_id
     or new.type is distinct from old.type
     or new.quantity is distinct from old.quantity
     or new.previous_stock is distinct from old.previous_stock
     or new.new_stock is distinct from old.new_stock
     or new.created_at is distinct from old.created_at
     or new.event_sequence is distinct from old.event_sequence then
    raise exception 'Stok hareketi geçmişi değiştirilemez';
  end if;

  if new.note is distinct from old.note
     and new.note <> '[Moderasyon tarafından kaldırıldı]' then
    raise exception 'Stok hareketi notu yalnız moderasyonla kaldırılabilir';
  end if;

  if new.actor_id is distinct from old.actor_id
     or new.actor_name is distinct from old.actor_name then
    if not (
      old.actor_id is not null
      and new.actor_id is null
      and new.actor_name = 'Silinmiş kullanıcı'
    ) then
      raise exception 'Stok hareketi aktörü yalnız hesap silmeyle anonimleştirilebilir';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists protect_stock_movement_history
  on public.stock_movements;
create trigger protect_stock_movement_history
before update on public.stock_movements
for each row execute function private.protect_stock_movement_history();

revoke all on function private.require_locked_inventory_profile(boolean)
  from public, anon, authenticated, service_role;
revoke all on function private.lock_writable_inventory_organization(public.profiles)
  from public, anon, authenticated, service_role;
revoke all on function private.claim_inventory_command(uuid, uuid, uuid, text, text)
  from public, anon, authenticated, service_role;
revoke all on function private.finish_inventory_command(uuid, uuid, uuid, jsonb)
  from public, anon, authenticated, service_role;
revoke all on function private.inventory_request_hash(jsonb)
  from public, anon, authenticated, service_role;
revoke all on function private.protect_stock_movement_history()
  from public, anon, authenticated, service_role;

revoke all on function private.create_inventory_product_v2(
  text, text, text, text, numeric, numeric, uuid
) from public, anon, authenticated, service_role;
revoke all on function private.update_inventory_product_v2(
  uuid, text, text, text, text, numeric, timestamptz, uuid
) from public, anon, authenticated, service_role;
revoke all on function private.archive_inventory_product_v2(uuid, timestamptz, uuid)
  from public, anon, authenticated, service_role;
revoke all on function private.record_stock_movement_v2(uuid, text, numeric, text, uuid)
  from public, anon, authenticated, service_role;
revoke all on function private.list_inventory_products_v2(text, uuid, integer, text, boolean)
  from public, anon, authenticated, service_role;
revoke all on function private.list_stock_movements_v2(bigint, integer)
  from public, anon, authenticated, service_role;
revoke all on function private.get_inventory_summary_v2()
  from public, anon, authenticated, service_role;

grant execute on function private.create_inventory_product_v2(
  text, text, text, text, numeric, numeric, uuid
) to authenticated;
grant execute on function private.update_inventory_product_v2(
  uuid, text, text, text, text, numeric, timestamptz, uuid
) to authenticated;
grant execute on function private.archive_inventory_product_v2(uuid, timestamptz, uuid)
  to authenticated;
grant execute on function private.record_stock_movement_v2(uuid, text, numeric, text, uuid)
  to authenticated;
grant execute on function private.list_inventory_products_v2(text, uuid, integer, text, boolean)
  to authenticated;
grant execute on function private.list_stock_movements_v2(bigint, integer)
  to authenticated;
grant execute on function private.get_inventory_summary_v2() to authenticated;

revoke all on function public.create_inventory_product(
  text, text, text, text, numeric, numeric, uuid
) from public, anon, authenticated, service_role;
revoke all on function public.update_inventory_product(
  uuid, text, text, text, text, numeric, timestamptz, uuid
) from public, anon, authenticated, service_role;
revoke all on function public.archive_inventory_product(uuid, timestamptz, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.record_stock_movement(uuid, text, numeric, text, uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.list_inventory_products(text, uuid, integer, text, boolean)
  from public, anon, authenticated, service_role;
revoke all on function public.list_stock_movements(bigint, integer)
  from public, anon, authenticated, service_role;
revoke all on function public.get_inventory_summary()
  from public, anon, authenticated, service_role;

grant execute on function public.create_inventory_product(
  text, text, text, text, numeric, numeric, uuid
) to authenticated;
grant execute on function public.update_inventory_product(
  uuid, text, text, text, text, numeric, timestamptz, uuid
) to authenticated;
grant execute on function public.archive_inventory_product(uuid, timestamptz, uuid)
  to authenticated;
grant execute on function public.record_stock_movement(uuid, text, numeric, text, uuid)
  to authenticated;
grant execute on function public.list_inventory_products(text, uuid, integer, text, boolean)
  to authenticated;
grant execute on function public.list_stock_movements(bigint, integer)
  to authenticated;
grant execute on function public.get_inventory_summary() to authenticated;

comment on table private.inventory_command_receipts is
  'Tenant/actor-bound idempotency receipts for inventory commands; never exposed through the Data API.';
comment on column public.stock_movements.event_sequence is
  'Server-assigned immutable ordering cursor used for gap-free keyset pagination.';
comment on function public.list_inventory_products(text, uuid, integer, text, boolean) is
  'Bounded tenant-scoped product keyset page with server-side search/low-stock filters; public wrapper is SECURITY INVOKER.';
comment on function public.list_stock_movements(bigint, integer) is
  'Bounded tenant-scoped movement keyset page; public wrapper is SECURITY INVOKER.';
comment on function public.get_inventory_summary() is
  'Tenant-scoped full-dataset counts, including Europe/Istanbul current-day movements.';

commit;
