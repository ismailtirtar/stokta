-- Stokdaş: Android-first shared inventory backend for Supabase.
-- All client writes go through RPC functions; tables are read-only to clients.

begin;

create extension if not exists pgcrypto;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
revoke create on schema public from public;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete restrict,
  username text not null unique,
  display_name text not null,
  role text not null default 'member' check (role in ('admin', 'member')),
  created_by uuid references public.profiles(id) on delete restrict,
  created_at timestamptz not null default now(),
  constraint profiles_username_format check (
    username = lower(username)
    and username ~ '^[a-z0-9][a-z0-9._-]{2,31}$'
  ),
  constraint profiles_display_name_length check (char_length(display_name) between 1 and 80)
);

create index if not exists profiles_created_by_idx on public.profiles (created_by);
create unique index if not exists profiles_single_admin_idx
  on public.profiles (role)
  where role = 'admin';

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 100),
  sku text not null unique check (char_length(sku) between 1 and 40),
  category text not null default 'Genel' check (char_length(category) between 1 and 60),
  unit text not null default 'adet' check (char_length(unit) between 1 and 20),
  stock numeric(14,3) not null default 0 check (stock >= 0),
  min_stock numeric(14,3) not null default 0 check (min_stock >= 0),
  active boolean not null default true,
  created_by uuid not null references public.profiles(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists products_created_by_idx on public.products (created_by);
create index if not exists products_name_idx on public.products (lower(name));
create index if not exists products_low_stock_idx
  on public.products (stock, min_stock)
  where active;

create table if not exists public.stock_movements (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete restrict,
  type text not null check (type in ('in', 'out')),
  quantity numeric(14,3) not null check (quantity > 0),
  previous_stock numeric(14,3) not null check (previous_stock >= 0),
  new_stock numeric(14,3) not null check (new_stock >= 0),
  note text not null default '' check (char_length(note) <= 200),
  actor_id uuid references public.profiles(id) on delete set null,
  actor_name text not null check (char_length(actor_name) between 1 and 80),
  created_at timestamptz not null default now()
);

create index if not exists stock_movements_created_idx
  on public.stock_movements (created_at desc);
create index if not exists stock_movements_product_created_idx
  on public.stock_movements (product_id, created_at desc);
create index if not exists stock_movements_actor_idx
  on public.stock_movements (actor_id);

-- Auth Admin API metadata is finalized after the auth.users insert. Profile
-- provisioning therefore happens in the service-role Edge Functions instead
-- of auth.users triggers. Unprofiled Auth users have no inventory access.
drop trigger if exists before_auth_user_created_stokta on auth.users;
drop trigger if exists on_auth_user_created_stokta on auth.users;
drop function if exists private.enforce_managed_user_provisioning();
drop function if exists private.handle_new_user();

create or replace function private.has_active_profile()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select auth.uid() is not null
    and exists (select 1 from public.profiles where id = auth.uid());
$$;

revoke all on function private.has_active_profile() from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.has_active_profile() to authenticated;

create or replace function private.require_active_profile()
returns public.profiles
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  if auth.uid() is null then
    raise exception 'Oturum gerekli';
  end if;

  select * into current_profile
  from public.profiles
  where id = auth.uid();

  if current_profile.id is null then
    raise exception 'Yetkili kullanıcı profili bulunamadı';
  end if;

  return current_profile;
end;
$$;

create or replace function private.require_admin_profile()
returns public.profiles
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  current_profile := private.require_active_profile();
  if current_profile.role <> 'admin' then
    raise exception 'Bu işlem yalnızca yöneticiye açıktır';
  end if;
  return current_profile;
end;
$$;

revoke all on function private.require_active_profile() from public, anon, authenticated;
revoke all on function private.require_admin_profile() from public, anon, authenticated;

create or replace function public.create_inventory_product(
  p_name text,
  p_sku text,
  p_category text,
  p_unit text,
  p_stock numeric,
  p_min_stock numeric
)
returns public.products
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  created_product public.products;
  normalized_stock numeric := round(coalesce(p_stock, 0), 3);
  normalized_min_stock numeric := round(coalesce(p_min_stock, 0), 3);
begin
  current_profile := private.require_admin_profile();

  if nullif(trim(p_name), '') is null or char_length(trim(p_name)) > 100 then
    raise exception 'Ürün adı 1-100 karakter olmalı';
  end if;
  if nullif(trim(p_sku), '') is null or char_length(trim(p_sku)) > 40 then
    raise exception 'SKU 1-40 karakter olmalı';
  end if;
  if normalized_stock < 0 or normalized_min_stock < 0 then
    raise exception 'Stok değerleri negatif olamaz';
  end if;

  insert into public.products (name, sku, category, unit, stock, min_stock, created_by)
  values (
    trim(p_name),
    upper(trim(p_sku)),
    coalesce(nullif(trim(p_category), ''), 'Genel'),
    lower(coalesce(nullif(trim(p_unit), ''), 'adet')),
    normalized_stock,
    normalized_min_stock,
    current_profile.id
  )
  returning * into created_product;

  if normalized_stock > 0 then
    insert into public.stock_movements
      (product_id, type, quantity, previous_stock, new_stock, note, actor_id, actor_name)
    values
      (created_product.id, 'in', normalized_stock, 0, normalized_stock,
       'İlk stok', current_profile.id, current_profile.display_name);
  end if;

  return created_product;
end;
$$;

create or replace function public.update_inventory_product(
  p_product_id uuid,
  p_name text,
  p_sku text,
  p_category text,
  p_unit text,
  p_min_stock numeric
)
returns public.products
language plpgsql
security definer
set search_path = ''
as $$
declare
  updated_product public.products;
  normalized_min_stock numeric := round(coalesce(p_min_stock, 0), 3);
begin
  perform private.require_admin_profile();

  if nullif(trim(p_name), '') is null or char_length(trim(p_name)) > 100 then
    raise exception 'Ürün adı 1-100 karakter olmalı';
  end if;
  if nullif(trim(p_sku), '') is null or char_length(trim(p_sku)) > 40 then
    raise exception 'SKU 1-40 karakter olmalı';
  end if;
  if normalized_min_stock < 0 then
    raise exception 'Uyarı sınırı negatif olamaz';
  end if;

  update public.products
  set name = trim(p_name),
      sku = upper(trim(p_sku)),
      category = coalesce(nullif(trim(p_category), ''), 'Genel'),
      unit = lower(coalesce(nullif(trim(p_unit), ''), 'adet')),
      min_stock = normalized_min_stock,
      updated_at = now()
  where id = p_product_id and active
  returning * into updated_product;

  if updated_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;

  return updated_product;
end;
$$;

create or replace function public.archive_inventory_product(p_product_id uuid)
returns public.products
language plpgsql
security definer
set search_path = ''
as $$
declare
  archived_product public.products;
begin
  perform private.require_admin_profile();

  update public.products
  set active = false, updated_at = now()
  where id = p_product_id and active
  returning * into archived_product;

  if archived_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;

  return archived_product;
end;
$$;

create or replace function public.record_stock_movement(
  p_product_id uuid,
  p_type text,
  p_quantity numeric,
  p_note text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_product public.products;
  normalized_quantity numeric := round(coalesce(p_quantity, 0), 3);
  next_stock numeric;
  movement_id uuid;
begin
  current_profile := private.require_active_profile();

  if p_type not in ('in', 'out') then
    raise exception 'Geçersiz işlem türü';
  end if;
  if normalized_quantity <= 0 then
    raise exception 'Miktar sıfırdan büyük olmalı';
  end if;

  select * into current_product
  from public.products
  where id = p_product_id and active
  for update;

  if current_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;
  if p_type = 'out' and normalized_quantity > current_product.stock then
    raise exception 'Stokta yalnızca % % bulunuyor', current_product.stock, current_product.unit;
  end if;

  next_stock := case
    when p_type = 'in' then current_product.stock + normalized_quantity
    else current_product.stock - normalized_quantity
  end;

  update public.products
  set stock = round(next_stock, 3), updated_at = now()
  where id = p_product_id;

  insert into public.stock_movements
    (product_id, type, quantity, previous_stock, new_stock, note, actor_id, actor_name)
  values
    (p_product_id, p_type, normalized_quantity, current_product.stock, round(next_stock, 3),
     left(coalesce(p_note, ''), 200), current_profile.id, current_profile.display_name)
  returning id into movement_id;

  return jsonb_build_object(
    'movement_id', movement_id,
    'product_id', p_product_id,
    'previous_stock', current_product.stock,
    'new_stock', round(next_stock, 3)
  );
end;
$$;

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.stock_movements enable row level security;

drop policy if exists "authenticated profiles read" on public.profiles;
create policy "authenticated profiles read"
  on public.profiles for select to authenticated
  using (id = (select auth.uid()));

drop policy if exists "authenticated active products read" on public.products;
create policy "authenticated active products read"
  on public.products for select to authenticated
  using (active and (select private.has_active_profile()));

drop policy if exists "authenticated movements read" on public.stock_movements;
create policy "authenticated movements read"
  on public.stock_movements for select to authenticated
  using ((select private.has_active_profile()));

revoke all on table public.profiles from anon, authenticated;
revoke all on table public.products from anon, authenticated;
revoke all on table public.stock_movements from anon, authenticated;
grant usage on schema public to authenticated;
grant select on table public.profiles to authenticated;
grant select on table public.products to authenticated;
grant select on table public.stock_movements to authenticated;
grant select, insert on table public.profiles to service_role;
grant update, delete on table public.profiles to service_role;
grant delete on table public.products to service_role;
grant update, delete on table public.stock_movements to service_role;

revoke all on function public.create_inventory_product(text, text, text, text, numeric, numeric) from public, anon;
revoke all on function public.update_inventory_product(uuid, text, text, text, text, numeric) from public, anon;
revoke all on function public.archive_inventory_product(uuid) from public, anon;
revoke all on function public.record_stock_movement(uuid, text, numeric, text) from public, anon;
grant execute on function public.create_inventory_product(text, text, text, text, numeric, numeric) to authenticated;
grant execute on function public.update_inventory_product(uuid, text, text, text, text, numeric) to authenticated;
grant execute on function public.archive_inventory_product(uuid) to authenticated;
grant execute on function public.record_stock_movement(uuid, text, numeric, text) to authenticated;

alter default privileges in schema public revoke execute on functions from public;

do $$
begin
  alter publication supabase_realtime add table public.products;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.stock_movements;
exception when duplicate_object then null;
end $$;

commit;
