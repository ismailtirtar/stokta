-- Convert the original single-shop workspace into a tenant-isolated SaaS.
-- Existing users, products, and movements are migrated into the first tenant.

begin;

set local statement_timeout = '30s';

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 100),
  slug text not null unique,
  subscription_status text not null default 'trial'
    check (subscription_status in ('trial', 'active', 'past_due', 'suspended', 'canceled')),
  trial_ends_at timestamptz,
  current_period_end timestamptz,
  max_members integer not null default 5 check (max_members between 1 and 10000),
  max_products integer not null default 1000 check (max_products between 1 and 1000000),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organizations_slug_format check (
    slug = lower(slug)
    and slug ~ '^[a-z0-9][a-z0-9-]{2,47}$'
  )
);

alter table public.profiles
  add column organization_id uuid,
  add column is_platform_operator boolean not null default false;

alter table public.products
  add column organization_id uuid;

alter table public.stock_movements
  add column organization_id uuid;

do $$
declare
  first_admin_id uuid;
  first_organization_id uuid;
begin
  select id into first_admin_id
  from public.profiles
  where role = 'admin'
  order by created_at
  limit 1;

  if first_admin_id is not null then
    insert into public.organizations (
      name, slug, subscription_status, trial_ends_at, current_period_end,
      max_members, max_products, created_by
    )
    values (
      'İsmail Tırtar İşletmesi', 'ismail-tirtar', 'active', null, null,
      25, 10000, first_admin_id
    )
    returning id into first_organization_id;

    update public.profiles
    set organization_id = first_organization_id,
        is_platform_operator = (id = first_admin_id);

    update public.products p
    set organization_id = pr.organization_id
    from public.profiles pr
    where pr.id = p.created_by;

    update public.stock_movements m
    set organization_id = p.organization_id
    from public.products p
    where p.id = m.product_id;
  end if;
end;
$$;

alter table public.profiles alter column organization_id set not null;
alter table public.products alter column organization_id set not null;
alter table public.stock_movements alter column organization_id set not null;

alter table public.profiles
  add constraint profiles_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete restrict;

alter table public.products
  add constraint products_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete restrict;

alter table public.stock_movements
  add constraint stock_movements_organization_id_fkey
  foreign key (organization_id) references public.organizations(id) on delete restrict;

alter table public.profiles
  add constraint profiles_id_organization_key unique (id, organization_id);

alter table public.products
  add constraint products_id_organization_key unique (id, organization_id);

alter table public.profiles drop constraint profiles_created_by_fkey;
alter table public.profiles
  add constraint profiles_created_by_organization_fkey
  foreign key (created_by, organization_id)
  references public.profiles(id, organization_id) on delete restrict;

alter table public.products drop constraint products_created_by_fkey;
alter table public.products
  add constraint products_created_by_organization_fkey
  foreign key (created_by, organization_id)
  references public.profiles(id, organization_id) on delete restrict;

alter table public.stock_movements drop constraint stock_movements_product_id_fkey;
alter table public.stock_movements
  add constraint stock_movements_product_organization_fkey
  foreign key (product_id, organization_id)
  references public.products(id, organization_id) on delete restrict;

drop index public.profiles_single_admin_idx;
create unique index profiles_single_admin_per_organization_idx
  on public.profiles (organization_id)
  where role = 'admin';

alter table public.products drop constraint products_sku_key;
alter table public.products
  add constraint products_organization_sku_key unique (organization_id, sku);

create index profiles_organization_idx
  on public.profiles (organization_id, role);
create index products_organization_active_name_idx
  on public.products (organization_id, active, name);
create index products_organization_low_stock_idx
  on public.products (organization_id, stock, min_stock)
  where active;
create index stock_movements_organization_created_idx
  on public.stock_movements (organization_id, created_at desc);
create index stock_movements_organization_product_created_idx
  on public.stock_movements (organization_id, product_id, created_at desc);

drop index public.products_low_stock_idx;
drop index public.stock_movements_created_idx;
drop index public.stock_movements_product_created_idx;

create or replace function private.current_organization_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.organization_id
  from public.profiles p
  where p.id = (select auth.uid());
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
stable
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
begin
  current_profile := private.require_active_profile();
  if current_profile.role <> 'admin' then
    raise exception 'Bu işlem yalnızca işletme yöneticisine açıktır';
  end if;
  return current_profile;
end;
$$;

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

create or replace function private.create_inventory_product(
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
  current_organization public.organizations;
  created_product public.products;
  normalized_stock numeric := round(coalesce(p_stock, 0), 3);
  normalized_min_stock numeric := round(coalesce(p_min_stock, 0), 3);
  active_product_count integer;
begin
  current_profile := private.require_admin_profile();
  current_organization := private.require_writable_organization(current_profile.organization_id);

  if nullif(trim(p_name), '') is null or char_length(trim(p_name)) > 100 then
    raise exception 'Ürün adı 1-100 karakter olmalı';
  end if;
  if nullif(trim(p_sku), '') is null or char_length(trim(p_sku)) > 40 then
    raise exception 'SKU 1-40 karakter olmalı';
  end if;
  if normalized_stock < 0 or normalized_min_stock < 0 then
    raise exception 'Stok değerleri negatif olamaz';
  end if;

  select count(*) into active_product_count
  from public.products
  where organization_id = current_profile.organization_id and active;

  if active_product_count >= current_organization.max_products then
    raise exception 'Ürün limitine ulaşıldı';
  end if;

  insert into public.products
    (organization_id, name, sku, category, unit, stock, min_stock, created_by)
  values (
    current_profile.organization_id,
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
      (organization_id, product_id, type, quantity, previous_stock, new_stock, note, actor_id, actor_name)
    values
      (current_profile.organization_id, created_product.id, 'in', normalized_stock, 0, normalized_stock,
       'İlk stok', current_profile.id, current_profile.display_name);
  end if;

  return created_product;
end;
$$;

create or replace function private.update_inventory_product(
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
  current_profile public.profiles;
  updated_product public.products;
  normalized_min_stock numeric := round(coalesce(p_min_stock, 0), 3);
begin
  current_profile := private.require_admin_profile();
  perform private.require_writable_organization(current_profile.organization_id);

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
  where id = p_product_id
    and organization_id = current_profile.organization_id
    and active
  returning * into updated_product;

  if updated_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;

  return updated_product;
end;
$$;

create or replace function private.archive_inventory_product(p_product_id uuid)
returns public.products
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  archived_product public.products;
begin
  current_profile := private.require_admin_profile();
  perform private.require_writable_organization(current_profile.organization_id);

  update public.products
  set active = false, updated_at = now()
  where id = p_product_id
    and organization_id = current_profile.organization_id
    and active
  returning * into archived_product;

  if archived_product.id is null then
    raise exception 'Ürün bulunamadı';
  end if;

  return archived_product;
end;
$$;

create or replace function private.record_stock_movement(
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
  perform private.require_writable_organization(current_profile.organization_id);

  if p_type not in ('in', 'out') then
    raise exception 'Geçersiz işlem türü';
  end if;
  if normalized_quantity <= 0 then
    raise exception 'Miktar sıfırdan büyük olmalı';
  end if;

  select * into current_product
  from public.products
  where id = p_product_id
    and organization_id = current_profile.organization_id
    and active
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
  where id = p_product_id and organization_id = current_profile.organization_id;

  insert into public.stock_movements
    (organization_id, product_id, type, quantity, previous_stock, new_stock, note, actor_id, actor_name)
  values
    (current_profile.organization_id, p_product_id, p_type, normalized_quantity,
     current_product.stock, round(next_stock, 3), left(coalesce(p_note, ''), 200),
     current_profile.id, current_profile.display_name)
  returning id into movement_id;

  return jsonb_build_object(
    'movement_id', movement_id,
    'product_id', p_product_id,
    'previous_stock', current_product.stock,
    'new_stock', round(next_stock, 3)
  );
end;
$$;

create or replace function public.create_inventory_product(
  p_name text, p_sku text, p_category text, p_unit text, p_stock numeric, p_min_stock numeric
)
returns public.products
language sql
security invoker
set search_path = ''
as $$
  select private.create_inventory_product(p_name, p_sku, p_category, p_unit, p_stock, p_min_stock);
$$;

create or replace function public.update_inventory_product(
  p_product_id uuid, p_name text, p_sku text, p_category text, p_unit text, p_min_stock numeric
)
returns public.products
language sql
security invoker
set search_path = ''
as $$
  select private.update_inventory_product(p_product_id, p_name, p_sku, p_category, p_unit, p_min_stock);
$$;

create or replace function public.archive_inventory_product(p_product_id uuid)
returns public.products
language sql
security invoker
set search_path = ''
as $$
  select private.archive_inventory_product(p_product_id);
$$;

create or replace function public.record_stock_movement(
  p_product_id uuid, p_type text, p_quantity numeric, p_note text default ''
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.record_stock_movement(p_product_id, p_type, p_quantity, p_note);
$$;

alter table public.organizations enable row level security;

drop policy if exists "organization members read own organization" on public.organizations;
create policy "organization members read own organization"
  on public.organizations for select to authenticated
  using (id = (select private.current_organization_id()));

drop policy if exists "authenticated profiles read" on public.profiles;
create policy "authenticated profiles read"
  on public.profiles for select to authenticated
  using (
    id = (select auth.uid())
    and organization_id = (select private.current_organization_id())
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

revoke all on table public.organizations from anon, authenticated;
grant select on table public.organizations to authenticated;
grant select, insert, update, delete on table public.organizations to service_role;

revoke all on function private.current_organization_id() from public, anon;
revoke all on function private.require_active_profile() from public, anon;
revoke all on function private.require_admin_profile() from public, anon;
revoke all on function private.require_writable_organization(uuid) from public, anon;
revoke all on function private.create_inventory_product(text, text, text, text, numeric, numeric) from public, anon;
revoke all on function private.update_inventory_product(uuid, text, text, text, text, numeric) from public, anon;
revoke all on function private.archive_inventory_product(uuid) from public, anon;
revoke all on function private.record_stock_movement(uuid, text, numeric, text) from public, anon;

grant usage on schema private to authenticated;
grant execute on function private.current_organization_id() to authenticated;
grant execute on function private.create_inventory_product(text, text, text, text, numeric, numeric) to authenticated;
grant execute on function private.update_inventory_product(uuid, text, text, text, text, numeric) to authenticated;
grant execute on function private.archive_inventory_product(uuid) to authenticated;
grant execute on function private.record_stock_movement(uuid, text, numeric, text) to authenticated;

revoke all on function public.create_inventory_product(text, text, text, text, numeric, numeric) from public, anon;
revoke all on function public.update_inventory_product(uuid, text, text, text, text, numeric) from public, anon;
revoke all on function public.archive_inventory_product(uuid) from public, anon;
revoke all on function public.record_stock_movement(uuid, text, numeric, text) from public, anon;
grant execute on function public.create_inventory_product(text, text, text, text, numeric, numeric) to authenticated;
grant execute on function public.update_inventory_product(uuid, text, text, text, text, numeric) to authenticated;
grant execute on function public.archive_inventory_product(uuid) to authenticated;
grant execute on function public.record_stock_movement(uuid, text, numeric, text) to authenticated;

commit;
