begin;

-- The source PDF never leaves the user's device. This table stores only the
-- minimum audit metadata needed to prevent accidental duplicate imports.
create table private.pdf_stock_imports (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null
    references public.organizations(id) on delete restrict,
  movement_type text not null check (movement_type in ('in', 'out')),
  file_name text not null check (char_length(file_name) between 1 and 160),
  document_sha256 text not null check (document_sha256 ~ '^[0-9a-f]{64}$'),
  invoice_number text check (
    invoice_number is null or char_length(invoice_number) between 1 and 80
  ),
  line_count integer not null check (line_count between 1 and 200),
  actor_id uuid references public.profiles(id) on delete set null,
  actor_name text not null check (char_length(actor_name) between 1 and 80),
  created_at timestamptz not null default now(),
  constraint pdf_stock_imports_id_organization_key
    unique (id, organization_id),
  constraint pdf_stock_imports_organization_document_key
    unique (organization_id, document_sha256)
);

alter table private.pdf_stock_imports enable row level security;

revoke all on table private.pdf_stock_imports from public, anon, authenticated;
grant select, insert, update, delete on table private.pdf_stock_imports to service_role;

alter table public.stock_movements
  add column pdf_import_id uuid;

alter table public.stock_movements
  add constraint stock_movements_pdf_import_id_fkey
  foreign key (pdf_import_id)
  references private.pdf_stock_imports(id)
  on delete set null;

create index stock_movements_pdf_import_idx
  on public.stock_movements (pdf_import_id)
  where pdf_import_id is not null;

create or replace function private.record_pdf_stock_import(
  p_type text,
  p_file_name text,
  p_document_sha256 text,
  p_invoice_number text,
  p_lines jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_profile public.profiles;
  current_product public.products;
  current_line record;
  imported_id uuid;
  duplicate_product_count integer;
  normalized_quantity numeric;
  next_stock numeric;
  normalized_file_name text := regexp_replace(
    coalesce(trim(p_file_name), ''),
    '[[:cntrl:]]',
    '',
    'g'
  );
  normalized_sha256 text := lower(coalesce(trim(p_document_sha256), ''));
  normalized_invoice_number text := nullif(
    regexp_replace(coalesce(trim(p_invoice_number), ''), '[[:cntrl:]]', '', 'g'),
    ''
  );
  movement_note text;
begin
  current_profile := private.require_active_profile();
  perform private.require_writable_organization(current_profile.organization_id);

  if p_type is null or p_type not in ('in', 'out') then
    raise exception 'Geçersiz işlem türü';
  end if;

  if normalized_file_name = '' or char_length(normalized_file_name) > 160 then
    raise exception 'PDF dosya adı 1-160 karakter olmalı';
  end if;

  if normalized_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'Geçersiz PDF parmak izi';
  end if;

  if normalized_invoice_number is not null
     and char_length(normalized_invoice_number) > 80 then
    raise exception 'Fatura numarası en fazla 80 karakter olabilir';
  end if;

  if p_lines is null or jsonb_typeof(p_lines) <> 'array' then
    raise exception 'PDF ürün satırları bir liste olmalı';
  end if;

  if jsonb_array_length(p_lines) < 1 or jsonb_array_length(p_lines) > 200 then
    raise exception 'PDF aktarımı 1-200 ürün satırı içermeli';
  end if;

  -- Validate the entire payload before taking locks or changing stock.
  for current_line in
    select entry.value as payload, entry.ordinality as line_number
    from jsonb_array_elements(p_lines) with ordinality as entry(value, ordinality)
    order by entry.ordinality
  loop
    if jsonb_typeof(current_line.payload) <> 'object' then
      raise exception 'PDF ürün satırı % geçersiz', current_line.line_number;
    end if;

    if jsonb_typeof(current_line.payload -> 'product_id') is distinct from 'string'
       or (current_line.payload ->> 'product_id') !~*
          '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
      raise exception 'PDF ürün satırı % için ürün seçimi geçersiz', current_line.line_number;
    end if;

    if jsonb_typeof(current_line.payload -> 'quantity') is distinct from 'number' then
      raise exception 'PDF ürün satırı % için miktar geçersiz', current_line.line_number;
    end if;

    normalized_quantity := round((current_line.payload ->> 'quantity')::numeric, 3);
    if normalized_quantity <= 0 or normalized_quantity > 1000000000 then
      raise exception 'PDF ürün satırı % için miktar 0 ile 1.000.000.000 arasında olmalı',
        current_line.line_number;
    end if;
  end loop;

  select count(*) into duplicate_product_count
  from (
    select entry.value ->> 'product_id'
    from jsonb_array_elements(p_lines) as entry(value)
    group by entry.value ->> 'product_id'
    having count(*) > 1
  ) duplicates;

  if duplicate_product_count > 0 then
    raise exception 'Aynı ürün PDF aktarımında yalnızca bir kez yer alabilir';
  end if;

  insert into private.pdf_stock_imports (
    organization_id,
    movement_type,
    file_name,
    document_sha256,
    invoice_number,
    line_count,
    actor_id,
    actor_name
  ) values (
    current_profile.organization_id,
    p_type,
    normalized_file_name,
    normalized_sha256,
    normalized_invoice_number,
    jsonb_array_length(p_lines),
    current_profile.id,
    current_profile.display_name
  )
  on conflict (organization_id, document_sha256) do nothing
  returning id into imported_id;

  if imported_id is null then
    raise exception 'Bu PDF daha önce işlendi';
  end if;

  -- Lock in a stable order so concurrent imports cannot interleave balances.
  for current_line in
    select
      (entry.value ->> 'product_id')::uuid as product_id,
      round((entry.value ->> 'quantity')::numeric, 3) as quantity
    from jsonb_array_elements(p_lines) as entry(value)
    order by (entry.value ->> 'product_id')::uuid
  loop
    select * into current_product
    from public.products
    where id = current_line.product_id
      and organization_id = current_profile.organization_id
      and active
    for update;

    if not found then
      raise exception 'PDF ürünlerinden biri bu işletmede bulunamadı';
    end if;

    if p_type = 'out' and current_line.quantity > current_product.stock then
      raise exception 'Stokta yalnızca % % bulunuyor: %',
        current_product.stock,
        current_product.unit,
        current_product.name;
    end if;
  end loop;

  movement_note := left(
    'PDF · ' || normalized_file_name
      || case
        when normalized_invoice_number is null then ''
        else ' · Fatura ' || normalized_invoice_number
      end,
    200
  );

  for current_line in
    select
      (entry.value ->> 'product_id')::uuid as product_id,
      round((entry.value ->> 'quantity')::numeric, 3) as quantity
    from jsonb_array_elements(p_lines) as entry(value)
    order by (entry.value ->> 'product_id')::uuid
  loop
    select * into strict current_product
    from public.products
    where id = current_line.product_id
      and organization_id = current_profile.organization_id
      and active
    for update;

    next_stock := case
      when p_type = 'in' then current_product.stock + current_line.quantity
      else current_product.stock - current_line.quantity
    end;

    update public.products
    set stock = round(next_stock, 3),
        updated_at = now()
    where id = current_product.id
      and organization_id = current_profile.organization_id;

    insert into public.stock_movements (
      organization_id,
      product_id,
      type,
      quantity,
      previous_stock,
      new_stock,
      note,
      actor_id,
      actor_name,
      pdf_import_id
    ) values (
      current_profile.organization_id,
      current_product.id,
      p_type,
      current_line.quantity,
      current_product.stock,
      round(next_stock, 3),
      movement_note,
      current_profile.id,
      current_profile.display_name,
      imported_id
    );
  end loop;

  return jsonb_build_object(
    'import_id', imported_id,
    'movement_type', p_type,
    'product_count', jsonb_array_length(p_lines)
  );
end;
$$;

create or replace function public.record_pdf_stock_import(
  p_type text,
  p_file_name text,
  p_document_sha256 text,
  p_invoice_number text,
  p_lines jsonb
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select private.record_pdf_stock_import(
    p_type,
    p_file_name,
    p_document_sha256,
    p_invoice_number,
    p_lines
  );
$$;

comment on table private.pdf_stock_imports is
  'Deduplicates approved local PDF stock imports without storing source documents.';

comment on function public.record_pdf_stock_import(text, text, text, text, jsonb) is
  'Atomically applies all approved PDF invoice lines to the current organization stock.';

revoke all on function private.record_pdf_stock_import(text, text, text, text, jsonb)
  from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.record_pdf_stock_import(text, text, text, text, jsonb)
  to authenticated;

revoke all on function public.record_pdf_stock_import(text, text, text, text, jsonb)
  from public, anon;
grant execute on function public.record_pdf_stock_import(text, text, text, text, jsonb)
  to authenticated;

commit;
