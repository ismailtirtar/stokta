-- Cover every multi-tenant foreign key with its source-column index.

begin;

set local statement_timeout = '30s';

create index organizations_created_by_idx
  on public.organizations (created_by);

create index products_created_by_organization_idx
  on public.products (created_by, organization_id);

create index profiles_created_by_organization_idx
  on public.profiles (created_by, organization_id);

create index stock_movements_product_organization_idx
  on public.stock_movements (product_id, organization_id);

drop index public.products_created_by_idx;
drop index public.profiles_created_by_idx;

commit;
