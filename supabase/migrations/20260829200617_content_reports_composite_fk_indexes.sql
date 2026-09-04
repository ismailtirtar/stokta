-- Add covering indexes for the tenant-qualified foreign keys on content reports.
-- The replacement indexes keep the same leading lookup columns used by the
-- original indexes while also covering organization_id for FK checks.

begin;

set local statement_timeout = '30s';

create index content_reports_reporter_organization_created_idx
  on public.content_reports (reporter_id, organization_id, created_at desc)
  where reporter_id is not null;

create index content_reports_product_organization_idx
  on public.content_reports (target_product_id, organization_id)
  where target_product_id is not null;

create index content_reports_movement_organization_idx
  on public.content_reports (target_movement_id, organization_id)
  where target_movement_id is not null;

create index content_reports_user_organization_idx
  on public.content_reports (target_user_id, organization_id)
  where target_user_id is not null;

create index content_reports_resolver_organization_idx
  on public.content_reports (resolved_by, organization_id)
  where resolved_by is not null;

drop index public.content_reports_reporter_created_idx;
drop index public.content_reports_product_target_idx;
drop index public.content_reports_movement_target_idx;
drop index public.content_reports_user_target_idx;
drop index public.content_reports_resolver_idx;

commit;
