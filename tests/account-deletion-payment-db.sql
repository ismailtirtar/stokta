-- Run with psql against a disposable Supabase database after applying the
-- account-deletion migration. The outer ROLLBACK removes every fixture.
\set ON_ERROR_STOP on
\set proof_host ''
\set proof_port ''
\set proof_database ''
\set proof_user ''
\set proof_host_address ''
\set proof_service ''
\getenv proof_host PGHOST
\getenv proof_port PGPORT
\getenv proof_database PGDATABASE
\getenv proof_user PGUSER
\getenv proof_host_address PGHOSTADDR
\getenv proof_service PGSERVICE
select (:'proof_host' = '127.0.0.1' and :'proof_port' = '54322'
  and :'proof_database' = 'postgres' and :'proof_user' = 'postgres'
  and :'proof_host_address' in ('', '127.0.0.1') and :'proof_service' = ''
  and current_database() = 'postgres' and session_user = 'postgres')
  as proof_is_disposable \gset
\if :proof_is_disposable
\else
do $$ begin raise exception 'Deletion proof requires disposable local Supabase'; end $$;
\endif

begin;

-- The workflow connects only to disposable local Supabase (127.0.0.1:54322).
-- Container server addresses may be Docker bridge addresses, so do not infer
-- production safety from inet_server_addr(). Never execute this fixture live.

create table private.account_deletion_test_restrict (
  organization_id uuid primary key references public.organizations(id) on delete restrict
);

create function pg_temp.reject_test_product_delete()
returns trigger
language plpgsql
as $$
begin
  raise exception 'fixture product delete failure';
end;
$$;

create trigger reject_test_product_delete
before delete on public.products
for each row execute function pg_temp.reject_test_product_delete();

do $$
declare
  v_admin uuid := gen_random_uuid();
  v_member uuid := gen_random_uuid();
  v_organization uuid := gen_random_uuid();
  v_product uuid;
  v_pdf_import uuid;
  v_notice uuid;
  v_admin_request uuid;
  v_member_request uuid;
  v_admin_session uuid := gen_random_uuid();
  v_member_session uuid := gen_random_uuid();
  v_operator uuid := gen_random_uuid();
  v_operator_org uuid := gen_random_uuid();
  v_operator_session uuid := gen_random_uuid();
  v_operator_factor uuid := gen_random_uuid();
  v_result jsonb;
  v_member_batch uuid;
  v_admin_batch uuid;
  v_failed boolean := false;
  v_denied boolean := false;
  v_suffix text := replace(gen_random_uuid()::text, '-', '');
begin
  if has_table_privilege('authenticated', 'private.account_deletion_auth_jobs', 'SELECT')
     or has_table_privilege('authenticated', 'private.account_deletion_requests', 'SELECT')
     or has_function_privilege('authenticated',
       'public.service_delete_account_data(uuid)', 'EXECUTE')
     or has_function_privilege('authenticated',
       'public.service_account_deletion_auth_batch_pending(uuid)', 'EXECUTE')
     or has_function_privilege('authenticated',
       'public.service_list_account_deletion_auth_jobs(uuid)', 'EXECUTE')
     or has_function_privilege('authenticated',
       'public.service_complete_account_deletion_auth_job(uuid,uuid)', 'EXECUTE')
     or has_function_privilege('authenticated',
       'public.service_account_deletion_auth_job_health()', 'EXECUTE')
     or not has_function_privilege('service_role',
       'public.service_list_account_deletion_auth_jobs(uuid)', 'EXECUTE') then
    raise exception 'Auth outbox privileges are not restricted to the service role';
  end if;

  insert into auth.users (
    id, instance_id, aud, role, email, encrypted_password,
    email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data
  ) values
    (v_admin, '00000000-0000-0000-0000-000000000000', 'authenticated',
      'authenticated', 'delete-admin-' || v_suffix || '@example.test', 'test',
      now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
    (v_member, '00000000-0000-0000-0000-000000000000', 'authenticated',
      'authenticated', 'delete-member-' || v_suffix || '@example.test', 'test',
      now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
    (v_operator, '00000000-0000-0000-0000-000000000000', 'authenticated',
      'authenticated', 'delete-operator-' || v_suffix || '@example.test', 'test',
      now(), now(), now(), '{}'::jsonb, '{}'::jsonb);

  insert into public.organizations (
    id, name, slug, subscription_status, trial_ends_at, created_by
  ) values (
    v_organization, 'Deletion test', 'delete-' || left(v_suffix, 24),
    'trial', now() + interval '14 days', v_admin
  );
  insert into public.profiles (
    id, username, display_name, role, created_by, organization_id
  ) values
    (v_admin, 'deleteadmin' || left(v_suffix, 8), 'Deletion Admin',
      'admin', null, v_organization),
    (v_member, 'deletemember' || left(v_suffix, 8), 'Deletion Member',
      'member', v_admin, v_organization);
  insert into public.organizations (id, name, slug, subscription_status, trial_ends_at, created_by)
  values (v_operator_org, 'Operator fixture', 'op-' || left(v_suffix, 24), 'trial', now() + interval '14 days', v_operator);
  insert into public.profiles (id, username, display_name, role, organization_id, is_platform_operator)
  values (v_operator, 'deleteop' || left(v_suffix, 8), 'Operator fixture', 'admin', v_operator_org, true);
  insert into auth.mfa_factors (id, user_id, factor_type, status, secret, created_at, updated_at)
  values (v_operator_factor, v_operator, 'totp', 'verified', 'fixture-only', now(), now());
  insert into auth.sessions (id, user_id, created_at, updated_at, aal, factor_id) values
    (v_admin_session, v_admin, now(), now(), 'aal1', null),
    (v_member_session, v_member, now(), now(), 'aal1', null),
    (v_operator_session, v_operator, now(), now(), 'aal2', v_operator_factor);
  insert into public.security_audit_events (organization_id, actor_id, subject_id, event_type, metadata)
  values (v_organization, v_admin, v_member, 'fixture.member.created', jsonb_build_object('username', 'deletemember' || left(v_suffix, 8))),
    (v_organization, v_admin, v_admin, 'fixture.admin.created', jsonb_build_object('username', 'deleteadmin' || left(v_suffix, 8)));

  insert into public.products (name, sku, stock, created_by, organization_id)
  values ('Fixture', 'DEL-' || left(v_suffix, 16), 1, v_admin, v_organization)
  returning id into v_product;
  insert into private.pdf_stock_imports (
    organization_id, movement_type, file_name, document_sha256,
    line_count, actor_id, actor_name
  ) values (
    v_organization, 'in', 'fixture.pdf', repeat('a', 64),
    1, v_member, 'Deletion Member'
  ) returning id into v_pdf_import;
  insert into public.stock_movements (
    product_id, type, quantity, previous_stock, new_stock,
    actor_id, actor_name, organization_id, pdf_import_id
  ) values (v_product, 'in', 1, 0, 1, v_member, 'Deletion Member', v_organization, v_pdf_import);

  insert into public.web_payment_notifications (
    organization_id, submitted_by, sender_name, amount_cents,
    paid_at, payment_reference
  ) values (
    v_organization, v_member, 'Fixture Sender', 29900,
    current_date, public.web_payment_reference(v_organization)
  ) returning id into v_notice;

  v_result := public.service_delete_account_data(v_admin);
  if v_result->>'code' <> 'PAYMENT_RECORDS_REQUIRE_REVIEW'
     or v_result->>'paymentStatus' <> 'pending'
     or v_result->>'requestStatus' <> 'requested'
     or v_result->>'requestId' is null then
    raise exception 'Pending notice failed to block deletion: %', v_result;
  end if;
  v_admin_request := (v_result->>'requestId')::uuid;
  v_result := public.service_delete_account_data(v_admin);
  if (v_result->>'requestId')::uuid <> v_admin_request
     or (select count(*) from private.account_deletion_requests where requester_user_id = v_admin) <> 1 then
    raise exception 'Repeated owner request is not idempotent';
  end if;

  update public.web_payment_notifications
  set status = 'rejected', reviewed_by = v_admin, reviewed_at = now(),
      rejection_reason = 'Fixture rejected', updated_at = now()
  where id = v_notice;
  v_result := public.service_delete_account_data(v_member);
  v_member_request := (v_result->>'requestId')::uuid;
  if v_result->>'code' <> 'PAYMENT_RECORDS_REQUIRE_REVIEW'
     or v_result->>'paymentStatus' <> 'reviewed' then
    raise exception 'Reviewed notice failed to block member deletion: %', v_result;
  end if;
  if not exists (select 1 from public.profiles where id = v_member)
     or not exists (select 1 from public.products where id = v_product)
     or not exists (select 1 from private.pdf_stock_imports
                    where id = v_pdf_import and actor_id = v_member
                      and actor_name = 'Deletion Member') then
    raise exception 'Blocked deletion changed tenant data';
  end if;

  -- Owner status RPC exposes only the current live account's request. Tenant
  -- administrators cannot use the cross-tenant operator review API.
  perform set_config('request.jwt.claims', jsonb_build_object('sub', v_member, 'role', 'authenticated', 'session_id', v_member_session, 'aal', 'aal1')::text, true);
  execute 'set local role authenticated';
  v_result := public.get_my_account_deletion_request();
  if (v_result->>'id')::uuid <> v_member_request then raise exception 'Owner request missing'; end if;
  begin perform public.platform_list_account_deletion_requests();
  exception when others then v_denied := true; end;
  if not v_denied then raise exception 'Tenant member gained operator access'; end if;
  execute 'reset role';
  perform set_config('request.jwt.claims', jsonb_build_object('sub', v_admin, 'role', 'authenticated', 'session_id', v_admin_session, 'aal', 'aal1')::text, true);
  execute 'set local role authenticated';
  v_result := public.get_my_account_deletion_request();
  if (v_result->>'id')::uuid <> v_admin_request or (v_result->>'id')::uuid = v_member_request then
    raise exception 'Status RPC leaked another owner request';
  end if;
  execute 'reset role';

  -- Even an actual operator with a live factor cannot use an AAL1 bearer.
  perform set_config('request.jwt.claims', jsonb_build_object('sub', v_operator, 'role', 'authenticated', 'session_id', v_operator_session, 'aal', 'aal1', 'amr', jsonb_build_array('password'))::text, true);
  execute 'set local role authenticated';
  v_denied := false;
  begin perform public.platform_review_account_deletion_request(v_admin_request);
  exception when insufficient_privilege then v_denied := true; end;
  if not v_denied then raise exception 'AAL1 operator reviewed deletion'; end if;
  execute 'reset role';
  perform set_config('request.jwt.claims', jsonb_build_object('sub', v_operator, 'role', 'authenticated', 'session_id', v_operator_session, 'aal', 'aal2', 'amr', jsonb_build_array('password', 'totp'))::text, true);
  execute 'set local role authenticated';
  if jsonb_array_length(public.platform_list_account_deletion_requests()) < 2 then raise exception 'AAL2 queue missing requests'; end if;
  v_result := public.platform_review_account_deletion_request(v_admin_request);
  if v_result->>'status' <> 'under_review' then raise exception 'AAL2 acknowledgement failed'; end if;
  execute 'reset role';
  if not exists (select 1 from public.web_payment_notifications where id = v_notice)
     or not exists (select 1 from public.profiles where id = v_admin) then
    raise exception 'Acknowledging review deleted financial or account data';
  end if;
  perform set_config('request.jwt.claims', '{}', true);

  delete from public.web_payment_notifications where id = v_notice;
  v_result := public.service_delete_account_data(v_member);
  v_member_batch := (v_result->>'batchId')::uuid;
  if v_result->>'deleted' <> 'true'
     or v_result->>'scope' <> 'account'
     or not exists (select 1 from private.account_deletion_auth_jobs
                    where batch_id = v_member_batch and auth_user_id = v_member
                      and kind = 'identity')
     or exists (select 1 from public.profiles where id = v_member)
     or not exists (select 1 from private.pdf_stock_imports
                    where id = v_pdf_import and actor_id is null
                      and actor_name = 'Silinmiş kullanıcı')
     or not exists (select 1 from public.stock_movements
                    where product_id = v_product and actor_id is null
                      and actor_name = 'Silinmiş kullanıcı') then
    raise exception 'No-notice member cleanup failed: %', v_result;
  end if;
  if exists (select 1 from public.security_audit_events
      where event_type = 'fixture.member.created' and metadata ? 'username') then
    raise exception 'Deleted member username survived in audit metadata';
  end if;
  if not public.service_fail_account_deletion_auth_job(v_member_batch, v_member, 'fixture_error') then
    raise exception 'Auth outbox failure was not recorded';
  end if;
  if not exists (select 1 from private.account_deletion_auth_jobs
                 where batch_id = v_member_batch and attempts = 1
                   and last_error_code = 'fixture_error')
     or (public.service_account_deletion_auth_job_health()->>'withFailures')::integer < 1 then
    raise exception 'Auth outbox failure state is missing';
  end if;
  if jsonb_array_length(public.service_list_account_deletion_auth_jobs(v_member_batch)) <> 0
     or public.service_account_deletion_auth_batch_pending(v_member_batch) <> 1 then
    raise exception 'Backoff delayed job was incorrectly treated as completed';
  end if;
  if not public.service_complete_account_deletion_auth_job(v_member_batch, v_member) then
    raise exception 'Auth outbox completion failed';
  end if;
  if public.service_complete_account_deletion_auth_job(v_member_batch, v_member) then
    raise exception 'Auth outbox completion is not idempotent';
  end if;
  if jsonb_array_length(public.service_list_account_deletion_auth_jobs(v_member_batch)) <> 0 then
    raise exception 'Completed Auth outbox job remains pending';
  end if;
  if not exists (select 1 from private.account_deletion_requests where id = v_member_request
      and status = 'completed' and requester_user_id is null and organization_id is null) then
    raise exception 'Completed request retained direct account links';
  end if;

  begin
    perform public.service_delete_account_data(v_admin);
  exception when others then
    if sqlerrm = 'fixture product delete failure' then
      v_failed := true;
    else
      raise;
    end if;
  end;
  if not v_failed
     or not exists (select 1 from public.organizations where id = v_organization)
     or not exists (select 1 from public.profiles where id = v_admin)
     or not exists (select 1 from public.products where id = v_product)
     or not exists (select 1 from public.stock_movements where product_id = v_product)
     or not exists (select 1 from private.pdf_stock_imports where id = v_pdf_import)
     or exists (select 1 from private.account_deletion_auth_jobs where auth_user_id = v_admin) then
    raise exception 'Database cleanup did not roll back as one transaction';
  end if;

  execute 'drop trigger reject_test_product_delete on public.products';
  -- A real FK RESTRICT failure occurs only after stock/PDF/products/profile
  -- deletion and request/audit mutation. All of those changes must roll back.
  insert into private.account_deletion_test_restrict values (v_organization);
  v_failed := false;
  begin perform public.service_delete_account_data(v_admin);
  exception when foreign_key_violation then v_failed := true; end;
  if not v_failed
     or not exists (select 1 from public.organizations where id = v_organization)
     or not exists (select 1 from public.profiles where id = v_admin and is_active)
     or not exists (select 1 from public.products where id = v_product)
     or not exists (select 1 from public.stock_movements where product_id = v_product)
     or not exists (select 1 from private.pdf_stock_imports where id = v_pdf_import)
     or not exists (select 1 from private.account_deletion_requests where id = v_admin_request and status = 'under_review' and batch_id is null)
     or not exists (select 1 from public.security_audit_events where subject_id = v_admin and metadata ? 'username')
     or exists (select 1 from private.account_deletion_auth_jobs where auth_user_id = v_admin) then
    raise exception 'RESTRICT failure left partially deleted or banned tenant data';
  end if;
  delete from private.account_deletion_test_restrict where organization_id = v_organization;
  v_result := public.service_delete_account_data(v_admin);
  v_admin_batch := (v_result->>'batchId')::uuid;
  if v_result->>'deleted' <> 'true'
     or v_result->>'scope' <> 'organization'
     or not exists (select 1 from private.account_deletion_auth_jobs
                    where batch_id = v_admin_batch and auth_user_id = v_admin)
     or exists (select 1 from public.organizations where id = v_organization)
     or exists (select 1 from public.profiles where organization_id = v_organization)
     or exists (select 1 from public.products where id = v_product)
     or exists (select 1 from private.pdf_stock_imports where id = v_pdf_import)
     or exists (select 1 from public.stock_movements where product_id = v_product) then
    raise exception 'No-notice organization cleanup failed: %', v_result;
  end if;
end;
$$;

rollback;
