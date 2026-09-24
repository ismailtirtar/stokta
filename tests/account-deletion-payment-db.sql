-- Run with psql against a disposable Supabase database after applying the
-- account-deletion migration. The outer ROLLBACK removes every fixture.
\set ON_ERROR_STOP on

begin;

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
  v_result jsonb;
  v_member_batch uuid;
  v_admin_batch uuid;
  v_failed boolean := false;
  v_suffix text := replace(gen_random_uuid()::text, '-', '');
begin
  if has_table_privilege('authenticated', 'private.account_deletion_auth_jobs', 'SELECT')
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
     or v_result->>'paymentStatus' <> 'pending' then
    raise exception 'Pending notice failed to block deletion: %', v_result;
  end if;

  update public.web_payment_notifications
  set status = 'rejected', reviewed_by = v_admin, reviewed_at = now(),
      rejection_reason = 'Fixture rejected', updated_at = now()
  where id = v_notice;
  v_result := public.service_delete_account_data(v_member);
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
  if not public.service_fail_account_deletion_auth_job(v_member_batch, v_member, 'fixture_error')
     or not exists (select 1 from private.account_deletion_auth_jobs
                    where batch_id = v_member_batch and attempts = 1
                      and last_error_code = 'fixture_error')
     or (public.service_account_deletion_auth_job_health()->>'withFailures')::integer < 1
     or not public.service_complete_account_deletion_auth_job(v_member_batch, v_member)
     or public.service_complete_account_deletion_auth_job(v_member_batch, v_member)
     or jsonb_array_length(public.service_list_account_deletion_auth_jobs(v_member_batch)) <> 0 then
    raise exception 'Auth outbox retry or idempotent completion failed';
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
