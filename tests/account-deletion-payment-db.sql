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
  v_notice uuid;
  v_result jsonb;
  v_failed boolean := false;
  v_suffix text := replace(gen_random_uuid()::text, '-', '');
begin
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
  insert into public.stock_movements (
    product_id, type, quantity, previous_stock, new_stock,
    actor_id, actor_name, organization_id
  ) values (v_product, 'in', 1, 0, 1, v_member, 'Deletion Member', v_organization);

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
     or not exists (select 1 from public.products where id = v_product) then
    raise exception 'Blocked deletion changed tenant data';
  end if;

  delete from public.web_payment_notifications where id = v_notice;
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
     or not exists (select 1 from public.profiles where id = v_member)
     or not exists (select 1 from public.products where id = v_product)
     or not exists (select 1 from public.stock_movements where product_id = v_product) then
    raise exception 'Database cleanup did not roll back as one transaction';
  end if;

  execute 'drop trigger reject_test_product_delete on public.products';
  v_result := public.service_delete_account_data(v_admin);
  if v_result->>'deleted' <> 'true'
     or v_result->>'scope' <> 'organization'
     or exists (select 1 from public.organizations where id = v_organization)
     or exists (select 1 from public.profiles where organization_id = v_organization)
     or exists (select 1 from public.products where id = v_product)
     or exists (select 1 from public.stock_movements where product_id = v_product) then
    raise exception 'No-notice organization cleanup failed: %', v_result;
  end if;
end;
$$;

rollback;
