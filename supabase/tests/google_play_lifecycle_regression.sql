-- Disposable Supabase CI database only. Synthetic observations below test SQL
-- invariants, not Google delivery; the outer ROLLBACK removes every fixture.
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
do $$ begin
  raise exception 'Billing regression requires the disposable local Supabase CI database';
end $$;
\endif

begin;
set local statement_timeout = '30s';
set local lock_timeout = '5s';

do $$
declare
  purchaser uuid := gen_random_uuid();
  reviewer uuid := gen_random_uuid();
  test_organization uuid := gen_random_uuid();
  reviewer_organization uuid := gen_random_uuid();
  suffix text := replace(gen_random_uuid()::text, '-', '');
  token_a text := repeat('7', 64);
  token_b text := repeat('8', 64);
  token_other text := repeat('9', 64);
  token_predecessor text := repeat('e', 64);
  token_successor text := repeat('f', 64);
  order_old text := repeat('a', 64);
  order_current text := repeat('b', 64);
  order_b text := repeat('c', 64);
  account_hash text;
  profile_hash text;
  expiry timestamptz := now() + interval '30 days';
  web_until timestamptz;
  notification_id uuid;
  result jsonb;
  claim jsonb;
  observation jsonb;
  state text;
  expected_entitled boolean;
  expected_status text;
  entitlement private.google_play_entitlements;
  organization public.organizations;
begin
  if exists (select 1 from private.google_play_subscriptions
      where purchase_token_hash in (token_a, token_b, token_other,
        token_predecessor, token_successor))
     or exists (select 1 from private.google_play_voided_orders
      where purchase_token_hash in (token_a, token_b, token_other,
        token_predecessor, token_successor)) then
    raise exception 'Synthetic billing hashes already exist';
  end if;

  insert into auth.users (
    id, instance_id, aud, role, email, encrypted_password,
    email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data
  ) values
    (purchaser, '00000000-0000-0000-0000-000000000000', 'authenticated',
      'authenticated', 'billing-admin-' || suffix || '@example.test', 'test',
      now(), now(), now(), '{}'::jsonb, '{}'::jsonb),
    (reviewer, '00000000-0000-0000-0000-000000000000', 'authenticated',
      'authenticated', 'billing-reviewer-' || suffix || '@example.test', 'test',
      now(), now(), now(), '{}'::jsonb, '{}'::jsonb);
  insert into public.organizations
    (id, name, slug, subscription_status, trial_ends_at, created_by)
  values
    (test_organization, 'CI Billing Lifecycle', 'ci-billing-' || left(suffix, 24),
      'trial', now() + interval '14 days', purchaser),
    (reviewer_organization, 'CI Billing Reviewer', 'ci-reviewer-' || left(suffix, 24),
      'trial', now() + interval '14 days', reviewer);
  insert into public.profiles
    (id, username, display_name, role, organization_id, is_active,
      must_change_password, is_platform_operator)
  values
    (purchaser, 'billingadmin' || left(suffix, 8), 'CI Billing Admin', 'admin',
      test_organization, true, false, false),
    (reviewer, 'billingreviewer' || left(suffix, 8), 'CI Billing Reviewer', 'admin',
      reviewer_organization, true, false, true);

  account_hash := encode(extensions.digest(convert_to(purchaser::text, 'UTF8'), 'sha256'), 'hex');
  profile_hash := encode(extensions.digest(convert_to(test_organization::text, 'UTF8'), 'sha256'), 'hex');
  update private.google_play_void_scan_state
    set page_token = null, last_completed_at = now() where singleton = true;
  perform public.service_activate_google_play_lifecycle();

  -- Grace retains paid access; hold closes it; recovery reopens the same token.
  foreach state in array array[
    'SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
    'SUBSCRIPTION_STATE_ON_HOLD', 'SUBSCRIPTION_STATE_ACTIVE'
  ] loop
    expected_entitled := state <> 'SUBSCRIPTION_STATE_ON_HOLD';
    expected_status := case when expected_entitled then 'active' else 'past_due' end;
    result := public.service_record_google_play_subscription(
      token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
      state, 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
      expected_entitled, now(), expiry, true, true,
      order_old, account_hash, profile_hash
    );
    select * into entitlement from private.google_play_entitlements
      where organization_id = test_organization;
    select * into organization from public.organizations where id = test_organization;
    if entitlement.current_purchase_token_hash is distinct from token_a
       or entitlement.entitled is distinct from expected_entitled
       or entitlement.subscription_state is distinct from state
       or organization.subscription_status is distinct from expected_status
       or (result->>'entitled')::boolean is distinct from expected_entitled then
      raise exception 'Grace/hold/recovery invariant failed for %', state;
    end if;
  end loop;

  -- A refund for an older renewal must not revoke the latest successful order.
  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, true, true,
    order_current, account_hash, profile_hash
  );
  if public.service_record_google_play_void(token_a, order_old, now()) then
    raise exception 'An older renewal refund was treated as the latest order';
  end if;
  if not exists (select 1 from private.google_play_voided_orders
      where purchase_token_hash = token_a and order_id_hash = order_old)
     or not exists (select 1 from private.google_play_entitlements
      where organization_id = test_organization
        and current_purchase_token_hash = token_a and entitled) then
    raise exception 'Old-order fence did not preserve the newest entitlement';
  end if;

  -- Use the actual reviewer RPC so the web entitlement is an approved period.
  insert into public.web_payment_notifications (
    organization_id, submitted_by, sender_name, amount_cents, paid_at, payment_reference
  ) values (
    test_organization, purchaser, 'CI Billing Admin', 29999,
    current_date, public.web_payment_reference(test_organization)
  ) returning id into notification_id;
  result := public.service_review_web_payment_notification(notification_id, 'approved', reviewer);
  web_until := (result->>'activated_until')::timestamptz;
  if web_until is null or web_until <= expiry then
    raise exception 'Web approval did not extend the paid period';
  end if;

  foreach state in array array['SUBSCRIPTION_STATE_ON_HOLD', 'SUBSCRIPTION_STATE_EXPIRED'] loop
    perform public.service_record_google_play_subscription(
      token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
      state, 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
      false, now(), expiry, false, true,
      order_current, account_hash, profile_hash
    );
    select * into organization from public.organizations where id = test_organization;
    if organization.subscription_status <> 'active'
       or organization.current_period_end is distinct from web_until
       or exists (select 1 from private.google_play_entitlements
         where organization_id = test_organization and entitled) then
      raise exception 'Play % shortened or closed the approved web period', state;
    end if;
  end loop;

  perform public.service_record_google_play_void(token_a, order_current, now());
  -- A stale ACTIVE Google resource must not resurrect its refunded last order.
  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, false, true,
    order_current, account_hash, profile_hash
  );
  select * into organization from public.organizations where id = test_organization;
  if organization.subscription_status <> 'active'
     or organization.current_period_end is distinct from web_until
     or exists (select 1 from private.google_play_subscriptions
       where purchase_token_hash = token_a and entitled)
     or exists (select 1 from private.google_play_entitlements
       where organization_id = test_organization and entitled) then
    raise exception 'Latest refund lost web access or revived Play access';
  end if;

  -- A pointer can hide an independent auto-renewing token. Account deletion
  -- must inspect all organization subscriptions, not only that pointer.
  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, true, true,
    order_current, account_hash, profile_hash
  );
  perform public.service_record_google_play_subscription(
    token_b, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry + interval '5 days', false, true,
    order_b, account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_entitlements
      where organization_id = test_organization and current_purchase_token_hash = token_b)
     or not public.service_google_play_subscription_requires_cancellation(test_organization) then
    raise exception 'Displaced independent auto-renewing token did not block deletion';
  end if;
  -- The refund fence alone is deliberately not proof of canceled renewal.
  if not exists (select 1 from private.google_play_voided_orders
      where purchase_token_hash = token_a and order_id_hash = order_current) then
    raise exception 'Cancellation proof lost its refunded independent token';
  end if;

  foreach state in array array['SUBSCRIPTION_STATE_EXPIRED', 'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'] loop
    perform public.service_record_google_play_subscription(
      token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
      state, 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
      false, now(), expiry, true, true,
      order_current, account_hash, profile_hash
    );
    if public.service_google_play_subscription_requires_cancellation(test_organization) then
      raise exception 'Terminal token % incorrectly blocked deletion', state;
    end if;
  end loop;
  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, false, true,
    order_current, account_hash, profile_hash
  );
  if public.service_google_play_subscription_requires_cancellation(test_organization) then
    raise exception 'Canceled renewal incorrectly blocked deletion';
  end if;

  -- A pending linked successor has not invalidated its renewing predecessor.
  -- After activation, that predecessor's intentionally stale renewal scalar
  -- must not block deletion when the successor itself no longer renews.
  perform public.service_record_google_play_subscription(
    token_predecessor, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry + interval '10 days', true, true,
    repeat('1', 64), account_hash, profile_hash
  );
  claim := public.service_claim_google_play_observation(token_successor);
  if claim is null then
    raise exception 'Linked cancellation proof could not claim an observation';
  end if;
  observation := jsonb_build_object(
    'purchaseTokenHash', token_successor,
    'predecessorTokenHash', token_predecessor,
    'predecessorKind', 'linked',
    'userId', purchaser,
    'organizationId', test_organization,
    'productId', 'stokdas_pro',
    'basePlanId', 'monthly',
    'subscriptionState', 'SUBSCRIPTION_STATE_PENDING',
    'acknowledgementState', 'ACKNOWLEDGEMENT_STATE_PENDING',
    'activateEntitlement', false,
    'verifiedAt', now(),
    'expiryTime', null,
    'autoRenewEnabled', false,
    'isTestPurchase', true,
    'latestOrderIdHash', null,
    'accountHash', account_hash,
    'profileHash', profile_hash
  );
  perform public.service_record_google_play_observation(
    (claim->>'leaseId')::uuid, (claim->>'generation')::bigint,
    observation, repeat('A', 32), repeat('A', 16)
  );
  if not exists (select 1 from private.google_play_token_replacements
      where old_token_hash = token_predecessor and new_token_hash = token_successor
        and activated_at is null)
     or not public.service_google_play_subscription_requires_cancellation(test_organization) then
    raise exception 'Unactivated replacement hid its renewing predecessor';
  end if;
  observation := observation || jsonb_build_object(
    'subscriptionState', 'SUBSCRIPTION_STATE_CANCELED',
    'acknowledgementState', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    'activateEntitlement', true,
    'expiryTime', expiry + interval '15 days',
    'latestOrderIdHash', repeat('2', 64)
  );
  perform public.service_record_google_play_observation(
    (claim->>'leaseId')::uuid, (claim->>'generation')::bigint,
    observation, repeat('A', 32), repeat('A', 16)
  );
  if not exists (select 1 from private.google_play_token_replacements
      where old_token_hash = token_predecessor and new_token_hash = token_successor
        and activated_at is not null)
     or not exists (select 1 from private.google_play_subscriptions
      where purchase_token_hash = token_predecessor
        and auto_renew_enabled is true and not entitled)
     or public.service_google_play_subscription_requires_cancellation(test_organization) then
    raise exception 'Activated predecessor with a canceled successor blocked deletion';
  end if;

  perform public.service_record_google_play_subscription(
    token_other, reviewer, reviewer_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, true, true, repeat('d', 64),
    encode(extensions.digest(convert_to(reviewer::text, 'UTF8'), 'sha256'), 'hex'),
    encode(extensions.digest(convert_to(reviewer_organization::text, 'UTF8'), 'sha256'), 'hex')
  );
  if public.service_google_play_subscription_requires_cancellation(test_organization)
     or not public.service_google_play_subscription_requires_cancellation(reviewer_organization) then
    raise exception 'Cancellation requirement crossed organization ownership';
  end if;
end;
$$;

rollback;
