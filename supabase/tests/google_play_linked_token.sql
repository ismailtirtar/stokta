-- Run only after the linked-token migration against an isolated database.
-- SQL ownership and replay proof; Google API identity is validated separately.
begin;

do $$
declare
  purchaser uuid;
  test_organization uuid;
  token_a text := repeat('1', 64);
  token_b text := repeat('2', 64);
  token_c text := repeat('3', 64);
  order_a text := repeat('4', 64);
  order_b text := repeat('5', 64);
  order_c text := repeat('6', 64);
  account_hash text;
  profile_hash text;
  a_expiry timestamptz := now() + interval '30 days';
  b_expiry timestamptz := now() + interval '60 days';
  c_expiry timestamptz := now() + interval '75 days';
  claimed jsonb;
  entitlement private.google_play_entitlements;
begin
  select p.id, p.organization_id into purchaser, test_organization
  from public.profiles p
  join public.organizations o on o.id = p.organization_id
  where p.role = 'admin' and p.is_active and not p.must_change_password
    and o.subscription_status <> 'suspended'
    and not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = p.organization_id)
    and not exists (select 1 from public.web_payment_notifications w
      where w.organization_id = p.organization_id and w.status = 'approved'
        and w.activated_until > now())
  limit 1;
  if purchaser is null then
    raise exception 'Seed an active admin with no Play/web entitlement first';
  end if;
  if exists (select 1 from private.google_play_subscriptions
      where purchase_token_hash in (token_a, token_b, token_c)) then
    raise exception 'Synthetic token hashes already exist';
  end if;
  account_hash := encode(extensions.digest(convert_to(purchaser::text, 'UTF8'), 'sha256'), 'hex');
  profile_hash := encode(extensions.digest(convert_to(test_organization::text, 'UTF8'), 'sha256'), 'hex');
  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now()
  where singleton = true;
  perform public.service_activate_google_play_lifecycle();

  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), a_expiry, true, true, order_a, account_hash, profile_hash
  );
  claimed := public.service_claim_google_play_observation(token_b);
  if claimed is null then
    raise exception 'New token observation lease could not be claimed';
  end if;
  perform public.service_record_google_play_observation(
    (claimed->>'leaseId')::uuid, (claimed->>'generation')::bigint,
    jsonb_build_object(
      'purchaseTokenHash', token_b,
      'predecessorTokenHash', token_a,
      'predecessorKind', 'linked',
      'userId', purchaser,
      'organizationId', test_organization,
      'productId', 'stokdas_pro',
      'basePlanId', 'monthly',
      'subscriptionState', 'SUBSCRIPTION_STATE_ACTIVE',
      'acknowledgementState', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
      'activateEntitlement', true,
      'verifiedAt', now(),
      'expiryTime', b_expiry,
      'autoRenewEnabled', true,
      'isTestPurchase', true,
      'latestOrderIdHash', order_b,
      'accountHash', account_hash,
      'profileHash', profile_hash
    ),
    repeat('A', 32), repeat('A', 16)
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = test_organization;
  if entitlement.current_purchase_token_hash is distinct from token_b
     or not entitlement.entitled
     or entitlement.current_period_end is distinct from b_expiry
     or not exists (
       select 1 from private.google_play_token_replacements r
       where r.old_token_hash = token_a and r.new_token_hash = token_b
         and r.purchaser_user_id = purchaser
         and r.organization_id = test_organization
         and r.activated_at is not null
     ) or exists (
       select 1 from private.google_play_subscriptions s
       where s.purchase_token_hash = token_a and s.entitled
     ) then
    raise exception 'A to B replacement did not atomically transfer entitlement';
  end if;

  -- A distinct valid C purchase wins the organization entitlement. The
  -- replaced A token must never reclaim it, even with a later expiry.
  perform public.service_record_google_play_subscription(
    token_c, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), c_expiry, true, true, order_c, account_hash, profile_hash
  );
  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), now() + interval '100 days', true, true,
    order_a, account_hash, profile_hash
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = test_organization;
  if entitlement.current_purchase_token_hash is distinct from token_c
     or not entitlement.entitled
     or entitlement.current_period_end is distinct from c_expiry then
    raise exception 'Replaced A token displaced independent valid C';
  end if;
end;
$$;

rollback;
