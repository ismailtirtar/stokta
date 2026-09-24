-- Preparation keeps the deployed RPC/ACK path available while the first
-- 29-day void sweep runs. Activation is explicit and requires a complete,
-- recent sweep; all changes in this proof roll back.
begin;

do $$
declare
  purchaser uuid;
  test_organization uuid;
  token_hash text := repeat('7', 64);
  new_token_hash text := repeat('5', 64);
  order_hash text := repeat('6', 64);
  account_hash text;
  profile_hash text;
  expiry timestamptz := now() + interval '30 days';
  claimed jsonb;
begin
  select p.id, p.organization_id into purchaser, test_organization
  from public.profiles p
  join public.organizations o on o.id = p.organization_id
  where p.role = 'admin' and p.is_active and not p.must_change_password
    and o.subscription_status <> 'suspended'
    and not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = p.organization_id)
    and not exists (select 1 from private.google_play_subscriptions s
      where s.organization_id = p.organization_id)
    and not exists (select 1 from public.web_payment_notifications w
      where w.organization_id = p.organization_id and w.status = 'approved'
        and w.activated_until > now())
  limit 1;
  if purchaser is null then
    raise exception 'Seed an active admin with no Play/web entitlement first';
  end if;
  account_hash := encode(extensions.digest(convert_to(purchaser::text, 'UTF8'), 'sha256'), 'hex');
  profile_hash := encode(extensions.digest(convert_to(test_organization::text, 'UTF8'), 'sha256'), 'hex');
  if (public.service_google_play_lifecycle_health()->>'lifecycleActive')::boolean
     is distinct from false then
    raise exception 'Lifecycle did not start in preparation mode';
  end if;

  claimed := public.service_claim_google_play_observation(new_token_hash);
  if claimed is null then
    raise exception 'Preparation observation lease could not be claimed';
  end if;
  begin
    perform public.service_record_google_play_observation(
      (claimed->>'leaseId')::uuid, (claimed->>'generation')::bigint,
      jsonb_build_object(
        'purchaseTokenHash', new_token_hash,
        'userId', purchaser,
        'organizationId', test_organization,
        'productId', 'stokdas_pro',
        'basePlanId', 'monthly',
        'subscriptionState', 'SUBSCRIPTION_STATE_ACTIVE',
        'acknowledgementState', 'ACKNOWLEDGEMENT_STATE_PENDING',
        'activateEntitlement', false,
        'verifiedAt', now(),
        'expiryTime', expiry,
        'autoRenewEnabled', true,
        'isTestPurchase', true,
        'latestOrderIdHash', order_hash,
        'accountHash', account_hash,
        'profileHash', profile_hash
      ),
      repeat('A', 32), repeat('A', 16)
    );
    raise exception 'New observation passed before lifecycle activation';
  exception when sqlstate '55000' then null;
  end;
  if exists (select 1 from private.google_play_subscriptions s
      where s.purchase_token_hash = new_token_hash) then
    raise exception 'Inactive observation wrote a Play ledger';
  end if;

  begin
    perform public.service_activate_google_play_lifecycle();
    raise exception 'Activation passed before the first refund scan';
  exception when sqlstate '55000' then null;
  end;

  -- This is exactly the deployed verifier's first (non-granting) RPC and
  -- later post-ACK RPC. Preparation preserves both calls without scan 503.
  perform public.service_record_google_play_subscription(
    token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_PENDING',
    false, now(), expiry, true, true, order_hash, account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_subscriptions s
      where s.purchase_token_hash = token_hash
        and s.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_PENDING'
        and not s.entitled) then
    raise exception 'Preparation pre-ACK ownership record failed';
  end if;
  perform public.service_record_google_play_subscription(
    token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, true, true, order_hash, account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled
        and e.current_purchase_token_hash = token_hash) then
    raise exception 'Preparation post-ACK grant failed';
  end if;

  -- The exact-order refund fence remains active during preparation.
  if not public.service_record_google_play_void(token_hash, order_hash, now()) then
    raise exception 'Preparation did not revoke a refunded order';
  end if;
  perform public.service_record_google_play_subscription(
    token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, true, true, order_hash, account_hash, profile_hash
  );
  if exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled) then
    raise exception 'Preparation re-granted a refunded order';
  end if;

  update private.google_play_void_scan_state
  set page_token = 'more', last_completed_at = now() where singleton = true;
  begin
    perform public.service_activate_google_play_lifecycle();
    raise exception 'Activation passed an incomplete refund scan';
  exception when sqlstate '55000' then null;
  end;
  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now() - interval '11 minutes'
  where singleton = true;
  begin
    perform public.service_activate_google_play_lifecycle();
    raise exception 'Activation passed a stale refund scan';
  exception when sqlstate '55000' then null;
  end;
  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now() where singleton = true;
  if not public.service_activate_google_play_lifecycle()
     or (public.service_google_play_lifecycle_health()->>'lifecycleActive')::boolean
       is distinct from true then
    raise exception 'Complete recent scan did not activate lifecycle';
  end if;
end;
$$;

rollback;
