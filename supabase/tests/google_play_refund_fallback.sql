-- The refunded current token must not hide an independent, still-valid Play
-- entitlement. Run on the isolated migration chain; no data persists.
begin;

do $$
declare
  purchaser uuid;
  test_organization uuid;
  token_a text := repeat('a', 64);
  token_b text := repeat('b', 64);
  order_a text := repeat('c', 64);
  order_b text := repeat('d', 64);
  account_hash text;
  profile_hash text;
  a_expiry timestamptz := now() + interval '30 days';
  b_expiry timestamptz := now() + interval '60 days';
  entitlement private.google_play_entitlements;
  organization public.organizations;
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
  if exists (select 1 from private.google_play_subscriptions
      where purchase_token_hash in (token_a, token_b)) then
    raise exception 'Synthetic token hashes already exist';
  end if;

  account_hash := encode(extensions.digest(convert_to(purchaser::text, 'UTF8'), 'sha256'), 'hex');
  profile_hash := encode(extensions.digest(convert_to(test_organization::text, 'UTF8'), 'sha256'), 'hex');
  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now()
  where singleton = true;

  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), a_expiry, true, true, order_a, account_hash, profile_hash
  );
  perform public.service_record_google_play_subscription(
    token_b, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), b_expiry, true, true, order_b, account_hash, profile_hash
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = test_organization;
  if entitlement.current_purchase_token_hash is distinct from token_b
     or not entitlement.entitled then
    raise exception 'Longer B period did not become the current entitlement';
  end if;

  if not public.service_record_google_play_void(token_b, order_b, now()) then
    raise exception 'Refunded current B order was not applied';
  end if;
  select * into entitlement from private.google_play_entitlements
  where organization_id = test_organization;
  select * into organization from public.organizations
  where id = test_organization;
  if entitlement.current_purchase_token_hash is distinct from token_a
     or not entitlement.entitled
     or entitlement.current_period_end is distinct from a_expiry
     or organization.subscription_status <> 'active'
     or organization.current_period_end is distinct from a_expiry
     or exists (select 1 from private.google_play_subscriptions s
       where s.purchase_token_hash = token_b and s.entitled) then
    raise exception 'Refunded B did not restore independent valid A';
  end if;

  -- Google may still report B as ACTIVE after the void. Replaying that GET
  -- must not displace the selected valid A token.
  perform public.service_record_google_play_subscription(
    token_b, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), b_expiry, true, true, order_b, account_hash, profile_hash
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = test_organization;
  if entitlement.current_purchase_token_hash is distinct from token_a
     or not entitlement.entitled then
    raise exception 'Refunded B replay displaced valid A';
  end if;
end;
$$;

rollback;
