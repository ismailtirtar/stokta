-- Run against an isolated database with the complete Stokdaş schema and one
-- active admin fixture. This script changes no persistent data (ROLLBACK).
-- It calls the public RPC signature and uses a privileged test role to inspect
-- private ledger state between calls.
begin;

do $$
declare
  purchaser uuid;
  organization uuid;
  token_a text := repeat('a', 64);
  token_b text := repeat('b', 64);
  order_a text := repeat('c', 64);
  order_b text := repeat('d', 64);
  account_hash text;
  profile_hash text;
  a_expiry timestamptz := now() + interval '30 days';
  b_expiry timestamptz := now() + interval '60 days';
  entitlement private.google_play_entitlements;
  b_ledger private.google_play_subscriptions;
begin
  select p.id, p.organization_id into purchaser, organization
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
      where purchase_token_hash in (token_a, token_b)) then
    raise exception 'Synthetic token hashes already exist';
  end if;

  account_hash := encode(extensions.digest(convert_to(purchaser::text, 'UTF8'), 'sha256'), 'hex');
  profile_hash := encode(extensions.digest(convert_to(organization::text, 'UTF8'), 'sha256'), 'hex');
  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now()
  where singleton = true;

  perform public.service_record_google_play_subscription(
    token_a, purchaser, organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), a_expiry, true, true, order_a, account_hash, profile_hash
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = organization;
  if entitlement.current_purchase_token_hash is distinct from token_a
     or not entitlement.entitled then
    raise exception 'Fixture A did not become the valid entitlement';
  end if;

  -- Google's void may arrive before the first B ledger insert. B appears to
  -- have a longer active term in subscriptionsv2.get, but its exact order is
  -- refunded. Its grant must never replace the independent valid A pointer.
  perform public.service_record_google_play_void(token_b, order_b, now());
  perform public.service_record_google_play_subscription(
    token_b, purchaser, organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), b_expiry, true, true, order_b, account_hash, profile_hash
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = organization;
  select * into b_ledger from private.google_play_subscriptions
  where purchase_token_hash = token_b;
  if entitlement.current_purchase_token_hash is distinct from token_a
     or not entitlement.entitled
     or entitlement.current_period_end is distinct from a_expiry
     or b_ledger.entitled then
    raise exception 'Refunded B displaced valid A';
  end if;

  perform public.service_record_google_play_subscription(
    token_b, purchaser, organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), b_expiry, true, true, order_b, account_hash, profile_hash
  );
  select * into entitlement from private.google_play_entitlements
  where organization_id = organization;
  if entitlement.current_purchase_token_hash is distinct from token_a
     or not entitlement.entitled then
    raise exception 'Repeated refunded B displaced valid A';
  end if;
end;
$$;

rollback;
