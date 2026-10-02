-- Two refunded tokens on different pages of the initial scan must never
-- restore the earlier token during activation. Isolated transaction only.
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

  perform public.service_record_google_play_subscription(
    token_a, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), now() + interval '30 days', true, true,
    order_a, account_hash, profile_hash
  );
  perform public.service_record_google_play_subscription(
    token_b, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), now() + interval '60 days', true, true,
    order_b, account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled
        and e.current_purchase_token_hash = token_b) then
    raise exception 'B was not the current Play token';
  end if;

  -- B is on an early page. A is still marked entitled in its ledger, but
  -- selecting it before the last page would be unsafe.
  perform public.service_record_google_play_void(token_b, order_b, now());
  if exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled) then
    raise exception 'Incomplete scan prematurely restored A';
  end if;

  -- A is refunded on a later page. Completing the scan and replaying the
  -- current B void during activation must leave the org without Play access.
  perform public.service_record_google_play_void(token_a, order_a, now());
  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now() where singleton = true;
  perform public.service_activate_google_play_lifecycle();
  if exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled)
     or exists (select 1 from private.google_play_subscriptions s
       where s.organization_id = test_organization and s.entitled)
     or not exists (select 1 from public.organizations o
       where o.id = test_organization and o.subscription_status = 'past_due') then
    raise exception 'Activation granted a later-page refunded token';
  end if;
end;
$$;

rollback;
