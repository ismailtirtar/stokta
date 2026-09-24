-- The deployed verifier writes ACK_PENDING through the old public RPC
-- before calling Google acknowledge. An incomplete refund scan must reject
-- that write before the external ACK can occur.
begin;

do $$
declare
  purchaser uuid;
  test_organization uuid;
  token_hash text := repeat('9', 64);
  order_hash text := repeat('8', 64);
  account_hash text;
  profile_hash text;
  expiry timestamptz := now() + interval '30 days';
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

  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = null where singleton = true;
  begin
    perform public.service_record_google_play_subscription(
      token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
      'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_PENDING',
      false, now(), expiry, true, true, order_hash, account_hash, profile_hash
    );
    raise exception 'ACK_PENDING passed before the first refund scan';
  exception when sqlstate '55000' then null;
  end;

  update private.google_play_void_scan_state
  set page_token = 'next-page', last_completed_at = now() where singleton = true;
  begin
    perform public.service_record_google_play_subscription(
      token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
      'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_PENDING',
      false, now(), expiry, true, true, order_hash, account_hash, profile_hash
    );
    raise exception 'ACK_PENDING passed an incomplete refund scan';
  exception when sqlstate '55000' then null;
  end;

  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now() - interval '11 minutes'
  where singleton = true;
  begin
    perform public.service_record_google_play_subscription(
      token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
      'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_PENDING',
      false, now(), expiry, true, true, order_hash, account_hash, profile_hash
    );
    raise exception 'ACK_PENDING passed the pre-ACK safety margin';
  exception when sqlstate '55000' then null;
  end;
  if exists (select 1 from private.google_play_subscriptions s
      where s.purchase_token_hash = token_hash) then
    raise exception 'Blocked pre-ACK call wrote a token ledger';
  end if;

  update private.google_play_void_scan_state
  set page_token = null, last_completed_at = now() where singleton = true;
  perform public.service_record_google_play_subscription(
    token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_PENDING',
    false, now(), expiry, true, true, order_hash, account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_subscriptions s
      where s.purchase_token_hash = token_hash
        and s.acknowledgement_state = 'ACKNOWLEDGEMENT_STATE_PENDING'
        and not s.entitled)
     or exists (select 1 from private.google_play_entitlements e
       where e.organization_id = test_organization and e.entitled) then
    raise exception 'Fresh-scan pre-ACK ownership record was not inert';
  end if;

  perform public.service_record_google_play_subscription(
    token_hash, purchaser, test_organization, 'stokdas_pro', 'monthly',
    'SUBSCRIPTION_STATE_ACTIVE', 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    true, now(), expiry, true, true, order_hash, account_hash, profile_hash
  );
  if not exists (select 1 from private.google_play_entitlements e
      where e.organization_id = test_organization and e.entitled
        and e.current_purchase_token_hash = token_hash) then
    raise exception 'Fresh-scan post-ACK grant failed';
  end if;
end;
$$;

rollback;
