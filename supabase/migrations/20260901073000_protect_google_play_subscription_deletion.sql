-- Do not erase the tenant ledger while Google Play can still renew billing.

begin;

set local statement_timeout = '30s';

create or replace function public.service_google_play_subscription_requires_cancellation(
  p_organization_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.google_play_entitlements e
    join private.google_play_subscriptions s
      on s.purchase_token_hash = e.current_purchase_token_hash
      and s.organization_id = e.organization_id
      and s.purchaser_user_id = e.purchaser_user_id
    where e.organization_id = p_organization_id
      and s.auto_renew_enabled is true
      and s.subscription_state not in (
        'SUBSCRIPTION_STATE_EXPIRED',
        'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED'
      )
  );
$$;

revoke all on function public.service_google_play_subscription_requires_cancellation(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.service_google_play_subscription_requires_cancellation(uuid)
  to service_role;

comment on function public.service_google_play_subscription_requires_cancellation(uuid) is
  'Prevents tenant deletion while the authoritative Google Play subscription can still auto-renew. Service role only.';

commit;
