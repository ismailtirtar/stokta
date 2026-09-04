-- Cover composite Google Play billing foreign keys in their declared order.

begin;

set local statement_timeout = '30s';

create index if not exists google_play_subscriptions_purchaser_organization_idx
  on private.google_play_subscriptions (purchaser_user_id, organization_id);

create index if not exists google_play_entitlements_subscription_owner_idx
  on private.google_play_entitlements (
    current_purchase_token_hash, organization_id, purchaser_user_id
  );

create index if not exists google_play_subscription_events_subscription_owner_idx
  on private.google_play_subscription_events (
    purchase_token_hash, organization_id, purchaser_user_id
  );

commit;
