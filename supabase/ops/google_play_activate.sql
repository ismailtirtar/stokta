-- Manual second phase, after the complete 29-day void scan is fresh and
-- previous verify-play-subscription requests have drained. This file is
-- intentionally outside migrations: automatic db push must not activate
-- lifecycle handling before the first scan.
select public.service_activate_google_play_lifecycle();
