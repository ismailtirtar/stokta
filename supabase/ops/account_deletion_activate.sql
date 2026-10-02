-- Deployment operation, NOT a migration or an instruction to run on live now.
-- Deploy delete-account and its atomic migration first. An operator must create
-- two Vault secrets in the Dashboard without placing either value in source:
-- account_deletion_function_url: this project's HTTPS /functions/v1/delete-account
-- account_deletion_service_role_key: this project's server-only legacy service JWT
-- The function has verify_jwt=true, so a publishable key is not suitable here.
-- Check a service retry with an EMPTY outbox before enabling the schedule.
begin;
create extension if not exists pg_cron;
create extension if not exists pg_net with schema extensions;
do $$
declare
  expected_ref constant text := 'wewqrnpwqvnjusehxxtz';
  endpoint text; service_jwt text; payload text; claims jsonb; job_id bigint;
begin
  if (select count(*) from vault.decrypted_secrets
      where name = 'account_deletion_function_url') <> 1
     or (select count(*) from vault.decrypted_secrets
      where name = 'account_deletion_service_role_key') <> 1 then
    raise exception 'Auth cleanup requires the two unique configured Vault secrets';
  end if;
  select decrypted_secret into endpoint from vault.decrypted_secrets
  where name = 'account_deletion_function_url';
  if endpoint is distinct from 'https://' || expected_ref || '.supabase.co/functions/v1/delete-account' then
    raise exception 'Auth cleanup endpoint must match the authorized project';
  end if;
  select decrypted_secret into service_jwt from vault.decrypted_secrets
  where name = 'account_deletion_service_role_key';
  begin
    payload := translate(split_part(service_jwt, '.', 2), '-_', '+/');
    claims := convert_from(decode(rpad(payload, length(payload) + (4 - length(payload) % 4) % 4, '='), 'base64'), 'UTF8')::jsonb;
  exception when others then
    raise exception 'Auth cleanup requires a valid server-only legacy service JWT';
  end;
  if claims->>'role' is distinct from 'service_role'
     or claims->>'ref' is distinct from expected_ref
     or coalesce(claims->>'exp', '') !~ '^[0-9]{1,12}$' then
    raise exception 'Auth cleanup Vault configuration is invalid';
  end if;
  if (claims->>'exp')::bigint <= extract(epoch from now()) then
    raise exception 'Auth cleanup service JWT is expired';
  end if;
  for job_id in select jobid from cron.job
    where jobname = 'stokdas-account-deletion-auth-cleanup'
  loop perform cron.unschedule(job_id); end loop;
  perform cron.schedule('stokdas-account-deletion-auth-cleanup', '*/5 * * * *', $job$
    select net.http_post(
      url := (select decrypted_secret from vault.decrypted_secrets
              where name = 'account_deletion_function_url'),
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets
                                      where name = 'account_deletion_service_role_key')
      ),
      body := jsonb_build_object('operation', 'retry-auth-cleanup'),
      timeout_milliseconds := 60000
    );
  $job$);
end;
$$;
commit;

-- Monitoring: service_account_deletion_auth_job_health() reports total jobs,
-- failures and oldest age, including jobs delayed by exponential backoff.
-- Inspect cron.job_run_details and net._http_response for transport errors;
-- 503 with pending=true is expected while a batch is queued or Auth is failing.
-- Never publish Vault decrypted_secret values or Authorization headers.
