-- ============================================================================
-- Why didn't a phone buzz?
--
-- Paste this whole file into the Supabase SQL editor. It changes nothing; it
-- only reports. Work down the results — the first "NO" is the answer.
--
-- The chain is:
--   request inserted -> trigger fires -> pg_net queues an HTTP call
--     -> pg_net worker sends it -> notify function receives and pushes
--
-- Nothing in the notify function's logs means the break is BEFORE the function,
-- so that is what most of this checks.
-- ============================================================================

select 'A. trigger exists on requests' as check,
       case when exists (select 1 from pg_trigger
                          where tgname = 'notify_on_request' and not tgisinternal)
            then 'YES' else 'NO — re-run db/schema.sql' end as result

union all
select 'B. pg_net installed, http_post lives in',
       coalesce((select n.nspname
                   from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                  where p.proname = 'http_post' limit 1),
                'NOT FOUND — pg_net is not installed')

union all
select 'C. notify_secret is set',
       coalesce((select 'YES (' || length(value) || ' characters)'
                   from public.app_secrets where key = 'notify_secret'),
                'NO — this alone stops everything, see the insert below')

union all
select 'D. notify function URL',
       coalesce(public.notify_url(), '(missing)')

union all
select 'E. requests inserted in the last hour',
       (select count(*)::text from public.requests
         where created_at > now() - interval '1 hour')

order by 1;


-- ----------------------------------------------------------------------------
-- What pg_net actually sent, and what came back. This is the useful one: if
-- rows appear here, the trigger fired and the problem is at the far end.
--
--   status 401/403  -> the x-notify-secret header does not match NOTIFY_SECRET
--                      in the function's settings, or Verify JWT is still ON
--   status 404      -> the function is not deployed, or the URL is wrong
--   status 200      -> it worked; the body says how many were sent
--   no rows at all  -> the trigger never queued anything; see A and C above
-- ----------------------------------------------------------------------------
select id,
       status_code,
       left(coalesce(content, error_msg, '(no body)'), 300) as response,
       created
  from net._http_response
 order by id desc
 limit 10;


-- ----------------------------------------------------------------------------
-- If C said NO, this is the line to run. Use the SAME string you set as
-- NOTIFY_SECRET in the notify function's settings.
-- ----------------------------------------------------------------------------
-- insert into public.app_secrets (key, value)
-- values ('notify_secret', 'paste-your-secret-here')
-- on conflict (key) do update set value = excluded.value;
