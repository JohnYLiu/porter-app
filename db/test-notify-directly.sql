-- ============================================================================
-- Send a test notification and report everything in one row.
--
-- Paste the whole file. It takes about five seconds — there is a deliberate
-- pause so the background worker has time to actually send.
--
-- Read the single result row left to right:
--
--   logins_today  0  -> nobody has signed in since 3am, so nobody is "on
--                       shift". Sign in on the phone and run this again.
--   targets_510   0  -> nobody matches: no subscription, wrong area label, or
--                       not signed in today. The query under this one says who.
--   status_code 200  -> the function ran. `response` says how many were pushed.
--         sent >= 1  -> the push was ACCEPTED by Apple. If the phone stayed
--                       quiet after that, the problem is on the device: the app
--                       was in the foreground, or notifications are off for it
--                       in iOS Settings.
--        failures[]  -> 401/403 there means the VAPID key in the function does
--                       not match the one the phone subscribed with.
-- ============================================================================

select net.http_post(
  url     := public.notify_url(),
  body    := jsonb_build_object('record', jsonb_build_object(
               'zone', '510', 'car_code', 'TEST', 'origin', '510',
               'destination', 'express')),
  headers := jsonb_build_object(
               'Content-Type',    'application/json',
               'x-notify-secret', (select value from public.app_secrets
                                    where key = 'notify_secret'))
) as queued;

select pg_sleep(9);   -- pg_net's worker is not instant; too short and you
                      -- read the PREVIOUS run's answer and misdiagnose it

select (select count(*) from public.login_attempts
         where succeeded and at >= public.app_day_start())        as logins_today,
       (select count(*) from public.push_targets('510'))          as targets_510,
       (select count(*) from public.push_targets('lower_lot'))    as targets_lower,
       (select count(*) from public.push_subscriptions)           as subscriptions,
       r.status_code,
       left(coalesce(r.content, r.error_msg, '(no body)'), 300)   as response,
       r.created                                                  as response_time,
       now() - r.created                                          as response_age
  from net._http_response r
 order by r.id desc
 limit 1;
