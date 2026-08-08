-- ============================================================================
-- Call the notify function straight from SQL, bypassing the trigger.
--
-- The trigger catches every error and turns it into a warning, so that a broken
-- notification can never stop a car being requested. Correct behaviour, and
-- exactly why there is nothing to look at right now. This has no handler: if
-- the call cannot be made, the editor shows the actual error.
--
-- Paste the whole thing. The editor shows the LAST result, which is the one
-- that matters.
-- ============================================================================

-- 1. Queue a call, exactly as the trigger would, with a fake 510 request.
select net.http_post(
  url     := public.notify_url(),
  body    := jsonb_build_object('record', jsonb_build_object(
               'zone', '510', 'car_code', 'TEST', 'origin', '510',
               'destination', 'express')),
  headers := jsonb_build_object(
               'Content-Type',    'application/json',
               'x-notify-secret', (select value from public.app_secrets
                                    where key = 'notify_secret'))
) as queued_request_id;

-- 2. Give the background worker a moment to actually send it.
select pg_sleep(4);

-- 3. What came back.
--
--    200          it worked. The body says how many devices were pushed to;
--                 sent: 0 just means nobody matched (wrong area label, or
--                 nobody has signed in today, or nobody has subscribed yet).
--    401 / 403    the secret does not match NOTIFY_SECRET in the function's
--                 settings, or Verify JWT is still ON for notify.
--    404          the function is not deployed under the name "notify".
--    error_msg    the request never left the database.
--    no rows      the worker has not run yet — wait a few seconds and re-run
--                 this last query on its own.
select id,
       status_code,
       left(coalesce(content, error_msg, '(no body)'), 400) as response,
       created
  from net._http_response
 order by id desc
 limit 5;
