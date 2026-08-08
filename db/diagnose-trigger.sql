-- ============================================================================
-- The test script notifies, but issuing a request does not.
--
-- Both end up calling the same function with the same secret, so the
-- difference is the trigger. Its exception handler turns any failure into a
-- warning nobody sees — deliberately, so a broken notification can never stop a
-- car being requested, and unhelpfully right now.
--
-- Paste the whole file. Read the LAST result.
-- ============================================================================

-- 1. Is the trigger there, and is it switched on?
--    tgenabled: O = enabled, D = DISABLED, R/A = replica-only
select tgname,
       tgenabled,
       case tgenabled when 'O' then 'enabled'
                      when 'D' then 'DISABLED — this is the answer'
                      else 'replica/always only' end as state
  from pg_trigger
 where tgrelid = 'public.requests'::regclass
   and not tgisinternal;


-- 2. Run the trigger's body with NO exception handler, so the real error
--    surfaces instead of being turned into a warning.
create or replace function public.debug_notify_now()
returns text
language plpgsql
security definer
set search_path = 'net, extensions'
as $$
declare
  v_secret text;
  v_id     bigint;
begin
  select value into v_secret from public.app_secrets where key = 'notify_secret';
  if v_secret is null then
    return 'no notify_secret in app_secrets';
  end if;

  select http_post(
    url     := public.notify_url(),
    body    := jsonb_build_object('record', jsonb_build_object(
                 'zone', '510', 'car_code', 'TRIGGERTEST',
                 'origin', '510', 'destination', 'express')),
    headers := jsonb_build_object(
                 'Content-Type',    'application/json',
                 'x-notify-secret', v_secret)
  ) into v_id;

  return 'queued ok, pg_net id ' || v_id;
end;
$$;

-- If this ERRORS, the message is why the trigger fails.
-- If it returns "queued ok", the body is fine and the trigger is simply not
-- running — which points at result 1 above.
select public.debug_notify_now() as result;
