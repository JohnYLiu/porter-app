-- ============================================================================
-- Porter Dispatch — database schema, security rules, and operations
-- ============================================================================
--
-- Run this once, whole, in the Supabase SQL editor. It is idempotent-ish:
-- re-running drops and recreates the functions and policies, but leaves table
-- data alone. Dropping the tables themselves is deliberate manual work.
--
-- Read the file top to bottom. It is ordered:
--   1. Extensions
--   2. Configuration you may want to change
--   3. Tables
--   4. Permission helpers
--   5. Row Level Security policies
--   6. Operations (every write goes through one of these)
--   7. Grants
--
-- THE ONE THING TO UNDERSTAND: the app is a public website carrying a public
-- key. Anyone can send any query they like to this database. The policies in
-- section 5 and the checks in section 6 are the only thing that stops them.
-- Nothing in the user interface is a security control.
-- ============================================================================


-- ============================================================================
-- 1. Extensions
-- ============================================================================

create extension if not exists pgcrypto with schema extensions;


-- ============================================================================
-- 2. Configuration
-- ============================================================================

-- The dealership's local timezone. Used to work out when "today" started, which
-- decides how long a porter may reopen their own completed request.
-- CHANGE THIS if the dealership is not in Pacific time.
create or replace function public.app_timezone()
returns text language sql immutable as $$ select 'America/Los_Angeles' $$;

-- The daily boundary, in local time. Sessions expire here and a porter's
-- self-reopen window closes here. 3 = 3am.
create or replace function public.app_day_boundary_hour()
returns int language sql immutable as $$ select 3 $$;

-- How many digits a login code has. Enforced in set_login_code() below, so this
-- is the only place the length is written down.
--
-- Why 8 and not 6: an attacker is not hunting one person's code, they are
-- hunting any valid one. With ~30 staff, roughly 1 in 33,000 random 6-digit
-- guesses lands on somebody. Even throttled hard, that is about a day of
-- quiet grinding. Eight digits makes it ~1 in 3,300,000 — months instead.
-- The cost is two extra taps on a number pad, once a day.
--
-- Raising this later is one line here, but it also means asking every member of
-- staff to memorise a new code. Cheap now, expensive after the pilot.
create or replace function public.app_code_length()
returns int language sql immutable as $$ select 8 $$;

-- The most recent 3am, as an absolute time. Everything "today" happened after
-- this instant.
create or replace function public.app_day_start()
returns timestamptz
language sql stable
set search_path = ''
as $$
  select case
           when now() at time zone public.app_timezone() >= boundary then boundary
           else boundary - interval '1 day'
         end at time zone public.app_timezone()
  from (
    select date_trunc('day', now() at time zone public.app_timezone())
             + make_interval(hours => public.app_day_boundary_hour()) as boundary
  ) t;
$$;


-- ============================================================================
-- 3. Tables
-- ============================================================================

-- ---------------------------------------------------------------------------
-- users — one row per person, mirroring an auth.users row of the same id.
--
-- Deliberately contains NO secrets, so every logged-in user can read the whole
-- table. They need to: the queue shows "claimed by Marcus T.", and the history
-- filters by porter and by cashier. Login codes live in a separate table that
-- nobody can read at all.
-- ---------------------------------------------------------------------------
create table if not exists public.users (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text        not null check (length(trim(name)) between 1 and 60),

  -- The checkboxes on the admin screen. is_manager implies all of the others;
  -- see the permission helpers in section 4, which are the single source of
  -- truth for that rule. Do not re-derive it anywhere else.
  can_issue        boolean not null default false,

  -- LABELS, NOT PERMISSIONS. These say where somebody normally works, and are
  -- shown under their name — "510 Porter", "Lower Lot Porter". They grant
  -- nothing: anyone signed in can claim and deliver a car in either area,
  -- including a cashier, because whoever is nearest should take it.
  --
  -- Kept as two flags rather than one field so a person who covers both is
  -- simply someone with both ticked. See app_can_claim_zone() in section 4,
  -- which is where the restriction would go back if it is ever wanted.
  can_claim_510    boolean not null default false,
  can_claim_lower  boolean not null default false,

  is_manager       boolean not null default false,

  -- What this person wants to be told about. Chosen by them in Settings, not
  -- by an admin: the area flags above say where somebody normally works, which
  -- is a reasonable starting guess and a bad permanent answer. A porter who
  -- covers the lower lot on Fridays should be able to say so himself.
  notify_510       boolean not null default false,
  notify_lower     boolean not null default false,
  notify_delivered boolean not null default false,

  -- How much of the talk about cars this person wants to hear.
  --   none  say nothing
  --   mine  only cars they asked for or are driving
  --   all   every car
  -- A three-way rather than a checkbox because "all" is genuinely useful to a
  -- manager and genuinely unbearable to everyone else.
  notify_messages  text not null default 'none'
                   check (notify_messages in ('none', 'mine', 'all')),

  -- Advisors only, and about THEIR cars — the ones whose key tag starts with
  -- their character — regardless of who raised the request. An advisor is
  -- answering for those cars to the customer, so "did it arrive" and "what is
  -- being said about it" are their questions even when the request is somebody
  -- else's. Harmless on an account with no advisor attached: nothing will ever
  -- match.
  notify_advisor_delivered boolean not null default false,
  notify_advisor_messages  boolean not null default false,

  -- Admin is John, and is not one of the checkboxes. Adding and editing users
  -- is admin-only; managers cannot promote themselves.
  is_admin    boolean     not null default false,

  -- Staff are deactivated, never deleted, so their name survives on the
  -- requests they issued or delivered months ago.
  active      boolean     not null default true,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- user_codes — the hashed 6-digit login codes. Split out from users precisely
-- so that users can be world-readable while this table is readable by nobody.
--
-- RLS is enabled below with ZERO policies, which means every request through
-- the public key returns nothing, forever. Only the login function reaches it.
--
-- Codes are hashed, so a forgotten code is reset, never recovered. Not even
-- John can look one up.
-- ---------------------------------------------------------------------------
create table if not exists public.user_codes (
  user_id    uuid primary key references public.users(id) on delete cascade,
  code_hash  text        not null,
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- service_advisors — a managed list, not app users. They never log in.
-- ---------------------------------------------------------------------------
create table if not exists public.service_advisors (
  id         uuid primary key default gen_random_uuid(),
  name       text        not null check (length(trim(name)) between 1 and 60),

  -- The first character of a key tag. This is what identifies the advisor —
  -- cashiers never pick one from a list, it is read off the tag they are
  -- already holding. One character, unique among active advisors.
  key_char   text        check (key_char is null or key_char ~ '^[0-9A-Z]$'),
  -- Hex colour, e.g. '#c2410c'. Always displayed alongside the advisor's name,
  -- never as the only signal — roughly 1 in 12 men cannot reliably tell some
  -- of these apart.
  color      text        not null check (color ~ '^#[0-9a-fA-F]{6}$'),
  active     boolean     not null default true,
  sort_order int         not null default 0,
  created_at timestamptz not null default now(),

  -- The advisor's own login, if they have one.
  --
  -- A link rather than a merge. requests.advisor_id points at THIS table and
  -- has to keep pointing at the same row for the whole life of the record —
  -- who the car belonged to is history, and it must not change because
  -- somebody's account did. Meanwhile the key character and the palette colour
  -- are properties of the tag, not of a person who can sign in. So the two stay
  -- separate tables with one pointer between them.
  --
  -- Nullable: an advisor is a name on a key tag first, and may never need to
  -- sign in at all. Unique, so two advisors cannot share one account.
  user_id    uuid        references public.users(id) on delete set null
);

-- ---------------------------------------------------------------------------
-- requests — the queue itself.
--
-- Status only moves through the operations in section 6. There is no policy
-- allowing a direct insert, update, or delete on this table by anyone, so the
-- transition rules cannot be bypassed by hand-writing a query.
-- ---------------------------------------------------------------------------
create table if not exists public.requests (
  id           uuid primary key default gen_random_uuid(),

  -- The car code. Letters, digits, or both; stored uppercase so that history
  -- filters and duplicate-spotting are not defeated by capitalisation.
  car_code     text        not null check (length(trim(car_code)) between 1 and 20),

  -- Where the car is now and where it is going. Any of the five locations can
  -- be either, including the same one for both — a car can be moved within a
  -- location, and refusing that would just make cashiers lie to the form.
  origin       text        not null check (origin      in ('510','525','express','drive','wash','lower_lot')),
  destination  text        not null check (destination in ('510','525','express','drive','wash','lower_lot')),

  -- A stop at the wash on the way. Deliberately separate from destination:
  -- "drive → wash" and "drive → wash → express" are different journeys, and
  -- only the second one has somewhere to be afterwards.
  via_wash     boolean     not null default false,

  -- Derived from the first character of the key tag when the request is
  -- created, never chosen. Nullable, because a towed-in car and a tag with no
  -- advisor assigned genuinely have none.
  --
  -- Stored rather than looked up live, so history is a record of who it WAS.
  -- Reassigning a key character later must not silently rewrite last month's
  -- requests.
  advisor_id   uuid        references public.service_advisors(id),
  note         text        check (note is null or length(note) <= 500),

  status       text        not null default 'unclaimed'
                           check (status in ('unclaimed', 'claimed', 'complete', 'cancelled')),

  issued_by    uuid        not null references public.users(id),
  created_at   timestamptz not null default now(),

  claimed_by   uuid        references public.users(id),
  claimed_at   timestamptz,
  completed_at timestamptz,
  cancelled_by uuid        references public.users(id),
  cancelled_at timestamptz,

  -- Which kind of porter this belongs to. Computed by the database, never sent
  -- by the app: it is a business rule, and a rule the client can supply is a
  -- rule the client can get wrong. Stored, so the queue can index it.
  --
  -- The rule: if EITHER end of the journey is 510 or 525, it is a 510 job.
  -- Otherwise it is lower lot. A wash stop does not change this — the wash is a
  -- waypoint, not an endpoint.
  --
  -- WORTH READING TWICE: 'lower_lot' is both a LOCATION and an AREA, and they
  -- are not the same thing. A car going 510 → Lower Lot is a 510 job, because
  -- one end is 510 — it is handled by a 510 porter even though it is headed for
  -- the lower lot. Only journeys that touch neither 510 nor 525 belong to the
  -- lower lot porters.
  zone text generated always as (
    case when origin      in ('510','525')
           or destination in ('510','525') then '510'
         else 'lower_lot' end
  ) stored,

  -- What the key tag says about who owns the car, independent of whether an
  -- advisor was matched. Lets the app tell "towed in" apart from "no advisor
  -- assigned" apart from "first character matches nobody we know" — three
  -- different things that would otherwise all look like a null advisor.
  --
  -- Length is checked FIRST: a three-character tag has no advisor even if it
  -- happens to begin with T.
  --
  -- No upper() here: car_code is uppercased on the way in by create_request and
  -- edit_request, which are the only paths that write it.
  tag_type text generated always as (
    -- A three-character tag is a tow-in. Those tags are printed as a bare
    -- number and never carry an advisor character, so there is nothing to
    -- derive from them — but they are not UNKNOWN either, which is what they
    -- used to read as. Shorter than three is still nothing: one or two
    -- characters is a mistyped tag, not a kind of job.
    case when length(trim(car_code)) = 3    then 'tow_in'
         when length(trim(car_code)) < 3    then 'none'
         when left(trim(car_code), 1) = 'T' then 'tow_in'
         else                                    'advisor' end
  ) stored,

  -- Guard rails so a bug cannot leave a row in a nonsensical shape.
  constraint claimed_has_claimer
    check (status <> 'claimed' or (claimed_by is not null and claimed_at is not null)),
  constraint complete_has_completion
    check (status <> 'complete' or (claimed_by is not null and completed_at is not null)),
  constraint cancelled_has_cancellation
    check (status <> 'cancelled' or cancelled_at is not null)
);

-- The unclaimed queue, oldest first — the single hottest query in the app.
create index if not exists requests_unclaimed_idx
  on public.requests (created_at)
  where status = 'unclaimed';

create index if not exists requests_status_idx    on public.requests (status);
create index if not exists requests_claimed_by_idx on public.requests (claimed_by);
create index if not exists requests_created_at_idx on public.requests (created_at desc);

-- ---------------------------------------------------------------------------
-- request_events — an append-only log of everything that happened to a request.
--
-- This is what makes a reopen honest. Marking a request complete a second time
-- does not erase the first completion; both are here. Without this, the
-- "how long do requests actually take" number silently rewrites itself every
-- time somebody fixes a mis-tap.
-- ---------------------------------------------------------------------------
create table if not exists public.request_events (
  id         bigint generated always as identity primary key,
  request_id uuid        not null references public.requests(id) on delete cascade,
  event      text        not null check (event in
               ('issued', 'edited', 'claimed', 'unclaimed',
                'completed', 'reopened', 'cancelled')),
  actor_id   uuid        references public.users(id),
  at         timestamptz not null default now(),
  detail     jsonb
);


-- Talk about one car.
--
-- Separate from request_events on purpose. Events are what the SYSTEM records
-- and nobody writes by hand; this is what PEOPLE say, and the two have
-- different lifetimes, different audiences and different trust. Mixing them
-- would mean a free-text field on the audit trail.
--
-- No edit and no delete. A dispatch log that can be quietly rewritten after the
-- fact is worth less than one that cannot, and "I said that, sorry" is a
-- cheaper fix than an argument about what a message used to say.
create table if not exists public.request_messages (
  id         bigint generated always as identity primary key,
  request_id uuid        not null references public.requests(id) on delete cascade,
  author_id  uuid        not null references public.users(id),
  body       text        not null check (length(trim(body)) between 1 and 1000),
  created_at timestamptz not null default now()
);

-- Every read is "the messages on this car, newest first".
create index if not exists request_messages_request_idx
  on public.request_messages (request_id, created_at desc);

-- And the app's own load is "everything said recently", across all cars.
create index if not exists request_messages_recent_idx
  on public.request_messages (created_at desc);

create index if not exists request_events_request_idx on public.request_events (request_id, at);

-- ---------------------------------------------------------------------------
-- login_attempts — every login try, successful or not, for the lockout counter.
--
-- Never stores the submitted code, only a fingerprint of it, so that this table
-- leaking would not hand anyone a working credential.
--
-- RLS enabled with zero policies: the login function is the only thing that
-- reads or writes it.
-- ---------------------------------------------------------------------------
create table if not exists public.login_attempts (
  id               bigint generated always as identity primary key,
  at               timestamptz not null default now(),
  ip               text,
  code_fingerprint text,
  succeeded        boolean     not null,
  -- SET NULL, so a login record never prevents an account from being removed.
  -- What matters here is the rate-limit history, not whose it was; a mistyped
  -- account that has only ever logged in should still be deletable.
  user_id          uuid        references public.users(id) on delete set null
);

create index if not exists login_attempts_recent_idx on public.login_attempts (at desc);
create index if not exists login_attempts_fingerprint_idx
  on public.login_attempts (code_fingerprint, at desc) where not succeeded;


-- ---------------------------------------------------------------------------
-- push_subscriptions — one row per device that has agreed to be notified.
--
-- Only the endpoint is stored. Push messages are sent with NO BODY: a body must
-- be encrypted with the subscriber's own keys, and since routing already decides
-- who hears about a car, the message itself has nothing to say beyond "there is
-- one". Nothing sensitive travels, and nothing appears on a lock screen.
--
-- Endpoint is unique: subscribing twice on the same phone must not double the
-- buzzes.
-- ---------------------------------------------------------------------------
create table if not exists public.push_subscriptions (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid        not null references public.users(id) on delete cascade,
  endpoint   text        not null unique,

  -- The device's own public key and auth secret. A push carrying a body must be
  -- encrypted with these — the spec forbids sending one in the clear, even over
  -- HTTPS. Nullable, because subscriptions made before this existed have none:
  -- those still get a push, just without the car on it. The app fills them in
  -- on the next sign-in rather than making everyone re-enable notifications.
  p256dh     text,
  auth       text,

  created_at timestamptz not null default now(),

  -- When a signed-in app on THIS device last confirmed it owns this
  -- subscription. It is what decides whether the device gets notified — see
  -- push_targets(). Not created_at: a device subscribes once and then goes on
  -- being a device for months.
  claimed_at timestamptz not null default now()
);

create index if not exists push_subscriptions_user_idx
  on public.push_subscriptions (user_id);


-- ---------------------------------------------------------------------------
-- app_secrets — values that must reach the database but not the repository.
--
-- Currently just the shared secret the notify trigger sends to the Edge
-- Function. RLS on, zero policies, and revoked from authenticated below: same
-- treatment as user_codes, for the same reason.
--
-- Set it once, from the SQL editor, with the value never entering git:
--   insert into public.app_secrets (key, value) values ('notify_secret', '…')
--   on conflict (key) do update set value = excluded.value;
-- ---------------------------------------------------------------------------
create table if not exists public.app_secrets (
  key        text primary key,
  value      text        not null,
  updated_at timestamptz not null default now()
);


-- ---------------------------------------------------------------------------
-- 3b. Migrations for databases created before the two porter areas existed.
--
-- `create table if not exists` above defines the shape for a fresh install and
-- does nothing at all to a table that already exists, so these bring an
-- existing database up to that same shape. Every step is idempotent — re-running
-- the whole file finds nothing left to do.
-- ---------------------------------------------------------------------------

-- --- requests: origin, wash stop, and the derived zone ---------------------
alter table public.requests add column if not exists origin   text;
alter table public.requests add column if not exists via_wash boolean not null default false;

-- Rows that predate origins. 'drive' is arbitrary — every one of these is test
-- data from before the field existed, and there is no real answer to recover.
update public.requests set origin = 'drive' where origin is null;

alter table public.requests alter column origin set not null;

alter table public.requests drop constraint if exists requests_origin_check;
alter table public.requests add  constraint requests_origin_check
  check (origin in ('510','525','express','drive','wash','lower_lot'));

-- Destination used to allow only drive and express.
alter table public.requests drop constraint if exists requests_destination_check;
alter table public.requests add  constraint requests_destination_check
  check (destination in ('510','525','express','drive','wash','lower_lot'));

alter table public.requests add column if not exists zone text
  generated always as (
    case when origin      in ('510','525')
           or destination in ('510','525') then '510'
         else 'lower_lot' end
  ) stored;

-- --- users: one claim flag becomes two ------------------------------------
alter table public.users add column if not exists can_claim_510   boolean not null default false;
alter table public.users add column if not exists can_claim_lower boolean not null default false;

do $$
begin
  if exists (select 1 from information_schema.columns
              where table_schema = 'public' and table_name = 'users'
                and column_name = 'can_claim') then
    -- Anyone who could claim before can claim in both areas until John narrows
    -- them down. Widening and then restricting is recoverable; guessing an area
    -- wrong silently hides work from a porter, which is not.
    execute 'update public.users set can_claim_510 = true, can_claim_lower = true
              where can_claim and not can_claim_510 and not can_claim_lower';
    execute 'alter table public.users drop column can_claim';
  end if;
end $$;

-- The queue is always filtered to one area, so it is the zone that wants the
-- index, not the status alone.
create index if not exists requests_zone_open_idx
  on public.requests (zone, created_at) where status = 'unclaimed';
create index if not exists requests_zone_active_idx
  on public.requests (zone, claimed_at) where status = 'claimed';

-- --- login records must not pin an account in place ------------------------
-- Originally a plain reference, which blocked deleting anyone who had ever
-- logged in — including a test account created by mistake.
alter table public.login_attempts drop constraint if exists login_attempts_user_id_fkey;
alter table public.login_attempts add  constraint login_attempts_user_id_fkey
  foreign key (user_id) references public.users(id) on delete set null;

-- --- advisors are identified by key character, not chosen from a list -------
alter table public.service_advisors add column if not exists key_char text;

alter table public.service_advisors drop constraint if exists service_advisors_key_char_check;
alter table public.service_advisors add  constraint service_advisors_key_char_check
  check (key_char is null or key_char ~ '^[0-9A-Z]$');

-- Unique among ACTIVE advisors only, so retiring someone frees their character
-- for a successor without having to edit the old row.
create unique index if not exists service_advisors_key_char_idx
  on public.service_advisors (key_char) where active and key_char is not null;

-- A towed-in car and a tag with no advisor both genuinely have none.
alter table public.requests alter column advisor_id drop not null;

alter table public.users add column if not exists notify_510       boolean not null default false;
alter table public.users add column if not exists notify_lower     boolean not null default false;
alter table public.users add column if not exists notify_delivered boolean not null default false;
alter table public.users add column if not exists notify_messages  text not null default 'none';
alter table public.users drop constraint if exists users_notify_messages_check;
alter table public.users add  constraint users_notify_messages_check
  check (notify_messages in ('none', 'mine', 'all'));
alter table public.users add column if not exists notify_advisor_delivered boolean not null default false;
alter table public.users add column if not exists notify_advisor_messages  boolean not null default false;

-- Seed each person's preferences from what they were already getting, once.
-- Guarded on "nobody has any set yet" so it cannot overwrite a real choice on a
-- later run — a porter who deliberately turns everything off must stay off.
do $$
begin
  if not exists (select 1 from public.users
                  where notify_510 or notify_lower or notify_delivered) then
    update public.users
       set notify_510       = can_claim_510,
           notify_lower     = can_claim_lower,
           notify_delivered = can_issue;
  end if;
end $$;

alter table public.push_subscriptions add column if not exists p256dh text;
alter table public.push_subscriptions add column if not exists auth   text;

-- Replaced rather than added, because the rule changed and a generated column
-- cannot be altered in place. Dropping one loses nothing: every value in it is
-- derived from car_code and is recomputed for every row on the way back in.
alter table public.requests drop column if exists tag_type;
alter table public.requests add  column tag_type text
  generated always as (
    -- A three-character tag is a tow-in. Those tags are printed as a bare
    -- number and never carry an advisor character, so there is nothing to
    -- derive from them — but they are not UNKNOWN either, which is what they
    -- used to read as. Shorter than three is still nothing: one or two
    -- characters is a mistyped tag, not a kind of job.
    case when length(trim(car_code)) = 3    then 'tow_in'
         when length(trim(car_code)) < 3    then 'none'
         when left(trim(car_code), 1) = 'T' then 'tow_in'
         else                                    'advisor' end
  ) stored;


alter table public.push_subscriptions
  add column if not exists claimed_at timestamptz not null default now();

alter table public.service_advisors
  add column if not exists user_id uuid references public.users(id) on delete set null;

create unique index if not exists service_advisors_user_idx
  on public.service_advisors (user_id) where user_id is not null;


-- ============================================================================
-- 4. Permission helpers
--
-- Every one is SECURITY DEFINER, which means it runs with the privileges of the
-- owner and so is not itself subject to RLS. That is required, not incidental:
-- a policy on `users` that queried `users` normally would recurse forever.
--
-- `set search_path = ''` and fully-qualified names throughout. Without it, a
-- caller can point `search_path` at a schema of their own and substitute their
-- own `users` table — a real and well-documented privilege escalation.
-- ============================================================================

create or replace function public.app_is_active()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.users where id = auth.uid() and active);
$$;

-- Manager implies both capabilities regardless of the other two checkboxes.
create or replace function public.app_can_issue()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select (can_issue or is_manager)
                   from public.users where id = auth.uid() and active), false);
$$;

-- Claiming is open to everyone signed in, in either area.
--
-- can_claim_510 and can_claim_lower NO LONGER GRANT ANYTHING. They survive as
-- a label — "510 Porter", "Lower Lot Porter" — shown under someone's name so it
-- is clear where they normally work. Whoever is nearest the car takes it,
-- including a cashier.
--
-- Kept as functions rather than deleted, and app_can_claim_zone keeps its now
-- unused argument, so restoring the restriction is a change to these two bodies
-- and nothing else. Issuing is still a real permission; see app_can_issue().
create or replace function public.app_can_claim()
returns boolean language sql stable security definer set search_path = '' as $$
  select public.app_is_active();
$$;

create or replace function public.app_can_claim_zone(p_zone text)
returns boolean language sql stable security definer set search_path = '' as $$
  select public.app_is_active();
$$;

create or replace function public.app_is_manager()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select is_manager from public.users where id = auth.uid() and active), false);
$$;

create or replace function public.app_is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce((select is_admin from public.users where id = auth.uid() and active), false);
$$;


-- ============================================================================
-- 5. Row Level Security
--
-- Enabled on every table without exception. A single table missed here is
-- readable in full by anyone on the internet holding the publishable key, with
-- no login and no trace.
-- ============================================================================

alter table public.users            enable row level security;
alter table public.user_codes       enable row level security;
alter table public.service_advisors enable row level security;
alter table public.requests         enable row level security;
alter table public.request_events   enable row level security;
alter table public.request_messages enable row level security;
alter table public.login_attempts   enable row level security;
alter table public.push_subscriptions enable row level security;
alter table public.app_secrets        enable row level security;

-- Note on FORCE ROW LEVEL SECURITY: deliberately NOT used on user_codes or
-- login_attempts. FORCE applies policies to the table owner as well, and the
-- login functions below are SECURITY DEFINER — they run as the owner. Since
-- those two tables have zero policies on purpose, forcing RLS would make the
-- login path read nothing and every login would fail. Ordinary callers are not
-- the owner, so they still get nothing, which is the point.

drop policy if exists users_select        on public.users;
drop policy if exists users_admin_update  on public.users;
drop policy if exists advisors_select     on public.service_advisors;
drop policy if exists advisors_admin_all  on public.service_advisors;
drop policy if exists requests_select     on public.requests;
drop policy if exists events_select       on public.request_events;
drop policy if exists messages_select     on public.request_messages;
drop policy if exists push_own             on public.push_subscriptions;

-- --- users -----------------------------------------------------------------
-- Any active, logged-in user reads the whole table: names are needed all over
-- the app. This is safe only because the codes live elsewhere.
create policy users_select on public.users
  for select to authenticated
  using (public.app_is_active());

-- Only John changes checkboxes or deactivates people. Note there is no INSERT
-- policy: creating a user also requires creating an auth.users row, so it goes
-- through the admin function in the Edge Function, never straight from a phone.
create policy users_admin_update on public.users
  for update to authenticated
  using (public.app_is_admin())
  with check (public.app_is_admin());

-- --- user_codes ------------------------------------------------------------
-- No policies, on purpose. Every read from a phone returns zero rows.

-- --- service_advisors ------------------------------------------------------
create policy advisors_select on public.service_advisors
  for select to authenticated
  using (public.app_is_active());

create policy advisors_admin_all on public.service_advisors
  for all to authenticated
  using (public.app_is_admin())
  with check (public.app_is_admin());

-- --- requests --------------------------------------------------------------
-- Everyone who is logged in sees every request. That is the design: the queue
-- is shared, and the In Progress tab is visible to all.
create policy requests_select on public.requests
  for select to authenticated
  using (public.app_is_active());

-- No insert, update, or delete policy exists. All writes go through section 6.

-- --- request_events --------------------------------------------------------
create policy events_select on public.request_events
  for select to authenticated
  using (public.app_is_active());

-- No write policy. Only the operations in section 6 append here.

-- --- request_messages ------------------------------------------------------
-- Same reasoning as requests: the queue is shared, so the conversation about a
-- car is shared. A porter needs to read what the cashier said about a car he is
-- about to take, and he is not the person the cashier was replying to.
create policy messages_select on public.request_messages
  for select to authenticated
  using (public.app_is_active());

-- No insert policy. Posting goes through post_message() so that authorship is
-- taken from the session rather than accepted from the client — otherwise
-- anyone could sign a message with somebody else's name.

-- --- login_attempts --------------------------------------------------------
-- No policies, on purpose.

-- --- push_subscriptions ----------------------------------------------------
-- A device may register and remove ITSELF, and see whether it is registered.
-- Nobody can read anybody else's: the list of endpoints is what a sender would
-- need, and it belongs only to the notify function.
create policy push_own on public.push_subscriptions
  for all to authenticated
  using (user_id = auth.uid() and public.app_is_active())
  with check (user_id = auth.uid() and public.app_is_active());


-- ============================================================================
-- 6. Operations
--
-- Every state change lives here, as a SECURITY DEFINER function that checks
-- permissions itself and writes the event log. Concentrating writes in one
-- place is what makes the rules testable: there is no second path to audit.
--
-- Each raises an exception on refusal rather than returning quietly, so a
-- rejected action can never be mistaken by the app for a successful one.
-- ============================================================================

-- Resolve the caller once, refusing deactivated and logged-out callers.
create or replace function public.app_require_user()
returns uuid language plpgsql stable security definer set search_path = '' as $$
declare v_id uuid;
begin
  select id into v_id from public.users where id = auth.uid() and active;
  if v_id is null then
    raise exception 'Not signed in' using errcode = '42501';
  end if;
  return v_id;
end;
$$;


-- --- issue -----------------------------------------------------------------
-- The old two-location signature is dropped rather than left alongside: an
-- overload that quietly ignores the origin would be a trap.
drop function if exists public.create_request(text, text, uuid, text);
drop function if exists public.create_request(text, text, text, text, boolean);

create or replace function public.create_request(
  p_car_code    text,
  p_origin      text,
  p_destination text,
  p_note        text default null,
  p_via_wash    boolean default false
)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := public.app_require_user();
  v_row public.requests;
begin
  if not public.app_can_issue() then
    raise exception 'You do not have permission to issue requests' using errcode = '42501';
  end if;

  -- A wash stop is meaningless when the wash is already an endpoint, and
  -- storing it would render as "wash → wash". Drop it rather than refuse the
  -- request: the cashier's intent is clear and unambiguous either way.
  if p_origin = 'wash' or p_destination = 'wash' then
    p_via_wash := false;
  end if;

  insert into public.requests
    (car_code, origin, destination, via_wash, advisor_id, note, issued_by)
  values (upper(trim(p_car_code)), p_origin, p_destination, coalesce(p_via_wash, false),
          public.advisor_for_code(p_car_code),
          nullif(trim(coalesce(p_note, '')), ''), v_uid)
  returning * into v_row;

  insert into public.request_events (request_id, event, actor_id)
  values (v_row.id, 'issued', v_uid);

  return v_row;
end;
$$;


-- --- edit (issuing cashier, while still unclaimed; or any manager) ----------
drop function if exists public.edit_request(uuid, text, text, uuid, text);
drop function if exists public.edit_request(uuid, text, text, text, text, boolean);

create or replace function public.edit_request(
  p_id          uuid,
  p_car_code    text,
  p_origin      text,
  p_destination text,
  p_note        text default null,
  p_via_wash    boolean default false
)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := public.app_require_user();
  v_row public.requests;
begin
  select * into v_row from public.requests where id = p_id for update;
  if not found then
    raise exception 'No such request' using errcode = '22023';
  end if;

  -- The cashier who issued it may fix it right up until a porter claims it.
  -- After that only a manager can, because a porter may already be walking to
  -- the wrong car.
  if not (public.app_is_manager()
          or (v_row.issued_by = v_uid and v_row.status = 'unclaimed')) then
    raise exception 'This request can no longer be edited by you' using errcode = '42501';
  end if;

  if v_row.status in ('complete', 'cancelled') then
    raise exception 'A finished request cannot be edited' using errcode = '42501';
  end if;

  if p_origin = 'wash' or p_destination = 'wash' then
    p_via_wash := false;
  end if;

  -- Note that editing the locations can move a request between areas, because
  -- `zone` is generated from them. That is correct: if a cashier corrects the
  -- destination to 525, it genuinely became a 510 job and should appear in that
  -- queue. It is only editable while unclaimed, so nobody has it in hand.
  update public.requests
     set car_code    = upper(trim(p_car_code)),
         origin      = p_origin,
         destination = p_destination,
         via_wash    = coalesce(p_via_wash, false),
         -- Re-derived: correcting the tag can change whose car it is.
         advisor_id  = public.advisor_for_code(p_car_code),
         note        = nullif(trim(coalesce(p_note, '')), '')
   where id = p_id
  returning * into v_row;

  insert into public.request_events (request_id, event, actor_id, detail)
  values (p_id, 'edited', v_uid,
          jsonb_build_object('car_code', v_row.car_code,
                             'origin', v_row.origin,
                             'destination', v_row.destination,
                             'via_wash', v_row.via_wash,
                             'zone', v_row.zone,
                             'advisor_id', v_row.advisor_id));

  return v_row;
end;
$$;


-- --- claim -----------------------------------------------------------------
-- THE critical operation. Two porters tapping Claim in the same second is not
-- an edge case; it is the exact failure the group chat has today.
--
-- The whole guarantee is `and status = 'unclaimed'` in the UPDATE. Postgres
-- serialises the two writes, and only one can find a matching row. The loser
-- gets zero rows back and is told who won.
--
-- Reading the row and then writing it back would compile, pass a casual test,
-- and be broken under exactly the conditions that matter.
create or replace function public.claim_request(p_id uuid)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid    uuid := public.app_require_user();
  v_row    public.requests;
  v_winner text;
  v_zone   text;
begin
  -- Both of these are permissive now: claiming is open to anyone signed in, in
  -- either area. The calls stay so that narrowing it again is a change to the
  -- two function bodies in section 4 and nothing here.
  if not public.app_can_claim() then
    raise exception 'You do not have permission to claim cars' using errcode = '42501';
  end if;

  select zone into v_zone from public.requests where id = p_id;
  if v_zone is null then
    raise exception 'No such request' using errcode = '22023';
  end if;
  if not public.app_can_claim_zone(v_zone) then
    raise exception 'That car is not in your area' using errcode = '42501';
  end if;

  update public.requests
     set status = 'claimed', claimed_by = v_uid, claimed_at = now()
   where id = p_id
     and status = 'unclaimed'
  returning * into v_row;

  if not found then
    -- Either somebody beat us to it, or it is not claimable at all. Say which.
    select u.name into v_winner
      from public.requests r left join public.users u on u.id = r.claimed_by
     where r.id = p_id;

    if v_winner is not null then
      raise exception 'Already claimed by %', v_winner using errcode = 'PT409';
    end if;
    raise exception 'That request is no longer available' using errcode = 'PT409';
  end if;

  insert into public.request_events (request_id, event, actor_id)
  values (p_id, 'claimed', v_uid);

  return v_row;
end;
$$;


-- --- unclaim (own claim; or any manager, for the porter whose phone died) ---
create or replace function public.unclaim_request(p_id uuid)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := public.app_require_user();
  v_row public.requests;
begin
  select * into v_row from public.requests where id = p_id for update;
  if not found then
    raise exception 'No such request' using errcode = '22023';
  end if;
  if v_row.status <> 'claimed' then
    raise exception 'That request is not currently claimed' using errcode = 'PT409';
  end if;
  if not (v_row.claimed_by = v_uid or public.app_is_manager()) then
    raise exception 'Only the porter who claimed this, or a manager, can release it'
      using errcode = '42501';
  end if;

  -- created_at is untouched, so the request returns to its rightful place near
  -- the top of the queue instead of going to the back of the line.
  update public.requests
     set status = 'unclaimed', claimed_by = null, claimed_at = null
   where id = p_id
  returning * into v_row;

  insert into public.request_events (request_id, event, actor_id, detail)
  values (p_id, 'unclaimed', v_uid,
          jsonb_build_object('by_manager', v_uid <> coalesce(v_row.claimed_by, v_uid)));

  return v_row;
end;
$$;


-- --- complete --------------------------------------------------------------
create or replace function public.complete_request(p_id uuid)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := public.app_require_user();
  v_row public.requests;
begin
  select * into v_row from public.requests where id = p_id for update;
  if not found then
    raise exception 'No such request' using errcode = '22023';
  end if;
  if v_row.status <> 'claimed' then
    raise exception 'Only a claimed car can be marked delivered' using errcode = 'PT409';
  end if;
  if not (v_row.claimed_by = v_uid or public.app_is_manager()) then
    raise exception 'Only the porter holding this car, or a manager, can complete it'
      using errcode = '42501';
  end if;

  update public.requests
     set status = 'complete', completed_at = now()
   where id = p_id
  returning * into v_row;

  insert into public.request_events (request_id, event, actor_id)
  values (p_id, 'completed', v_uid);

  return v_row;
end;
$$;


-- --- reopen ----------------------------------------------------------------
-- A porter may undo their own mis-tap, but only for something they completed
-- since the last 3am. A porter reopening last Tuesday's request is far more
-- likely to be a mistake than a fix. Managers have no time limit.
--
-- The original completion stays in request_events. Nothing is erased.
create or replace function public.reopen_request(p_id uuid)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := public.app_require_user();
  v_row public.requests;
begin
  select * into v_row from public.requests where id = p_id for update;
  if not found then
    raise exception 'No such request' using errcode = '22023';
  end if;
  if v_row.status <> 'complete' then
    raise exception 'Only a completed request can be reopened' using errcode = 'PT409';
  end if;

  if not public.app_is_manager() then
    if v_row.claimed_by <> v_uid then
      raise exception 'You can only reopen a car you delivered yourself'
        using errcode = '42501';
    end if;
    if v_row.completed_at < public.app_day_start() then
      raise exception 'That was completed on an earlier day. Ask a manager to reopen it'
        using errcode = '42501';
    end if;
  end if;

  -- Back to In Progress under the porter who had it: the common case is a
  -- mis-tap while the car is still in hand.
  update public.requests
     set status = 'claimed', completed_at = null
   where id = p_id
  returning * into v_row;

  insert into public.request_events (request_id, event, actor_id, detail)
  values (p_id, 'reopened', v_uid, jsonb_build_object('by_manager', public.app_is_manager()));

  return v_row;
end;
$$;


-- --- cancel (issuing cashier while unclaimed; or any manager, any time) -----
create or replace function public.cancel_request(p_id uuid)
returns public.requests
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := public.app_require_user();
  v_row public.requests;
begin
  select * into v_row from public.requests where id = p_id for update;
  if not found then
    raise exception 'No such request' using errcode = '22023';
  end if;
  if v_row.status in ('complete', 'cancelled') then
    raise exception 'That request is already finished' using errcode = 'PT409';
  end if;
  -- Any cashier, not only the one who raised it. Cashiers cover for each other
  -- at the desk, and the person who spots that a car is no longer needed is
  -- routinely not the person who asked for it — requiring the original issuer
  -- meant the request sat in the queue until they came back.
  --
  -- Still only while it is UNCLAIMED. Once a porter has taken it they are
  -- walking to the car, and pulling the job out from under them is a manager's
  -- call, not any cashier's.
  if not (public.app_is_manager()
          or (public.app_can_issue() and v_row.status = 'unclaimed')) then
    raise exception 'This request can no longer be cancelled by you' using errcode = '42501';
  end if;

  update public.requests
     set status = 'cancelled', cancelled_at = now(), cancelled_by = v_uid
   where id = p_id
  returning * into v_row;

  insert into public.request_events (request_id, event, actor_id)
  values (p_id, 'cancelled', v_uid);

  return v_row;
end;
$$;


-- --- a person sets their own notification preferences ----------------------
--
-- Through a function, not a policy. users_admin_update is admin-only for good
-- reason, and widening it so people could edit their own row would hand
-- everybody is_admin. This writes exactly three columns, always for the caller,
-- and cannot touch anything else.
drop function if exists public.set_notification_preferences(boolean, boolean, boolean);
create or replace function public.set_notification_preferences(
  p_510 boolean, p_lower boolean, p_delivered boolean,
  p_messages text, p_advisor_delivered boolean, p_advisor_messages boolean)
returns void
language sql security definer set search_path = '' as $$
  update public.users
     set notify_510       = coalesce(p_510, false),
         notify_lower     = coalesce(p_lower, false),
         notify_delivered = coalesce(p_delivered, false),
         -- Anything unrecognised means silence. A client sending nonsense
         -- should not be able to sign somebody up for every message.
         notify_messages  = case when p_messages in ('none','mine','all')
                                 then p_messages else 'none' end,
         notify_advisor_delivered = coalesce(p_advisor_delivered, false),
         notify_advisor_messages  = coalesce(p_advisor_messages, false)
   where id = auth.uid() and active;
$$;


-- --- who to notify about a new car -----------------------------------------
--
-- Driven by each person's own choice in Settings, not by the area labels. The
-- labels seeded the first set of preferences and have no say after that.
--
-- "Signed in today" stands in for "on shift". Sessions reset at 3am, so someone
-- who has not signed in since then is almost certainly not at work, and buzzing
-- a porter at home on their day off is the fastest way to have the whole team
-- turn notifications off.
--
-- service_role only: this returns a list of push endpoints, which is exactly
-- the sort of thing that should never be readable from a phone.
drop function if exists public.push_targets(text);

create or replace function public.push_targets(p_zone text)
returns table(endpoint text, p256dh text, auth text)
language sql stable security definer set search_path = '' as $$
  select ps.endpoint, ps.p256dh, ps.auth
    from public.push_subscriptions ps
    join public.users u on u.id = ps.user_id
   where u.active
     and case when p_zone = '510' then u.notify_510 else u.notify_lower end
     -- THIS DEVICE was signed in today, not "this person signed in somewhere
     -- today". The old test asked login_attempts, which is per-person: a phone
     -- that had been logged out went on being buzzed as soon as its owner
     -- signed in anywhere else, because the row still existed and the person
     -- had a login for the day.
     --
     -- It also leaned on sign-out having deleted the row, and that delete is
     -- fire-and-forget with whatever token the session had. At 3am that token
     -- is an hour stale, so the delete 401s and the row survives — a device
     -- could be logged out and still on the list all day.
     --
     -- claimed_at inverts it into something positive: a device is notified
     -- because it said it was signed in, not because nothing managed to say
     -- otherwise. A failed delete now costs nothing.
     and ps.claimed_at >= public.app_day_start();
$$;

-- Who to tell that a car they asked for has arrived: the cashier who issued it,
-- if they want to hear about it. Same "signed in today" rule — somebody who has
-- gone home does not need to know a car moved.
-- Takes the REQUEST, not a person: two different people can want to hear about
-- the same car arriving, and only the row knows who they are.
drop function if exists public.push_targets_delivered(uuid);
create or replace function public.push_targets_delivered(p_request uuid)
returns table(endpoint text, p256dh text, auth text)
language sql stable security definer set search_path = '' as $$
  select ps.endpoint, ps.p256dh, ps.auth
    from public.push_subscriptions ps
    join public.users u on u.id = ps.user_id
    join public.requests r on r.id = p_request
    -- Left join: most accounts are not an advisor, and they still qualify on
    -- the first branch below.
    left join public.service_advisors sa on sa.user_id = u.id
   where u.active
     and (
          -- The person who asked for it.
          (u.notify_delivered and r.issued_by = u.id)
          -- Or the advisor whose key character is on the tag, whoever raised it.
       or (u.notify_advisor_delivered and sa.id is not null and sa.id = r.advisor_id)
     )
     -- THIS DEVICE was signed in today, not "this person signed in somewhere
     -- today". The old test asked login_attempts, which is per-person: a phone
     -- that had been logged out went on being buzzed as soon as its owner
     -- signed in anywhere else, because the row still existed and the person
     -- had a login for the day.
     --
     -- It also leaned on sign-out having deleted the row, and that delete is
     -- fire-and-forget with whatever token the session had. At 3am that token
     -- is an hour stale, so the delete 401s and the row survives — a device
     -- could be logged out and still on the list all day.
     --
     -- claimed_at inverts it into something positive: a device is notified
     -- because it said it was signed in, not because nothing managed to say
     -- otherwise. A failed delete now costs nothing.
     and ps.claimed_at >= public.app_day_start();
$$;

-- Drop an endpoint the push service has told us is dead. Called by the notify
-- function on a 404 or 410; without it, dead endpoints accumulate forever and
-- every send gets slower.
create or replace function public.forget_push_endpoint(p_endpoint text)
returns void
language sql security definer set search_path = '' as $$
  delete from public.push_subscriptions where endpoint = p_endpoint;
$$;


-- --- fire a notification when a car is requested ---------------------------
--
-- This is the database webhook, written as a trigger rather than clicked
-- together in the dashboard. Same mechanism — Supabase's own webhooks are
-- exactly this — but it lives in version control with everything else instead
-- of being a setting nobody can find again.
--
-- pg_net's http_post is asynchronous: it queues the request and returns, so
-- issuing a car never waits on a push service.
create extension if not exists pg_net;

create or replace function public.notify_url()
returns text language sql immutable as $$
  select 'https://txnijhgfitfklyjativk.supabase.co/functions/v1/notify'
$$;

-- net.http_post is FULLY QUALIFIED, and search_path stays empty like every
-- other function here.
--
-- The previous version used `set search_path = 'net, extensions'` and called
-- http_post unqualified. Quoted that way, PostgreSQL reads the whole string as
-- ONE schema name — a schema called "net, extensions" — so `net` was never on
-- the path and the call failed every time with "function http_post does not
-- exist". The exception handler below caught it, wrote a warning nobody reads,
-- and let the request through. Notifications simply never fired, while a
-- direct net.http_post from the SQL editor worked perfectly.
--
-- Section 8 now checks net.http_post exists, so a project where pg_net lands
-- somewhere else fails loudly instead of going quiet.
create or replace function public.notify_new_request()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare v_secret text;
begin
  select value into v_secret from public.app_secrets where key = 'notify_secret';

  -- Not configured yet? Do nothing and let the insert through. A cashier must
  -- always be able to get a car moved; notifications are an accessory, and a
  -- missing secret must never be the reason a request cannot be issued.
  if v_secret is null then
    return new;
  end if;

  perform net.http_post(
    url     := public.notify_url(),
    body    := jsonb_build_object('record', to_jsonb(new), 'event', 'requested'),
    headers := jsonb_build_object(
                 'Content-Type',    'application/json',
                 'x-notify-secret', v_secret)
  );
  return new;
exception when others then
  -- Same reasoning. If the queue call fails for any reason, the car request
  -- still stands.
  raise warning 'notify_new_request failed: %', sqlerrm;
  return new;
end;
$$;

drop function if exists public.debug_notify_now();

drop trigger if exists notify_on_request on public.requests;
create trigger notify_on_request
  after insert on public.requests
  for each row execute function public.notify_new_request();


-- --- and when the car actually arrives -------------------------------------
--
-- The cashier who asked for it wants to know it is done, so they can stop
-- wondering. Fires only on the transition INTO complete: reopening and
-- completing again would otherwise buzz them twice for one car.
create or replace function public.notify_request_delivered()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare v_secret text;
begin
  select value into v_secret from public.app_secrets where key = 'notify_secret';
  if v_secret is null then
    return new;
  end if;

  perform net.http_post(
    url     := public.notify_url(),
    body    := jsonb_build_object('record', to_jsonb(new), 'event', 'delivered'),
    headers := jsonb_build_object(
                 'Content-Type',    'application/json',
                 'x-notify-secret', v_secret)
  );
  return new;
exception when others then
  -- Same rule as issuing: a car being marked delivered must never fail because
  -- a notification could not be sent.
  raise warning 'notify_request_delivered failed: %', sqlerrm;
  return new;
end;
$$;

-- --- and when somebody says something about a car ---------------------------
--
-- Carries the car code with it. The Edge Function would otherwise have to go
-- and fetch the request just to name the notification, and this trigger is
-- already holding the row.
create or replace function public.notify_new_message()
returns trigger
language plpgsql security definer set search_path = ''
as $$
declare
  v_secret text;
  v_code   text;
begin
  select value into v_secret from public.app_secrets where key = 'notify_secret';
  if v_secret is null then
    return new;
  end if;

  select car_code into v_code from public.requests where id = new.request_id;

  perform net.http_post(
    url     := public.notify_url(),
    body    := jsonb_build_object(
                 'event',  'message',
                 'record', jsonb_build_object(
                   'request_id', new.request_id,
                   'author_id',  new.author_id,
                   'body',       new.body,
                   'car_code',   v_code)),
    headers := jsonb_build_object(
                 'Content-Type',    'application/json',
                 'x-notify-secret', v_secret)
  );
  return new;
exception when others then
  -- Same rule as the other two: saying something must never fail because the
  -- notification could not be sent.
  raise warning 'notify_new_message failed: %', sqlerrm;
  return new;
end;
$$;

drop trigger if exists notify_on_message on public.request_messages;
create trigger notify_on_message
  after insert on public.request_messages
  for each row execute function public.notify_new_message();


drop trigger if exists notify_on_delivered on public.requests;
create trigger notify_on_delivered
  after update on public.requests
  for each row
  when (old.status is distinct from 'complete' and new.status = 'complete')
  execute function public.notify_request_delivered();


-- --- login (service_role only — never callable from a phone) ----------------
-- Checks a submitted code against every active user's hash. Returns the user id
-- or null. The Edge Function calls this, applies the lockout counter, and only
-- then mints a session.
--
-- Deliberately not reachable with the publishable key: exposed to the internet
-- it would be a brute-force oracle against the whole code space.
--
-- Cost note: this is one bcrypt comparison per active user, because the stored
-- hashes are salted and cannot be looked up directly. At dealership scale
-- (tens of staff) that is a few milliseconds. At thousands it would need a
-- rethink.
create or replace function public.verify_login_code(p_code text)
returns uuid
language sql stable security definer set search_path = '' as $$
  select u.id
    from public.users u
    join public.user_codes c on c.user_id = u.id
   where u.active
     and c.code_hash = extensions.crypt(p_code, c.code_hash)
   limit 1;
$$;

-- Sets or resets somebody's code. Service_role only, called by the admin path
-- in the Edge Function. Codes are hashed on the way in and are unreadable
-- afterwards by anyone, John included.
--
-- The length check is here rather than only in the app because this is the one
-- place a code can be set. A short code slipped in through a script or a future
-- admin path would silently undo the reasoning in app_code_length().
create or replace function public.set_login_code(p_user_id uuid, p_code text)
returns void
language plpgsql security definer set search_path = '' as $$
declare v_len int := public.app_code_length();
begin
  if p_code !~ ('^[0-9]{' || v_len || '}$') then
    raise exception 'A login code must be exactly % digits', v_len using errcode = '22023';
  end if;

  insert into public.user_codes (user_id, code_hash, updated_at)
  values (p_user_id, extensions.crypt(p_code, extensions.gen_salt('bf', 10)), now())
  on conflict (user_id)
  do update set code_hash = excluded.code_hash, updated_at = now();
end;
$$;


-- Say something about a car.
--
-- Authorship comes from the session, never from the caller. That is the whole
-- reason this is a function rather than an insert policy: a client that can
-- name the author can sign a message as anybody.
--
-- Deliberately allowed on a request in ANY state, including finished ones.
-- "Left it in bay 3, keys with Josh" is said after the car is delivered more
-- often than before, and a log that closes the moment the job does would miss
-- exactly the messages worth keeping.
create or replace function public.post_message(p_id uuid, p_body text)
returns public.request_messages
language plpgsql security definer set search_path = '' as $$
declare
  v_uid  uuid := public.app_require_user();
  v_body text := trim(coalesce(p_body, ''));
  v_row  public.request_messages;
begin
  if v_body = '' then
    raise exception 'Write something first' using errcode = '22023';
  end if;
  if length(v_body) > 1000 then
    raise exception 'That message is too long' using errcode = '22023';
  end if;

  -- Checked here so a bad id is a sentence rather than a foreign key violation.
  if not exists (select 1 from public.requests where id = p_id) then
    raise exception 'No such request' using errcode = '22023';
  end if;

  insert into public.request_messages (request_id, author_id, body)
  values (p_id, v_uid, v_body)
  returning * into v_row;

  return v_row;
end;
$$;


-- Who hears about a message on a car.
--
-- Never the person who wrote it. Being buzzed by your own sentence is the
-- fastest way to make somebody turn the whole feature off, and the author is
-- looking at the screen it appeared on.
create or replace function public.push_targets_message(p_request uuid, p_author uuid)
returns table(endpoint text, p256dh text, auth text)
language sql stable security definer set search_path = '' as $$
  select ps.endpoint, ps.p256dh, ps.auth
    from public.push_subscriptions ps
    join public.users u on u.id = ps.user_id
    join public.requests r on r.id = p_request
    left join public.service_advisors sa on sa.user_id = u.id
   where u.active
     and ps.user_id is distinct from p_author
     and (
          u.notify_messages = 'all'
          -- "Mine" is both ends of the job: the cashier who asked for the car
          -- and the porter driving it are the two people a message is usually
          -- aimed at.
       or (u.notify_messages = 'mine'
           and (r.issued_by = u.id or r.claimed_by = u.id))
       or (u.notify_advisor_messages and sa.id is not null and sa.id = r.advisor_id)
     )
     and ps.claimed_at >= public.app_day_start();
$$;


-- Mark this device as signed in, right now.
--
-- An RPC rather than letting the app PATCH the column, so the timestamp comes
-- from the SERVER's clock. A phone with a wrong clock could otherwise write a
-- date next year and be notified forever, and phone clocks are exactly the kind
-- of thing that is wrong.
create or replace function public.claim_push(p_endpoint text)
returns void
language sql security definer set search_path = '' as $$
  update public.push_subscriptions
     set claimed_at = now()
   where endpoint = p_endpoint
     and user_id = auth.uid();
$$;


-- ============================================================================
-- 6b. Advisor colours
--
-- Twelve hues, evenly spaced in OKLCH at fixed lightness and chroma. OKLCH
-- rather than HSL because HSL is not perceptually even — yellow at "50%
-- lightness" reads far brighter than blue at the same number, and a hand-picked
-- set comes out lumpy. These all land between 4.9:1 and 6.1:1 against the page
-- background, a spread of about one point rather than three.
--
-- HONEST LIMIT: twelve colours cannot all be told apart by someone with
-- red-green colour blindness — roughly one man in twelve. Simulated, two pairs
-- collapse: #cd632d/#b97600 and #0096c9/#4087de. That is a ceiling, not a bug;
-- the real limit for a dichromat is about five. It is why the advisor's NAME is
-- always rendered beside the colour, and why colour must stay a grouping aid
-- rather than the identifier. Do not "simplify" the card by dropping the name.
-- ============================================================================

create or replace function public.advisor_palette()
returns table(ord int, color text)
language sql immutable as $$
  select * from (values
    ( 1, '#d05a69'), ( 2, '#cd632d'), ( 3, '#b97600'), ( 4, '#958900'),
    ( 5, '#5c9932'), ( 6, '#00a16f'), ( 7, '#00a0a2'), ( 8, '#0096c9'),
    ( 9, '#4087de'), (10, '#7f76dc'), (11, '#a867c3'), (12, '#c35c9b')
  ) as t(ord, color);
$$;

-- The next colour to hand out: the palette entry used by the fewest ACTIVE
-- advisors, earliest in the palette breaking ties.
--
-- Counting only active advisors is what "frees" a colour on removal — deactivate
-- someone and their colour is immediately available again, with nothing to
-- unbind by hand. Because it returns the least-used rather than only an unused
-- one, a thirteenth advisor still gets a colour (shared) instead of an error.
-- VOLATILE, not stable, and that matters. A stable function uses the snapshot
-- from the start of the statement, so inserting several advisors in one command
-- would hand every one of them the same colour — each call would be blind to
-- the rows just created alongside it.
create or replace function public.next_free_advisor_color()
returns text
language sql volatile security definer set search_path = '' as $$
  select p.color
    from public.advisor_palette() p
    left join public.service_advisors sa
           on sa.color = p.color and sa.active
   group by p.ord, p.color
   order by count(sa.id), p.ord
   limit 1;
$$;

create or replace function public.assign_advisor_color()
returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  -- Insert with no colour: assign one. Runs BEFORE the NOT NULL check, so
  -- callers can simply omit the column.
  if tg_op = 'INSERT' and new.color is null then
    new.color := public.next_free_advisor_color();

  -- Reactivating someone whose colour was handed to somebody else while they
  -- were inactive: give them a fresh one rather than a silent duplicate.
  elsif tg_op = 'UPDATE' and new.active and not old.active
        and exists (select 1 from public.service_advisors
                     where active and color = new.color and id <> new.id) then
    new.color := public.next_free_advisor_color();
  end if;

  return new;
end;
$$;

drop trigger if exists advisor_color on public.service_advisors;
create trigger advisor_color
  before insert or update on public.service_advisors
  for each row execute function public.assign_advisor_color();

-- Which advisor a key tag belongs to.
--
--   3 characters or fewer -> nobody. No advisor was assigned.
--   starts with T         -> nobody. The car was towed in.
--   otherwise             -> the active advisor holding that first character,
--                            or nobody if it matches none of them.
--
-- Returning null for an unmatched character rather than raising is deliberate:
-- a cashier holding a real tag should never be blocked from getting a car
-- moved because the advisor list is out of date. The app renders it as
-- "Unknown" so it is visible instead of silent.
create or replace function public.advisor_for_code(p_code text)
returns uuid
language plpgsql stable security definer set search_path = '' as $$
declare
  v_code  text := upper(trim(coalesce(p_code, '')));
  v_first text;
begin
  if length(v_code) <= 3 then return null; end if;
  v_first := left(v_code, 1);
  if v_first = 'T' then return null; end if;
  return (select id from public.service_advisors
           where active and key_char = v_first limit 1);
end;
$$;

-- --- The real advisors ------------------------------------------------------
--
-- Replaces the placeholder names used during the build. The old ones carry no
-- key character, which is exactly what distinguishes them.
--
-- Requests pointing at a placeholder are unpicked rather than deleted: they are
-- test data, but throwing away rows to satisfy a foreign key is a habit worth
-- not starting. They render as "N/A" afterwards.
do $$
begin
  update public.requests set advisor_id = null
   where advisor_id in (select id from public.service_advisors where key_char is null);

  delete from public.service_advisors where key_char is null;
end $$;

-- Inserted one at a time so each picks up the next free palette colour. A
-- single multi-row insert would give them all the same one.
do $$
declare r record;
begin
  for r in
    select * from (values
      ('Anthony', '1', 1), ('Mark',   '2', 2), ('Johnny', '3', 3),
      ('Ralph',   '4', 4), ('Skip',   '6', 5), ('Josh',   '8', 6),
      ('Jovis',   '9', 7), ('Jimmy',  '0', 8), ('Igor',   'A', 9)
    ) as v(name, key_char, ord)
  loop
    if not exists (select 1 from public.service_advisors
                    where key_char = r.key_char and active) then
      insert into public.service_advisors (name, key_char, sort_order)
      values (r.name, r.key_char, r.ord);      -- colour assigned by the trigger
    end if;
  end loop;
end $$;

-- Bring any advisor still on a pre-palette colour onto the palette. Idempotent:
-- once every advisor holds a palette colour this loop finds nothing to do.
do $$
declare r record; c text;
begin
  for r in select id from public.service_advisors
            where color not in (select color from public.advisor_palette())
            order by sort_order, created_at
  loop
    select public.next_free_advisor_color() into c;
    update public.service_advisors set color = c where id = r.id;
  end loop;
end $$;


-- ============================================================================
-- 7. Grants
--
-- RLS decides which rows; grants decide which tables and functions are
-- reachable at all. Both matter. These revokes are the second lock on the
-- tables that must never be read from a phone.
-- ============================================================================

-- --- Functions: default-deny, then grant back deliberately -----------------
--
-- PostgreSQL grants EXECUTE on a NEW function to PUBLIC automatically. That
-- means every function added to this file in future is exposed to anonymous
-- callers unless somebody remembers to revoke it, and eventually somebody will
-- not. This already happened: advisor_for_code() was callable without a login,
-- and since it is SECURITY DEFINER it read straight past RLS — an anonymous
-- caller could ask "is key character 5 assigned?" and get an answer about a
-- table they cannot otherwise see at all.
--
-- Sweeping first and granting afterwards makes forgetting safe instead of
-- dangerous. Note it revokes from PUBLIC, which `authenticated` inherits, so
-- everything the app genuinely needs is granted again below.
revoke all on all functions in schema public from public;
revoke all on all functions in schema public from anon;

-- And for functions added in future. Supabase's default privileges hand EXECUTE
-- to anon on anything new in this schema, which is the actual root cause — the
-- next function written here would have been exposed again the moment it was
-- created, with nothing failing to say so.
alter default privileges in schema public revoke execute on functions from public;
alter default privileges in schema public revoke execute on functions from anon;

-- The permission helpers are named inside the RLS policies, and policy
-- expressions are evaluated with the CALLER's privileges — without these grants
-- every policy fails and the app stops working entirely.
--
-- They are safe to expose to a logged-in user: each one reports only that
-- caller's own permissions, which they can already see in their own session.
grant execute on function public.app_is_active()            to authenticated;
grant execute on function public.app_is_admin()             to authenticated;
grant execute on function public.app_can_issue()            to authenticated;
grant execute on function public.app_can_claim()            to authenticated;
grant execute on function public.app_can_claim_zone(text)   to authenticated;
grant execute on function public.app_is_manager()           to authenticated;
grant execute on function public.set_notification_preferences(
  boolean, boolean, boolean, text, boolean, boolean) to authenticated;

-- --- Tables: nothing at all for logged-out callers --------------------------
--
-- Swept rather than listed, for the same reason as the functions above. Supabase
-- grants anon access to every NEW table in this schema by default, so an
-- enumerated revoke list is a list somebody has to remember to extend — and
-- push_subscriptions proved the point the day it was added. The check in
-- section 8 caught it, which is the only reason this is a comment rather than a
-- table of push endpoints readable by the internet.
--
-- Nothing is granted back: anon has no business reading any of it. Every table
-- also has RLS with no anon policy, so this is the second lock, not the only one.
revoke all on all tables in schema public from anon;
alter default privileges in schema public revoke all on tables from anon;

-- --- service_role: say it out loud rather than inheriting it ---------------
--
-- The login, admin and notify functions run as service_role. Supabase grants it
-- everything by default, so this was never written down — and then the sweeps
-- above took it away, and the login function lost the ability to record who had
-- signed in. Logins carried on working; only notifications broke, silently,
-- because "signed in today" is how the app knows who is on shift.
--
-- Granting it back explicitly means this file no longer depends on a default
-- that a later revoke can quietly undo. Section 8 checks it held.
grant all on all tables    in schema public to service_role;
grant all on all sequences in schema public to service_role;
alter default privileges in schema public grant all on tables    to service_role;
alter default privileges in schema public grant all on sequences to service_role;

-- Kept for authenticated: these two are readable by nobody but the login and
-- notify functions, which run as service_role.
revoke all on public.user_codes        from authenticated;
revoke all on public.login_attempts    from authenticated;
revoke all on public.app_secrets       from authenticated;

-- Writes to these go through section 6 only.
revoke insert, update, delete on public.requests         from authenticated;
revoke insert, update, delete on public.request_events   from authenticated;

-- Readable by anyone signed in, writable by nobody directly. Posting is
-- post_message() below, which is what stops a client choosing the author. No
-- update or delete for anyone: the log does not get rewritten.
grant  select                 on public.request_messages to authenticated;
revoke insert, update, delete on public.request_messages from authenticated;
revoke insert, delete         on public.users          from authenticated;

-- Operations: logged-in users may call them; the functions themselves decide
-- whether the caller is allowed to do the thing.
revoke all on function public.create_request(text, text, text, text, boolean)          from public, anon;
revoke all on function public.edit_request(uuid, text, text, text, text, boolean)      from public, anon;
revoke all on function public.claim_request(uuid)                             from public, anon;
revoke all on function public.unclaim_request(uuid)                           from public, anon;
revoke all on function public.complete_request(uuid)                          from public, anon;
revoke all on function public.reopen_request(uuid)                            from public, anon;
revoke all on function public.cancel_request(uuid)                            from public, anon;
revoke all on function public.post_message(uuid, text)                        from public, anon;

grant execute on function public.create_request(text, text, text, text, boolean)       to authenticated;
grant execute on function public.edit_request(uuid, text, text, text, text, boolean)   to authenticated;
grant execute on function public.claim_request(uuid)                          to authenticated;
grant execute on function public.unclaim_request(uuid)                        to authenticated;
grant execute on function public.complete_request(uuid)                       to authenticated;
grant execute on function public.reopen_request(uuid)                         to authenticated;
grant execute on function public.cancel_request(uuid)                         to authenticated;
grant execute on function public.post_message(uuid, text)                     to authenticated;
revoke all    on function public.claim_push(text)                     from public, anon;
grant execute on function public.claim_push(text)                       to authenticated;

-- advisor_palette() and next_free_advisor_color() are deliberately granted to
-- NOBODY. The admin screen works out which key characters are free from the
-- advisor rows it already reads, and colours are assigned by the database
-- trigger, so nothing outside the database ever needs to call either. A
-- function nobody calls should not be reachable.

-- The login functions are for the Edge Function alone. If either of these is
-- ever callable by `anon` or `authenticated`, the six-digit codes are guessable
-- at whatever rate the internet can manage.
revoke all on function public.verify_login_code(text)      from public, anon, authenticated;
revoke all on function public.set_login_code(uuid, text)   from public, anon, authenticated;
grant execute on function public.push_targets(text)                to service_role;
grant execute on function public.push_targets_delivered(uuid)      to service_role;
grant execute on function public.push_targets_message(uuid, uuid) to service_role;
grant execute on function public.forget_push_endpoint(text) to service_role;
grant execute on function public.verify_login_code(text)    to service_role;
grant execute on function public.set_login_code(uuid, text) to service_role;

-- ============================================================================
-- 8. The script checks its own most important claim
--
-- Everything above is only worth anything if it actually took. A revoke that
-- silently fails leaves the database exactly as exposed as before while the
-- script reports success — which is precisely what happened once already, and
-- was only caught because somebody asked the right question.
--
-- This raises, so the SQL editor rolls the whole run back and shows the reason.
-- A refusal you can read beats a success you cannot trust.
-- ============================================================================
do $$
declare leaked text;
begin
  select string_agg(p.oid::regprocedure::text, ', ' order by p.oid::regprocedure::text)
    into leaked
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public'
     and p.prokind = 'f'
     and has_function_privilege('anon', p.oid, 'execute');

  if leaked is not null then
    raise exception
      'anon can still execute: %. The revokes above did not take — do not deploy.', leaked;
  end if;
end $$;

do $$
declare leaked text;
begin
  select string_agg(c.relname, ', ' order by c.relname)
    into leaked
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind = 'r'
     and has_table_privilege('anon', c.oid, 'select');

  if leaked is not null then
    raise exception 'anon can still read tables: %. Do not deploy.', leaked;
  end if;
end $$;

-- The notification trigger calls net.http_post, and its exception handler turns
-- any failure into a warning nobody reads — so if that function is not where
-- this file expects, notifications stop and nothing anywhere says so. They were
-- broken this way for hours while every other check passed.
do $$
begin
  if not exists (
    select 1 from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'net' and p.proname = 'http_post'
  ) then
    raise exception
      'net.http_post not found — pg_net is missing or installed in another '
      'schema, and notifications would fail silently. Fix the call in '
      'notify_new_request() to match where it actually lives.';
  end if;
end $$;

-- And the reverse mistake, which is what actually happened: tightening so far
-- that the server's own functions cannot do their job.
--
-- This one is nastier than a leak, because nothing fails visibly. The login
-- function could not write login_attempts for weeks; logging in still worked,
-- and the only symptom was notifications never arriving, which is
-- indistinguishable from nobody being rostered.
do $$
declare missing text;
begin
  select string_agg(t.name, ', ' order by t.name)
    into missing
    from (values
      ('public.login_attempts',     'insert'),
      ('public.login_attempts',     'select'),
      ('public.push_subscriptions', 'select'),
      ('public.push_subscriptions', 'delete'),
      ('public.users',              'insert'),
      ('public.users',              'select'),
      ('public.app_secrets',        'select')
    ) as t(name, priv)
   where not has_table_privilege('service_role', t.name, t.priv);

  if missing is not null then
    raise exception
      'service_role cannot use: %. Logins and notifications would break quietly.', missing;
  end if;
end $$;


-- Realtime: the queue must update on every phone within a second.
-- Guarded, because adding a table that is already published raises an error and
-- this file is meant to be safe to re-run.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
     where pubname = 'supabase_realtime'
       and schemaname = 'public' and tablename = 'requests'
  ) then
    alter publication supabase_realtime add table public.requests;
  end if;
end
$$;
