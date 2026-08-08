# Porter Dispatch

A shared queue that replaces the dealership group chat. Cashiers request a car by code;
porters claim it so everyone knows who's handling it; the car gets marked delivered.

Background and rationale: [PLAN.md](PLAN.md). This file is the design as actually built.

## Roles

Each person has a unique 8-digit code. Typing it identifies them and their permissions —
there is no name to pick from a list. Four independent checkboxes per person, set by
John in the admin dashboard:

| Checkbox | Grants |
| --- | --- |
| **Issue requests** | Create requests; edit or cancel their own while still unclaimed |
| **Claim 510** | Claim, deliver, unclaim and reopen cars in the 510 area |
| **Claim Lower Lot** | The same, for the lower lot |
| **Management** | All of the above regardless of the other boxes, plus: unclaim anyone's car, cancel any request at any stage, reopen any completed request |

The two porter areas are independent flags rather than one "porter type", so somebody
who covers both is a person with both ticked — no third type to invent.

## Areas

Every request belongs to the **510** area or the **lower lot**, decided by the database
from the two locations:

> If either the origin or the destination is **510** or **525**, it is a 510 job.
> Otherwise it goes to the lower lot.

A wash stop doesn't affect this — the wash is a waypoint, not an endpoint. The `zone`
column is `generated always as`, so the app never sends it and cannot get it wrong.

**"Lower Lot" is both a location and an area, and they are not the same thing.** A car
going **510 → Lower Lot** is a *510 job* — one end is 510, so a 510 porter handles it,
even though it is headed for the lower lot. Only journeys touching neither 510 nor 525
belong to the lower lot porters. This is easy to get backwards, so there is a test
pinning it down.

Porters see only their own area's Queue and In Progress; cashiers and managers see both
via sub-tabs. **The split in the interface is presentation — the refusal is in the
database.** A 510 porter who never sees a lower lot car in a list can still send the
claim by hand, so `claim_request` checks the area itself.

**Admin** is John alone and is not a checkbox. Only the admin creates users, sets
checkboxes, and manages the advisor list. A manager cannot promote themselves.

Staff are deactivated, never deleted, so their name survives on requests they handled
months ago.

## A request

Car code (letters, digits, or both — stored uppercase), an **origin** and a
**destination** from the six locations — 510, 525, Express, Drive, Wash, Lower Lot — an optional
**stop at the wash on the way**, a service advisor from John's managed list, and an
optional note. The issuing cashier and timestamp are attached automatically.

Origin and destination may be the same location; a car can be moved within one, and
refusing that would only make cashiers lie to the form. The wash stop is stored
separately from the destination because "drive → wash" and "drive → wash → express" are
different journeys, and only the second has somewhere to be afterwards. Ticking it when
the wash is already an endpoint is ignored rather than rejected — the intent is
unambiguous either way. Every request is colour-coded
by advisor, always shown alongside the advisor's name — never colour alone, because
roughly 1 in 12 men cannot reliably distinguish some of these.

## Service advisors come from the key tag

Cashiers never pick an advisor. **The first character of the four-character key tag is
the advisor**, and the database derives it when the request is created:

| First character | Advisor | | First character | Advisor |
| --- | --- | --- | --- | --- |
| `1` | Anthony | | `8` | Josh |
| `2` | Mark | | `9` | Jovis |
| `3` | Johnny | | `0` | Jimmy |
| `4` | Ralph | | `A` | Igor |
| `6` | Skip | | | |

Three cases have no advisor, and they are deliberately distinguishable rather than all
showing as blank:

| Tag | Shows | Meaning |
| --- | --- | --- |
| starts with `T` | **Tow-In** | the car was towed in |
| three characters | **N/A** | no advisor was assigned |
| first character matches nobody | **Unknown**, in red | a bad tag, or an advisor not yet added |

Length is checked first, so `TE1` is *N/A*, not a tow-in.

An unmatched character is warned about, never blocked — a cashier holding a real tag
should not be stuck because the advisor list is stale. The request still reaches a porter.

The advisor is **stored** on the request, not looked up live, so history stays a record of
who it *was*. Reassigning a key character later must not silently rewrite last month.

Service advisors are labels, not users. They never log in.

## Lifecycle

```
unclaimed ──claim──> claimed ──complete──> complete
    ^                   │                     │
    └────unclaim────────┘                     │
    └──────────────reopen──────────────────────┘

any of the above ──cancel──> cancelled
```

- The issuing cashier may **edit or cancel** their own request until a porter claims it.
  After that, only a manager can — a porter may already be walking to the wrong car.
- **Unclaiming leaves `created_at` untouched**, so the request returns to its rightful
  place near the top of the queue rather than the back of the line.
- **Reopening** puts the car back In Progress under the porter who had it. A porter may
  reopen their own completion until the next 3am; managers have no time limit.
- Nothing is ever deleted. Cancelled requests appear in history, marked as such.

## Tabs

Shown according to capability, not job title, so someone with all three boxes sees
everything.

| Tab | Who | What |
| --- | --- | --- |
| **Unclaimed** | everyone | The queue, oldest first. Claiming happens here. |
| **My Car** | can claim | Opens straight to the request if there's one; a list if more. Complete or unclaim from here. |
| **In Progress** | everyone | Read-only, except managers, who can unclaim and cancel. |
| **Issue Request** | can issue | The request form. |
| **History** | everyone | Newest first; sortable by recency, filterable by date, advisor, cashier, or porter. |
| **Admin** | admin | Users, checkboxes, advisor list and colours. |

Sessions expire at 3am local time — one login per day.

## How the security actually works

The app is a public website carrying a public key. Anyone can send any query they like
to this database. What stops them is entirely in [`db/schema.sql`](db/schema.sql):

1. **Row Level Security is on for every table.** One table missed is one table readable
   in full by anyone on the internet, with no login and no trace.
2. **Login codes live in their own table, `user_codes`, with zero policies.** RLS filters
   rows, not columns — so the only way to make `users` safely world-readable (and the app
   needs it: "claimed by Marcus T.", history filtered by porter) was to move the secret
   out of it entirely. Nobody can read `user_codes`. Ever.
3. **No table has an insert, update, or delete policy for requests.** Every state change
   goes through a `SECURITY DEFINER` function that checks permissions itself and writes
   the event log. One path to audit, not several.
4. **Codes are hashed.** A forgotten code is reset, never recovered — not even by John.
   A database leak exposes no working credential.
   Eight digits, not six, because an attacker hunts *any* valid code rather than one
   person's: with ~30 staff, roughly 1 in 33,000 random 6-digit guesses would land on
   somebody. Eight makes it 1 in 3,300,000. Length lives in `app_code_length()`.
5. **The secret key never enters this repo.** It bypasses every rule above. It lives only
   in the login function's environment inside Supabase.

### The claim is a single conditional write

```sql
update requests set status = 'claimed', ...
 where id = $1 and status = 'unclaimed'
```

`and status = 'unclaimed'` is the whole trick. Two porters tapping Claim in the same
second is not an edge case — it's the exact failure the group chat has today. Postgres
serialises the writes and only one can match. The loser gets zero rows and is told who
won. Reading the row and then writing it back would pass a casual test and break under
precisely the conditions that matter.

## Setup

**1. Apply the schema.** Paste [`db/schema.sql`](db/schema.sql) into the Supabase SQL
editor and run it. Safe to re-run: it recreates functions and policies without touching
data.

**2. Run the security tests.**

```bash
python3 tests/security_test.py
```

Phase A works as soon as the schema is applied. Phase B needs the login function and
seeded accounts, and skips itself cleanly until then. **Exit code 0 is a release gate,
not a formality** — a failure means data is reachable by someone who should not reach it.

Results get recorded in `SECURITY-TESTS.md` so there's a record of what was checked
rather than a memory of having looked.

## Deploying a change

Push to `main` and Pages rebuilds in about a minute. **Bump `CACHE` in
[`sw.js`](sw.js) as part of every deploy**, even one that doesn't touch that file.

Browsers detect a new service worker by fetching `sw.js` and comparing bytes. If it
is byte-identical, no update is found, and an app already on someone's Home Screen
never reloads — iOS restores a backgrounded web app rather than re-navigating it, so
a porter can run last week's code with no symptom. Editing that line is the whole
trigger.

## Advisor colours

Twelve hues, evenly spaced in OKLCH, defined in `advisor_palette()` in
[`db/schema.sql`](db/schema.sql). Adding an advisor with no colour assigns the
palette entry used by the fewest **active** advisors — so deactivating someone frees
their colour immediately, with nothing to unbind by hand. A thirteenth advisor gets a
shared colour rather than an error.

Twelve colours cannot all be distinguished by someone with red-green colour blindness
— about one man in twelve. Two pairs collapse under simulation. That is a ceiling,
not a defect: the real limit for a dichromat is around five. It is why the advisor's
**name is always rendered beside the colour**, and why colour must remain a grouping
aid rather than the identifier. Don't drop the name to tidy the card.

## Things to change before real use

- **`app_timezone()` in `db/schema.sql`** is set to `America/Los_Angeles`. It decides when
  "today" starts, which is what bounds a porter's self-reopen window.
- **Test accounts must be deactivated before the pilot.** A leftover account with a code
  like `11111111` undoes all of the above.
