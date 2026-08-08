# Porter Dispatch App — Build Plan

A shared queue that replaces the dealership group chat. Employees request a car by
code; porters claim it so everyone knows who's handling it; the car gets marked
delivered. Nobody has to scroll a chat to work out what's outstanding.

Read this first in the new chat. It is meant to be self-contained.

---

## 1. The problem

Today: an employee posts in a group chat, a porter reads it and goes. Failure modes:

- Two porters fetch the same car because neither knew the other saw it.
- A request scrolls away and nobody goes at all.
- No way to answer "what's outstanding right now?" without reading the whole chat.
- No history, so nobody knows how long requests actually take.

A chat cannot fix these, because a chat has no notion of a request having a *state*.

## 2. Who uses it

| Role | What they do |
| --- | --- |
| **Employee** (sales/service) | Requests a car by code. Sees the status of their own requests. |
| **Porter** | Sees the live queue of open requests. Claims one. Marks it delivered. |
| **Admin** (John) | Adds and removes porters. Views today's activity. Nothing else, ever. |

**Design constraint:** adding a porter is the *only* recurring human task. Anything
that would otherwise require a developer on a regular basis is a design bug.

## 3. What we're building on

- **Supabase** — hosted Postgres database, logins, and realtime sync. Replaces
  writing and maintaining a server. Free to start; $25/mo for the Pro tier.
- **A web app** — one page, added to the Home Screen on each phone. Same approach as
  the workout tracker: works on iPhone and Android, no App Store review, no installs.
- **GitHub Pages** — hosts the app itself, free, same as the workout tracker.

Supabase stores and syncs the data. We write only the screens.

## 4. Data model

```
users
  id            uuid, primary key
  name          text            -- displayed on claims, e.g. "Marcus T."
  role          text            -- 'employee' | 'porter' | 'admin'
  pin_hash      text            -- never store the raw PIN
  active        boolean         -- deactivate instead of deleting, to keep history
  created_at    timestamptz

requests
  id            uuid, primary key
  stock_code    text            -- the car code (see open question 1)
  note          text            -- optional: customer name, bay number
  status        text            -- 'open' | 'claimed' | 'delivered' | 'cancelled'
  requested_by  uuid -> users
  created_at    timestamptz
  claimed_by    uuid -> users, null
  claimed_at    timestamptz, null
  delivered_at  timestamptz, null
  cancelled_at  timestamptz, null
```

Status only ever moves forward: `open → claimed → delivered`, with `cancelled` as an
escape hatch. Rows are never deleted, so history and response times come free.

## 5. The one technically critical detail

Two porters tapping "Claim" at the same instant is not an edge case — it is the exact
failure the group chat has today. The claim must be a single conditional write:

```sql
update requests
   set status = 'claimed', claimed_by = $2, claimed_at = now()
 where id = $1
   and status = 'open'
returning *;
```

The `and status = 'open'` is the whole trick. The database guarantees only one of two
simultaneous claims can match. Zero rows back means someone beat you, and the app
shows "Already claimed by Marcus."

Reading the row and then writing it back — the obvious approach — is broken here, and
the bug appears only under exactly the conditions that matter. This is the main reason
for choosing Postgres over a spreadsheet-backed tool.

## 6. Security: the database rules are the only thing protecting the data

The app is a website, so its code is downloadable by anyone who loads it — that is true
whether the repo is public or private. Shipped with it is the Supabase **anon key**,
which is *designed* to be public.

That means repo privacy protects nothing. The only barrier between a stranger and the
dealership's data is **Row Level Security**: rules stored in Postgres that decide what
any given request is allowed to see. Get them right and an outsider holding the anon
key retrieves empty results forever. Leave one table with RLS switched off, or write
one policy too loosely, and that same key reads the whole table with no login at all.

This is the single most common way Supabase and Firebase projects leak data. It is not
an exotic attack; it is a default that was never changed.

### These policies get tested, not assumed

Verification is a deliverable, not a good intention. Before Phase 1 is called done:

- [ ] **Confirm RLS is enabled on every table.** A table without it is readable by
      anyone holding the anon key.
- [ ] **Query every table while logged out** using the anon key, exactly as an outsider
      would, and confirm each returns zero rows rather than data.
- [ ] **Log in as a porter and attempt employee-only actions**, and vice versa. Each
      must be refused by the database, not merely hidden in the interface. A button
      that isn't rendered is not a security control.
- [ ] **Attempt to claim an already-claimed request** as a second porter and confirm
      it is rejected.
- [ ] **Attempt to read the `users` table** while logged out and while logged in as a
      non-admin. PIN hashes must never be reachable by either.
- [ ] **Attempt to modify someone else's request** as an ordinary porter.

Every one of these is written down with its result when run, so there's a record of
what was checked rather than a memory of having looked at it.

### Two standing rules

- **The `service_role` key never enters the repo or the frontend.** It bypasses RLS
  entirely. Git history is permanent, and bots scan public GitHub for leaked keys
  within minutes — so if it is ever committed, the fix is to rotate the key
  immediately, not to delete the line in a later commit.
- **PINs are stored hashed, never in plain text.** After John creates a porter's PIN
  and passes it on, nobody — including John — can look it up again; a forgotten PIN is
  reset, not recovered. A database leak then exposes no working credentials.

## 7. Phases

### Phase 0 — Setup (short)
- Create the Supabase account and project.
- Create the two tables, enable RLS on both, and write the security rules.
- Create the GitHub repo and turn on Pages.
- **Done when:** an empty page loads on a phone and can reach the database, and RLS is
  confirmed enabled on every table.

### Phase 1 — Core flow (the bulk of the work)
- Login: pick your name, enter your PIN.
- Employee: request form (stock code + optional note).
- Porter: live queue, Claim button, Delivered button.
- Realtime sync, so claims appear on every phone within a second.
- **Done when:** two phones can run a full request → claim → delivered cycle, neither
  can double-claim, and every checkbox in section 6 has been run and recorded.

### Phase 2 — Admin and self-maintenance
- Add/remove porters, with generated PINs.
- Today's activity view.
- Auto-close stale requests: a porter delivering a car and forgetting to tap
  "Delivered" is the thing that would otherwise drag John in every week.
- **Done when:** John can run it without ever opening the Supabase dashboard.

### Phase 3 — Notifications
- Web push, which on iOS requires the app be added to the Home Screen.
- Escalation: nothing claimed within N minutes re-alerts, or pings a manager.
- **Done when:** a porter with the app closed gets a phone notification.

### Phase 4 — Pilot and handover
- Run alongside the group chat for a week. Do not cut over cold: if this breaks,
  customers don't get their cars.
- Fix whatever the porters actually complain about.
- Write the runbook: adding a porter, what to do if X, who to call.
- **Done when:** the group chat is switched off.

## 8. Costs

| Item | Cost |
| --- | --- |
| Supabase free tier | $0 — fine for the pilot |
| Supabase Pro | $25/mo — buys backups; worth it once real operations depend on it |
| GitHub Pages | $0 |
| Web push | $0 |
| SMS (optional, Phase 3) | ~$0.01/message, a few dollars a month |

Start at $0. The only cost worth arguing for is Pro, for backups.

## 9. Open questions to answer before Phase 0

1. **What exactly is the "code" for a car?** Stock number, last 6 of the VIN,
   something else? How long, and is it digits or mixed? This drives the input field,
   the keyboard that pops up, and validation — getting it right saves porters real
   time on every single request.
2. **How many porters, how many requesting employees, how many requests a day?**
   Changes almost nothing technically, but tells us what the queue screen should
   prioritise showing.
3. **Should employees see all requests, or only their own?** Affects the security
   rules.
4. **Do porters use personal phones?** If so, check whether the dealership has a
   policy about work apps on personal devices before rolling out.
5. **Is there cell signal in the warehouse?** See risks below.

## 10. Known risks

- **Misconfigured Row Level Security.** The highest-consequence risk in the project: a
  single table left unprotected exposes dealership and customer data to anyone on the
  internet, with no login and no trace. Mitigated by the test pass in section 6, which
  is a gate on Phase 1 rather than a nice-to-have.
- **Warehouse signal.** If porters have no reception where the cars are, claims will
  fail at the exact moment they matter. Worth testing early with a phone in the actual
  building. Fixable (optimistic UI plus retry), but much cheaper to know up front than
  to discover during the pilot.
- **iOS web push needs Home Screen install.** Notifications do not work in a normal
  Safari tab, on any iOS version. If a porter deletes the icon, their alerts silently
  stop. Part of onboarding, and a thing to check when someone says they aren't getting
  notified.
- **Single maintainer.** John is the only person who can change this. Mitigation: keep
  the code in a repo his brother's team can access, and keep the runbook current, so a
  competent developer could pick it up cold.
- **The pilot will change the design.** Porters will want something neither of us
  predicted. Phase 1 is deliberately thin for this reason.

## 11. To bring to the next chat

- A Supabase account (sign up free at supabase.com) — or we create it together.
- The GitHub account (already set up from the workout tracker).
- Answers to as many of the section 9 questions as possible, especially #1.
