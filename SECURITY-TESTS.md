# Security test results

PLAN.md section 6 requires each check to be written down with its result when run,
so there's a record of what was verified rather than a memory of having looked.

Re-run with `python3 tests/security_test.py` after any change to
[`db/schema.sql`](db/schema.sql) or the login function. Exit code 0 is a release gate.

---

## 2026-08-08 — Lower Lot added as a sixth location, 55/55

Locations are now 510, Lower Lot, Drive, Express, 525, Wash. The added test pins down
the one case that reads wrong at a glance:

```
  PASS  lower lot location to 510 is a 510 job  — zone=510
```

Verified against the live database, and through the app as each porter:

| Request | Area | Seen by |
| --- | --- | --- |
| Lower Lot → 510 | 510 | 510 porter |
| 525 → Lower Lot | 510 | 510 porter |
| Lower Lot → Wash → Express | lower lot | Lower Lot porter |

"Lower Lot" is a location AND an area. A car going **510 → Lower Lot** is a 510 job — one
end is 510, so a 510 porter handles it even though it is headed for the lower lot. That
follows from the stated rule and is deliberate; the test exists so nobody "corrects" it.

---

## 2026-08-08 — full pass after the two porter areas, 54/54

Adds the area rule: every request belongs to the 510 area or the lower lot, decided by
a generated column from the two locations.

```
 A porter's area is enforced, not just filtered out of the list:
  PASS  fixture: porter holds only the 510 area       — 510=True lower=False
  PASS  fixture: lower holds only the lower lot area  — 510=False lower=True
  PASS  drive to express is routed to the lower lot   — zone=lower_lot
  PASS  510 porter claims a lower lot car             — HTTP 403
  PASS  lower lot porter claims it                    — HTTP 200
  PASS  525 to wash is routed to 510                  — zone=510
  PASS  lower lot porter claims a 510 car             — HTTP 403
  PASS  510 porter claims it                          — HTTP 200
  PASS  manager claims in either area                 — HTTP 200

54/54 checks passed
```

Routing verified directly against the database on six journeys:

| Journey | Area |
| --- | --- |
| 510 → Express | 510 |
| 525 → 510 | 510 |
| 510 → 525 | 510 |
| Drive → Wash | lower lot |
| Drive → Wash → Express | lower lot |
| Express → Drive | lower lot |

A wash stop does not change the area — it is a waypoint, not an endpoint.

### A failure that was not a failure

The first run reported *"510 porter claims a lower lot car — HTTP 200"* as a security
breach. It was not. `Test Porter` held **both** areas, so the 200 was correct: the rule
worked and the test data was wrong. The cause was two of my own decisions colliding —
the migration deliberately widens every existing claimer to both areas (safer than
guessing), and `seed.py` then skipped the account as "already exists" and never narrowed
it back.

Fixed in both places, because either alone leaves the trap set:

- `seed.py` now corrects permissions on existing **test** accounts rather than skipping
  them. Not applied to the admin account, so re-seeding never restores a permission John
  removed from himself.
- The suite verifies each test porter holds exactly one area **before** asserting
  anything about areas, and reports a fixture problem as a fixture problem. It no longer
  prints "data is reachable by someone who should not reach it" for mis-seeded test data.
  A suite that raises the same alarm for both teaches people to ignore the alarm.

---

## 2026-08-07 — full pass, 42/42

Project `txnijhgfitfklyjativk`. Schema applied, login Edge Function deployed, test
accounts seeded.

### Phase A — anonymous, holding only the key that ships inside the app

```
 Reading every table while logged out:
  PASS  anon read users              — HTTP 401
  PASS  anon read user_codes         — HTTP 401
  PASS  anon read service_advisors   — HTTP 401
  PASS  anon read requests           — HTTP 401
  PASS  anon read request_events     — HTTP 401
  PASS  anon read login_attempts     — HTTP 401

 Writing while logged out:
  PASS  anon insert into requests    — HTTP 401
  PASS  anon grant itself admin      — HTTP 401

 Calling operations while logged out:
  PASS  anon call create_request()   — HTTP 401
  PASS  anon call claim_request()    — HTTP 401
  PASS  anon call unclaim_request()  — HTTP 401
  PASS  anon call complete_request() — HTTP 401
  PASS  anon call reopen_request()   — HTTP 401
  PASS  anon call cancel_request()   — HTTP 401
  PASS  anon call verify_login_code()— HTTP 401
  PASS  anon call set_login_code()   — HTTP 401
```

A blanket `401` would look identical if the tables had never been created, so the two
cases were compared directly:

| Request | Response |
| --- | --- |
| `GET /rest/v1/does_not_exist` | `404` — `PGRST205 Could not find the table` |
| `GET /rest/v1/users` | `401` — `42501 permission denied for table users` |

Different errors. The tables exist and access is refused.

### Phase B — logged in, crossing role boundaries

```
  PASS  log in as porter / porter2 / cashier / manager

 Secrets stay unreachable even when logged in:
  PASS  porter, porter2, cashier, manager read user_codes      — HTTP 403 (all four)
  PASS  porter, porter2, cashier, manager read login_attempts  — HTTP 403 (all four)

 Capabilities are enforced by the database, not by hidden buttons:
  PASS  porter issues a request                     — HTTP 403
  PASS  porter makes itself admin                   — is_admin=False
  PASS  porter makes another user admin             — is_admin=False
  PASS  cashier claims a car                        — HTTP 403

 Two porters, one car:
  PASS  porter edits the requests table directly    — status=unclaimed
  PASS  first porter claims                         — HTTP 200
  PASS  second porter is refused                    — HTTP 409: Already claimed by Test Porter
  PASS  other porter completes it                   — HTTP 403
  PASS  other porter unclaims it                    — HTTP 403
  PASS  issuing cashier edits it after it was claimed — HTTP 403

 Reopening is limited to your own delivery:
  PASS  the holding porter completes it             — HTTP 200
  PASS  a different porter reopens it               — HTTP 403
  PASS  the delivering porter reopens their own     — HTTP 200
  PASS  manager may unclaim someone else's car      — HTTP 200

42/42 checks passed
```

---

## Two findings from this run

Both were faults in the tests, not the security model. Recorded because a test that
passes for the wrong reason is worse than no test — it buys confidence that isn't there.

### An unfiltered `PATCH` never reaches the security model

The first version tested privilege escalation with `PATCH /rest/v1/users` and no filter.
It returned `400` and the test passed. But `400` was PostgREST's *"UPDATE requires a
WHERE clause"* guard — a safety net against accidental mass updates. The request was
rejected before RLS was ever consulted.

### An update that RLS filters to zero rows returns `204`

Retried with a proper filter, `PATCH /rest/v1/users?id=eq.<self>` setting `is_admin`
returns **`204 No Content`** — indistinguishable from success. The policy matched no
rows, so nothing changed, but nothing said so either.

Every write test now asserts by reading the value back. `is_admin=False` and
`status=unclaimed` in the output above are actual stored values after the attempted
write, not status codes.

---

## Not yet covered

- **Lockout thresholds** (5 per code, 15 per IP, 15-minute window) are implemented in the
  login function but not exercised by the suite. Testing them means deliberately locking
  an account, so it needs a throwaway code and a 15-minute wait.
- **The 3am session expiry** is enforced in the app, not the database. It is session
  hygiene rather than a security boundary, and is not claimed as one.
- **Test accounts are still live.** `11111111` through `44444444` must be deactivated
  before the pilot — a runbook step, not something to leave to memory.
