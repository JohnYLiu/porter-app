# Security test results

PLAN.md section 6 requires each check to be written down with its result when run,
so there's a record of what was verified rather than a memory of having looked.

Re-run with `python3 tests/security_test.py` after any change to
[`db/schema.sql`](db/schema.sql) or the login function. Exit code 0 is a release gate.

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
