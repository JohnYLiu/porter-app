#!/usr/bin/env python3
"""
Porter Dispatch — security test pass.

Every checkbox in PLAN.md section 6, as something that runs and reports, rather
than something we remember looking at once.

    python3 tests/security_test.py

No dependencies. Standard library only, so there is nothing to install and
nothing to keep up to date.

Two phases:

  PHASE A  Logged out, using the publishable key exactly as a stranger who read
           the app's source would. Runs as soon as db/schema.sql has been
           applied. Every table must come back empty or refused.

  PHASE B  Logged in as each role, attempting the other roles' actions. Needs
           the seeded test accounts and the login Edge Function, so it skips
           itself cleanly until those exist.

Exit code is 0 only if every check that ran passed.
"""

import json
import os
import sys
import urllib.error
import urllib.request

# Both of these are public by design and ship inside the app itself. The one
# that must never appear in this repo is the secret / service_role key.
URL = os.environ.get("SUPABASE_URL", "https://txnijhgfitfklyjativk.supabase.co").rstrip("/")
KEY = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "sb_publishable_rJEFL4ZmSL_fWJ2v33rVUg_Ovwcmosw")

# Fill these in after seeding, then Phase B runs. Codes for throwaway test
# accounts only — never a real member of staff's code.
TEST_ACCOUNTS = {
    "porter":   "11111111",
    "porter2":  "22222222",
    "cashier":  "33333333",
    "manager":  "44444444",
}

TABLES = [
    "users",
    "user_codes",
    "service_advisors",
    "requests",
    "request_events",
    "login_attempts",
]

# Tables that must be unreachable even by a fully logged-in ordinary user.
SECRET_TABLES = ["user_codes", "login_attempts"]

OPERATIONS = [
    ("create_request",   {"p_car_code": "TEST1", "p_destination": "drive",
                          "p_advisor_id": "00000000-0000-0000-0000-000000000000"}),
    ("claim_request",    {"p_id": "00000000-0000-0000-0000-000000000000"}),
    ("unclaim_request",  {"p_id": "00000000-0000-0000-0000-000000000000"}),
    ("complete_request", {"p_id": "00000000-0000-0000-0000-000000000000"}),
    ("reopen_request",   {"p_id": "00000000-0000-0000-0000-000000000000"}),
    ("cancel_request",   {"p_id": "00000000-0000-0000-0000-000000000000"}),
    ("verify_login_code", {"p_code": "12345678"}),
    ("set_login_code",   {"p_user_id": "00000000-0000-0000-0000-000000000000",
                          "p_code": "12345678"}),
]

results = []


def request(path, method="GET", body=None, token=None):
    """Returns (status, parsed_body_or_text). Never raises on an HTTP error."""
    headers = {"apikey": KEY, "Authorization": f"Bearer {token or KEY}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        status = e.code
    except Exception as e:  # network, DNS, TLS
        return 0, str(e)
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def check(name, passed, detail=""):
    results.append((name, passed, detail))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))
    return passed


def refused(status, body):
    """Did the database refuse this, rather than quietly doing it?

    A 200 carrying an empty list is also a refusal: RLS filtered every row.
    """
    if status in (401, 403, 404):
        return True
    if status == 200 and isinstance(body, list) and len(body) == 0:
        return True
    return False


# ---------------------------------------------------------------------------
# PHASE A — logged out, holding only the key that ships inside the app
# ---------------------------------------------------------------------------

def phase_a():
    print("\nPHASE A — anonymous, using the publishable key\n")

    print(" Reading every table while logged out:")
    for table in TABLES:
        status, body = request(f"/rest/v1/{table}?select=*&limit=5")
        if status == 404 and isinstance(body, dict) and body.get("code") == "PGRST205":
            check(f"anon read {table}", False, "table does not exist — has schema.sql been run?")
            continue
        rows = len(body) if isinstance(body, list) else "n/a"
        check(f"anon read {table}", refused(status, body), f"HTTP {status}, rows={rows}")

    print("\n Writing while logged out:")
    status, body = request("/rest/v1/requests", "POST",
                           {"car_code": "HACK", "destination": "drive"})
    check("anon insert into requests", status >= 400, f"HTTP {status}")

    status, body = request("/rest/v1/users?id=neq.00000000-0000-0000-0000-000000000000",
                           "PATCH", {"is_admin": True})
    check("anon grant itself admin", status >= 400 or body == [], f"HTTP {status}")

    print("\n Calling operations while logged out:")
    for fn, args in OPERATIONS:
        status, body = request(f"/rest/v1/rpc/{fn}", "POST", args)
        # 404 here means PostgREST will not even admit the function exists to
        # this caller, which is what we want for the two login functions.
        check(f"anon call {fn}()", status >= 400, f"HTTP {status}")


# ---------------------------------------------------------------------------
# PHASE B — logged in, attempting other roles' actions
# ---------------------------------------------------------------------------

def login(code):
    """Exchange an 8-digit code for a session. Returns (token, user_id)."""
    status, body = request("/functions/v1/login", "POST", {"code": code})
    if status == 200 and isinstance(body, dict) and body.get("access_token"):
        return body["access_token"], (body.get("user") or {}).get("id")
    return None, None


def field(path, token):
    """Read a single value back. The only trustworthy way to test a write."""
    status, rows = request(path, token=token)
    if status == 200 and isinstance(rows, list) and rows:
        return next(iter(rows[0].values()))
    return None


def phase_b():
    print("\nPHASE B — logged in, crossing role boundaries\n")

    if not TEST_ACCOUNTS:
        print("  SKIPPED — no test accounts configured yet (Step 3 not done).")
        print("  Fill in TEST_ACCOUNTS at the top of this file after seeding.")
        return

    tokens, ids = {}, {}
    for role, code in TEST_ACCOUNTS.items():
        tok, uid = login(code)
        if not check(f"log in as {role}", tok is not None):
            return
        tokens[role], ids[role] = tok, uid

    porter, cashier = tokens.get("porter"), tokens.get("cashier")
    porter2, manager = tokens.get("porter2"), tokens.get("manager")

    print("\n Secrets stay unreachable even when logged in:")
    for table in SECRET_TABLES:
        for role, tok in tokens.items():
            status, body = request(f"/rest/v1/{table}?select=*", token=tok)
            check(f"{role} read {table}", refused(status, body), f"HTTP {status}")

    print("\n Capabilities are enforced by the database, not by hidden buttons:")
    if porter:
        status, body = request("/rest/v1/rpc/create_request", "POST",
                               {"p_car_code": "X1", "p_destination": "drive",
                                "p_advisor_id": "00000000-0000-0000-0000-000000000000"},
                               token=porter)
        check("porter issues a request", status >= 400, f"HTTP {status}")

        # Privilege escalation is checked by READING THE VALUE BACK, not by the
        # status code. An update that RLS filters to zero rows returns 204 — it
        # looks exactly like success, and an earlier version of this test was
        # fooled by it. Worse, an unfiltered PATCH gets a 400 from PostgREST's
        # "UPDATE requires a WHERE clause" guard, so that test never reached the
        # security model at all. Only the stored value settles it.
        for target, label in ((ids.get("porter"), "itself"),
                              (ids.get("porter2"), "another user")):
            if not target:
                continue
            request(f"/rest/v1/users?id=eq.{target}", "PATCH",
                    {"is_admin": True}, token=porter)
            still = field(f"/rest/v1/users?id=eq.{target}&select=is_admin", porter)
            check(f"porter makes {label} admin", still is False, f"is_admin={still}")

    if cashier:
        status, body = request("/rest/v1/rpc/claim_request", "POST",
                               {"p_id": "00000000-0000-0000-0000-000000000000"},
                               token=cashier)
        check("cashier claims a car", status >= 400, f"HTTP {status}")

    print("\n Two porters, one car:")
    if not (cashier and porter and porter2):
        return

    status, advisors = request("/rest/v1/service_advisors?select=id&active=is.true&limit=1",
                               token=cashier)
    if not (isinstance(advisors, list) and advisors):
        check("find an advisor to file against", False, f"HTTP {status}")
        return
    aid = advisors[0]["id"]

    status, req = request("/rest/v1/rpc/create_request", "POST",
                          {"p_car_code": "RACE1", "p_destination": "express",
                           "p_advisor_id": aid}, token=cashier)
    if status != 200:
        check("create a request to race on", False, f"HTTP {status}")
        return
    rid = req["id"] if isinstance(req, dict) else req[0]["id"]

    # The transition rules only hold if the table itself cannot be written by
    # hand. Verified by reading the status back, for the same reason as above.
    request(f"/rest/v1/requests?id=eq.{rid}", "PATCH",
            {"status": "complete", "claimed_by": ids.get("porter")}, token=porter)
    st = field(f"/rest/v1/requests?id=eq.{rid}&select=status", porter)
    check("porter edits the requests table directly", st == "unclaimed", f"status={st}")

    s1, _ = request("/rest/v1/rpc/claim_request", "POST", {"p_id": rid}, token=porter)
    check("first porter claims", s1 == 200, f"HTTP {s1}")

    s2, b2 = request("/rest/v1/rpc/claim_request", "POST", {"p_id": rid}, token=porter2)
    msg = b2.get("message", "") if isinstance(b2, dict) else ""
    check("second porter is refused", s2 == 409, f"HTTP {s2}: {msg}")

    s3, _ = request("/rest/v1/rpc/complete_request", "POST", {"p_id": rid}, token=porter2)
    check("other porter completes it", s3 >= 400, f"HTTP {s3}")

    s4, _ = request("/rest/v1/rpc/unclaim_request", "POST", {"p_id": rid}, token=porter2)
    check("other porter unclaims it", s4 >= 400, f"HTTP {s4}")

    s5, _ = request("/rest/v1/rpc/edit_request", "POST",
                    {"p_id": rid, "p_car_code": "EDITED", "p_destination": "drive",
                     "p_advisor_id": aid}, token=cashier)
    check("issuing cashier edits it after it was claimed", s5 >= 400, f"HTTP {s5}")

    print("\n Reopening is limited to your own delivery:")
    s6, _ = request("/rest/v1/rpc/complete_request", "POST", {"p_id": rid}, token=porter)
    check("the holding porter completes it", s6 == 200, f"HTTP {s6}")

    s7, _ = request("/rest/v1/rpc/reopen_request", "POST", {"p_id": rid}, token=porter2)
    check("a different porter reopens it", s7 >= 400, f"HTTP {s7}")

    s8, _ = request("/rest/v1/rpc/reopen_request", "POST", {"p_id": rid}, token=porter)
    check("the delivering porter reopens their own", s8 == 200, f"HTTP {s8}")

    if manager:
        s9, _ = request("/rest/v1/rpc/unclaim_request", "POST", {"p_id": rid}, token=manager)
        check("manager may unclaim someone else's car", s9 == 200, f"HTTP {s9}")

    # Leave nothing behind in the queue.
    request("/rest/v1/rpc/cancel_request", "POST", {"p_id": rid}, token=manager or cashier)


def main():
    print(f"Porter Dispatch security test pass\n{URL}")
    phase_a()
    phase_b()

    passed = sum(1 for _, p, _ in results if p)
    failed = [r for r in results if not r[1]]
    print(f"\n{'=' * 60}\n{passed}/{len(results)} checks passed")
    if failed:
        print("\nFAILED:")
        for name, _, detail in failed:
            print(f"  - {name}  {detail}")
        print("\nA failure here means data is reachable by someone who should")
        print("not reach it. Do not deploy until this is empty.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
