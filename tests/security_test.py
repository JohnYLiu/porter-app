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
    "lower":    "55555555",
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
    ("create_request",   {"p_car_code": "TEST1", "p_origin": "510",
                          "p_destination": "drive",
                          }),
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

    # Every helper too, not just the obvious ones. PostgreSQL grants EXECUTE on
    # a new function to PUBLIC by default, so a function added later is exposed
    # to anonymous callers until somebody remembers to revoke it — and these are
    # SECURITY DEFINER, so they read straight past RLS.
    #
    # advisor_for_code was exactly this: anonymously callable, and it answered
    # "is key character 5 assigned?" about a table anon cannot otherwise see.
    print("\n Helper functions are not reachable without a login either:")
    for fn, args in [
        ("advisor_for_code",        {"p_code": "1A47"}),
        ("advisor_palette",         {}),
        ("next_free_advisor_color", {}),
        ("app_day_start",           {}),
        ("app_is_admin",            {}),
        ("app_is_active",           {}),
        ("app_can_claim_zone",      {"p_zone": "510"}),
    ]:
        status, body = request(f"/rest/v1/rpc/{fn}", "POST", args)
        check(f"anon call {fn}()", status >= 400, f"HTTP {status}")


# ---------------------------------------------------------------------------
# PHASE B — logged in, attempting other roles' actions
# ---------------------------------------------------------------------------

def login(code):
    """Exchange an 8-digit code for a session. Returns (token, user)."""
    status, body = request("/functions/v1/login", "POST", {"code": code})
    if status == 200 and isinstance(body, dict) and body.get("access_token"):
        return body["access_token"], (body.get("user") or {})
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

    tokens, ids, users = {}, {}, {}
    for role, code in TEST_ACCOUNTS.items():
        tok, user = login(code)
        if not check(f"log in as {role}", tok is not None):
            return
        tokens[role] = tok
        users[role] = user or {}
        ids[role] = (user or {}).get("id")

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
                               {"p_car_code": "X1", "p_origin": "510",
                                "p_destination": "drive"},
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

    # --- The key tag decides the advisor ------------------------------------
    # The cashier no longer picks one, so the derivation is the only thing
    # standing between a tag and the right person's name on the card.
    print("\n The key tag decides the advisor:")
    status, advisors = request(
        "/rest/v1/service_advisors?select=id,name,key_char&active=is.true", token=cashier)
    by_char = {a["key_char"]: a["name"] for a in advisors} if isinstance(advisors, list) else {}
    check("the nine real advisors are loaded", len(by_char) == 9, f"{len(by_char)} found")

    def tag_case(code, want_name, want_type):
        st, rq = request("/rest/v1/rpc/create_request", "POST",
                         {"p_car_code": code, "p_origin": "drive",
                          "p_destination": "express"}, token=cashier)
        if st != 200:
            return check(f"tag {code}", False, f"HTTP {st}")
        row = rq if isinstance(rq, dict) else rq[0]
        got_name = by_char.get(code[0].upper()) if row.get("advisor_id") else None
        ok = row.get("tag_type") == want_type and got_name == want_name
        check(f"tag {code} -> {want_name or want_type}", ok,
              f"tag_type={row.get('tag_type')} advisor={got_name}")
        request("/rest/v1/rpc/cancel_request", "POST", {"p_id": row["id"]},
                token=manager or cashier)

    tag_case("1A47", "Anthony", "advisor")   # first character is the advisor
    tag_case("0B12", "Jimmy",   "advisor")   # 0 is a real character, not "none"
    tag_case("AC93", "Igor",    "advisor")   # letters work too
    tag_case("TD55", None,      "tow_in")    # towed in
    tag_case("9E1",  None,      "none")      # three characters, no advisor
    tag_case("TE1",  None,      "none")      # length wins over the T rule
    tag_case("ZF88", None,      "advisor")   # unmatched character: no advisor,
                                             # but still a tag that wants one

    # Origin 510 makes this a 510 job, so both test porters are entitled to it —
    # otherwise the race below would be decided by area, not by the race.
    status, req = request("/rest/v1/rpc/create_request", "POST",
                          {"p_car_code": "RACE1", "p_origin": "510",
                           "p_destination": "express",
                           }, token=cashier)
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
                    {"p_id": rid, "p_car_code": "EDITED", "p_origin": "510",
                     "p_destination": "drive"}, token=cashier)
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

    # --- The admin function -------------------------------------------------
    # It holds the secret key, so it is the single most dangerous endpoint in
    # the system. It must refuse everyone who is not John, including a manager,
    # who is the closest thing to an admin that exists.
    print("\n The admin endpoint refuses everyone who is not the admin:")

    def admin_call(payload, token=None):
        return request("/functions/v1/admin", "POST", payload, token=token)

    probe_new = {"action": "create_user", "name": "Intruder", "is_manager": True}
    st, body = admin_call(probe_new, token=manager)

    if st == 404:
        check("admin function is deployed", False,
              "not found — deploy supabase/functions/admin, then re-run")
    else:
        check("manager creates a user", st == 403, f"HTTP {st}")
        for role in ("porter", "cashier", "lower"):
            s, _ = admin_call(probe_new, token=tokens.get(role))
            check(f"{role} creates a user", s == 403, f"HTTP {s}")

        s, _ = admin_call(probe_new)                       # no session at all
        check("anon creates a user", s in (401, 403), f"HTTP {s}")

        s, _ = admin_call({"action": "reset_code", "user_id": ids.get("porter")},
                          token=manager)
        check("manager resets someone's code", s == 403, f"HTTP {s}")

        # And nobody actually got created by any of the above.
        st2, rows = request("/rest/v1/users?select=id&name=eq.Intruder", token=cashier)
        check("no account was created by any of those",
              isinstance(rows, list) and len(rows) == 0,
              f"{len(rows) if isinstance(rows, list) else '?'} found")

    # --- Porter areas -------------------------------------------------------
    # The two queues are separated in the interface, but that is presentation. A
    # 510 porter who never sees a lower lot car in a list can still send the
    # claim by hand, so the refusal has to come from the database.
    print("\n A porter's area is enforced, not just filtered out of the list:")
    lower = tokens.get("lower")
    if not lower:
        check("lower lot porter available", False, "no 'lower' test account")
        return

    # Check the fixture BEFORE asserting anything about it.
    #
    # These tests only mean something if each porter holds exactly one area. The
    # first time this ran, the migration had widened both test porters to BOTH
    # areas, so a correct refusal never happened and the suite reported a
    # security failure that did not exist. A security test that cries wolf over
    # its own test data is worse than no test — people stop believing it.
    def one_area_only(role, want_510):
        u = users.get(role, {})
        ok = bool(u.get("can_claim_510")) == want_510 and \
             bool(u.get("can_claim_lower")) == (not want_510)
        return check(f"fixture: {role} holds only the "
                     f"{'510' if want_510 else 'lower lot'} area",
                     ok, f"510={u.get('can_claim_510')} lower={u.get('can_claim_lower')}")

    fixture_ok = one_area_only("porter", True) & one_area_only("lower", False)
    if not fixture_ok:
        print("      ^ re-run tools/seed.py; it now corrects test account areas.")
        print("        The area checks below are skipped — they cannot mean")
        print("        anything until each test porter holds one area.")
        return

    # drive -> express: neither end is 510 or 525, so this is a lower lot job.
    status, req2 = request("/rest/v1/rpc/create_request", "POST",
                           {"p_car_code": "LOWER1", "p_origin": "drive",
                            "p_destination": "express"}, token=cashier)
    if status != 200:
        check("create a lower lot request", False, f"HTTP {status}")
        return
    r2 = req2["id"] if isinstance(req2, dict) else req2[0]["id"]
    zone2 = (req2 if isinstance(req2, dict) else req2[0]).get("zone")
    check("drive to express is routed to the lower lot", zone2 == "lower_lot", f"zone={zone2}")

    sa, _ = request("/rest/v1/rpc/claim_request", "POST", {"p_id": r2}, token=porter)
    check("510 porter claims a lower lot car", sa == 403, f"HTTP {sa}")

    sb, _ = request("/rest/v1/rpc/claim_request", "POST", {"p_id": r2}, token=lower)
    check("lower lot porter claims it", sb == 200, f"HTTP {sb}")

    # 'lower_lot' is a LOCATION as well as an AREA, and they are not the same
    # thing. A car going FROM the lower lot TO 510 is a 510 job, because one end
    # is 510 — a 510 porter handles it even though it starts in the lower lot.
    # Easy to get backwards, so it is pinned down here.
    status, req4 = request("/rest/v1/rpc/create_request", "POST",
                           {"p_car_code": "LOCVAREA", "p_origin": "lower_lot",
                            "p_destination": "510"}, token=cashier)
    if status == 200:
        row4 = req4 if isinstance(req4, dict) else req4[0]
        check("lower lot location to 510 is a 510 job",
              row4.get("zone") == "510", f"zone={row4.get('zone')}")
        request("/rest/v1/rpc/cancel_request", "POST", {"p_id": row4["id"]},
                token=manager or cashier)
    else:
        check("lower lot is accepted as a location", False, f"HTTP {status}")

    # And the reverse: a lower lot porter must not take a 510 job.
    status, req3 = request("/rest/v1/rpc/create_request", "POST",
                           {"p_car_code": "UPPER1", "p_origin": "525",
                            "p_destination": "wash"}, token=cashier)
    if status == 200:
        r3 = req3["id"] if isinstance(req3, dict) else req3[0]["id"]
        zone3 = (req3 if isinstance(req3, dict) else req3[0]).get("zone")
        check("525 to wash is routed to 510", zone3 == "510", f"zone={zone3}")

        sc, _ = request("/rest/v1/rpc/claim_request", "POST", {"p_id": r3}, token=lower)
        check("lower lot porter claims a 510 car", sc == 403, f"HTTP {sc}")

        sd, _ = request("/rest/v1/rpc/claim_request", "POST", {"p_id": r3}, token=porter)
        check("510 porter claims it", sd == 200, f"HTTP {sd}")

        request("/rest/v1/rpc/cancel_request", "POST", {"p_id": r3}, token=manager)

    # A manager works both areas.
    if manager:
        se, _ = request("/rest/v1/rpc/unclaim_request", "POST", {"p_id": r2}, token=manager)
        sf, _ = request("/rest/v1/rpc/claim_request", "POST", {"p_id": r2}, token=manager)
        check("manager claims in either area", sf == 200, f"HTTP {sf}")

    request("/rest/v1/rpc/cancel_request", "POST", {"p_id": r2}, token=manager or cashier)


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

        # Say which kind of failure this is. "Data is reachable by someone who
        # should not reach it" is the right alarm for a real breach and badly
        # wrong for a mis-seeded test account — and a suite that raises the same
        # alarm for both teaches people to ignore it.
        if all(name.startswith("fixture:") for name, _, _ in failed):
            print("\nThese are test-data problems, not security failures: the")
            print("accounts are not set up the way the checks assume, so those")
            print("checks were skipped rather than run. Re-run tools/seed.py,")
            print("which corrects test account permissions, then run this again.")
        else:
            print("\nA failure here means data is reachable by someone who should")
            print("not reach it. Do not deploy until this is empty.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
