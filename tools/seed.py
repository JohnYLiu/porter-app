#!/usr/bin/env python3
"""
Porter Dispatch — first-run seeding.

Creates the service advisor list, four throwaway test accounts, and John's admin
account. Run once, on your own machine.

    export PORTER_SECRET_KEY='sb_secret_...'
    python3 tools/seed.py

WHY THIS RUNS LOCALLY AND NOT FROM THE APP: creating a user means creating a
login, which requires the secret key — the one that bypasses every security rule
in db/schema.sql. That key must never reach the repo, the app, or a phone. Here
it lives in one shell variable for the length of one command.

There is also a chicken-and-egg to break: only an admin can create users, and
until this runs there is no admin.

Safe to re-run. Anything already present is skipped rather than duplicated.

No dependencies — standard library only.
"""

import getpass
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

URL = os.environ.get("SUPABASE_URL", "https://txnijhgfitfklyjativk.supabase.co").rstrip("/")
SECRET = os.environ.get("PORTER_SECRET_KEY", "")

# Reserved TLD (RFC 2606) that is guaranteed never to resolve. These addresses
# are internal handles for Supabase Auth; no mail is ever sent and staff never
# see them.
EMAIL_DOMAIN = "porter.invalid"

# Placeholder advisors. Real names go in later through the admin dashboard —
# that is the whole point of the dashboard, and nothing here needs a developer.
#
# Colours are dark enough to carry white text and far enough apart to survive
# a cracked phone screen in daylight. Past eight or ten advisors this stops
# working and the display needs rethinking.
ADVISORS = [
    ("Alex Rivera",   "#1d4ed8"),
    ("Dana Brooks",   "#c2410c"),
    ("Sam Okafor",    "#15803d"),
    ("Priya Nair",    "#7e22ce"),
    ("Chris Vaughn",  "#b91c1c"),
    ("Jordan Ellis",  "#0f766e"),
]

# Throwaway accounts, with codes chosen to be obviously fake. Phase B of the
# security tests logs in as these to prove the roles are enforced by the
# database rather than by hidden buttons.
#
# DEACTIVATE THESE BEFORE THE PILOT. A live account with the code 11111111
# undoes every protection in schema.sql. It is a step in the runbook, not
# something either of us should be relying on memory for.
TEST_USERS = [
    # name              code        issue  claim  manager
    ("Test Porter",     "11111111", False, True,  False),
    ("Test Porter Two", "22222222", False, True,  False),
    ("Test Cashier",    "33333333", True,  False, False),
    ("Test Manager",    "44444444", False, False, True),
]


def call(path, method="GET", body=None):
    headers = {
        "apikey": SECRET,
        "Authorization": f"Bearer {SECRET}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        status = e.code
    except Exception as e:
        return 0, str(e)
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw


def die(msg):
    print(f"\n  {msg}", file=sys.stderr)
    sys.exit(1)


def create_user(name, code, can_issue, can_claim, is_manager, is_admin=False):
    """Create the auth login, the profile row, and the hashed code."""
    status, existing = call(f"/rest/v1/users?select=id,name&name=eq.{urllib.parse.quote(name)}")
    if status == 200 and existing:
        print(f"  · {name} already exists — skipped")
        return existing[0]["id"]

    # The auth password is random and thrown away. Nothing ever signs in with
    # it: the login function mints sessions through a single-use token instead,
    # so there is no replayable password stored anywhere.
    email = f"u-{secrets.token_hex(8)}@{EMAIL_DOMAIN}"
    status, auth_user = call("/auth/v1/admin/users", "POST", {
        "email": email,
        "password": secrets.token_urlsafe(32),
        "email_confirm": True,
    })
    if status not in (200, 201) or not isinstance(auth_user, dict) or "id" not in auth_user:
        die(f"Could not create the login for {name}: HTTP {status} {auth_user}")

    uid = auth_user["id"]

    status, _ = call("/rest/v1/users", "POST", {
        "id": uid, "name": name,
        "can_issue": can_issue, "can_claim": can_claim,
        "is_manager": is_manager, "is_admin": is_admin,
    })
    if status not in (200, 201):
        die(f"Created a login for {name} but could not create the profile: HTTP {status}")

    status, _ = call("/rest/v1/rpc/set_login_code", "POST", {"p_user_id": uid, "p_code": code})
    if status not in (200, 204):
        die(f"Created {name} but could not set their code: HTTP {status}")

    print(f"  ✓ {name}")
    return uid


def main():
    print(f"Porter Dispatch — seeding {URL}\n")

    if not SECRET:
        die("PORTER_SECRET_KEY is not set.\n"
            "  Find it in Supabase under Project Settings → API Keys, as the\n"
            "  secret key (older projects call it service_role). Then:\n\n"
            "    export PORTER_SECRET_KEY='sb_secret_...'\n")

    if SECRET.startswith("sb_publishable_"):
        die("That is the publishable key, not the secret one. Seeding needs the\n"
            "  secret key, which is the one that must never enter the repo.")

    status, _ = call("/rest/v1/users?select=id&limit=1")
    if status != 200:
        die(f"Could not reach the database with that key (HTTP {status}).\n"
            "  Check the key is right and that db/schema.sql has been applied.")

    # --- Advisors ---------------------------------------------------------
    print("Service advisors:")
    for i, (name, color) in enumerate(ADVISORS):
        status, existing = call(
            f"/rest/v1/service_advisors?select=id&name=eq.{urllib.parse.quote(name)}")
        if status == 200 and existing:
            print(f"  · {name} already exists — skipped")
            continue
        status, _ = call("/rest/v1/service_advisors", "POST",
                         {"name": name, "color": color, "sort_order": i})
        if status not in (200, 201):
            die(f"Could not create advisor {name}: HTTP {status}")
        print(f"  ✓ {name}  {color}")

    # --- Test accounts ----------------------------------------------------
    print("\nTest accounts:")
    for name, code, issue, claim, manager in TEST_USERS:
        create_user(name, code, issue, claim, manager)

    # --- Admin ------------------------------------------------------------
    print("\nYour admin account.")
    print("Pick an 8-digit code. It is hashed immediately — nobody can read it")
    print("back afterwards, including you. A forgotten code is reset, not")
    print("recovered, so put it somewhere safe now.\n")

    status, existing = call("/rest/v1/users?select=id&is_admin=eq.true")
    if status == 200 and existing:
        print("  · An admin account already exists — skipped")
    else:
        while True:
            code = getpass.getpass("  8-digit code: ").strip()
            if not re.fullmatch(r"[0-9]{8}", code):
                print("  Must be exactly 8 digits.")
                continue
            if code == getpass.getpass("  Again to confirm: ").strip():
                break
            print("  Those did not match.")

        name = input("  Your name as it should appear on requests: ").strip() or "John"
        create_user(name, code, can_issue=True, can_claim=True,
                    is_manager=True, is_admin=True)

    print("\nDone.\n")
    print("Test account codes — throwaway, for the security tests only:")
    for name, code, *_ in TEST_USERS:
        print(f"  {code}  {name}")
    print("\nDeactivate all four before the pilot. A live account with the code")
    print("11111111 undoes everything db/schema.sql is protecting.")


if __name__ == "__main__":
    main()
