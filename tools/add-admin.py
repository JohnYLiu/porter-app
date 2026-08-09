#!/usr/bin/env python3
"""
Porter Dispatch — add one more admin account.

    python3 tools/add-admin.py

WHY THIS IS NOT A BUTTON IN THE APP: the admin Edge Function creates staff, but
it will not grant is_admin, and that is deliberate — admin is the account that
controls everyone else's permissions, so promoting someone should cost a
deliberate act at the database rather than a checkbox one hijacked session
could tick. Creating a login also needs the secret key, which bypasses every
rule in db/schema.sql and must never reach the repo, the app, or a phone.

So it lives here, and the key lives in this process for the length of one
command. The script prompts for it rather than reading a shell variable: an
`export` line stays in your shell history, and this is the one credential that
must not.

Safe to stop at any point — nothing is written until every check has passed,
and a half-made account is rolled back rather than left behind.

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

# Reserved TLD (RFC 2606), guaranteed never to resolve. These addresses are
# internal handles for Supabase Auth; no mail is ever sent and nobody sees them.
EMAIL_DOMAIN = "porter.invalid"
CODE_LENGTH = 8          # mirrors app_code_length() in db/schema.sql

SECRET = ""              # filled in by main(), never written anywhere


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
            raw, status = r.read().decode(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read().decode(), e.code
    except Exception as e:
        return 0, str(e)
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw


def die(msg):
    print(f"\n  {msg}\n", file=sys.stderr)
    sys.exit(1)


def ask_code():
    """Read the code twice, without echoing it, and never from argv.

    Not a command-line argument on purpose: arguments land in shell history and
    in the process list, where anyone on the machine can read them. The code is
    hashed the moment it reaches the database and cannot be read back, so this
    prompt is the only time it exists in the clear.
    """
    while True:
        code = getpass.getpass(f"  {CODE_LENGTH}-digit code: ").strip()
        if not re.fullmatch(rf"[0-9]{{{CODE_LENGTH}}}", code):
            print(f"  Must be exactly {CODE_LENGTH} digits.")
            continue
        if code != getpass.getpass("  Again to confirm: ").strip():
            print("  Those did not match.")
            continue
        return code


def main():
    global SECRET

    print(f"\nPorter Dispatch — add an admin on {URL}\n")

    SECRET = os.environ.get("PORTER_SECRET_KEY", "") or getpass.getpass(
        "  Secret key (paste; it will not be shown): ").strip()
    if not SECRET:
        die("No key given. Find it in Supabase under Project Settings → API Keys,\n"
            "  as the secret key — older projects call it service_role.")
    if SECRET.startswith("sb_publishable_"):
        die("That is the publishable key. This needs the SECRET one, which is the\n"
            "  key that must never enter the repo.")

    status, _ = call("/rest/v1/users?select=id&limit=1")
    if status != 200:
        die(f"Could not reach the database with that key (HTTP {status}).\n"
            "  Check the key, and that db/schema.sql has been applied.")

    status, admins = call("/rest/v1/users?select=name&is_admin=eq.true&order=name.asc")
    if status == 200 and admins:
        print("  Existing admins: " + ", ".join(a["name"] for a in admins) + "\n")

    name = input("  Name as it should appear on requests: ").strip()
    if not (1 <= len(name) <= 60):
        die("A name is required.")

    # Not fatal — two people really can share a first name — but worth a pause,
    # because the usual reason for seeing this is running the script twice.
    status, clash = call(
        f"/rest/v1/users?select=id,is_admin,active&name=eq.{urllib.parse.quote(name)}")
    if status == 200 and clash:
        print(f"\n  Careful: {len(clash)} account(s) already use that exact name.")
        if input("  Add another anyway? [y/N] ").strip().lower() != "y":
            die("Nothing was created.")

    print("\n  Pick their code. It is hashed on arrival — nobody can read it back")
    print("  afterwards, including you, so write it down before you finish here.")
    print("  A forgotten code is reset from the dashboard, not recovered.\n")
    code = ask_code()

    # A shared code makes logins ambiguous: verify_login_code returns whichever
    # row matches first, so two people with one code is two people who might get
    # each other's session.
    status, taken = call("/rest/v1/rpc/verify_login_code", "POST", {"p_code": code})
    if status not in (200, 204):
        die(f"Could not check whether that code is free (HTTP {status}).")
    if taken:
        die("That code is already in use by another account. Pick a different one.")

    # --- From here on something exists, so every failure has to clean up ----
    email = f"u-{secrets.token_hex(8)}@{EMAIL_DOMAIN}"
    status, auth_user = call("/auth/v1/admin/users", "POST", {
        # Random and thrown away. Nothing ever signs in with it — the login
        # function mints sessions through a single-use token, so there is no
        # replayable password stored anywhere.
        "email": email,
        "password": secrets.token_urlsafe(32),
        "email_confirm": True,
    })
    if status not in (200, 201) or not isinstance(auth_user, dict) or "id" not in auth_user:
        die(f"Could not create the login: HTTP {status} {auth_user}")
    uid = auth_user["id"]

    def rollback(why):
        call(f"/auth/v1/admin/users/{uid}", "DELETE")
        die(f"{why}\n  The half-made login was removed. Nothing was left behind.")

    status, _ = call("/rest/v1/users", "POST", {
        "id": uid, "name": name,
        # is_admin does not imply the rest. app_can_issue() and app_is_manager()
        # in db/schema.sql read is_manager and can_issue, not is_admin, so an
        # admin without these could open the dashboard and not much else.
        "is_admin": True, "is_manager": True, "can_issue": True,
        "can_claim_510": True, "can_claim_lower": True,
        "active": True,
    })
    if status not in (200, 201):
        rollback(f"Created the login but not the profile: HTTP {status}")

    status, _ = call("/rest/v1/rpc/set_login_code", "POST",
                     {"p_user_id": uid, "p_code": code})
    if status not in (200, 204):
        rollback(f"Created the account but could not set the code: HTTP {status}")

    print(f"\n  ✓ {name} is an admin and can sign in now.")
    print("    The code is not printed here. If you did not write it down, reset")
    print("    it from the admin dashboard rather than guessing.\n")


if __name__ == "__main__":
    main()
