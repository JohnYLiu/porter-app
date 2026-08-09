// ============================================================================
// Porter Dispatch — admin
// ============================================================================
//
// Two operations, and deliberately only two:
//
//   create_user   creating staff means creating a LOGIN, which needs the secret
//                 key. Nothing reachable with a normal session can do it. Also
//                 attaches that login to a service advisor when asked, since
//                 doing it in two calls can strand an orphaned account.
//   reset_code    user_codes has RLS on with zero policies, so nothing but the
//                 secret key can write there. That is the point of the table.
//
// Everything else John does — ticking permissions, deactivating people, adding
// and retiring advisors — goes straight through the app against the admin RLS
// policies in db/schema.sql. Keeping those OUT of here is on purpose: this
// function holds the key that bypasses every rule in the database, so the less
// it is allowed to do, the smaller the blast radius if it is ever wrong.
//
// DEPLOYMENT: "Verify JWT" should be ON for this one — unlike login, every
// caller already has a session. That check only proves the token is real
// though, not that it belongs to John, so the admin check below is what
// actually matters.
// ============================================================================

import { createClient } from "npm:@supabase/supabase-js@2";

const URL = Deno.env.get("SUPABASE_URL")!;
const SECRET =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? Deno.env.get("PORTER_SECRET_KEY")!;

const EMAIL_DOMAIN = "porter.invalid";
const CODE_LENGTH = 8;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

// Uniform over 0-9. The modulo bias from a 32-bit source is around one part in
// 400 million, which is not the weak link in an 8-digit code.
function randomCode(len = CODE_LENGTH) {
  const d = new Uint32Array(len);
  crypto.getRandomValues(d);
  return [...d].map((n) => n % 10).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  if (!URL || !SECRET) {
    console.error("Missing SUPABASE_URL or secret key in function environment");
    return json({ error: "Admin is misconfigured" }, 500);
  }

  const admin = createClient(URL, SECRET, { auth: { persistSession: false } });

  // --- Who is asking -------------------------------------------------------
  const token = req.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return json({ error: "Not signed in" }, 401);

  const { data: caller, error: callerErr } = await admin.auth.getUser(token);
  if (callerErr || !caller?.user) return json({ error: "Not signed in" }, 401);

  // Read is_admin from the database, not from anything in the token. Token
  // claims are shaped by Supabase Auth, which knows nothing about this app's
  // permissions — trusting a claim here would mean trusting the client.
  const { data: profile } = await admin
    .from("users")
    .select("id, is_admin, active")
    .eq("id", caller.user.id)
    .single();

  if (!profile?.is_admin || !profile.active) {
    return json({ error: "Admins only" }, 403);
  }

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { return json({ error: "Bad request" }, 400); }
  const action = String(body.action ?? "");

  // --------------------------------------------------------------------------
  // create_user
  // --------------------------------------------------------------------------
  if (action === "create_user") {
    const name = String(body.name ?? "").trim();
    if (name.length < 1 || name.length > 60) {
      return json({ error: "Enter a name" }, 400);
    }

    let code = String(body.code ?? "").trim();
    if (code && !new RegExp(`^[0-9]{${CODE_LENGTH}}$`).test(code)) {
      return json({ error: `A code must be exactly ${CODE_LENGTH} digits` }, 400);
    }

    // A code shared by two people would make logins ambiguous — verify_login_code
    // returns whichever row matches first. Generated codes are retried; a code
    // John typed is reported back to him rather than silently changed.
    for (let attempt = 0; attempt < 12; attempt++) {
      const candidate = code || randomCode();
      const { data: clash } = await admin.rpc("verify_login_code", { p_code: candidate });
      if (!clash) { code = candidate; break; }
      if (code) return json({ error: "That code is already in use. Try another." }, 409);
      code = "";
    }
    if (!code) return json({ error: "Could not allocate a code. Try again." }, 500);

    // Random, thrown away, never used to sign in — the login function mints
    // sessions through a single-use token, so there is no replayable password.
    const email = `u-${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}@${EMAIL_DOMAIN}`;
    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email,
      password: crypto.randomUUID() + crypto.randomUUID(),
      email_confirm: true,
    });
    if (createErr || !created?.user) {
      console.error("createUser failed:", createErr?.message);
      return json({ error: "Could not create the login" }, 500);
    }

    const { error: profileErr } = await admin.from("users").insert({
      id: created.user.id,
      name,
      can_issue:       !!body.can_issue,
      can_claim_510:   !!body.can_claim_510,
      can_claim_lower: !!body.can_claim_lower,
      is_manager:      !!body.is_manager,
      is_admin:        false,   // never granted here; see the note below
    });
    if (profileErr) {
      // Do not leave an orphaned login behind that nothing can reach.
      await admin.auth.admin.deleteUser(created.user.id);
      console.error("profile insert failed:", profileErr.message);
      return json({ error: "Could not create the profile" }, 500);
    }

    const { error: codeErr } = await admin.rpc("set_login_code", {
      p_user_id: created.user.id, p_code: code,
    });
    if (codeErr) {
      await admin.auth.admin.deleteUser(created.user.id);
      console.error("set_login_code failed:", codeErr.message);
      return json({ error: "Could not set the code" }, 500);
    }

    // Optionally, this account belongs to a service advisor. Linking here rather
    // than letting the app do it afterwards, because a second call that fails
    // leaves an orphan: a live login, with manager rights, attached to nobody
    // and sitting in the staff list. Rolled back like every other step.
    const advisorId = String(body.advisor_id ?? "");
    if (advisorId) {
      const { error: linkErr } = await admin
        .from("service_advisors")
        .update({ user_id: created.user.id })
        .eq("id", advisorId)
        .is("user_id", null);          // never steal an advisor's existing login
      if (linkErr) {
        await admin.auth.admin.deleteUser(created.user.id);
        console.error("advisor link failed:", linkErr.message);
        return json({ error: "Could not attach the login to that advisor" }, 500);
      }
    }

    // The only time this code is ever readable. It is hashed in the database and
    // cannot be recovered — a forgotten code is reset, not looked up.
    return json({ id: created.user.id, name, code });
  }

  // --------------------------------------------------------------------------
  // reset_code
  // --------------------------------------------------------------------------
  if (action === "reset_code") {
    const userId = String(body.user_id ?? "");
    if (!userId) return json({ error: "Which person?" }, 400);

    const { data: target } = await admin
      .from("users").select("id, name").eq("id", userId).single();
    if (!target) return json({ error: "No such person" }, 404);

    let code = "";
    for (let attempt = 0; attempt < 12; attempt++) {
      const candidate = randomCode();
      const { data: clash } = await admin.rpc("verify_login_code", { p_code: candidate });
      if (!clash) { code = candidate; break; }
    }
    if (!code) return json({ error: "Could not allocate a code. Try again." }, 500);

    const { error } = await admin.rpc("set_login_code", { p_user_id: userId, p_code: code });
    if (error) {
      console.error("set_login_code failed:", error.message);
      return json({ error: "Could not reset the code" }, 500);
    }
    return json({ id: userId, name: target.name, code });
  }

  // --------------------------------------------------------------------------
  // delete_user
  //
  // Only for accounts with NOTHING behind them — a typo, a test account, someone
  // added twice. The moment a person has issued or moved a car, deactivating is
  // the only correct answer: their name is part of the record of who did what,
  // and removing them would either blank that or take the requests with it.
  //
  // The check happens HERE rather than in the interface. A button that isn't
  // drawn is not a rule.
  // --------------------------------------------------------------------------
  if (action === "delete_user") {
    const userId = String(body.user_id ?? "");
    if (!userId) return json({ error: "Which person?" }, 400);
    if (userId === caller.user.id) {
      return json({ error: "You cannot remove your own account" }, 400);
    }

    const { data: target } = await admin
      .from("users").select("id, name, active, is_admin").eq("id", userId).single();
    if (!target) return json({ error: "No such person" }, 404);
    if (target.is_admin) return json({ error: "An admin account cannot be removed here" }, 400);
    if (target.active) {
      return json({ error: "Deactivate them first, so this cannot happen by accident" }, 400);
    }

    const countOf = async (table: string, column: string) => {
      const { count } = await admin
        .from(table).select("id", { count: "exact", head: true }).eq(column, userId);
      return count ?? 0;
    };
    const [issued, claimed, cancelled, acted] = await Promise.all([
      countOf("requests", "issued_by"),
      countOf("requests", "claimed_by"),
      countOf("requests", "cancelled_by"),
      countOf("request_events", "actor_id"),
    ]);
    const history = issued + claimed + cancelled + acted;

    if (history > 0) {
      return json({
        error: `${target.name} appears on ${history} record${history === 1 ? "" : "s"} ` +
               `and cannot be removed. Deactivated is the right state for them — it ` +
               `keeps their name on the cars they handled.`,
      }, 409);
    }

    // Deleting the auth user cascades to public.users and user_codes.
    const { error } = await admin.auth.admin.deleteUser(userId);
    if (error) {
      console.error("deleteUser failed:", error.message);
      return json({ error: "Could not remove that account" }, 500);
    }
    return json({ removed: target.name });
  }

  return json({ error: "Unknown action" }, 400);
});

// NOTE ON is_admin: this function never grants it, and there is no action here
// that can. Admin is the account that controls everyone else's permissions, so
// promoting someone should be a deliberate act at the database, not a checkbox
// one compromised session could tick.
