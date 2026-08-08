// ============================================================================
// Porter Dispatch — notify
// ============================================================================
//
// Sends a push to everyone who should hear about a newly issued car.
//
// Called by a Supabase Database Webhook on INSERT into public.requests. The
// webhook hands over the new row; this function reads its `zone`, asks the
// database who works that area and is signed in today, and pushes to each of
// their devices.
//
// NO PAYLOAD IS SENT. A push body has to be encrypted with each subscriber's
// own keys — real crypto, and crypto that cannot be tested from here. There is
// also nothing worth saying: routing already decided this person hears about
// this car, so the service worker says "New car request" and tapping it opens
// the queue. Nothing lands on a lock screen either.
//
// That leaves one piece of cryptography: a VAPID JWT, signed ES256, which Web
// Crypto does natively.
//
// DEPLOYMENT
//   Verify JWT: OFF. The caller is a database webhook, not a signed-in person.
//   Secrets:
//     VAPID_PRIVATE_JWK   the JSON written to your Desktop when the keys were
//                         generated. Never in this repo.
//     VAPID_SUBJECT       mailto:you@example.com — push services want a way to
//                         contact whoever is sending.
//     NOTIFY_SECRET       any long random string. The webhook sends it as a
//                         header and this function refuses anything without it,
//                         since Verify JWT is off and the URL is public.
// ============================================================================

const VAPID_PUBLIC =
  "BAILS8UFrR9WZXmQB0O4tl_dnEvQl52mQt7muNsA7CurRpifK5QcJVolnd7O3lwwFVphvGhFRbq7yAb0eFB9uHM";

const URL_ = Deno.env.get("SUPABASE_URL")!;
const SECRET =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? Deno.env.get("PORTER_SECRET_KEY")!;
const VAPID_JWK = Deno.env.get("VAPID_PRIVATE_JWK");
const VAPID_SUBJECT = Deno.env.get("VAPID_SUBJECT") ?? "mailto:admin@porter.invalid";
const NOTIFY_SECRET = Deno.env.get("NOTIFY_SECRET");

const b64u = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

async function signingKey() {
  if (!VAPID_JWK) throw new Error("VAPID_PRIVATE_JWK is not set");
  return await crypto.subtle.importKey(
    "jwk", JSON.parse(VAPID_JWK),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  );
}

/* A VAPID token is per-origin, not per-subscription, so it is built once and
 * reused across every endpoint on the same push service. Twelve hours; the spec
 * caps it at 24 and being near the edge invites clock-skew rejections. */
async function vapidHeader(audience: string, key: CryptoKey) {
  const header = b64u(new TextEncoder().encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(new TextEncoder().encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
    sub: VAPID_SUBJECT,
  })));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, key,
    new TextEncoder().encode(`${header}.${claims}`),
  );
  // Web Crypto returns the raw r||s pair, which is exactly what JWS wants —
  // no DER unwrapping needed.
  return `vapid t=${header}.${claims}.${b64u(signature)}, k=${VAPID_PUBLIC}`;
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  // Verify JWT is off for this function, so its URL is callable by anyone who
  // finds it. This shared secret is the only thing standing in the way of
  // somebody buzzing every phone in the dealership at 3am.
  if (!NOTIFY_SECRET || req.headers.get("x-notify-secret") !== NOTIFY_SECRET) {
    return new Response("Forbidden", { status: 403 });
  }

  let zone = "";
  try {
    const body = await req.json();
    // Database Webhooks post { type, table, schema, record, old_record }.
    const row = body?.record ?? body ?? {};
    zone = String(row.zone ?? "");

    // `zone` is a generated column, so it should be in the row — but if the
    // webhook ever ships without it, recomputing from the two locations is the
    // same rule and beats dropping the notification on the floor.
    if (!zone && (row.origin || row.destination)) {
      zone = ["510", "525"].includes(row.origin) ||
             ["510", "525"].includes(row.destination) ? "510" : "lower_lot";
    }
  } catch {
    return new Response("Bad request", { status: 400 });
  }
  if (zone !== "510" && zone !== "lower_lot") {
    return new Response(JSON.stringify({ skipped: `unknown zone ${zone}` }), { status: 200 });
  }

  // Who works this area and is signed in today. Both halves matter: the areas
  // route, and "signed in today" keeps someone's day off quiet.
  const targetsRes = await fetch(`${URL_}/rest/v1/rpc/push_targets`, {
    method: "POST",
    headers: { apikey: SECRET, Authorization: `Bearer ${SECRET}`,
               "Content-Type": "application/json" },
    body: JSON.stringify({ p_zone: zone }),
  });
  if (!targetsRes.ok) {
    console.error("push_targets failed:", await targetsRes.text());
    return new Response("Could not look up subscribers", { status: 500 });
  }
  const targets: { endpoint: string }[] = await targetsRes.json();
  if (targets.length === 0) {
    return new Response(JSON.stringify({ sent: 0, note: "nobody on shift for this area" }),
                        { status: 200 });
  }

  let key: CryptoKey;
  try { key = await signingKey(); }
  catch (e) { console.error(String(e)); return new Response("Push is misconfigured", { status: 500 }); }

  const audiences = new Map<string, string>();
  let sent = 0, dropped = 0;
  const failures: string[] = [];

  for (const { endpoint } of targets) {
    try {
      const origin = new URL(endpoint).origin;
      if (!audiences.has(origin)) audiences.set(origin, await vapidHeader(origin, key));

      const res = await fetch(endpoint, {
        method: "POST",
        headers: {
          Authorization: audiences.get(origin)!,
          TTL: "300",                       // useless after five minutes anyway
          "Content-Length": "0",
          Urgency: "high",
        },
      });

      if (res.status === 404 || res.status === 410) {
        // The push service says this device is gone for good. Without pruning,
        // dead endpoints pile up and every send gets slower for everyone.
        await fetch(`${URL_}/rest/v1/rpc/forget_push_endpoint`, {
          method: "POST",
          headers: { apikey: SECRET, Authorization: `Bearer ${SECRET}`,
                     "Content-Type": "application/json" },
          body: JSON.stringify({ p_endpoint: endpoint }),
        });
        dropped++;
      } else if (res.ok) {
        sent++;
      } else {
        // Reported rather than swallowed: a 401 here means the VAPID key is
        // wrong, and silence would look exactly like "nobody was on shift".
        failures.push(`${res.status} ${(await res.text()).slice(0, 120)}`);
      }
    } catch (e) {
      failures.push(String(e).slice(0, 120));
    }
  }

  if (failures.length) console.error("push failures:", failures);
  return new Response(JSON.stringify({ zone, sent, dropped, failures }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
});
