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
// The message names the car — "1A47", "510 → Express" — so a porter can judge
// from the lock screen whether it is worth walking over. That requires an
// encrypted payload, since the spec forbids sending a body in the clear even
// over HTTPS. See encryptPayload below.
//
// A device subscribed before the keys were stored still gets a push, just
// without the car on it. Degrading to the old generic notification is better
// than going silent, and the app fills the keys in on the next sign-in.
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

/* --- Payload encryption (RFC 8291, aes128gcm) -------------------------------
 *
 * A push carrying a body must be encrypted with the subscriber's own keys — the
 * spec forbids sending one in the clear even over HTTPS. So this is not
 * optional if the notification is to name the car.
 *
 * Ported from an implementation checked against the RFC's published test vector
 * BEFORE it was written here: PRK_key, IKM, PRK, CEK, nonce and the complete
 * encrypted body all reproduced byte for byte. That verification mattered
 * because one wrong byte returns 400 from the push service and the notification
 * simply never arrives — indistinguishable from a quiet afternoon, and not
 * something that can be rehearsed once deployed.
 */
const b64uDecode = (s: string) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

async function hmacSha256(key: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

const hkdfExtract = (salt: Uint8Array, ikm: Uint8Array) => hmacSha256(salt, ikm);
const hkdfExpand = async (prk: Uint8Array, info: Uint8Array, length: number) =>
  (await hmacSha256(prk, concat(info, new Uint8Array([1])))).slice(0, length);

async function encryptPayload(plaintext: string, p256dh: string, authSecret: string) {
  const uaPublic = b64uDecode(p256dh);
  const auth     = b64uDecode(authSecret);

  // A fresh sender keypair for every message, as the spec requires.
  const eph = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));

  const uaKey = await crypto.subtle.importKey(
    "raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: uaKey }, eph.privateKey, 256));

  // Combine the ECDH output with the subscription's auth secret.
  const prkKey  = await hkdfExtract(auth, shared);
  const keyInfo = concat(new TextEncoder().encode("WebPush: info\0"), uaPublic, asPublic);
  const ikm     = await hkdfExpand(prkKey, keyInfo, 32);

  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const prk   = await hkdfExtract(salt, ikm);
  const cek   = await hkdfExpand(prk, new TextEncoder().encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdfExpand(prk, new TextEncoder().encode("Content-Encoding: nonce\0"), 12);

  const key = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  // 0x02 is the record delimiter, this being the last and only record.
  const padded = concat(new TextEncoder().encode(plaintext), new Uint8Array([2]));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: 128 }, key, padded));

  // salt | record size | key id length | sender public key | ciphertext
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ct);
}

/* What the notification says. Built here rather than in the service worker,
   because only the server knows WHICH car triggered this particular push. */
/* "Delivered by Marcus T." beats a bare "Delivered": it tells the cashier who
   to ask if something looks wrong, without opening the app. */
async function porterName(id: string) {
  if (!id) return "";
  try {
    const res = await fetch(`${URL_}/rest/v1/users?select=name&id=eq.${id}`, {
      headers: { apikey: SECRET, Authorization: `Bearer ${SECRET}` },
    });
    const rows = await res.json();
    return rows?.[0]?.name ? ` by ${rows[0].name}` : "";
  } catch { return ""; }
}

const LOCATION_LABEL: Record<string, string> = {
  "510": "510", "525": "525", express: "Express",
  drive: "Drive", wash: "Wash", lower_lot: "Lower Lot",
};

function describeRequest(row: Record<string, unknown>) {
  const stop = (s: unknown) => LOCATION_LABEL[String(s)] ?? String(s ?? "?");
  const legs = [stop(row.origin)];
  if (row.via_wash && row.origin !== "wash" && row.destination !== "wash") legs.push("Wash");
  legs.push(stop(row.destination));
  // ASCII "->" rather than the arrow character. U+2192 is three bytes in UTF-8,
  // and iOS decoded them one byte at a time — "Drive ,Üí Lower Lot" on the lock
  // screen. Nothing on this side is wrong, and nothing on this side can fix it,
  // so the notification stays within ASCII. The app's own route display keeps
  // the real arrow, where it renders correctly.
  return {
    title: String(row.car_code ?? "New car request"),
    body: legs.join(" -> "),
  };
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
  let event = "requested";
  let row: Record<string, unknown> = {};
  try {
    const body = await req.json();
    row = body?.record ?? body ?? {};
    event = String(body?.event ?? "requested");
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
  // Two things get announced, to two different audiences.
  //
  //   requested  a car is waiting — goes to whoever asked for that area
  //   delivered  it has arrived   — goes to the cashier who requested it
  //
  // Both are opt-in per person, and both respect "signed in today", so nobody
  // is buzzed on their day off.
  let rpc: string;
  let args: Record<string, unknown>;
  let message: { title: string; body: string };

  if (event === "delivered") {
    const issuedBy = String(row.issued_by ?? "");
    if (!issuedBy) {
      return new Response(JSON.stringify({ skipped: "no issuer on the row" }), { status: 200 });
    }
    rpc = "push_targets_delivered";
    args = { p_user: issuedBy };
    message = { title: String(row.car_code ?? "Car delivered"),
                body: "Delivered" + (await porterName(String(row.claimed_by ?? ""))) };
  } else {
    if (zone !== "510" && zone !== "lower_lot") {
      return new Response(JSON.stringify({ skipped: `unknown zone ${zone}` }), { status: 200 });
    }
    rpc = "push_targets";
    args = { p_zone: zone };
    message = describeRequest(row);
  }

  const targetsRes = await fetch(`${URL_}/rest/v1/rpc/${rpc}`, {
    method: "POST",
    headers: { apikey: SECRET, Authorization: `Bearer ${SECRET}`,
               "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!targetsRes.ok) {
    console.error("push_targets failed:", await targetsRes.text());
    return new Response("Could not look up subscribers", { status: 500 });
  }
  const targets: { endpoint: string; p256dh: string | null; auth: string | null }[] =
    await targetsRes.json();
  if (targets.length === 0) {
    return new Response(JSON.stringify({ event, sent: 0, note: "nobody wants this one" }),
                        { status: 200 });
  }

  let key: CryptoKey;
  try { key = await signingKey(); }
  catch (e) { console.error(String(e)); return new Response("Push is misconfigured", { status: 500 }); }

  const audiences = new Map<string, string>();
  let sent = 0, dropped = 0;
  const failures: string[] = [];

  const payloadText = JSON.stringify(message);
  let plain = 0;

  for (const { endpoint, p256dh, auth } of targets) {
    try {
      const origin = new URL(endpoint).origin;
      if (!audiences.has(origin)) audiences.set(origin, await vapidHeader(origin, key));

      // Subscriptions made before the keys were stored have none. Those still
      // get a push, just without the car on it — degrading to the old generic
      // notification beats going silent while the app fills the keys in.
      const canEncrypt = !!(p256dh && auth);
      if (!canEncrypt) plain++;

      const headers: Record<string, string> = {
        Authorization: audiences.get(origin)!,
        TTL: "300",                       // useless after five minutes anyway
        Urgency: "high",
      };
      let payload: Uint8Array | undefined;

      if (canEncrypt) {
        payload = await encryptPayload(payloadText, p256dh!, auth!);
        headers["Content-Encoding"] = "aes128gcm";
        headers["Content-Type"] = "application/octet-stream";
      } else {
        headers["Content-Length"] = "0";
      }

      const res = await fetch(endpoint, { method: "POST", headers, body: payload });

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
  return new Response(JSON.stringify({ event, zone, sent, dropped, plain, failures }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
});
