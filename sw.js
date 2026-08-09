/* Porter Dispatch — service worker.
 *
 * Two jobs, and only two:
 *
 *   1. Cache the app shell so it opens instantly and survives a dead spot in
 *      the building. Porters lose signal between the lot and the service bay;
 *      the app should still open and show the last queue it saw rather than a
 *      browser error page.
 *
 *   2. On iOS, exist at all — web push later requires the app to have been
 *      added to the Home Screen, which requires this.
 *
 * Network-first, so a reload while online always picks up new code. API calls
 * are never cached: a stale queue that looked live would be worse than no
 * queue at all, and index.html handles the offline case explicitly.
 *
 * Bump CACHE to force old caches out.
 */
/* BUMP THIS ON EVERY DEPLOY. Not just when this file changes — every deploy.
 *
 * A browser only looks for a new service worker by fetching THIS file and
 * comparing bytes. Ship a change to index.html alone and this file is
 * identical, so no update is detected, so the installed app on someone's Home
 * Screen never reloads and keeps running the old code indefinitely. Editing
 * this line is what makes the update mechanism in index.html fire at all.
 */
const CACHE = "porter-v57";

/* Kept separate from CACHE, and NOT cleared on activate. It holds one flag:
   "a notification was tapped, show the queue". A service worker cannot reach
   localStorage, and postMessage only works if it can find the window — which on
   iOS it often cannot. This survives both. */
const INTENT = "porter-intent";

const SHELL = [
  "./",
  "./index.html",
  "./logo.png",
  "./icon-192.png",
  "./icon-512.png",
  "./apple-touch-icon.png",
  "./manifest.webmanifest",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE && k !== INTENT).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* --- Push -----------------------------------------------------------------
 *
 * Messages arrive with NO BODY. A body would have to be encrypted with this
 * device's own keys, and there is nothing worth saying in it: routing already
 * decided that this person hears about this car, so "there is one" is the whole
 * message. Nothing sensitive lands on a lock screen either.
 *
 * iOS requires a visible notification for every push received. Showing nothing
 * — even briefly — gets the subscription revoked, so there is no silent path
 * here on purpose.
 */
self.addEventListener("push", (e) => {
  // The server names the car, because only it knows which one triggered THIS
  // push. Older subscriptions have no encryption keys and arrive empty — those
  // fall back to the generic wording rather than showing nothing.
  let title = "New car request";
  let body  = "Tap to see the queue.";
  try {
    const d = e.data?.json();
    if (d?.title) title = d.title;
    if (d?.body)  body  = d.body;
  } catch { /* not JSON, or no payload — the fallback stands */ }

  // NO `tag`. A shared tag makes each push REPLACE the last one, and iOS
  // honours `renotify` inconsistently — so the first car buzzed and every one
  // after it silently overwrote the notification with no sound. Exactly the
  // failure this app exists to prevent.
  //
  // Untagged, each request is its own line: five cars waiting look like five
  // cars waiting, which is the whole point of a queue.
  e.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: "./icon-192.png",
      badge: "./icon-192.png",
      timestamp: Date.now(),
    })
  );
});

/* Tapping a notification lands on the Queue, not wherever they were before.
 *
 * The notification means "a car is waiting", so the queue is the only screen
 * worth arriving at. Someone who left the app on History last night should not
 * have to find their way back at 7am.
 *
 * Two paths: if the app is already running, focus it and tell it to switch —
 * a focused window does not reload, so a URL alone would do nothing. If it is
 * not running, open it with a hash the app reads on startup.
 */
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    // Leave the flag FIRST, before anything that might not work. On iOS the
    // system often foregrounds an installed app itself, without matchAll ever
    // finding the window and without the URL being read — so neither focus()
    // nor openWindow() is dependable. The app picks this up whenever it next
    // becomes visible, which covers every one of those paths.
    try {
      const c = await caches.open(INTENT);
      const now = String(Date.now());
      await c.put("/__show-queue", new Response(now));
      // Never consumed, never expires. Purely so the sign-in screen can answer
      // "did tapping a notification reach the service worker at all?" — which
      // is otherwise unknowable on a phone with no console.
      await c.put("/__last-click", new Response(now));
    } catch { /* nothing better to do */ }

    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of clients) {
      if (c.url.startsWith(self.location.origin)) {
        c.postMessage({ type: "show-queue" });
        return c.focus();
      }
    }
    return self.clients.openWindow("./#queue");
  })());
});

// So the app can report which worker it is actually running — the difference
// between "the fix does not work" and "the fix has not arrived yet".
self.addEventListener("message", (e) => {
  if (e.data?.type === "version") e.ports?.[0]?.postMessage(CACHE);
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);

  // Anything that isn't our own origin is Supabase. Never cache it — the app
  // needs to know when it is offline, not be handed yesterday's queue.
  if (url.origin !== self.location.origin) return;
  if (e.request.method !== "GET") return;

  // `cache: "reload"` bypasses the browser's OWN http cache before going out.
  //
  // Without it, "network-first" is a lie: GitHub Pages sends max-age=600, so
  // this fetch could be answered from a ten-minute-old copy sitting in Safari's
  // cache, and a shipped update would look like it never happened. That is
  // exactly what it did — the app was network-first and still serving stale
  // code on iOS.
  //
  // This adds no extra requests, since network-first already went out every
  // time. It only stops the http cache short-circuiting the trip.
  e.respondWith(
    fetch(e.request.url, { cache: "reload", credentials: "same-origin" })
      .then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request).then(r => r || caches.match("./index.html")))
  );
});
