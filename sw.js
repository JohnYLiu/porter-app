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
const CACHE = "porter-v13";

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
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
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
