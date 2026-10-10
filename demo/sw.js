/* BrandSentra service worker: caches the app shell so the console (engine included)
 * opens offline. Live lookups (DoH, crt.sh, RDAP, URLhaus, CertStream) always go to the network. */
const VERSION = "brandsentra-2.5.0";
const SHELL = ["./", "./index.html", "./engine-data.js", "./engine.js", "./app.js", "./features.js", "./discovery.js", "./manifest.webmanifest", "./icon.svg", "./icon-maskable.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin) return;
  event.respondWith(
    fetch(event.request)
      .then((resp) => { const copy = resp.clone(); caches.open(VERSION).then((c) => c.put(event.request, copy)).catch(() => {}); return resp; })
      .catch(() => caches.match(event.request).then((hit) => hit || caches.match("./index.html")))
  );
});
