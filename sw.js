// わが家のこよみ service worker: push notifications + offline shell.
const SHELL = 'koyomi-shell-v31';
const FILES = ['./', './index.html', './manifest.webmanifest', './icon-192.png', './apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(SHELL).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== SHELL).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
// Pages: always ask the network for the newest copy (bypassing the browser's HTTP cache),
// but never leave a blank screen — if the network is slow (e.g. right after returning from another app), show the saved copy.
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  const nav = req.mode === 'navigate';
  e.respondWith((async () => {
    const cached = async () => (await caches.match(req, { ignoreSearch: nav })) || (nav ? ((await caches.match('./index.html')) || (await caches.match('./'))) : null);
    const net = fetch(req, { cache: 'no-cache' }).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(SHELL).then(c => c.put(nav ? './index.html' : req, copy)); }
      return res;
    });
    const timeout = new Promise(r => setTimeout(r, nav ? 3500 : 6000, null));
    try {
      const first = await Promise.race([net, timeout]);
      if (first) return first;
      const c = await cached(); if (c) return c;       // slow network: use the saved page now (it refreshes in the background)
      return await net;
    } catch {
      const c = await cached(); if (c) return c;
      return new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;padding:40px 24px;text-align:center"><p>つながりません。電波のよいところで</p><button onclick="location.reload()" style="font-size:16px;padding:10px 18px;border-radius:999px;border:0;background:#222;color:#fff">もう一度ひらく</button>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
  })());
});

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'わが家のこよみ', {
    body: d.body || '',
    tag: d.tag || 'koyomi',
    renotify: true,
    icon: 'icon-192.png',
    badge: 'icon-192.png',
    data: { url: d.url || './' },
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const target = new URL(e.notification.data?.url || './', self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) { if (c.url.startsWith(self.registration.scope)) { c.focus(); return; } }
    return self.clients.openWindow(target);
  }));
});
