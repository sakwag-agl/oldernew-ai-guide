const scope = new URL(self.registration.scope);
const contentPath = `${scope.pathname}content/`;
const bundleCache = new Map();
const MAX_CACHED_BUNDLES = 3;

function openStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('oldernew-guide-access', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('session');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function readSession() {
  const db = await openStore();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('session', 'readonly');
    const request = transaction.objectStore('session').get('current');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    transaction.oncomplete = () => db.close();
  });
}

async function writeSession(value) {
  const db = await openStore();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('session', 'readwrite');
    transaction.objectStore('session').put(value, 'current');
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => reject(transaction.error);
  });
}

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('message', event => {
  const port = event.ports?.[0];
  if (!port) return;
  event.waitUntil((async () => {
    try {
      if (event.data?.type === 'unlock') {
        const { key, manifest } = event.data;
        if (!key || manifest?.version !== 1 || !manifest.files?.['index.html']) throw new Error('invalid_unlock');
        await writeSession({ key, manifest, expires: Date.now() + 8 * 60 * 60 * 1000 });
        port.postMessage({ ok: true });
      } else if (event.data?.type === 'status') {
        const session = await readSession();
        port.postMessage({ authorized: Boolean(session && session.expires > Date.now()) });
      } else if (event.data?.type === 'logout') {
        await writeSession(null);
        bundleCache.clear();
        port.postMessage({ ok: true });
      }
    } catch {
      port.postMessage({ ok: false });
    }
  })());
});

async function getBundle(name) {
  if (bundleCache.has(name)) return bundleCache.get(name);
  const promise = fetch(new URL(name, scope), { cache: 'force-cache' })
    .then(response => {
      if (!response.ok) throw new Error(`asset_${response.status}`);
      return response.arrayBuffer();
    });
  bundleCache.set(name, promise);
  if (bundleCache.size > MAX_CACHED_BUNDLES) bundleCache.delete(bundleCache.keys().next().value);
  try { return await promise; }
  catch (error) { bundleCache.delete(name); throw error; }
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== scope.origin || !url.pathname.startsWith(contentPath)) return;
  event.respondWith((async () => {
    const session = await readSession().catch(() => null);
    if (!session || session.expires <= Date.now()) {
      if (event.request.mode === 'navigate') {
        const target = encodeURIComponent(`content/${url.pathname.slice(contentPath.length)}${url.search}`);
        return Response.redirect(new URL(`./index.html?next=${target}`, scope), 302);
      }
      return new Response('Password required', { status: 401, headers: { 'Cache-Control': 'no-store' } });
    }
    let name;
    try { name = decodeURIComponent(url.pathname.slice(contentPath.length)) || 'index.html'; }
    catch { return new Response('Bad path', { status: 400 }); }
    if (name.endsWith('/')) name += 'index.html';
    const file = session.manifest.files[name];
    if (!file) return new Response('Not found', { status: 404 });
    try {
      const bundle = await getBundle(file.bundle);
      const sealed = new Uint8Array(bundle, file.offset, file.length);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: sealed.slice(0, 12) }, session.key, sealed.slice(12)
      );
      return new Response(plaintext, {
        status: 200,
        headers: {
          'Content-Type': file.type,
          'Cache-Control': 'private, no-store',
          'X-Robots-Tag': 'noindex, nofollow, noarchive',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    } catch {
      return new Response('Unable to open file', { status: 502, headers: { 'Cache-Control': 'no-store' } });
    }
  })());
});
