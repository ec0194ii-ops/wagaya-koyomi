// わが家のこよみ API. No third-party dependencies; the service-role key stays in the Supabase runtime.
// All tables deny direct access (RLS on, no policies); this function is the only way in, behind a family login.
const ORIGINS = ['https://ec0194ii-ops.github.io', ...(Deno.env.get('KOYOMI_EXTRA_ORIGINS') || '').split(',').map(x => x.trim()).filter(Boolean)];
const BASE = Deno.env.get('SUPABASE_URL')!;
const ADMIN = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const MEMBERS: Record<string, string> = { papa: 'パパ', mama: 'ママ' };
const WRITABLE = ['event', 'todo', 'shop', 'wish', 'garbage', 'place'];
const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(b as ArrayBuffer), x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => Uint8Array.from(s.match(/../g) || [], x => parseInt(x, 16));
const sha = async (s: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const fail = (status: number, message: string): never => { throw Object.assign(new Error(message), { status }); };

async function db(table: string, method = 'GET', query = '', data?: unknown) {
  const r = await fetch(`${BASE}/rest/v1/${table}?${query}`, {
    method,
    headers: { apikey: ADMIN, Authorization: `Bearer ${ADMIN}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  if (!r.ok) { if (r.status === 409) fail(409, 'conflict'); fail(503, 'storage_unavailable'); }
  return await r.json();
}
async function limit(scope: string, maximum: number, ms = 600000) {
  const key = await sha(`${scope}:${Math.floor(Date.now() / ms)}`);
  for (let n = 0; n < 8; n++) {
    const [row] = await db('koyomi_limits', 'GET', `bucket_hash=eq.${key}`);
    if (!row) {
      try { await db('koyomi_limits', 'POST', '', { bucket_hash: key, attempts: 1 }); return; }
      catch (e) { if ((e as any).status === 409) continue; throw e; }
    }
    if (row.attempts >= maximum) fail(429, 'too_many_attempts');
    const changed = await db('koyomi_limits', 'PATCH', `bucket_hash=eq.${key}&attempts=eq.${row.attempts}`, { attempts: row.attempts + 1 });
    if (changed.length) return;
  }
  fail(429, 'try_again_later');
}
async function derive(password: string, salt: string, iterations: number) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unhex(salt), iterations, hash: 'SHA-256' }, key, 256));
}
function equal(a: string, b: string) { let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; }
function text(x: unknown, max: number, required = false) {
  if (typeof x !== 'string' || x.length > max || (required && !x.trim())) fail(400, 'invalid_text');
  return x as string;
}
function httpsUrl(x: unknown) {
  const s = text(x, 2000);
  try { if (new URL(s).protocol !== 'https:') fail(400, 'https_required'); } catch { fail(400, 'invalid_url'); }
  return s;
}
// Payloads are plain JSON objects of strings, numbers, booleans and arrays of those; size-capped.
function clean(v: unknown, depth = 0): unknown {
  if (depth > 4) fail(400, 'too_deep');
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') { if (!Number.isFinite(v)) fail(400, 'invalid_number'); return v; }
  if (typeof v === 'string') return text(v, 5000);
  if (Array.isArray(v)) { if (v.length > 200) fail(400, 'too_long'); return v.map(x => clean(x, depth + 1)); }
  if (typeof v === 'object') {
    const o: Record<string, unknown> = {};
    const keys = Object.keys(v as object); if (keys.length > 60) fail(400, 'too_many_fields');
    for (const k of keys) { if (!/^[A-Za-z0-9_]{1,40}$/.test(k)) fail(400, 'invalid_field'); o[k] = clean((v as any)[k], depth + 1); }
    return o;
  }
  fail(400, 'invalid_value');
}
function payload(kind: string, p: unknown) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) fail(400, 'invalid_payload');
  const out = clean(p) as Record<string, unknown>;
  if (JSON.stringify(out).length > 20000) fail(413, 'payload_too_large');
  const title = (kind === 'shop' ? out.name : out.title) as unknown;
  if (['event', 'todo', 'shop', 'wish'].includes(kind)) text(title, 300, true);
  if (kind === 'event' && !/^\d{4}-\d{2}-\d{2}$/.test(String(out.date || ''))) fail(400, 'invalid_date');
  if (out.url) out.url = httpsUrl(out.url);
  return out;
}

/* ---------- Web Push (RFC 8291 + VAPID), no third-party code ---------- */
const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b as ArrayBuffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const cat = (...a: Uint8Array[]) => { const n = a.reduce((x, y) => x + y.length, 0), o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number) { const k = await crypto.subtle.importKey('raw', ikm as any, 'HKDF', false, ['deriveBits']); return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt as any, info: info as any }, k, len * 8)); }
let vapidCache: { pub: string; key: CryptoKey } | null = null;
async function vapid() {
  if (vapidCache) return vapidCache;
  let [row] = await db('koyomi_push_config', 'GET', 'id=eq.true');
  if (!row) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey), pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
    try { await db('koyomi_push_config', 'POST', '', { id: true, public_key: pub, private_jwk: jwk }); } catch (e) { if ((e as any).status !== 409) throw e; }
    [row] = await db('koyomi_push_config', 'GET', 'id=eq.true');
  }
  const key = await crypto.subtle.importKey('jwk', row.private_jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  vapidCache = { pub: row.public_key, key }; return vapidCache;
}
async function vapidJwt(endpoint: string) {
  const { pub, key } = await vapid(); const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))), c = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://ec0194ii-ops.github.io/' })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + c));
  return `vapid t=${h}.${c}.${b64u(sig)}, k=${pub}`;
}
async function encryptPush(p256dh: string, authSecret: string, body: string) {
  const ua = unb64u(p256dh), auth = unb64u(authSecret);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey) as ArrayBuffer);
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey } as any, as.privateKey, 256));
  const ikm = await hkdf(auth, secret, cat(enc.encode('WebPush: info\0'), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16), nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const k = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, k, cat(enc.encode(body), new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([65]), asPub, ct);
}
async function sendPush(exceptMember: string | null, body: string, tag = 'koyomi-change') {
  let subs = await db('koyomi_push_subs', 'GET', 'select=endpoint,member,p256dh,auth' + (exceptMember ? `&member=neq.${exceptMember}` : ''));
  if (!subs.length) return;
  const ok: string[] = [];
  for (const m of [...new Set(subs.map((x: any) => x.member))] as string[]) { try { await limit(`push:${m}:${tag}`, 30); ok.push(m); } catch { /* quiet when flooded */ } }
  subs = subs.filter((x: any) => ok.includes(x.member));
  const msg = JSON.stringify({ title: 'わが家のこよみ', body, url: './', tag });
  await Promise.all(subs.map(async (s: any) => {
    try {
      const r = await fetch(s.endpoint, { method: 'POST', headers: { Authorization: await vapidJwt(s.endpoint), TTL: '86400', Urgency: 'normal', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream' }, body: await encryptPush(s.p256dh, s.auth, msg) });
      if (r.status === 404 || r.status === 410) await db('koyomi_push_subs', 'DELETE', `endpoint=eq.${encodeURIComponent(s.endpoint)}`);
    } catch { /* one bad device never blocks the others */ }
  }));
}
const later = (p: Promise<unknown>) => { const w = (globalThis as any).EdgeRuntime?.waitUntil; if (w) w.call((globalThis as any).EdgeRuntime, p.catch(() => {})); else return p.catch(() => {}); };
const md = (k: unknown) => { const m = String(k || '').match(/^\d{4}-(\d{2})-(\d{2})$/); return m ? `${+m[1]}/${+m[2]}` : ''; };
function describe(kind: string, p: any, old: any, created: boolean, deleted: boolean) {
  const t = kind === 'shop' ? p.name : p.title;
  const label = kind === 'event' ? `予定「${t}」${p.date ? `（${md(p.date)}）` : ''}` : kind === 'todo' ? `やること「${t}」` : kind === 'shop' ? `買い物「${t}」` : kind === 'wish' ? `やりたいこと「${t}」` : '';
  if (!label) return '';
  if (deleted) return `${label}を消しました`;
  if (created) return `${label}を追加しました`;
  if (kind === 'todo' && p.done && !old?.done) return `「${t}」を終わらせました`;
  if (kind === 'shop' && p.done !== old?.done) return '';      // ticking items off the list stays quiet
  if (kind === 'wish' && p.done && !old?.done) return `やりたいこと「${t}」が叶いました`;
  if (kind === 'event') return `${label}を変更しました`;
  return '';
}

/* ---------- morning summary ---------- */
const DOW = ['日', '月', '火', '水', '木', '金', '土'];
function jstKey(offsetDays = 0) { const d = new Date(Date.now() + 9 * 3600000 + offsetDays * 86400000); return d.toISOString().slice(0, 10); }
const keyDow = (k: string) => new Date(k + 'T00:00:00Z').getUTCDay();
function occursOn(e: any, k: string) {
  if (!e.date) return false;
  if (e.repeat === 'weekly') { if (k < e.date || (e.until && k > e.until)) return false; if (Array.isArray(e.skip) && e.skip.includes(k)) return false; return keyDow(k) === keyDow(e.date); }
  const end = e.endDate && e.endDate > e.date ? e.endDate : e.date;
  return k >= e.date && k <= end;
}
async function morningText() {
  const rows = await db('koyomi_items', 'GET', 'select=kind,payload&deleted_at=is.null&kind=in.(event,todo,garbage,info)&limit=5000');
  const today = jstKey(0), tmr = jstKey(1);
  const evs = rows.filter((r: any) => r.kind === 'event' && occursOn(r.payload, today)).map((r: any) => r.payload)
    .sort((a: any, b: any) => (a.time || '99').localeCompare(b.time || '99'));
  const due = rows.filter((r: any) => r.kind === 'todo' && !r.payload.done && r.payload.due && r.payload.due <= tmr).map((r: any) => r.payload);
  const d = new Date(today + 'T00:00:00Z'), nth = Math.ceil(d.getUTCDate() / 7), dow = d.getUTCDay();
  const garb = rows.filter((r: any) => r.kind === 'garbage' && Array.isArray(r.payload.weekdays) && r.payload.weekdays.includes(dow) && (!Array.isArray(r.payload.weeks) || !r.payload.weeks.length || r.payload.weeks.includes(nth))).map((r: any) => r.payload.kind);
  const wxRow = rows.find((r: any) => r.kind === 'info' && r.payload.key === 'weather');
  const wx = wxRow && Array.isArray(wxRow.payload.days) ? wxRow.payload.days.find((x: any) => x.date === today) : null;
  const parts: string[] = [];
  parts.push(`${+today.slice(5, 7)}/${+today.slice(8, 10)}（${DOW[dow]}）`);
  if (wx) parts.push(`${wx.icon || ''}${wx.text || ''} ${wx.hi ?? '-'}°/${wx.lo ?? '-'}°${wx.pop != null ? ' ☂' + wx.pop + '%' : ''}`);
  parts.push(evs.length ? '予定：' + evs.slice(0, 4).map((e: any) => (e.time ? e.time + ' ' : '') + e.title).join('、') + (evs.length > 4 ? ` ほか${evs.length - 4}件` : '') : '予定なし');
  if (due.length) parts.push('締切：' + due.slice(0, 3).map((t: any) => t.title + (t.due < today ? '（期限切れ）' : t.due === today ? '（今日）' : '（明日）')).join('、'));
  if (garb.length) parts.push('🗑 ' + garb.join('・') + 'の日');
  return parts.join('\n');
}

async function readBody(req: Request) {
  const reader = req.body?.getReader(); if (!reader) fail(400, 'body_required');
  const chunks: Uint8Array[] = []; let size = 0;
  while (true) { const { done, value } = await reader!.read(); if (done) break; size += value.length; if (size > 200000) { await reader!.cancel(); fail(413, 'body_too_large'); } chunks.push(value); }
  try { return JSON.parse(new TextDecoder().decode(cat(...chunks))); } catch { fail(400, 'invalid_json'); }
}

async function ogImage(target: string) {
  const host = new URL(target).hostname;
  if (/^(localhost|0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(host) || host.endsWith('.local') || host.endsWith('.internal') || host.startsWith('[') || !host.includes('.')) fail(400, 'invalid_url');
  const c = new AbortController(); const timer = setTimeout(() => c.abort(), 7000);
  try {
    const r = await fetch(target, { signal: c.signal, redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0 (compatible; KoyomiPhoto/1.0)', Accept: 'text/html' } });
    if (!r.ok || !r.body) return '';
    const reader = r.body.getReader(); const dec = new TextDecoder(); let html = '', n = 0;
    while (n < 400000) { const { done, value } = await reader.read(); if (done) break; n += value.length; html += dec.decode(value, { stream: true }); if (/<\/head>/i.test(html)) break; }
    reader.cancel().catch(() => {});
    const tags = html.match(/<meta\b[^>]*>/gi) || [];
    const pick = (re: RegExp) => { for (const t of tags) { if (re.test(t)) { const m = t.match(/content\s*=\s*["']([^"']+)["']/i); if (m) return m[1]; } } return ''; };
    let img = pick(/(property|name)\s*=\s*["']og:image(:secure_url)?["']/i) || pick(/(property|name)\s*=\s*["']twitter:image(:src)?["']/i);
    if (img) { img = new URL(img.replace(/&amp;/g, '&'), r.url || target).toString(); if (!img.startsWith('https://') || img.length > 2000) img = ''; }
    return img;
  } catch { return ''; } finally { clearTimeout(timer); }
}

Deno.serve(async req => {
  const origin = req.headers.get('Origin');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json', 'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': ORIGINS.includes(origin || '') ? origin! : ORIGINS[0],
    'Access-Control-Allow-Headers': 'authorization,content-type,apikey,x-client-info',
    'Access-Control-Allow-Methods': 'POST,OPTIONS', Vary: 'Origin', 'X-Content-Type-Options': 'nosniff',
  };
  const response = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers });
  try {
    if (origin && !ORIGINS.includes(origin)) fail(403, 'origin_not_allowed');
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers });
    if (req.method !== 'POST') fail(405, 'post_required');
    if ((req.headers.get('Content-Type') || '').split(';')[0] !== 'application/json') fail(415, 'json_required');
    const body = await readBody(req);
    if (!body || typeof body !== 'object') fail(400, 'invalid_body');

    if (body.action === 'morning') {
      // Called once a day by the database scheduler (pg_cron); authorised by a secret whose hash is in koyomi_config.
      const secret = req.headers.get('x-koyomi-cron') || '';
      const [cfg] = await db('koyomi_config', 'GET', 'id=eq.true&select=cron_hash');
      if (!cfg?.cron_hash || !/^[0-9a-f]{64}$/.test(secret) || !equal(await sha(secret), cfg.cron_hash)) fail(401, 'not_allowed');
      const msg = await morningText();
      if (msg) await sendPush(null, msg, 'koyomi-morning');
      return response({ ok: true, msg });
    }

    if (body.action === 'login') {
      if (!MEMBERS[body.member]) fail(400, 'invalid_member');
      const password = text(body.password, 256, true);
      await limit('login:global', 60);
      const ip = req.headers.get('x-forwarded-for')?.split(',').at(-1)?.trim() || 'unknown';
      await limit(`login:ip:${ip}`, 10);
      const [cfg] = await db('koyomi_config', 'GET', 'id=eq.true');
      if (!cfg) fail(503, 'not_configured');
      if (!equal(await derive(password, cfg.password_salt, cfg.password_iterations), cfg.password_hash)) fail(401, 'wrong_password');
      const token = hex(crypto.getRandomValues(new Uint8Array(32)));
      const expires_at = new Date(Date.now() + 180 * 86400000).toISOString();   // stay signed in on this phone for ~6 months
      await db('koyomi_sessions', 'POST', '', { token_hash: await sha(token), member: body.member, expires_at });
      return response({ token, expires_at, member: body.member });
    }

    const token = (req.headers.get('Authorization') || '').replace(/^Bearer /, '');
    if (!/^[0-9a-f]{64}$/.test(token)) fail(401, 'sign_in_required');
    const actor = await sha(token);
    const [session] = await db('koyomi_sessions', 'GET', `token_hash=eq.${actor}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}`);
    if (!session) fail(401, 'session_expired');
    const who = MEMBERS[session.member] || '家族';

    if (body.action === 'logout') {
      await db('koyomi_sessions', 'PATCH', `token_hash=eq.${actor}`, { expires_at: new Date(0).toISOString() });
      return response({ ok: true });
    }
    if (body.action === 'snapshot') {
      const items: unknown[] = [];
      for (let offset = 0; ; offset += 1000) {
        const page = await db('koyomi_items', 'GET', `select=id,kind,payload,version,updated_by,updated_at&deleted_at=is.null&order=id&limit=1000&offset=${offset}`);
        items.push(...page); if (page.length < 1000) break; if (offset >= 20000) fail(503, 'dataset_too_large');
      }
      return response({ items, member: session.member, now: new Date().toISOString() });
    }
    if (body.action === 'push_key') return response({ key: (await vapid()).pub });
    if (body.action === 'push_subscribe') {
      await limit(`push-sub:${actor}`, 20);
      const sub = body.subscription || {};
      const ep = text(sub.endpoint, 1000, true), p256dh = text(sub.keys?.p256dh, 200, true), au = text(sub.keys?.auth, 100, true);
      if (!ep.startsWith('https://')) fail(400, 'invalid_endpoint');
      await db('koyomi_push_subs', 'DELETE', `endpoint=eq.${encodeURIComponent(ep)}`);
      await db('koyomi_push_subs', 'POST', '', { endpoint: ep, member: session.member, p256dh, auth: au });
      return response({ ok: true });
    }
    if (body.action === 'push_unsubscribe') { const ep = text(body.endpoint, 1000, true); await db('koyomi_push_subs', 'DELETE', `endpoint=eq.${encodeURIComponent(ep)}`); return response({ ok: true }); }
    if (body.action === 'push_test') { await limit(`push-test:${actor}`, 5); await sendPush(null, `${who}のスマホで通知が使えるようになりました`, 'koyomi-test'); return response({ ok: true }); }
    if (body.action === 'og_image') { await limit(`og:${actor}`, 120); return response({ image: await ogImage(httpsUrl(body.url)) }); }

    await limit(`write:${actor}`, 120, 60000);
    if (body.action !== 'save') fail(400, 'invalid_action');
    if (typeof body.id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(body.id)) fail(400, 'invalid_id');
    if (!WRITABLE.includes(body.kind)) fail(400, 'invalid_kind');
    if (!Number.isSafeInteger(body.version) || body.version < 0) fail(400, 'invalid_version');
    const now = new Date().toISOString();
    if (body.version === 0) {
      if (body.deleted) fail(400, 'invalid_delete');
      const p = payload(body.kind, body.payload);
      try {
        const [r] = await db('koyomi_items', 'POST', '', { id: body.id, kind: body.kind, payload: p, updated_by: session.member });
        const msg = describe(body.kind, p, null, true, false); if (msg) await later(sendPush(session.member, `${who}が${msg}`));
        return response({ record: r });
      } catch (e) { if ((e as any).status !== 409) throw e; const [existing] = await db('koyomi_items', 'GET', `id=eq.${body.id}`); return response({ error: 'conflict', record: existing }, 409); }
    }
    const [old] = await db('koyomi_items', 'GET', `id=eq.${body.id}&kind=eq.${body.kind}`);
    if (!old) fail(404, 'not_found');
    const p = body.deleted ? old.payload : payload(body.kind, body.payload);
    const [r] = await db('koyomi_items', 'PATCH', `id=eq.${body.id}&kind=eq.${body.kind}&version=eq.${body.version}`, {
      payload: p, version: body.version + 1, updated_by: session.member, updated_at: now, deleted_at: body.deleted ? now : null,
    });
    if (!r) { const [cur] = await db('koyomi_items', 'GET', `id=eq.${body.id}`); return response({ error: 'conflict', record: cur }, 409); }
    const msg = describe(body.kind, p, old.payload, false, !!body.deleted); if (msg) await later(sendPush(session.member, `${who}が${msg}`));
    return response({ record: r });
  } catch (e) {
    const status = (e as any).status;
    return response({ error: status ? (e as Error).message : 'internal_error' }, status || 500);
  }
});
