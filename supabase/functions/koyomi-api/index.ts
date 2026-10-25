// わが家のこよみ API. No third-party dependencies; the service-role key stays in the Supabase runtime.
// All tables deny direct access (RLS on, no policies); this function is the only way in, behind a family login.
const ORIGINS = ['https://ec0194ii-ops.github.io', ...(Deno.env.get('KOYOMI_EXTRA_ORIGINS') || '').split(',').map(x => x.trim()).filter(Boolean)];
const BASE = Deno.env.get('SUPABASE_URL')!;
const ADMIN = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const MEMBERS: Record<string, string> = { papa: 'パパ', mama: 'ママ' };
const WRITABLE = ['event', 'todo', 'shop', 'wish', 'garbage', 'place', 'note'];
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
async function sendPush(exceptMember: string | null, body: string, tag = 'koyomi-change', only?: string[]) {
  let subs = await db('koyomi_push_subs', 'GET', 'select=endpoint,member,p256dh,auth' + (exceptMember ? `&member=neq.${exceptMember}` : ''));
  if (only) subs = subs.filter((x: any) => only.includes(x.member));
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
  const label = kind === 'event' ? `予定「${t}」${p.date ? `（${md(p.date)}）` : ''}` : kind === 'todo' ? `Todo「${t}」` : kind === 'shop' ? `買い物「${t}」` : kind === 'wish' ? `Wish「${t}」` : '';
  if (!label) return '';
  if (deleted) return `${label}を消しました`;
  if (created) return `${label}を追加しました`;
  if (kind === 'todo' && p.done && !old?.done) return `「${t}」を終わらせました`;
  if (kind === 'shop' && p.done !== old?.done) return '';      // ticking items off the list stays quiet
  if (kind === 'wish' && p.done && !old?.done) return `Wish「${t}」が叶いました`;
  if (kind === 'event') return `${label}を変更しました`;
  return '';
}


/* ---------- weather (気象庁 open data for 滋賀県南部 / 大津) ---------- */
function codeInfo(code: unknown): [string, string] {
  const c = Number(code);
  if (!c) return ['', ''];
  if (c >= 400) return ['❄️', '雪'];
  if (c >= 300) return c === 301 ? ['🌦', '雨時々晴れ'] : ['☔', '雨'];
  if (c >= 200) return [200, 209, 231].includes(c) ? ['☁️', 'くもり'] : [201, 210, 211, 223].includes(c) ? ['⛅', 'くもり時々晴れ'] : ['🌧', 'くもり一時雨'];
  return [100, 123, 124, 130, 131].includes(c) ? ['☀️', '晴れ'] : [101, 110, 111, 132].includes(c) ? ['⛅', '晴れ時々くもり'] : ['🌦', '晴れ一時雨'];
}
async function saveInfo(id: string, p: Record<string, unknown>) {
  const [cur] = await db('koyomi_items', 'GET', `id=eq.${id}&select=version`);
  if (cur) await db('koyomi_items', 'PATCH', `id=eq.${id}`, { payload: p, version: cur.version + 1, updated_at: new Date().toISOString(), updated_by: 'system', deleted_at: null });
  else await db('koyomi_items', 'POST', '', { id, kind: 'info', payload: p, updated_by: 'system' });
}
async function updateWeather() {
  const r = await fetch('https://www.jma.go.jp/bosai/forecast/data/forecast/250000.json', { headers: { Accept: 'application/json' } });
  if (!r.ok) fail(502, 'jma_unavailable');
  const j = await r.json();
  const days: Record<string, any> = {};
  const day = (t: string) => { const k = t.slice(0, 10); return days[k] = days[k] || { date: k }; };
  const pick = (areas: any[], code: string) => areas.find((a: any) => a.area?.code === code) || areas[0];
  const short = j[0].timeSeries;
  const w = pick(short[0].areas, '250010');
  short[0].timeDefines.forEach((t: string, i: number) => { const d = day(t); if (w.weatherCodes?.[i]) d.code = w.weatherCodes[i]; if (w.weathers?.[i]) d.detail = String(w.weathers[i]).replace(/[\s　]+/g, ' ').trim(); });
  const pp = pick(short[1].areas, '250010');
  const blocks: { from: number; pop: number }[] = [];
  short[1].timeDefines.forEach((t: string, i: number) => { const v = pp.pops?.[i]; if (v === '' || v == null) return; const d = day(t); d.pop = Math.max(d.pop ?? 0, Number(v)); blocks.push({ from: Date.parse(t), pop: Number(v) }); });
  const tt = pick(short[2].areas, '60216');
  short[2].timeDefines.forEach((t: string, i: number) => { const v = tt.temps?.[i]; if (v === '' || v == null) return; const d = day(t); if (t.slice(11, 13) === '00') d.lo = Number(v); else d.hi = Number(v); });
  const wk = j[1]?.timeSeries || [];
  if (wk[0]) { const a = wk[0].areas[0]; wk[0].timeDefines.forEach((t: string, i: number) => { const d = day(t); if (!d.code && a.weatherCodes?.[i]) d.code = a.weatherCodes[i]; if (d.pop == null && a.pops?.[i]) d.pop = Number(a.pops[i]); if (a.reliabilities?.[i]) d.rel = a.reliabilities[i]; }); }
  if (wk[1]) { const a = pick(wk[1].areas, '60216'); wk[1].timeDefines.forEach((t: string, i: number) => { const d = day(t); if (d.lo == null && a.tempsMin?.[i]) d.lo = Number(a.tempsMin[i]); if (d.hi == null && a.tempsMax?.[i]) d.hi = Number(a.tempsMax[i]); }); }
  const today = jstKey(0);
  const list = Object.values(days).filter((d: any) => d.date >= today && d.code).sort((a: any, b: any) => a.date.localeCompare(b.date)).slice(0, 7)
    .map((d: any) => { const [icon, text] = codeInfo(d.code); return { date: d.date, icon, text, hi: d.hi ?? null, lo: (d.lo != null && d.hi != null && d.lo >= d.hi) ? null : (d.lo ?? null), pop: d.pop ?? null, ...(d.detail ? { detail: d.detail } : {}), ...(d.rel ? { rel: d.rel } : {}) }; });
  if (!list.length) fail(502, 'jma_empty');
  const now = new Date(Date.now() + 9 * 3600000);
  const updated = `${now.getUTCMonth() + 1}/${now.getUTCDate()} ${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}`;
  let hourly: unknown[] = [], hsrc = '気象庁';
  try { hourly = await jmaHourly(blocks); } catch { hourly = []; }
  if (hourly.length < 4) { try { hourly = await hourlyForecast(blocks); hsrc = '気象庁・Open-Meteo'; } catch { /* the daily forecast still goes out */ } }
  try {   // rain amount for each 3-hour slot (気象庁 does not publish it per point; Open-Meteo's model total)
    const mm = await rainMm();
    for (const h of hourly as any[]) { const base = Date.parse(String(h.t).slice(0, 16) + ':00+09:00'); if (!(base > 0)) continue; let sum = 0, n = 0;
      for (let i = 1; i <= 3; i++) { const k = new Date(base + i * 3600000 + 9 * 3600000).toISOString().slice(0, 13); if (mm[k] != null) { sum += mm[k]; n++; } }
      if (n) h.mm = Math.round(sum * 10) / 10; }
  } catch { /* amounts are a nice-to-have */ }
  await saveInfo('weather', { key: 'weather', area: '大津市', source: hsrc, updated, url: 'https://weather.yahoo.co.jp/weather/jp/25/6010/25201.html', days: list, hourly });
  return list.length;
}
async function rainMm() {
  const r = await fetch('https://api.open-meteo.com/v1/forecast?latitude=35.0045&longitude=135.8686&hourly=precipitation&timezone=Asia%2FTokyo&forecast_days=3');
  if (!r.ok) fail(502, 'rain_unavailable');
  const j = await r.json(); const out: Record<string, number> = {};
  (j.hourly?.time || []).forEach((t: string, i: number) => { const v = j.hourly.precipitation?.[i]; if (v != null) out[t.slice(0, 13)] = Number(v); });
  return out;
}
// 雨雲レーダー: the frame times of 気象庁's 高解像度降水ナウキャスト (the tiles themselves load straight from jma.go.jp)
let radarCache: { at: number; data: unknown } | null = null;
async function radarTimes() {
  if (radarCache && Date.now() - radarCache.at < 60000) return radarCache.data;
  const get = async (n: string) => { const r = await fetch(`https://www.jma.go.jp/bosai/jmatile/data/nowc/targetTimes_${n}.json`); if (!r.ok) fail(502, 'radar_unavailable'); return await r.json(); };
  const [a, b] = await Promise.all([get('N1'), get('N2')]);
  const ok = (x: any) => x && /^\d{14}$/.test(x.basetime) && /^\d{14}$/.test(x.validtime) && Array.isArray(x.elements) && x.elements.includes('hrpns');
  const by = (x: any, y: any) => String(x.validtime).localeCompare(String(y.validtime));
  const past = (Array.isArray(a) ? a : []).filter(ok).sort(by).slice(-13);
  const fut = (Array.isArray(b) ? b : []).filter(ok).sort(by).slice(0, 12);
  const data = { frames: [...past.map((x: any) => ({ b: x.basetime, v: x.validtime, f: 0 })), ...fut.map((x: any) => ({ b: x.basetime, v: x.validtime, f: 1 }))] };
  radarCache = { at: Date.now(), data }; return data;
}
function wmo(c: number): [string, string] {
  if (c === 0) return ['☀️', '晴れ'];
  if (c === 1 || c === 2) return ['⛅', '晴れ時々くもり'];
  if (c === 3) return ['☁️', 'くもり'];
  if (c === 45 || c === 48) return ['🌫', '霧'];
  if (c >= 51 && c <= 57) return ['🌦', '霧雨'];
  if ((c >= 61 && c <= 67) || (c >= 80 && c <= 82)) return ['☔', '雨'];
  if ((c >= 71 && c <= 77) || c === 85 || c === 86) return ['❄️', '雪'];
  if (c >= 95) return ['⛈', '雷雨'];
  return ['☁️', 'くもり'];
}
// 3-hourly forecast straight from 気象庁 (地域時系列予報: 滋賀県南部 weather, 大津 temperature).
function jmaIcon(t: string): [string, string] {
  const s = String(t || '');
  if (/雪/.test(s) && /雨/.test(s)) return ['🌨', s];
  if (/雪/.test(s)) return ['❄️', s];
  if (/雨/.test(s)) return ['☔', s];
  if (/くもり|曇/.test(s)) return ['☁️', s];
  if (/晴/.test(s)) return ['☀️', s];
  return ['☁️', s || 'くもり'];
}
async function jmaHourly(blocks: { from: number; pop: number }[] = []) {
  const r = await fetch('https://www.jma.go.jp/bosai/jmatile/data/wdist/VPFD/250010.json', { headers: { Accept: 'application/json' } });
  if (!r.ok) fail(502, 'jma_hourly_unavailable');
  const j = await r.json();
  const at = j.areaTimeSeries || {}, pt = j.pointTimeSeries || {};
  const wx: Record<string, string> = {};
  (at.timeDefines || []).forEach((d: any, i: number) => { wx[String(d.dateTime || d).slice(0, 13)] = (at.weather || [])[i]; });
  const nowSlot = Date.now() - 3 * 3600000;
  const out: unknown[] = [];
  (pt.timeDefines || []).forEach((d: any, i: number) => {
    const iso = String(d.dateTime || d); const ms = Date.parse(iso);
    if (!(ms >= nowSlot) || out.length >= 10) return;
    const temp = (pt.temperature || [])[i]; if (temp === '' || temp == null) return;
    const key = iso.slice(0, 13); const w = wx[key]; if (!w) return;
    const [icon, text] = jmaIcon(w);
    const blk = blocks.find(b => ms >= b.from && ms < b.from + 6 * 3600000);
    out.push({ t: iso.slice(0, 16), h: Number(iso.slice(11, 13)), temp: Number(temp), pop: blk ? blk.pop : null, src: 'jma', icon, text });
  });
  return out;
}
// Fallback: 3-hourly temperature, weather and rain chance for the next ~27 hours (大津市役所付近).
async function hourlyForecast(blocks: { from: number; pop: number }[] = []) {
  const u = 'https://api.open-meteo.com/v1/forecast?latitude=35.0045&longitude=135.8686&hourly=temperature_2m,precipitation_probability,weather_code&timezone=Asia%2FTokyo&forecast_days=3';
  const r = await fetch(u); if (!r.ok) fail(502, 'hourly_unavailable');
  const j = await r.json(); const h = j.hourly || {};
  const nowJst = new Date(Date.now() + 9 * 3600000).toISOString().slice(0, 13);   // YYYY-MM-DDTHH
  const out: unknown[] = [];
  (h.time || []).forEach((t: string, i: number) => {
    const hh = Number(t.slice(11, 13));
    if (hh % 3 !== 0 || t.slice(0, 13) < nowJst.slice(0, 11) + String(Math.floor(Number(nowJst.slice(11, 13)) / 3) * 3).padStart(2, '0')) return;
    if (out.length >= 10) return;
    const [icon, text] = wmo(Number(h.weather_code?.[i]));
    // Rain chance: the 気象庁 6-hour figure when the slot falls inside one (what Yahoo!天気 shows too); otherwise the model value rounded to 10%.
    const at = Date.parse(t + ':00+09:00');
    const blk = blocks.find(b => at >= b.from && at < b.from + 6 * 3600000);
    const raw = h.precipitation_probability?.[i];
    const pop = blk ? blk.pop : raw == null ? null : Math.round(Number(raw) / 10) * 10;
    out.push({ t, h: hh, temp: h.temperature_2m?.[i] != null ? Math.round(h.temperature_2m[i]) : null, pop, src: blk ? 'jma' : 'model', icon, text });
  });
  return out;
}


/* ---------- outing photos: the event's own picture from its otsu-event.site page ---------- */
async function eventImage(url: string) {
  const m = url.match(/^https:\/\/otsu-event\.site\/events\/([0-9A-Za-z]+)$/); if (!m) return '';
  const id = m[1];
  const c = new AbortController(); const timer = setTimeout(() => c.abort(), 8000);
  try {
    const r = await fetch(url, { signal: c.signal, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; KoyomiPhoto/1.0)', Accept: 'text/html' } });
    if (!r.ok) return '';
    const html = await r.text();
    const at = html.indexOf(id + '\\",\\"title\\"');
    if (at < 0) return '';
    const seg = html.slice(at, at + 4000);
    const mm = seg.match(/\\"imageUrl\\":\\"(https:[^"\\]+)/);
    if (!mm) return '';
    let img = mm[1].replace(/\\u0026/g, '&').replace(/&amp;?$/, '').replace(/&$/, '');
    if (!/^https:\/\//.test(img) || img.length > 2000 || /otsu-event\.site\/logo/.test(img)) return '';
    return img;
  } catch { return ''; } finally { clearTimeout(timer); }
}
async function fillOutingImages() {
  const rows = await db('koyomi_items', 'GET', 'select=id,payload,version&kind=eq.outing&deleted_at=is.null&limit=200');
  let n = 0;
  for (const row of rows) {
    const p = row.payload || {};
    if (p.img || p.imgChecked || typeof p.url !== 'string') continue;
    const img = await eventImage(p.url);
    const next = { ...p, ...(img ? { img } : {}), imgChecked: new Date().toISOString().slice(0, 10) };
    await db('koyomi_items', 'PATCH', `id=eq.${row.id}&version=eq.${row.version}`, { payload: next, version: row.version + 1, updated_at: new Date().toISOString() });
    if (img) n++;
  }
  return n;
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
  const hs = wxRow && Array.isArray(wxRow.payload.hourly) ? wxRow.payload.hourly.filter((x: any) => String(x.t || '').slice(0, 10) === today && x.temp != null).map((x: any) => Number(x.temp)) : [];
  if (wx) parts.push(`${wx.icon || ''}${wx.text || ''} ${wx.hi ?? (hs.length ? Math.max(...hs) : '-')}°/${wx.lo ?? (hs.length ? Math.min(...hs) : '-')}°${wx.pop != null ? ' ☂' + wx.pop + '%' : ''}`);
  parts.push(evs.length ? '予定：' + evs.slice(0, 4).map((e: any) => (e.time ? e.time + ' ' : '') + e.title).join('、') + (evs.length > 4 ? ` ほか${evs.length - 4}件` : '') : '予定なし');
  if (due.length) parts.push('締切：' + due.slice(0, 3).map((t: any) => t.title + (t.due < today ? '（期限切れ）' : t.due === today ? '（今日）' : '（明日）')).join('、'));
  if (garb.length) parts.push('🗑 ' + garb.join('・') + 'の日');
  return parts.join('\n');
}


/* ---------- memories: one photo per day in a private bucket; only this function can read or write it ---------- */
const BUCKET = 'koyomi-photos';
const PHOTO_PATH = /^\d{4}-\d{2}-\d{2}\/[0-9a-f]{24}\.jpg$/;
async function storage(method: string, path: string, body?: BodyInit, type = 'application/json', extra: Record<string, string> = {}) {
  const r = await fetch(`${BASE}/storage/v1/${path}`, { method, headers: { apikey: ADMIN, Authorization: `Bearer ${ADMIN}`, 'Content-Type': type, ...extra }, body });
  if (!r.ok) fail(503, 'photo_storage_unavailable');
  return r;
}
function photoDate(x: unknown) {
  const d = String(x || ''); if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || isNaN(Date.parse(d + 'T00:00:00Z'))) fail(400, 'invalid_date');
  if (d > jstKey(1)) fail(400, 'future_date');
  return d;
}
async function photoRow(date: string) { const [r] = await db('koyomi_items', 'GET', `id=eq.photo-${date}`); return r || null; }
async function putPhotoRow(date: string, p: Record<string, unknown>, member: string, existing: any) {
  const now = new Date().toISOString();
  if (!existing) { const [r] = await db('koyomi_items', 'POST', '', { id: `photo-${date}`, kind: 'photo', payload: p, updated_by: member }); return r; }
  const [r] = await db('koyomi_items', 'PATCH', `id=eq.photo-${date}&version=eq.${existing.version}`, { payload: p, version: existing.version + 1, updated_by: member, updated_at: now, deleted_at: null });
  if (!r) fail(409, 'conflict');
  return r;
}
async function removeObject(path: unknown) { if (typeof path === 'string' && PHOTO_PATH.test(path)) { try { await storage('DELETE', `object/${BUCKET}`, JSON.stringify({ prefixes: [path] })); } catch { /* leftover file is harmless; it is private */ } } }


/* ---------- reminders: shortly before timed events, and a digest the evening before ---------- */
const LEADS: Record<string, number> = { '10': 10, '30': 30, '60': 60, '120': 120 };
function targets(who: unknown) {   // papa → パパ's phones, mama → ママ's, ゆづ / family → both
  const a = Array.isArray(who) ? who as string[] : [];
  const m = a.filter(x => x === 'papa' || x === 'mama');
  return a.includes('family') || a.includes('yuzu') || !m.length ? ['papa', 'mama'] : m;
}
const whoJa = (who: unknown) => { const a = Array.isArray(who) ? who as string[] : []; if (!a.length || a.includes('family')) return '家族'; return a.map(x => ({ papa: 'パパ', mama: 'ママ', yuzu: 'ゆづ' } as any)[x] || '').filter(Boolean).join('・'); };
async function claim(key: string) {
  try { await db('koyomi_sent', 'POST', '', { key }); return true; } catch (e) { if ((e as any).status === 409) return false; throw e; }
}
async function runReminders() {
  const nowMs = Date.now(); const jst = new Date(nowMs + 9 * 3600000);
  const today = jstKey(0), tmr = jstKey(1);
  const minNow = jst.getUTCHours() * 60 + jst.getUTCMinutes();
  const rows = await db('koyomi_items', 'GET', 'select=id,kind,payload&deleted_at=is.null&kind=in.(event,todo,garbage)&limit=5000');
  let sent = 0;
  // 1) shortly before each timed event (default 30 min), to the people it belongs to
  for (const day of [today, tmr]) {
    const base = day === today ? 0 : 1440;
    for (const r of rows) {
      if (r.kind !== 'event') continue; const e = r.payload || {};
      if (!e.time || !/^\d{2}:\d{2}$/.test(e.time) || !occursOn(e, day)) continue;
      const lead = e.remind === 'none' ? 0 : (LEADS[String(e.remind || '30')] || 30); if (!lead) continue;
      const startMin = base + Number(e.time.slice(0, 2)) * 60 + Number(e.time.slice(3, 5));
      const fire = startMin - lead;
      if (!(fire <= minNow && minNow - fire < 15)) continue;        // cron runs every 5 min; allow a little slack
      if (!(await claim(`ev|${r.id}|${day}|${lead}`))) continue;
      const left = lead >= 60 ? `${lead / 60}時間後` : `${lead}分後`;
      const body = `⏰ ${left}：${e.title}（${e.time}${e.end ? '〜' + e.end : ''}・${whoJa(e.who)}）${e.memo ? '\n持ち物・メモ：' + String(e.memo).slice(0, 60) : ''}`;
      await sendPush(null, body, 'koyomi-remind-' + r.id, targets(e.who)); sent++;
    }
  }
  // 2) the evening before (20:30): tomorrow at a glance, plus deadlines and garbage
  if (minNow >= 20 * 60 + 30 && minNow < 21 * 60 + 30 && await claim(`eve|${tmr}`)) {
    const evs = rows.filter((r: any) => r.kind === 'event' && occursOn(r.payload, tmr)).map((r: any) => r.payload).sort((a: any, b: any) => (a.time || '00').localeCompare(b.time || '00'));
    const due = rows.filter((r: any) => r.kind === 'todo' && !r.payload.done && r.payload.due === tmr).map((r: any) => r.payload);
    const d = new Date(tmr + 'T00:00:00Z'), nth = Math.ceil(d.getUTCDate() / 7), dow = d.getUTCDay();
    const garb = rows.filter((r: any) => r.kind === 'garbage' && Array.isArray(r.payload.weekdays) && r.payload.weekdays.includes(dow) && (!Array.isArray(r.payload.weeks) || !r.payload.weeks.length || r.payload.weeks.includes(nth))).map((r: any) => r.payload.kind);
    const notable = evs.filter((e: any) => e.repeat !== 'weekly' || e.time);
    if (notable.length || due.length || garb.length) {
      const parts = [`🌙 明日 ${+tmr.slice(5, 7)}/${+tmr.slice(8, 10)}（${DOW[dow]}）`];
      if (notable.length) parts.push(notable.slice(0, 5).map((e: any) => `・${e.time ? e.time + ' ' : ''}${e.title}${e.memo ? '（' + String(e.memo).slice(0, 24) + '）' : ''}`).join('\n') + (notable.length > 5 ? `\nほか${notable.length - 5}件` : ''));
      if (due.length) parts.push('📝 締切：' + due.map((t: any) => t.title).join('、'));
      if (garb.length) parts.push('🗑 ' + garb.join('・') + 'の日');
      await sendPush(null, parts.join('\n'), 'koyomi-evening'); sent++;
    }
  }
  if (Math.random() < 0.02) await db('koyomi_sent', 'DELETE', `sent_at=lt.${encodeURIComponent(new Date(nowMs - 14 * 86400000).toISOString())}`);
  return sent;
}


/* ---------- calendar feed (iPhone / Google calendar subscription), behind a secret link ---------- */
const icsEsc = (t: unknown) => String(t ?? '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
function icsFold(line: string) {
  const out: string[] = []; let cur = '', bytes = 0;
  for (const ch of line) { const b = enc.encode(ch).length; if (bytes + b > 73) { out.push(cur); cur = ' ' + ch; bytes = 1 + b; } else { cur += ch; bytes += b; } }
  out.push(cur); return out.join('\r\n');
}
const ymdC = (k: string) => k.replace(/-/g, '');
const nextDay = (k: string) => { const d = new Date(k + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + 1); return d.toISOString().slice(0, 10); };
const addMin = (k: string, t: string, m: number) => { const d = new Date(`${k}T${t}:00Z`); d.setUTCMinutes(d.getUTCMinutes() + m); return d.toISOString().slice(0, 16); };
const WHO_TAG: Record<string, string> = { papa: 'パ', mama: 'マ', yuzu: 'ゆ', family: '家' };
function whoTag(who: unknown) { const a = Array.isArray(who) ? who as string[] : []; if (!a.length || a.includes('family')) return '家'; return a.map(x => WHO_TAG[x] || '').join(''); }
async function buildIcs() {
  const rows = await db('koyomi_items', 'GET', 'select=id,kind,payload,updated_at&deleted_at=is.null&kind=in.(event,todo)&limit=5000');
  const from = jstKey(-120);
  const stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15) + 'Z';
  const L: string[] = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//wagaya-koyomi//JA', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    'X-WR-CALNAME:わが家のこよみ', 'X-WR-TIMEZONE:Asia/Tokyo', 'REFRESH-INTERVAL;VALUE=DURATION:PT1H', 'X-PUBLISHED-TTL:PT1H',
    'BEGIN:VTIMEZONE', 'TZID:Asia/Tokyo', 'BEGIN:STANDARD', 'DTSTART:19700101T000000', 'TZOFFSETFROM:+0900', 'TZOFFSETTO:+0900', 'TZNAME:JST', 'END:STANDARD', 'END:VTIMEZONE'];
  for (const r of rows) {
    const p = r.payload || {};
    if (r.kind === 'event') {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(p.date || '')) continue;
      const weekly = p.repeat === 'weekly';
      const lastDay = weekly ? (p.until || '9999-12-31') : (p.endDate && p.endDate > p.date ? p.endDate : p.date);
      if (lastDay < from) continue;
      const timed = /^\d{2}:\d{2}$/.test(p.time || '');
      L.push('BEGIN:VEVENT', `UID:${r.id}@wagaya-koyomi`, `DTSTAMP:${stamp}`);
      if (timed) {
        const end = /^\d{2}:\d{2}$/.test(p.end || '') && p.end > p.time ? `${p.date}T${p.end}` : addMin(p.date, p.time, 60);
        L.push(`DTSTART;TZID=Asia/Tokyo:${ymdC(p.date)}T${p.time.replace(':', '')}00`, `DTEND;TZID=Asia/Tokyo:${ymdC(end.slice(0, 10))}T${end.slice(11, 16).replace(':', '')}00`);
        if (p.remind !== 'none') L.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:' + icsEsc(p.title), `TRIGGER:-PT${Number(p.remind) > 0 ? Number(p.remind) : 30}M`, 'END:VALARM');
      } else {
        const endEx = nextDay(!weekly && p.endDate && p.endDate > p.date ? p.endDate : p.date);
        L.push(`DTSTART;VALUE=DATE:${ymdC(p.date)}`, `DTEND;VALUE=DATE:${ymdC(endEx)}`, 'TRANSP:TRANSPARENT');
      }
      if (weekly) {
        L.push('RRULE:FREQ=WEEKLY' + (p.until ? `;UNTIL=${ymdC(p.until)}${timed ? 'T145959Z' : ''}` : ''));
        if (Array.isArray(p.skip)) for (const k of p.skip) if (/^\d{4}-\d{2}-\d{2}$/.test(k)) L.push(timed ? `EXDATE;TZID=Asia/Tokyo:${ymdC(k)}T${p.time.replace(':', '')}00` : `EXDATE;VALUE=DATE:${ymdC(k)}`);
      }
      L.push(icsFold('SUMMARY:' + icsEsc(`【${whoTag(p.who)}】${p.title || ''}`)));
      if (p.memo) L.push(icsFold('DESCRIPTION:' + icsEsc(p.memo)));
      L.push('END:VEVENT');
    } else if (r.kind === 'todo' && !p.done && /^\d{4}-\d{2}-\d{2}$/.test(p.due || '') && p.due >= from) {
      L.push('BEGIN:VEVENT', `UID:${r.id}@wagaya-koyomi`, `DTSTAMP:${stamp}`, `DTSTART;VALUE=DATE:${ymdC(p.due)}`, `DTEND;VALUE=DATE:${ymdC(nextDay(p.due))}`, 'TRANSP:TRANSPARENT',
        icsFold('SUMMARY:' + icsEsc(`📝 ${p.span === 'week' ? '今週中' : '締切'}：${p.title || ''}`)), 'END:VEVENT');
    }
  }
  L.push('END:VCALENDAR');
  return L.join('\r\n') + '\r\n';
}


/* ---------- home-screen widget feed (Scriptable), read-only, behind its own secret link ---------- */
async function buildWidget() {
  const rows = await db('koyomi_items', 'GET', 'select=id,kind,payload&deleted_at=is.null&kind=in.(event,todo,shop)&limit=5000');
  const today = jstKey(0), d0 = new Date(today + 'T00:00:00Z'), ws = jstKey(-((d0.getUTCDay() + 6) % 7)), we = jstKey(6 - ((d0.getUTCDay() + 6) % 7));
  const shop = rows.filter((r: any) => r.kind === 'shop' && !r.payload.done).map((r: any) => r.payload)
    .sort((a: any, b: any) => String(a.createdAt || '').localeCompare(String(b.createdAt || ''))).map((p: any) => ({ name: String(p.name || ''), qty: String(p.qty || '') }));
  const open = rows.filter((r: any) => r.kind === 'todo' && !r.payload.done).map((r: any) => r.payload);
  const lab = (t: any) => t.span === 'week' ? '今週中' : t.due === today ? '今日' : t.due < today ? '期限切れ' : `${+t.due.slice(5, 7)}/${+t.due.slice(8, 10)}`;
  const todayT = open.filter((t: any) => t.due && t.due <= today && t.span !== 'week').sort((a: any, b: any) => a.due.localeCompare(b.due));
  const weekT = open.filter((t: any) => !todayT.includes(t) && ((t.due && t.due <= we) || (!t.due && t.week === ws))).sort((a: any, b: any) => String(a.due).localeCompare(String(b.due)));
  const evs = rows.filter((r: any) => r.kind === 'event' && occursOn(r.payload, today)).map((r: any) => r.payload)
    .sort((a: any, b: any) => (a.time || '00').localeCompare(b.time || '00')).map((e: any) => ({ time: e.time || '', title: String(e.title || ''), who: whoTag(e.who) }));
  return { today, dow: DOW[d0.getUTCDay()], shop, todos: [...todayT, ...weekT].map((t: any) => ({ title: String(t.title || ''), label: t.due ? lab(t) : '今週中', late: !!(t.due && t.due < today && t.span !== 'week') })), events: evs, updated: new Date().toISOString() };
}

async function readBody(req: Request) {
  const reader = req.body?.getReader(); if (!reader) fail(400, 'body_required');
  const chunks: Uint8Array[] = []; let size = 0;
  while (true) { const { done, value } = await reader!.read(); if (done) break; size += value.length; if (size > 1500000) { await reader!.cancel(); fail(413, 'body_too_large'); } chunks.push(value); }
  let out: any; try { out = JSON.parse(new TextDecoder().decode(cat(...chunks))); } catch { fail(400, 'invalid_json'); }
  if (size > 200000 && out?.action !== 'photo_upload') fail(413, 'body_too_large');   // only photos may be big
  return out;
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
    if (req.method === 'GET' && new URL(req.url).searchParams.has('w')) {   // home-screen widget
      const t = new URL(req.url).searchParams.get('w') || '';
      const [cfg] = await db('koyomi_config', 'GET', 'id=eq.true&select=widget_hash');
      let hs: Record<string, string> = {}; try { hs = JSON.parse(cfg?.widget_hash || '{}') || {}; } catch { hs = {}; }
      const th = /^[0-9a-f]{64}$/.test(t) ? await sha(t) : '';
      if (!th || !Object.values(hs).some(h => typeof h === 'string' && equal(th, h))) return new Response('{"error":"not_found"}', { status: 404, headers: { 'Content-Type': 'application/json' } });
      return new Response(JSON.stringify(await buildWidget()), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (req.method === 'GET') {   // calendar apps subscribe with ?ics=<secret>
      const t = new URL(req.url).searchParams.get('ics') || '';
      if (!/^[0-9a-f]{64}$/.test(t)) return new Response('not found', { status: 404 });
      const [cfg] = await db('koyomi_config', 'GET', 'id=eq.true&select=ics_hash');
      let ih: Record<string, string> = {}; try { ih = (cfg?.ics_hash || '').startsWith('{') ? JSON.parse(cfg.ics_hash) : { any: cfg?.ics_hash || '' }; } catch { ih = {}; }
      const tih = await sha(t);
      if (!Object.values(ih).some(h => typeof h === 'string' && h && equal(tih, h))) return new Response('not found', { status: 404 });
      return new Response(await buildIcs(), { status: 200, headers: { 'Content-Type': 'text/calendar; charset=utf-8', 'Cache-Control': 'private, max-age=900', 'Content-Disposition': 'inline; filename="wagaya-koyomi.ics"' } });
    }
    if (origin && !ORIGINS.includes(origin)) fail(403, 'origin_not_allowed');
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers });
    if (req.method !== 'POST') fail(405, 'post_required');
    if ((req.headers.get('Content-Type') || '').split(';')[0] !== 'application/json') fail(415, 'json_required');
    const body = await readBody(req);
    if (!body || typeof body !== 'object') fail(400, 'invalid_body');

    if (body.action === 'morning' || body.action === 'weather' || body.action === 'outing_images' || body.action === 'reminders') {
      // Called by the database scheduler (pg_cron); authorised by a secret whose hash is in koyomi_config.
      const secret = req.headers.get('x-koyomi-cron') || '';
      const [cfg] = await db('koyomi_config', 'GET', 'id=eq.true&select=cron_hash');
      if (!cfg?.cron_hash || !/^[0-9a-f]{64}$/.test(secret) || !equal(await sha(secret), cfg.cron_hash)) fail(401, 'not_allowed');
      if (body.action === 'outing_images') return response({ ok: true, photos: await fillOutingImages() });
      if (body.action === 'reminders') return response({ ok: true, sent: await runReminders() });
      let wx = 0; try { wx = await updateWeather(); } catch { /* keep yesterday's forecast */ }
      if (body.action === 'weather') return response({ ok: true, days: wx });
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
    if (body.action === 'shop_go') {   // "I'm off to the shops" — tells the rest of the family to add things now
      await limit(`shop-go:${actor}`, 6);
      const n = Number.isSafeInteger(body.count) ? Math.min(Math.max(body.count, 0), 999) : 0;
      await sendPush(session.member, `🛒 ${who}がいまから買い物に行きます。ほしいものは今のうちにリストへ${n ? `（いま${n}品）` : ''}`, 'koyomi-shop-go');
      return response({ ok: true });
    }
    if (body.action === 'widget_link') {   // (re)make the widget's private link; the old one stops working
      await limit(`widget:${actor}`, 10);
      const t = hex(crypto.getRandomValues(new Uint8Array(32)));
      const [cfg] = await db('koyomi_config', 'GET', 'id=eq.true&select=widget_hash');
      let hs: Record<string, string> = {}; try { hs = JSON.parse(cfg?.widget_hash || '{}') || {}; } catch { hs = {}; }
      hs[session.member] = await sha(t);                       // one link per person, so each phone can renew its own
      await db('koyomi_config', 'PATCH', 'id=eq.true', { widget_hash: JSON.stringify(hs) });
      return response({ url: `${BASE}/functions/v1/koyomi-api?w=${t}` });
    }
    if (body.action === 'ics_link') {   // make (or remake, which retires the old one) the private calendar link
      await limit(`ics:${actor}`, 10);
      const t = hex(crypto.getRandomValues(new Uint8Array(32)));
      const [ic] = await db('koyomi_config', 'GET', 'id=eq.true&select=ics_hash');
      let ih: Record<string, string> = {}; try { ih = (ic?.ics_hash || '').startsWith('{') ? JSON.parse(ic.ics_hash) : {}; } catch { ih = {}; }
      ih[session.member] = await sha(t);                       // one link per person
      await db('koyomi_config', 'PATCH', 'id=eq.true', { ics_hash: JSON.stringify(ih) });
      const u = `${BASE}/functions/v1/koyomi-api?ics=${t}`;
      return response({ url: u, webcal: u.replace(/^https:/, 'webcal:') });
    }
    if (body.action === 'radar_times') { await limit(`radar:${actor}`, 300); return response(await radarTimes()); }
    if (body.action === 'og_image') { await limit(`og:${actor}`, 120); return response({ image: await ogImage(httpsUrl(body.url)) }); }


    if (body.action === 'photo_urls') {
      const paths = Array.isArray(body.paths) ? body.paths.filter((x: unknown) => typeof x === 'string' && PHOTO_PATH.test(x as string)).slice(0, 80) : [];
      if (!paths.length) return response({ urls: {} });
      await limit(`photo-url:${actor}`, 300);
      const r = await storage('POST', `object/sign/${BUCKET}`, JSON.stringify({ expiresIn: 600, paths }));
      const list = await r.json(); const urls: Record<string, string> = {};
      for (const x of list) if (x && x.signedURL && !x.error) urls[x.path] = `${BASE}/storage/v1${x.signedURL}`;
      return response({ urls, expiresIn: 600 });
    }
    if (body.action === 'photo_upload') {
      await limit(`photo:${actor}`, 40);
      const date = photoDate(body.date);
      const caption = text(body.caption ?? '', 120).trim();
      const b64 = text(body.image, 1450000, true);
      let bytes: Uint8Array; try { bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0)); } catch { fail(400, 'invalid_image'); }
      if (bytes!.length > 1000000) fail(413, 'image_too_large');
      if (!(bytes![0] === 0xff && bytes![1] === 0xd8 && bytes![2] === 0xff)) fail(400, 'jpeg_required');
      const path = `${date}/${hex(crypto.getRandomValues(new Uint8Array(12)))}.jpg`;
      await storage('POST', `object/${BUCKET}/${path}`, bytes! as any, 'image/jpeg', { 'x-upsert': 'false', 'cache-control': 'private, max-age=600' });
      const old = await photoRow(date);
      const w = Number.isSafeInteger(body.w) ? Math.min(body.w, 4000) : 0, h = Number.isSafeInteger(body.h) ? Math.min(body.h, 4000) : 0;
      let r; try { r = await putPhotoRow(date, { date, caption, path, by: session.member, w, h, at: new Date().toISOString() }, session.member, old); }
      catch (e) { await removeObject(path); throw e; }
      if (old && !old.deleted_at) await removeObject(old.payload?.path);
      await later(sendPush(session.member, `${who}が${md(date)}の思い出写真を${old && !old.deleted_at ? '変えました' : 'のせました'}${caption ? `「${caption.slice(0, 30)}」` : ''}`, 'koyomi-photo'));
      return response({ record: r });
    }
    if (body.action === 'photo_caption') {
      await limit(`write:${actor}`, 120, 60000);
      const date = photoDate(body.date); const caption = text(body.caption ?? '', 120).trim();
      const old = await photoRow(date); if (!old || old.deleted_at) fail(404, 'not_found');
      return response({ record: await putPhotoRow(date, { ...old.payload, caption }, session.member, old) });
    }
    if (body.action === 'photo_delete') {
      await limit(`write:${actor}`, 120, 60000);
      const date = photoDate(body.date);
      const old = await photoRow(date); if (!old || old.deleted_at) return response({ ok: true });
      const [r] = await db('koyomi_items', 'PATCH', `id=eq.photo-${date}&version=eq.${old.version}`, { version: old.version + 1, updated_by: session.member, updated_at: new Date().toISOString(), deleted_at: new Date().toISOString(), payload: { date, caption: '', path: '' } });
      if (!r) fail(409, 'conflict');
      await removeObject(old.payload?.path);
      return response({ record: r });
    }

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
