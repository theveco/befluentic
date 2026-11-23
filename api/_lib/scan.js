'use strict';
// Shared helpers for the Opportunity Scanner scan service. Files under
// api/_lib are not routed.
const crypto = require('crypto');
const dns = require('dns');
const TAKEN_DOWN = require('./blocked').map((d) => String(d).trim().toLowerCase()).filter(Boolean);

const ERROR_TEXT = "We couldn't read that site.";
const ID_RE = /^[a-f0-9]{32}$/;
// SHA-256 of the private test key. The key itself is not in this repo.
const TEST_KEY_SHA256 = 'd5660b083821fa22ac6cff55fd60cb3b4f677b901f96d33cc7ad542b7d12259b';

// Reads a whole number from the environment. Zero is a real value: a limit of
// 0 refuses everything. Anything that is not a whole number falls back.
function int(v, d, min) {
  if (v === undefined || v === null || String(v).trim() === '') return d;
  const n = Number(String(v).trim());
  return Number.isInteger(n) && n >= (min === undefined ? 0 : min) ? n : d;
}

function list(v, d) {
  return (v === undefined ? d : v).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function cfg() {
  const env = process.env;
  // The agent posts its result back to the live domain. Preview deployments sit
  // behind Vercel's login, so the agent could never reach a preview address.
  // The apex befluentic.com redirects to www, so www is used.
  const baseUrl = env.SCAN_BASE_URL || 'https://www.befluentic.com';
  return {
    redisUrl: (env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, ''),
    redisToken: env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN || '',
    webhookUrl: env.SCAN_WEBHOOK_URL || '',
    webhookSecret: env.SCAN_WEBHOOK_SECRET || '',
    baseUrl: baseUrl.replace(/\/+$/, ''),
    // Closed by default. Visitors are let in only when SCAN_PUBLIC is "1".
    // A preview deployment is also let in, for private testing: previews on
    // this project are reachable only through Vercel's login. If that login
    // wall is ever switched off, remove the preview clause.
    isPublic: env.SCAN_PUBLIC === '1' || env.VERCEL_ENV === 'preview',
    // Fresh agent runs per day across all visitors. This is what bounds the
    // daily spend: the most a day can cost is this number times the dearest run.
    dailyCap: int(env.SCAN_DAILY_CAP, 20),
    // Fresh agent runs per network address per day. This is the only per-visitor
    // limit: no browser identifier is used. Saved results do not count, so
    // colleagues in one office who enter the same domain are not held back.
    perIpDay: int(env.SCAN_PER_IP_DAY, 3),
    // How long a finished scan is kept, counted from the day it was made.
    keepSeconds: int(env.SCAN_KEEP_DAYS, 30, 1) * 86400,
    // A scan reads up to 4 company pages, then runs up to 5 searches and opens
    // up to 5 benchmark pages. Four trial runs of that job took 35 to 51
    // seconds, so three minutes leaves room for a slow source page.
    timeoutMs: int(env.SCAN_TIMEOUT_SECONDS, 180, 30) * 1000,
    jobTtl: 3600,
    blocklist: list(env.SCAN_BLOCKLIST, ''),
    // Domains that are never scanned or served. Fluentic's own site is always on
    // the list. A company that disputes its scan is added to blocked.js (or to
    // SCAN_BLOCKED_DOMAINS in the project settings) to take it down.
    blockedDomains: ['befluentic.com'].concat(TAKEN_DOWN, list(env.SCAN_BLOCKED_DOMAINS, '')),
  };
}

function configured(c) {
  return Boolean(c.redisToken && c.webhookSecret
    && c.redisUrl.startsWith('https://') && c.webhookUrl.startsWith('https://'));
}

// Outbound calls never follow a redirect (a redirect would carry the secret
// header to another address) and never wait longer than 8 seconds.
function outbound(url, opts) {
  return fetch(url, Object.assign({ redirect: 'error', signal: AbortSignal.timeout(8000) }, opts));
}

async function redis(cmd) {
  const c = cfg();
  const r = await outbound(c.redisUrl, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + c.redisToken, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  if (!r.ok) throw new Error('store_http_' + r.status);
  const j = await r.json();
  if (j && j.error) throw new Error('store_error');
  return j ? j.result : null;
}

async function getJson(key) {
  const raw = await redis(['GET', key]);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

function getJob(id) { return getJson('sc:job:' + id); }

async function putJob(job) {
  await redis(['SET', 'sc:job:' + job.id, JSON.stringify(job), 'EX', cfg().jobTtl]);
}

// Counter with a fixed window. Returns the count after this hit.
async function hit(key, ttlSeconds) {
  const n = await redis(['INCR', key]);
  // A store that answers without a number must not read as "under the limit".
  if (!Number.isInteger(n)) throw new Error('store_bad');
  if (n === 1) await redis(['EXPIRE', key, ttlSeconds]);
  return n;
}

// First caller wins.
async function claim(key, value, ttlSeconds) {
  return (await redis(['SET', key, value, 'NX', 'EX', ttlSeconds])) === 'OK';
}

// Where a domain's "running" marker and saved scan live. Scans started by the
// team page are kept apart from the public ones, so a team scan never becomes
// the result a visitor is shown for that domain, and a visitor never joins a
// run the team started.
const TEAM_SCANS_SHARED = false;
function pendKey(domain, internal) { return (internal ? 'sc:ipend:' : 'sc:pend:') + domain; }
function savedKey(domain, internal) { return (internal && !TEAM_SCANS_SHARED ? 'sc:idom:' : 'sc:dom:') + domain; }

// Removes a domain's "running" marker only if it still belongs to this job, so
// a late job can never clear the marker of the job that replaced it.
function release(domain, id, internal) {
  return redis(['EVAL', "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0", '1', pendKey(domain, internal), id]);
}

function sha(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function clientKey(req, c) {
  const h = req.headers || {};
  let ip = String(h['x-real-ip'] || h['x-forwarded-for'] || 'unknown').split(',')[0].trim().toLowerCase();
  // One IPv6 host usually owns a whole /64, so the limit is kept per /64. The
  // address is written out in full first, so "::" shorthand cannot split it.
  if (ip.includes(':') && !ip.includes('.')) {
    const [head, tail] = ip.split('::');
    const a = head ? head.split(':') : [];
    const b = tail === undefined ? null : (tail ? tail.split(':') : []);
    const all = b === null ? a : a.concat(Array(Math.max(0, 8 - a.length - b.length)).fill('0'), b);
    ip = all.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':');
  }
  // Only a keyed hash of the address is stored, never the address itself.
  return crypto.createHmac('sha256', c.webhookSecret).update(ip).digest('hex').slice(0, 32);
}

function hasTestKey(req) {
  const k = (req.headers || {})['x-scan-test'];
  return typeof k === 'string' && k.length <= 200 && safeEqual(sha(k), TEST_KEY_SHA256);
}

// While the service is not public, only a caller holding the test key gets in.
function allowed(req, c) {
  return c.isPublic || hasTestKey(req);
}

function body(req) {
  let b;
  try { b = req.body; } catch (e) { return null; }
  if (typeof b === 'string') {
    if (b.length > 60000) return null;
    try { b = JSON.parse(b); } catch (e) { return null; }
  }
  return b && typeof b === 'object' && !Array.isArray(b) ? b : null;
}

function cleanStr(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.normalize('NFKC')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')
    .trim();
  return s && s.length <= max ? s : null;
}

// For text that came back from the agent. Angle brackets are dropped as a
// second line of defence. The page must still insert this as plain text, never
// as HTML, an attribute or a link.
function cleanOut(v, max) {
  // Brackets are removed after normalising, so look-alike brackets go too.
  const s = cleanStr(v, max);
  if (!s) return null;
  const t = s.replace(/[<>]/g, '').trim();
  return t || null;
}

function sameOrigin(req) {
  const h = req.headers || {};
  if (!h.origin) return true; // server-side callers carry no Origin; limits still apply
  try {
    const host = new URL(h.origin).host;
    return host === h.host || host === 'befluentic.com' || host === 'www.befluentic.com';
  } catch (e) {
    return false;
  }
}

const SECOND_LEVEL = ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'or', 'ne', 'go', 'mil', 'nom', 'info', 'biz'];
const SHARED_HOSTS = ['github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev', 'web.app', 'firebaseapp.com',
  'herokuapp.com', 'azurewebsites.net', 'onrender.com', 'fly.dev', 'workers.dev', 'blogspot.com', 'wordpress.com',
  'wixsite.com', 'weebly.com', 'squarespace.com', 'webflow.io', 'myshopify.com', 'carrd.co', 'framer.website',
  'framer.app', 'notion.site', 'substack.com', 'medium.com', 'tumblr.com', 'godaddysites.com', 'business.site',
  'sites.google.com', 'cloudfront.net', 'amazonaws.com', 'nip.io', 'sslip.io', 'xip.io', 'localtest.me', 'lvh.me'];

function privateAddress(addr, family) {
  const a = String(addr).toLowerCase();
  if (family === 6 || a.includes(':')) {
    const m = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return privateAddress(m[1], 4);
    return a === '::' || a === '::1' || /^f[cd]/.test(a) || /^fe[89ab]/.test(a) || /^ff/.test(a) || /^64:ff9b:/.test(a);
  }
  const o = a.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [x, y] = o;
  return x === 0 || x === 10 || x === 127 || (x === 100 && y >= 64 && y <= 127) || (x === 169 && y === 254)
    || (x === 172 && y >= 16 && y <= 31) || (x === 192 && (y === 168 || y === 0)) || (x === 198 && (y === 18 || y === 19)) || x >= 224;
}

// Looks the name up before any money is spent. "ok" only if it resolves and
// every address is a public one, so a public name that points at a private or
// this-machine address is never handed to the agent. A screen, not a
// guarantee: the agent's own fetcher has the last word.
async function reach(domain) {
  let list;
  try {
    list = await Promise.race([
      dns.promises.lookup(domain, { all: true }),
      new Promise((_, no) => setTimeout(() => no(new Error('dns_timeout')), 3000)),
    ]);
  } catch (e) {
    return 'none';
  }
  if (!Array.isArray(list) || !list.length) return 'none';
  return list.some((x) => privateAddress(x.address, x.family)) ? 'private' : 'ok';
}

// True for a public host name. Letters-only top level, so raw IP addresses and
// "localhost" never pass, and no name that only resolves inside a network.
function publicName(h) {
  if (typeof h !== 'string' || h.length < 4 || h.length > 253) return false;
  if (!/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$/.test(h)) return false;
  return !/\.(local|internal|intranet|private|lan|home|corp|localdomain|localhost|test|example|invalid|onion|arpa)$/.test(h);
}

// The only thing a visitor can submit is a public company domain. Whatever is
// typed is cut down to the bare host name: no path, query, port, login or
// "www.". Returns null when it is not a public domain name.
function parseDomain(raw) {
  const s = cleanStr(raw, 300);
  if (!s || /\s/.test(s) || s.includes('@')) return null;
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'http://' + s); } catch (e) { return null; }
  if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.username || u.password) return null;
  let h = u.hostname.toLowerCase().replace(/\.$/, '');
  while (h.startsWith('www.')) h = h.slice(4);
  if (!publicName(h)) return null;
  // A label that is mostly a long number looks like a phone number, not a company.
  if (h.split('.').some((l) => (l.match(/\d/g) || []).length >= 9)) return null;
  // A bare registry suffix ("co.uk") or a shared hosting suffix ("github.io")
  // is not one company. A site hosted under one ("acme.github.io") is fine.
  const labels = h.split('.');
  if (labels.length === 2 && labels[1].length === 2 && SECOND_LEVEL.includes(labels[0])) return null;
  if (SHARED_HOSTS.includes(h)) return null;
  return h;
}

// Contact details have no place in a scan: any "@", or 9 or more digits in a
// row allowing up to three separator characters between digits (9 is the
// length of a local Kosovo mobile number; card, account and ID numbers are
// longer). Pattern-based only.
const LONG_NUMBER = /\p{Nd}(?:[\s().\/\-\u2010-\u2015_]{0,3}\p{Nd}){8,}/u;
function personal(text) {
  return text.includes('@') || LONG_NUMBER.test(text);
}

function refs(v, n, max) {
  if (!Array.isArray(v) || !v.length || v.length > max) return null;
  return v.every((i) => Number.isInteger(i) && i >= 1 && i <= n) ? v.slice() : null;
}

// The numbers written in a text, exactly as written: "1,200" and "1200" are
// not the same, nor are "15" and "15.000". Digits glued to a word ("COVID-19",
// "Q4") and "24/7" are not figures.
function numberTokens(text) {
  return String(text).replace(/\b24\/7\b/g, ' ').match(/(?<![\d.,\p{L}])(?<!\p{L}-)\d+(?:[.,]\d+)*/gu) || [];
}

// The part of a host name that one organisation owns: "shop.acme.com" and
// "acme.com" are both "acme.com", "acme.co.uk" stays whole, and a site on a
// shared host ("acme.github.io") is its own.
function site(h) {
  const l = h.split('.');
  const shared = SHARED_HOSTS.find((x) => h.endsWith('.' + x));
  if (shared) return l.slice(-(shared.split('.').length + 1)).join('.');
  const n = l.length >= 3 && l[l.length - 1].length === 2 && SECOND_LEVEL.includes(l[l.length - 2]) ? 3 : 2;
  return l.slice(-n).join('.');
}

function onBlocked(host, c) {
  return c.blockedDomains.some((d) => host === d || host.endsWith('.' + d));
}

// Names that answer with whatever address is written into them.
const WILDCARD_DNS = ['nip.io', 'sslip.io', 'xip.io', 'localtest.me', 'lvh.me'];

// A benchmark's source is a page somewhere else on the web. The address must
// be plain https on a public host name, never the scanned company's own site
// (any part of it) and never a blocked domain. It is kept in its normalised
// form. Returns [address, host] or [null, null, reason].
function outsideLink(v, domain, c) {
  const no = (m) => [null, null, m];
  const u = cleanStr(v, 500);
  if (!u) return no('missing or over 500');
  let p;
  try { p = new URL(u); } catch (e) { return no('not a web address'); }
  if (p.protocol !== 'https:') return no('not https');
  if (p.username || p.password) return no('carries a login');
  if (p.port) return no('carries a port');
  const host = p.hostname.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  if (!publicName(host)) return no('not a public host name');
  // A look-alike name written in another alphabet shows up here as "xn--".
  if (host.split('.').some((l) => l.startsWith('xn--'))) return no('host in a non-Latin alphabet');
  if (WILDCARD_DNS.some((w) => host === w || host.endsWith('.' + w))) return no('host that points wherever it is told');
  if (site(host) === site(domain)) return no("on the company's own domain");
  if (onBlocked(host, c)) return no('on a blocked domain');
  if (/["'<>`\s\\]/.test(p.href) || p.href.length > 500) return no('unsafe character or too long');
  // No contact details. The path is the publisher's and often carries dates
  // and article numbers, so the long-number rule is applied to the rest only.
  let whole; let tail;
  try { whole = decodeURIComponent(p.href); tail = decodeURIComponent(p.search + p.hash); } catch (e) { return no('cannot be decoded'); }
  if (whole.includes('@') || personal(tail)) return no('contact detail');
  return [p.href, host];
}

// The optional calculator inputs. These are the agent's own arithmetic on the
// source's numbers, so the service can only check that they are sane. A calc
// that is not is left out; the benchmark itself stands.
function cleanCalc(k) {
  if (!k || typeof k !== 'object' || Array.isArray(k)) return null;
  const unit = cleanOut(k.unit, 60);
  if (!unit || personal(unit)) return null;
  if (k.kind !== 'minutes' && k.kind !== 'money') return null;
  if (k.per !== 'week' && k.per !== 'month') return null;
  const top = k.kind === 'minutes' ? 600 : 100000;
  if (typeof k.low !== 'number' || typeof k.high !== 'number' || !Number.isFinite(k.low) || !Number.isFinite(k.high)) return null;
  // Rounded first, so nothing that rounds to zero is kept.
  const low = Math.round(k.low * 100) / 100;
  const high = Math.round(k.high * 100) / 100;
  if (!(low >= 0.01) || !(high >= low) || !(high <= top)) return null;
  const out = { unit, kind: k.kind, low, high, per: k.per };
  if (k.kind === 'money') {
    const cur = cleanOut(k.currency, 3);
    if (!cur || !/^(?:\p{Sc}|[A-Z]{1,2}\p{Sc}|[A-Z]{3})$/u.test(cur)) return null;
    out.currency = cur;
  }
  return out;
}

// One published figure for one bottleneck. Returns [bench] or [null, reason].
// The reason names fields and sizes only, never the content.
function cleanBench(b, domain, c) {
  const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'list' : typeof v);
  const len = (v) => (typeof v === 'string' ? v.length : kind(v));
  if (!b || typeof b !== 'object' || Array.isArray(b)) return [null, 'is ' + kind(b) + ', not an object'];
  const src = b.source && typeof b.source === 'object' && !Array.isArray(b.source) ? b.source : {};
  const o = { figure: cleanOut(b.figure, 40), label: cleanOut(b.label, 160), scope: cleanOut(b.scope, 300) };
  const t = cleanOut(src.t, 200);
  const srcQuote = cleanOut(b.srcQuote, 500);
  if (!o.figure || !o.label || !o.scope || !t || !srcQuote) {
    return [null, 'figure ' + len(b.figure) + ' (40), label ' + len(b.label) + ' (160), scope ' + len(b.scope) + ' (300), source.t ' + len(src.t) + ' (200), srcQuote ' + len(b.srcQuote) + ' (500)'];
  }
  // The link's text must not pass itself off as another address. The page is
  // given the real host name to show beside it.
  if (/:\/\/|www\./i.test(t)) return [null, 'source.t looks like a web address'];
  const [u, host, bad] = outsideLink(src.u, domain, c);
  if (!u) return [null, 'source.u ' + bad];
  // A bottleneck is never shown without a number, and every number in the
  // figure must stand, written the same way, in the words copied from the
  // source. The service cannot open the source page: that the words are really
  // on it rests on the agent.
  if (/[^\P{Nd}0-9]/u.test(o.figure)) return [null, 'figure has digits in another script'];
  const want = numberTokens(o.figure);
  if (!want.length) return [null, 'figure has no number'];
  const have = numberTokens(srcQuote);
  if (!want.every((n) => have.includes(n))) return [null, 'a number in figure is not in srcQuote'];
  // Years are common in a published figure ("2019-2024 (40%)") and are not
  // contact details, so they are set aside before the long-number rule.
  if (personal([o.figure, o.label, o.scope, t, srcQuote].join(' ').replace(/\b(?:19|20)\d{2}\b/g, 'Y'))) return [null, 'contact detail or long number'];
  o.source = { t, u, host };
  o.srcQuote = srcQuote;
  const calc = b.calc === undefined || b.calc === null ? null : cleanCalc(b.calc);
  if (calc) o.calc = calc;
  return [o];
}

// True for a saved scan in the shape the page now expects: three bottlenecks,
// each with its own published figure, none of them citing a domain that has
// since been blocked. Any other saved scan is not served; the domain is
// scanned again on the next request.
function current(r, c) {
  if (!r || !Array.isArray(r.bottlenecks) || r.bottlenecks.length !== 3) return false;
  return r.bottlenecks.every((b) => {
    const k = b && b.bench;
    if (!k || typeof k !== 'object' || typeof k.figure !== 'string' || !k.figure || !k.source || typeof k.source.u !== 'string') return false;
    let h;
    try { h = new URL(k.source.u).hostname.toLowerCase().replace(/^www\./, ''); } catch (e) { return false; }
    return !onBlocked(h, c);
  });
}

// Returns the agent's object reduced to the agreed fields, the error shape if
// the agent returned one, or null if it matches neither. A fact that carries
// contact details is dropped and the rest of the scan stands. There are always
// exactly three bottlenecks, so one that fails any check rejects the scan.
// "why", when given, receives one short line naming the rule that rejected the
// result. It names fields and sizes only, never the content.
function validateScan(x, domain, c, why) {
  const fail = (m) => { if (why) why.push(m); return null; };
  const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'list' : typeof v);
  const len = (v) => (typeof v === 'string' ? v.length : kind(v));
  // Describes a value without quoting it: its kind, a small whole number, or
  // the size of a list.
  const shape = (v) => (Number.isInteger(v) && Math.abs(v) < 1000 ? String(v) : Array.isArray(v) ? 'list of ' + v.length : kind(v));
  if (typeof x === 'string') {
    if (x.length > 60000) return fail('result is text of ' + x.length + ' chars, limit 60000');
    const a = x.indexOf('{'); const z = x.lastIndexOf('}'); // tolerate a sentence around the object
    try { x = JSON.parse(a >= 0 && z > a ? x.slice(a, z + 1) : x); } catch (e) { return fail('result is text that is not JSON (' + x.length + ' chars)'); }
  }
  if (!x || typeof x !== 'object' || Array.isArray(x)) return fail('result is ' + kind(x) + ', not an object');
  if (why) why.push('fields: ' + keyNames(x, 20));
  if (x.type === 'error') {
    const text = cleanOut(x.text, 300);
    return text && !personal(text) ? { type: 'error', text } : fail('error shape with bad text (' + len(x.text) + ')');
  }

  if (!Array.isArray(x.sources) || !x.sources.length || x.sources.length > 4) {
    return fail('sources: ' + (Array.isArray(x.sources) ? x.sources.length + ' entries, allowed 1 to 4' : kind(x.sources)));
  }
  const sources = [];
  for (let i = 0; i < x.sources.length; i++) {
    const s = x.sources[i];
    const t = s && cleanOut(s.t, 160);
    const u = s && cleanStr(s.u, 300);
    if (!t || !u) return fail('sources[' + (i + 1) + ']: t ' + len(s && s.t) + ', u ' + len(s && s.u));
    let host; let p;
    try {
      p = new URL(u);
      if (p.protocol !== 'http:' && p.protocol !== 'https:') return fail('sources[' + (i + 1) + ']: not http(s)');
      if (p.username || p.password) return fail('sources[' + (i + 1) + ']: carries a login');
      host = p.hostname.toLowerCase().replace(/^www\./, '');
    } catch (e) { return fail('sources[' + (i + 1) + ']: not a web address'); }
    // Every source must be a page on the company's own domain.
    if (host !== domain && !host.endsWith('.' + domain)) return fail('sources[' + (i + 1) + ']: on another domain (' + (publicName(host) ? host.slice(0, 60) : 'unusual host name') + ')');
    // The link is kept in its normalised form and may carry nothing that could
    // break out of a link on the page.
    if (/["'<>`\s\\]/.test(p.href) || p.href.length > 300) return fail('sources[' + (i + 1) + ']: unsafe character or too long');
    if (personal(t) || personal(p.href)) return fail('sources[' + (i + 1) + ']: contact detail or long number');
    sources.push({ t, u: p.href });
  }
  const n = sources.length;

  const name = cleanOut(x.name, 160);
  const description = cleanOut(x.description, 600);
  const descSrc = refs(x.descSrc, n, 4);
  if (!name) return fail('name: ' + len(x.name) + ', limit 160');
  if (!description) return fail('description: ' + len(x.description) + ', limit 600');
  if (!descSrc) return fail('descSrc: ' + shape(x.descSrc) + ', sources 1 to ' + n);
  if (personal(name) || personal(description)) return fail('name or description: contact detail or long number');

  if (!Array.isArray(x.pages) || !x.pages.length || x.pages.length > 4) {
    return fail('pages: ' + (Array.isArray(x.pages) ? x.pages.length + ' entries, allowed 1 to 4' : kind(x.pages)));
  }
  const pages = x.pages.map((p) => cleanOut(p, 80));
  if (pages.some((p) => !p || personal(p))) return fail('pages: an entry is ' + x.pages.map(len).join('/') + ', limit 80');

  if (!Array.isArray(x.facts) || !x.facts.length || x.facts.length > 8) {
    return fail('facts: ' + (Array.isArray(x.facts) ? x.facts.length + ' entries, allowed 1 to 8' : kind(x.facts)));
  }
  const facts = [];
  for (let i = 0; i < x.facts.length; i++) {
    const f = x.facts[i];
    const k = f && cleanOut(f.k, 40);
    const v = f && cleanOut(f.v, 300);
    const s = f && refs(f.s, n, 4);
    if (!k || !v || !s) return fail('facts[' + i + ']: k ' + len(f && f.k) + ' (limit 40), v ' + len(f && f.v) + ' (limit 300), s ' + shape(f && f.s));
    if (!personal(k + ' ' + v)) facts.push({ k, v, s });
  }

  if (!Array.isArray(x.bottlenecks) || x.bottlenecks.length !== 3) {
    return fail('bottlenecks: ' + (Array.isArray(x.bottlenecks) ? x.bottlenecks.length + ' entries, must be 3' : kind(x.bottlenecks)));
  }
  const bottlenecks = [];
  for (let i = 0; i < x.bottlenecks.length; i++) {
    const b = x.bottlenecks[i];
    const w = 'bottlenecks[' + i + ']';
    if (!b || typeof b !== 'object') return fail(w + ': ' + kind(b));
    const o = { name: cleanOut(b.name, 120), text: cleanOut(b.text, 400), quote: cleanOut(b.quote, 300) };
    if (!o.name || !o.text || !o.quote) return fail(w + ': name ' + len(b.name) + ' (120), text ' + len(b.text) + ' (400), quote ' + len(b.quote) + ' (300)');
    if (!Number.isInteger(b.s) || b.s < 1 || b.s > n) return fail(w + '.s: ' + shape(b.s) + ', sources 1 to ' + n);
    o.s = b.s;
    if (b.note !== undefined && b.note !== null) {
      o.note = cleanOut(b.note, 300);
      if (!o.note) return fail(w + '.note: ' + len(b.note) + ', limit 300');
    }
    if (Number.isInteger(b.also) && b.also >= 1 && b.also <= n) o.also = b.also;
    if (![0, 1, 2].includes(b.sol)) return fail(w + '.sol: ' + shape(b.sol));
    o.sol = b.sol;
    if (personal([o.name, o.text, o.quote, o.note || ''].join(' '))) return fail(w + ': contact detail or long number');
    const [bench, bad] = cleanBench(b.bench, domain, c);
    if (!bench) return fail(w + '.bench: ' + bad);
    o.bench = bench;
    bottlenecks.push(o);
  }
  if (!facts.length) return fail('facts: all dropped for contact details');

  if (!Array.isArray(x.solutions) || x.solutions.length !== 3) {
    return fail('solutions: ' + (Array.isArray(x.solutions) ? x.solutions.length + ' entries, must be 3' : kind(x.solutions)));
  }
  const solutions = [];
  for (let i = 0; i < 3; i++) {
    const s = x.solutions[i];
    const o = s && { type: cleanOut(s.type, 60), name: cleanOut(s.name, 120), text: cleanOut(s.text, 400), keep: cleanOut(s.keep, 200) };
    if (!o || !o.type || !o.name || !o.text || !o.keep) {
      return fail('solutions[' + i + ']: type ' + len(s && s.type) + ' (60), name ' + len(s && s.name) + ' (120), text ' + len(s && s.text) + ' (400), keep ' + len(s && s.keep) + ' (200)');
    }
    if (personal([o.type, o.name, o.text, o.keep].join(' '))) return fail('solutions[' + i + ']: contact detail or long number');
    solutions.push(o);
  }

  // "domain" is always the one that was asked for, never what came back.
  const out = { domain, name, description, descSrc, pages, facts, bottlenecks, solutions, sources };
  if (c.blocklist.length) {
    const hay = JSON.stringify(out).toLowerCase();
    if (c.blocklist.some((w) => hay.includes(w))) return fail('blocklist word present');
  }
  return out;
}

// Field names for a rejection note. A name that is not a plain short word is
// shown as "?", so nothing the agent wrote can ride along as a name.
function keyNames(o, max) {
  return Object.keys(o).slice(0, max).map((k) => (/^[A-Za-z0-9_]{1,24}$/.test(k) ? k : '?')).join(',');
}

function errorResult() {
  return { type: 'error', text: ERROR_TEXT };
}

function send(res, status, obj) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  return res.status(status).json(obj);
}

module.exports = {
  ID_RE, cfg, configured, outbound, redis, getJson, getJob, putJob, hit, claim, release, pendKey, savedKey, reach, privateAddress, sha,
  safeEqual, clientKey, allowed, hasTestKey, body, cleanStr, sameOrigin, parseDomain, personal,
  validateScan, current, numberTokens, keyNames, errorResult, send,
  newId: () => crypto.randomBytes(16).toString('hex'),
  newToken: () => crypto.randomBytes(32).toString('hex'),
};
