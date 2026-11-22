'use strict';
// Shared helpers for the Opportunity Scanner scan service. Files under
// api/_lib are not routed.
const crypto = require('crypto');

const ERROR_TEXT = "We couldn't read that site.";
const ID_RE = /^[a-f0-9]{32}$/;
const BENCH = ['order_entry', 'takeoff', 'invoice_ar', 'order_status'];
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
    // Fresh agent runs per day across all visitors. Tracks daily spend: the
    // dearest run measured so far cost $0.30, so 20 runs is at most about $6.
    dailyCap: int(env.SCAN_DAILY_CAP, 20),
    // Fresh agent runs per network address per day. The browser identifier is
    // what recognises a visitor; this only stops someone clearing it to scan
    // again and again. Saved results do not count, so colleagues in one office
    // who enter the same domain are not held back.
    perIpDay: int(env.SCAN_PER_IP_DAY, 3),
    // How long a finished scan and the visitor's link to it are kept.
    keepSeconds: int(env.SCAN_KEEP_DAYS, 30, 1) * 86400,
    // Measured runs took 17 to 24 seconds. The live route adds one step.
    timeoutMs: int(env.SCAN_TIMEOUT_SECONDS, 120, 30) * 1000,
    jobTtl: 3600,
    blocklist: list(env.SCAN_BLOCKLIST, ''),
    blockedDomains: list(env.SCAN_BLOCKED_DOMAINS, 'befluentic.com'),
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
  let ip = String(h['x-real-ip'] || h['x-forwarded-for'] || 'unknown').split(',')[0].trim();
  // One IPv6 host usually owns a whole /64, so the limit is kept per /64.
  if (ip.includes(':') && !ip.includes('.')) ip = ip.split(':').slice(0, 4).join(':');
  // Only a keyed hash of the address is stored, never the address itself.
  return crypto.createHmac('sha256', c.webhookSecret).update(ip).digest('hex').slice(0, 32);
}

// While the service is not public, only a caller holding the test key gets in.
function allowed(req, c) {
  if (c.isPublic) return true;
  const k = (req.headers || {})['x-scan-test'];
  return typeof k === 'string' && k.length <= 200 && safeEqual(sha(k), TEST_KEY_SHA256);
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
  return cleanStr(typeof v === 'string' ? v.replace(/[<>]/g, '') : v, max);
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
  if (h.startsWith('www.')) h = h.slice(4);
  if (h.length < 4 || h.length > 253) return null;
  // Letters-only top level, so raw IP addresses and "localhost" never pass.
  if (!/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$/.test(h)) return null;
  if (/\.(local|internal|lan|home|corp|localdomain|localhost|test|example|invalid|onion|arpa)$/.test(h)) return null;
  // A label that is mostly a long number looks like a phone number, not a company.
  if (h.split('.').some((l) => (l.match(/\d/g) || []).length >= 9)) return null;
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

// Returns the agent's object reduced to the agreed fields, the error shape if
// the agent returned one, or null if it matches neither. A fact or bottleneck
// that carries contact details is dropped; the rest of the scan stands.
function validateScan(x, domain, c) {
  if (typeof x === 'string') {
    const m = x.match(/\{[\s\S]*\}/); // tolerate a sentence around the object
    try { x = JSON.parse(m ? m[0] : x); } catch (e) { return null; }
  }
  if (!x || typeof x !== 'object' || Array.isArray(x)) return null;
  if (x.type === 'error') {
    const text = cleanOut(x.text, 300);
    return text && !personal(text) ? { type: 'error', text } : null;
  }

  if (!Array.isArray(x.sources) || !x.sources.length || x.sources.length > 4) return null;
  const sources = [];
  for (const s of x.sources) {
    const t = s && cleanOut(s.t, 160);
    const u = s && cleanStr(s.u, 300);
    if (!t || !u) return null;
    let host;
    try {
      const p = new URL(u);
      if (p.protocol !== 'http:' && p.protocol !== 'https:') return null;
      if (p.username || p.password) return null;
      host = p.hostname.toLowerCase().replace(/^www\./, '');
    } catch (e) { return null; }
    // Every source must be a page on the company's own domain.
    if (host !== domain && !host.endsWith('.' + domain)) return null;
    if (personal(t) || personal(u)) return null;
    sources.push({ t, u });
  }
  const n = sources.length;

  const name = cleanOut(x.name, 160);
  const description = cleanOut(x.description, 600);
  const descSrc = refs(x.descSrc, n, 4);
  if (!name || !description || !descSrc || personal(name) || personal(description)) return null;

  if (!Array.isArray(x.pages) || !x.pages.length || x.pages.length > 4) return null;
  const pages = x.pages.map((p) => cleanOut(p, 80));
  if (pages.some((p) => !p || personal(p))) return null;

  if (!Array.isArray(x.facts) || !x.facts.length || x.facts.length > 8) return null;
  const facts = [];
  for (const f of x.facts) {
    const k = f && cleanOut(f.k, 40);
    const v = f && cleanOut(f.v, 300);
    const s = f && refs(f.s, n, 4);
    if (!k || !v || !s) return null;
    if (!personal(k + ' ' + v)) facts.push({ k, v, s });
  }

  if (!Array.isArray(x.bottlenecks) || !x.bottlenecks.length || x.bottlenecks.length > 6) return null;
  const bottlenecks = [];
  for (const b of x.bottlenecks) {
    if (!b || typeof b !== 'object') return null;
    const o = { name: cleanOut(b.name, 120), text: cleanOut(b.text, 400), quote: cleanOut(b.quote, 300) };
    if (!o.name || !o.text || !o.quote) return null;
    if (!Number.isInteger(b.s) || b.s < 1 || b.s > n) return null;
    o.s = b.s;
    if (b.note !== undefined && b.note !== null) {
      o.note = cleanOut(b.note, 300);
      if (!o.note) return null;
    }
    if (Number.isInteger(b.also) && b.also >= 1 && b.also <= n) o.also = b.also;
    if (![0, 1, 2].includes(b.sol)) return null;
    o.sol = b.sol;
    if (b.bench !== null && !BENCH.includes(b.bench)) return null;
    o.bench = b.bench;
    if (!personal([o.name, o.text, o.quote, o.note || ''].join(' '))) bottlenecks.push(o);
  }
  if (!facts.length || !bottlenecks.length) return null;

  if (!Array.isArray(x.solutions) || x.solutions.length !== 3) return null;
  const solutions = [];
  for (const s of x.solutions) {
    const o = s && { type: cleanOut(s.type, 60), name: cleanOut(s.name, 120), text: cleanOut(s.text, 400), keep: cleanOut(s.keep, 200) };
    if (!o || !o.type || !o.name || !o.text || !o.keep) return null;
    if (personal([o.type, o.name, o.text, o.keep].join(' '))) return null;
    solutions.push(o);
  }

  // "domain" is always the one that was asked for, never what came back.
  const out = { domain, name, description, descSrc, pages, facts, bottlenecks, solutions, sources };
  if (c.blocklist.length) {
    const hay = JSON.stringify(out).toLowerCase();
    if (c.blocklist.some((w) => hay.includes(w))) return null;
  }
  return out;
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
  ID_RE, cfg, configured, outbound, redis, getJson, getJob, putJob, hit, claim, sha,
  safeEqual, clientKey, allowed, body, cleanStr, sameOrigin, parseDomain, personal,
  validateScan, errorResult, send,
  newId: () => crypto.randomBytes(16).toString('hex'),
  newToken: () => crypto.randomBytes(32).toString('hex'),
};
