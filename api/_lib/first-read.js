'use strict';
// Shared helpers for the First Read relay. Files under api/_lib are not routed.
const crypto = require('crypto');

const ERROR_TEXT = "We couldn't read that site. Describe your business in one line instead.";
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

function cfg() {
  const env = process.env;
  // The agent posts its result back to the live domain. Preview deployments sit
  // behind Vercel's login, so the agent could never reach a preview address.
  // The apex befluentic.com redirects to www, so www is used.
  const baseUrl = env.FIRST_READ_BASE_URL || 'https://www.befluentic.com';
  return {
    redisUrl: (env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, ''),
    redisToken: env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN || '',
    webhookUrl: env.FIRST_READ_WEBHOOK_URL || '',
    webhookSecret: env.FIRST_READ_WEBHOOK_SECRET || '',
    baseUrl: baseUrl.replace(/\/+$/, ''),
    // Closed by default. Visitors are let in only when FIRST_READ_PUBLIC is "1".
    // A preview deployment is also let in, for private testing: previews on
    // this project are reachable only through Vercel's login. If that login
    // wall is ever switched off, remove the preview clause.
    isPublic: env.FIRST_READ_PUBLIC === '1' || env.VERCEL_ENV === 'preview',
    // Provisional limits. Daily cap tracks credit spend per day and stays low
    // until the cost of one run is measured. Per-visitor limit tracks one
    // session: a read plus up to two replies, twice an hour.
    dailyCap: int(env.FIRST_READ_DAILY_CAP, 50),
    perIpHour: int(env.FIRST_READ_PER_IP_HOUR, 6),
    perIpDay: int(env.FIRST_READ_PER_IP_DAY, 12),
    maxTurns: int(env.FIRST_READ_MAX_TURNS, 4, 1),
    timeoutMs: int(env.FIRST_READ_TIMEOUT_SECONDS, 150, 30) * 1000,
    jobTtl: 3600,
    blocklist: (env.FIRST_READ_BLOCKLIST || '')
      .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
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

async function getJob(id) {
  const raw = await redis(['GET', 'fr:job:' + id]);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function putJob(job) {
  await redis(['SET', 'fr:job:' + job.id, JSON.stringify(job), 'EX', cfg().jobTtl]);
}

// Counter with a fixed window. Returns the count after this hit.
async function hit(key, ttlSeconds) {
  const n = await redis(['INCR', key]);
  // A store that answers without a number must not read as "under the limit".
  if (!Number.isInteger(n)) throw new Error('store_bad');
  if (n === 1) await redis(['EXPIRE', key, ttlSeconds]);
  return n;
}

// First caller wins. Used so a job is closed exactly once and answers one reply.
async function claim(key, ttlSeconds) {
  return (await redis(['SET', key, '1', 'NX', 'EX', ttlSeconds])) === 'OK';
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

// While the relay is not public, only a caller holding the test key gets in.
function allowed(req, c) {
  if (c.isPublic) return true;
  const k = (req.headers || {})['x-first-read-test'];
  return typeof k === 'string' && k.length <= 200 && safeEqual(sha(k), TEST_KEY_SHA256);
}

function body(req) {
  let b;
  try { b = req.body; } catch (e) { return null; }
  if (typeof b === 'string') {
    if (b.length > 20000) return null;
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

// Refuses text that carries obvious personal identifiers, before anything is
// stored or forwarded. Pattern-based only: any "@" (email addresses, in any
// spacing), or 9 or more digits in a row allowing up to three separator
// characters between digits (9 is the length of a local Kosovo mobile number;
// card, account and ID numbers are longer). For a web address only the host
// name is set aside, so a number in its path or query still counts, and a host
// name that is itself a long number is refused. It cannot judge meaning; the
// agent's own rules cover private details written in words.
const LONG_NUMBER = /\p{Nd}(?:[\s().\/\-\u2010-\u2015_]{0,3}\p{Nd}){8,}/u;
const HOST = /^(https?:\/\/)?((?:[\w-]+\.)+[a-z]{2,})(:\d+)?/i;
function personal(text) {
  if (text.includes('@')) return true;
  const rest = text.split(/\s+/).map((t) => {
    const m = HOST.exec(t);
    if (!m) return t;
    if (/\d{9}/.test(m[2].replace(/[.-]/g, ''))) return '000000000';
    return ' ' + t.slice(m[0].length);
  }).join(' ');
  return LONG_NUMBER.test(rest);
}

// A web address is cut down to its host: paths and query strings can carry
// personal details and are never stored or forwarded. The agent starts from
// the home page in any case.
function tidy(text) {
  return text.split(/\s+/).map((t) => {
    const m = HOST.exec(t);
    if (!m) return t;
    const trail = t.slice(m[0].length);
    return trail === '' || /^[\/?#]/.test(trail) ? (m[1] || '') + m[2].toLowerCase() : t;
  }).join(' ');
}

// Refuses addresses the agent should never be sent to read: this-machine and
// private-network names, raw IP addresses, and anything that is not http(s).
function unsafeTarget(text) {
  return /(^|[^\w.-])localhost\b/i.test(text)
    || /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text)
    || /\[[0-9a-f:.]+\]/i.test(text)
    || /\b(?!https?:\/\/)[a-z][a-z0-9+.-]*:\/\//i.test(text)
    || /\.(local|internal|lan|home|corp|localdomain)\b/i.test(text);
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

function items(a) {
  if (!Array.isArray(a) || a.length !== 3) return null;
  const out = [];
  for (const it of a) {
    if (!it || typeof it !== 'object') return null;
    const name = cleanOut(it.name, 160);
    const text = cleanOut(it.text, 1200);
    if (!name || !text) return null;
    out.push({ name, text });
  }
  return out;
}

// Returns the agent's object reduced to the agreed fields, or null if it does
// not match one of the three shapes.
function validateResult(x, c) {
  if (typeof x === 'string') {
    try { x = JSON.parse(x); } catch (e) { return null; }
  }
  if (!x || typeof x !== 'object' || Array.isArray(x)) return null;
  let out = null;
  if (x.type === 'read') {
    const company = cleanOut(x.company, 160);
    const description = cleanOut(x.description, 1500);
    const bottlenecks = items(x.bottlenecks);
    const actions = items(x.actions);
    if (company && description && bottlenecks && actions) {
      out = { type: 'read', company, description, bottlenecks, actions };
    }
  } else if (x.type === 'question' || x.type === 'error') {
    const text = cleanOut(x.text, 600);
    if (text) out = { type: x.type, text };
  }
  if (!out) return null;
  // The read must carry no contact details, so it is held to the same check.
  const said = out.type === 'read'
    ? [out.company, out.description].concat(out.bottlenecks.concat(out.actions).map((i) => i.name + ' ' + i.text))
    : [out.text];
  if (said.some((t) => personal(t))) return null;
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
  ID_RE, cfg, configured, redis, getJob, putJob, hit, sha, safeEqual, clientKey,
  allowed, body, claim, cleanStr, outbound, personal, tidy, unsafeTarget, sameOrigin, validateResult, errorResult, send,
  newId: () => crypto.randomBytes(16).toString('hex'),
  newToken: () => crypto.randomBytes(32).toString('hex'),
};
