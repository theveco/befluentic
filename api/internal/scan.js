'use strict';
// Team scanner: the same scan as /api/scan, for the Fluentic team page at
// /internal/scan/. Every request carries the team password in X-Team-Password.
//   GET  /api/internal/scan?check=1   200 if the password is right
//   POST /api/internal/scan { domain } same answers as /api/scan
//   GET  /api/internal/scan?id=...    same answers as /api/scan
// The password lives only in the SCAN_TEAM_PASSWORD project setting. Wrong or
// missing: 401 with an empty body. Too many wrong tries from one network
// address: 429 with an empty body, even for the right password, until the
// window ends.
// These scans have no per-address limit and do not touch the public counters.
// They are not saved as the public result for a domain. Nothing is emailed or
// recorded as a lead.
const crypto = require('crypto');
const L = require('../_lib/scan');

// At least this long, or the team route stays shut: the password is the only
// thing between the internet and unlimited agent runs.
const MIN_PASSWORD = 16;
// Wrong passwords allowed per network address per window.
const MAX_WRONG = 10;
const WINDOW_SECONDS = 900;

function team() {
  const env = process.env;
  const pw = typeof env.SCAN_TEAM_PASSWORD === 'string' ? env.SCAN_TEAM_PASSWORD.trim() : '';
  // Optional brake on team spend, off unless set. It has its own counter.
  const cap = env.SCAN_TEAM_DAILY_CAP;
  const n = cap === undefined || String(cap).trim() === '' ? null : Number(String(cap).trim());
  return { pw: pw.length >= MIN_PASSWORD ? pw : '', dailyCap: Number.isInteger(n) && n >= 0 ? n : null };
}

function plain(res, status) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.statusCode = status;
  return res.end();
}

function json(res, status, obj) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  return res.status(status).json(obj);
}

// Both sides are hashed first, so the comparison takes the same time whatever
// the length or content of what was sent.
function samePassword(given, real) {
  const a = crypto.createHash('sha256').update(String(given)).digest();
  const b = crypto.createHash('sha256').update(String(real)).digest();
  return crypto.timingSafeEqual(a, b);
}

// Returns null when the caller may go on, otherwise the status to answer with.
async function gate(req, c, t) {
  const given = (req.headers || {})['x-team-password'];
  if (!t.pw || typeof given !== 'string' || !given || given.length > 500) return 401;
  const win = Math.floor(Date.now() / (WINDOW_SECONDS * 1000));
  const key = 'sc:tpw:' + win + ':' + L.clientKey(req, c);
  const wrong = Number(await L.redis(['GET', key])) || 0;
  if (wrong >= MAX_WRONG) return 429;
  if (samePassword(given, t.pw)) return null;
  await L.hit(key, WINDOW_SECONDS + 60);
  return 401;
}

async function start(req, res, c, t) {
  if (!L.sameOrigin(req)) return json(res, 403, { error: 'forbidden' });
  const b = L.body(req);
  if (!b || typeof b.domain !== 'string') return json(res, 400, { error: 'bad_request' });
  const domain = L.parseDomain(b.domain);
  if (!domain) return json(res, 422, { error: 'not_a_domain' });
  if (c.blockedDomains.some((d) => domain === d || domain.endsWith('.' + d))) {
    return json(res, 422, { error: 'unsupported_domain' });
  }

  // 1. A saved scan costs nothing: the public one first, then the team's own.
  for (const key of ['sc:dom:' + domain, L.savedKey(domain, true)]) {
    const known = await L.getJson(key);
    if (known && L.current(known, c)) return json(res, 200, { status: 'done', result: known, cached: true });
  }
  //    A run already going for this domain, public or team, is joined.
  for (const key of [L.pendKey(domain, false), L.pendKey(domain, true)]) {
    const running = await L.redis(['GET', key]);
    if (running) return json(res, 202, { id: running, status: 'pending' });
  }

  // 2. A fresh run. The name must resolve to public addresses only.
  const where = await L.reach(domain);
  if (where === 'private') return json(res, 422, { error: 'unsupported_domain' });
  if (where !== 'ok') return json(res, 422, { error: 'unreachable_domain' });

  //    No per-address limit and no public counter. Only the optional team cap.
  const day = new Date().toISOString().slice(0, 10);
  const capKey = 'sc:tcap:' + day;
  if (t.dailyCap !== null && (await L.hit(capKey, 90000)) > t.dailyCap) {
    return json(res, 429, { error: 'daily_cap' });
  }

  const id = L.newId();
  const token = L.newToken();
  const pendTtl = Math.ceil(c.timeoutMs / 1000) + 30;
  const pend = L.pendKey(domain, true);
  if (!(await L.claim(pend, id, pendTtl))) {
    const other = await L.redis(['GET', pend]);
    if (other) {
      if (t.dailyCap !== null) await L.redis(['DECR', capKey]);
      return json(res, 202, { id: other, status: 'pending' });
    }
    await L.redis(['SET', pend, id, 'EX', pendTtl]);
  }
  const job = { id, status: 'pending', created: Date.now(), domain, internal: true, tokenHash: L.sha(token), result: null, reason: null };
  await L.putJob(job);

  let ok = false; let unsure = false;
  try {
    const r = await L.outbound(c.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Hyperagent-Webhook-Secret': c.webhookSecret },
      body: JSON.stringify({ jobId: id, token, callbackUrl: c.baseUrl + '/api/scan-callback', domain }),
    });
    ok = r.ok;
  } catch (e) {
    unsure = Boolean(e && (e.name === 'TimeoutError' || e.name === 'AbortError'));
  }

  if (!ok && !unsure) {
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'upstream';
    job.tokenHash = null;
    await L.putJob(job);
    await L.release(domain, id, true);
    return json(res, 502, { id, status: 'done', result: job.result, reason: 'upstream' });
  }
  return json(res, 202, { id, status: 'pending' });
}

async function poll(req, res, c) {
  const id = req.query && req.query.id;
  if (typeof id !== 'string' || !L.ID_RE.test(id)) return json(res, 400, { error: 'bad_request' });
  const job = await L.getJob(id);
  if (!job) return json(res, 404, { error: 'not_found' });
  if (job.status === 'pending') {
    if (Date.now() - job.created <= c.timeoutMs) return json(res, 200, { id: job.id, status: 'pending' });
    if (!(await L.claim('sc:closed:' + job.id, '1', c.jobTtl))) return json(res, 200, { id: job.id, status: 'pending' });
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'timeout';
    job.tokenHash = null;
    await L.putJob(job);
    await L.release(job.domain, job.id, job.internal);
  }
  const out = { id: job.id, status: 'done', result: job.result };
  if (job.reason) out.reason = job.reason;
  // The team sees which rule rejected a scan: field names and sizes, no content.
  if (job.detail) out.detail = job.detail;
  return json(res, 200, out);
}

module.exports = async (req, res) => {
  try {
    if (req.method !== 'GET' && req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return plain(res, 405);
    }
    const c = L.cfg();
    const t = team();
    // Shut, or not set up: the route gives nothing away.
    const given = (req.headers || {})['x-team-password'];
    if (!t.pw || typeof given !== 'string' || !given) return plain(res, 401);
    if (!L.configured(c)) return json(res, 503, { error: 'not_configured' });
    const shut = await gate(req, c, t);
    if (shut) return plain(res, shut);

    if (req.method === 'POST') return await start(req, res, c, t);
    if (req.query && req.query.check !== undefined) return json(res, 200, { ok: true });
    return await poll(req, res, c);
  } catch (e) {
    return json(res, 503, { error: 'unavailable' });
  }
};
