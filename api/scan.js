'use strict';
// Opportunity Scanner scan service.
//   POST /api/scan  { domain, visitor }   ask for a scan
//   GET  /api/scan?id=...                 poll a scan that is running
//   GET  /api/scan?visitor=...            does this browser already have a scan?
// "visitor" is a random identifier the page keeps in the browser. One scan per
// visitor: a returning visitor gets the scan they were shown, whatever they
// type. A domain scanned before is answered from the saved result.
// The booking button is a plain link. Nothing is sent anywhere on that click.
const L = require('./_lib/scan');

// What this browser was already shown, if anything.
async function saved(visitor) {
  if (!visitor) return null;
  const domain = await L.redis(['GET', 'sc:vis:' + visitor]);
  if (!domain) return null;
  const result = await L.getJson('sc:dom:' + domain);
  if (result) return { status: 'done', result, returning: true };
  const id = await L.redis(['GET', 'sc:pend:' + domain]);
  if (id) return { id, status: 'pending', returning: true };
  // The scan failed or has expired: the visitor has not had their one scan.
  await L.redis(['DEL', 'sc:vis:' + visitor]);
  return null;
}

async function start(req, res) {
  const c = L.cfg();
  if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
  if (!L.allowed(req, c)) return L.send(res, 403, { error: 'closed' });
  if (!L.sameOrigin(req)) return L.send(res, 403, { error: 'forbidden' });

  const b = L.body(req);
  if (!b || typeof b.domain !== 'string') return L.send(res, 400, { error: 'bad_request' });
  if (b.visitor !== undefined && (typeof b.visitor !== 'string' || !L.ID_RE.test(b.visitor))) {
    return L.send(res, 400, { error: 'bad_request' });
  }
  const visitor = b.visitor || null;
  const domain = L.parseDomain(b.domain);
  if (!domain) return L.send(res, 422, { error: 'not_a_domain' });
  if (c.blockedDomains.some((d) => domain === d || domain.endsWith('.' + d))) {
    return L.send(res, 422, { error: 'unsupported_domain' });
  }

  // 1. One scan per visitor.
  const mine = await saved(visitor);
  if (mine) return L.send(res, mine.status === 'done' ? 200 : 202, mine);

  // 2. A domain scanned before, or being scanned right now, costs nothing.
  const link = async () => { if (visitor) await L.redis(['SET', 'sc:vis:' + visitor, domain, 'EX', c.keepSeconds]); };
  const known = await L.getJson('sc:dom:' + domain);
  if (known) { await link(); return L.send(res, 200, { status: 'done', result: known, cached: true }); }
  const running = await L.redis(['GET', 'sc:pend:' + domain]);
  if (running) { await link(); return L.send(res, 202, { id: running, status: 'pending' }); }

  // 3. A fresh run. Limits are checked before anything is spent. If the store
  //    is down the service refuses, so a run never starts without the cap.
  const day = new Date().toISOString().slice(0, 10);
  if ((await L.hit('sc:ipd:' + day + ':' + L.clientKey(req, c), 90000)) > c.perIpDay) {
    return L.send(res, 429, { error: 'rate_limited' });
  }
  if ((await L.hit('sc:cap:' + day, 90000)) > c.dailyCap) {
    return L.send(res, 429, { error: 'daily_cap' });
  }

  const id = L.newId();
  const token = L.newToken();
  const pendTtl = Math.ceil(c.timeoutMs / 1000) + 30;
  if (!(await L.claim('sc:pend:' + domain, id, pendTtl))) {
    // Someone asked for the same domain in the same instant. Join their run.
    const other = await L.redis(['GET', 'sc:pend:' + domain]);
    if (other) { await link(); return L.send(res, 202, { id: other, status: 'pending' }); }
    await L.redis(['SET', 'sc:pend:' + domain, id, 'EX', pendTtl]);
  }
  const job = { id, status: 'pending', created: Date.now(), domain, tokenHash: L.sha(token), result: null, reason: null };
  await L.putJob(job);
  await link();

  let ok = false;
  try {
    const r = await L.outbound(c.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Hyperagent-Webhook-Secret': c.webhookSecret },
      body: JSON.stringify({ jobId: id, token, callbackUrl: c.baseUrl + '/api/scan-callback', domain }),
    });
    ok = r.ok;
  } catch (e) {
    ok = false;
  }

  if (!ok) {
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'upstream';
    job.tokenHash = null;
    await L.putJob(job);
    await L.redis(['DEL', 'sc:pend:' + domain]);
    if (visitor) await L.redis(['DEL', 'sc:vis:' + visitor]);
    return L.send(res, 502, { id, status: 'done', result: job.result, reason: 'upstream' });
  }
  return L.send(res, 202, { id, status: 'pending' });
}

async function look(req, res) {
  const c = L.cfg();
  if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
  // While closed, strangers cannot make the service touch the store at all.
  if (!L.allowed(req, c)) return L.send(res, 403, { error: 'closed' });
  const q = req.query || {};

  if (q.visitor !== undefined) {
    if (typeof q.visitor !== 'string' || !L.ID_RE.test(q.visitor)) return L.send(res, 400, { error: 'bad_request' });
    const mine = await saved(q.visitor);
    return L.send(res, 200, mine || { status: 'none' });
  }

  if (typeof q.id !== 'string' || !L.ID_RE.test(q.id)) return L.send(res, 400, { error: 'bad_request' });
  const job = await L.getJob(q.id);
  if (!job) return L.send(res, 404, { error: 'not_found' });
  if (job.status === 'pending') {
    if (Date.now() - job.created <= c.timeoutMs) return L.send(res, 200, { id: job.id, status: 'pending' });
    // If the agent's result is landing at this very moment, let it win.
    if (!(await L.claim('sc:closed:' + job.id, '1', c.jobTtl))) return L.send(res, 200, { id: job.id, status: 'pending' });
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'timeout';
    job.tokenHash = null;
    await L.putJob(job);
    await L.redis(['DEL', 'sc:pend:' + job.domain]);
  }
  const out = { id: job.id, status: 'done', result: job.result };
  if (job.reason) out.reason = job.reason;
  return L.send(res, 200, out);
}

module.exports = async (req, res) => {
  try {
    if (req.method === 'POST') return await start(req, res);
    if (req.method === 'GET') return await look(req, res);
    res.setHeader('Allow', 'GET, POST');
    return L.send(res, 405, { error: 'method_not_allowed' });
  } catch (e) {
    return L.send(res, 503, { error: 'unavailable' });
  }
};
