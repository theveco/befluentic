'use strict';
// Opportunity Scanner scan service.
//   POST /api/scan  { domain }     ask for a scan
//   GET  /api/scan?id=...          poll a scan that is running
// No visitor is recognised by the service. A domain scanned before is
// answered from the saved result; fresh runs are limited per network address
// (successful scans only, plus a limit on failed ones) and by a daily cap.
// The booking button is a plain link. Nothing is sent anywhere on that click.
const L = require('./_lib/scan');

async function start(req, res) {
  const c = L.cfg();
  if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
  if (!L.allowed(req, c)) return L.send(res, 403, { error: 'closed' });
  if (!L.sameOrigin(req)) return L.send(res, 403, { error: 'forbidden' });

  const b = L.body(req);
  if (!b || typeof b.domain !== 'string') return L.send(res, 400, { error: 'bad_request' });
  const domain = L.parseDomain(b.domain);
  if (!domain) return L.send(res, 422, { error: 'not_a_domain' });
  if (c.blockedDomains.some((d) => domain === d || domain.endsWith('.' + d))) {
    return L.send(res, 422, { error: 'unsupported_domain' });
  }

  // 1. A domain scanned before, or being scanned right now, costs nothing.
  //    A scan saved in the earlier shape is not served: it is made again.
  const known = await L.getJson('sc:dom:' + domain);
  if (known && L.current(known, c)) return L.send(res, 200, { status: 'done', result: known, cached: true });
  const running = await L.redis(['GET', 'sc:pend:' + domain]);
  if (running) return L.send(res, 202, { id: running, status: 'pending' });

  // 2. A fresh run. The name must resolve to public addresses only.
  const where = await L.reach(domain);
  if (where === 'private') return L.send(res, 422, { error: 'unsupported_domain' });
  if (where !== 'ok') return L.send(res, 422, { error: 'unreachable_domain' });

  //    Limits are checked before anything is spent. If the store is down the
  //    service refuses, so a run never starts without the cap.
  //    The address count holds this run while it is going; it is handed back
  //    if the run ends without a result, so only a successful scan uses up the
  //    visitor's scan. Failed runs are counted apart and limited.
  const day = new Date().toISOString().slice(0, 10);
  const who = L.clientKey(req, c);
  const ipKey = 'sc:ipd:' + day + ':' + who;
  const failKey = 'sc:ipf:' + day + ':' + who;
  if ((Number(await L.redis(['GET', failKey])) || 0) >= c.perIpFails) {
    return L.send(res, 429, { error: 'rate_limited', failed: true });
  }
  if ((await L.hit(ipKey, 90000)) > c.perIpDay) {
    await L.redis(['DECR', ipKey]);
    return L.send(res, 429, { error: 'rate_limited' });
  }
  if ((await L.hit('sc:cap:' + day, 90000)) > c.dailyCap) {
    // No run, so the visitor's scan is not used up.
    await L.redis(['DECR', ipKey]);
    return L.send(res, 429, { error: 'daily_cap' });
  }

  const id = L.newId();
  const token = L.newToken();
  const pendTtl = Math.ceil(c.timeoutMs / 1000) + 30;
  if (!(await L.claim('sc:pend:' + domain, id, pendTtl))) {
    // Someone asked for the same domain in the same instant. Join their run.
    const other = await L.redis(['GET', 'sc:pend:' + domain]);
    if (other) {
      // No run of our own after all, so hand both counts back.
      await L.redis(['DECR', ipKey]);
      await L.redis(['DECR', 'sc:cap:' + day]);
      return L.send(res, 202, { id: other, status: 'pending' });
    }
    await L.redis(['SET', 'sc:pend:' + domain, id, 'EX', pendTtl]);
  }
  const job = { id, status: 'pending', created: Date.now(), domain, ipKey, failKey, tokenHash: L.sha(token), result: null, reason: null };
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
    // No answer in time: the run may have been queued all the same. Leave the
    // scan pending, so a retry cannot pay for the same run twice.
    unsure = Boolean(e && (e.name === 'TimeoutError' || e.name === 'AbortError'));
  }

  if (!ok && !unsure) {
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'upstream';
    job.tokenHash = null;
    await L.putJob(job);
    await L.release(domain, id);
    await L.refund(job);
    return L.send(res, 502, { id, status: 'done', result: job.result, reason: 'upstream' });
  }
  return L.send(res, 202, { id, status: 'pending' });
}

async function poll(req, res) {
  const c = L.cfg();
  if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
  // While closed, strangers cannot make this route touch the store at all.
  if (!L.allowed(req, c)) return L.send(res, 403, { error: 'closed' });
  const id = req.query && req.query.id;
  if (typeof id !== 'string' || !L.ID_RE.test(id)) return L.send(res, 400, { error: 'bad_request' });
  const job = await L.getJob(id);
  // A scan the team page started is not answered here.
  if (!job || job.internal) return L.send(res, 404, { error: 'not_found' });
  if (job.status === 'pending') {
    if (Date.now() - job.created <= c.timeoutMs) return L.send(res, 200, { id: job.id, status: 'pending' });
    // If the agent's result is landing at this very moment, let it win.
    if (!(await L.claim('sc:closed:' + job.id, '1', c.jobTtl))) return L.send(res, 200, { id: job.id, status: 'pending' });
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'timeout';
    job.tokenHash = null;
    await L.putJob(job);
    await L.release(job.domain, job.id);
    await L.refund(job);
  }
  const out = { id: job.id, status: 'done', result: job.result };
  if (job.reason) out.reason = job.reason;
  // The rejection detail is shown only to the holder of the test key.
  if (job.detail && L.hasTestKey(req)) out.detail = job.detail;
  return L.send(res, 200, out);
}

module.exports = async (req, res) => {
  try {
    if (req.method === 'POST') return await start(req, res);
    if (req.method === 'GET') return await poll(req, res);
    res.setHeader('Allow', 'GET, POST');
    return L.send(res, 405, { error: 'method_not_allowed' });
  } catch (e) {
    return L.send(res, 503, { error: 'unavailable' });
  }
};
