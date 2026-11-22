'use strict';
// Opportunity Scanner scan service: the agent posts its finished scan here.
//   POST /api/scan-callback  { jobId, token, result }
// The token is issued per scan, sent only to the agent, and works once.
const L = require('./_lib/scan');

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return L.send(res, 405, { error: 'method_not_allowed' });
    }
    const c = L.cfg();
    if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });

    const b = L.body(req);
    if (!b || typeof b.jobId !== 'string' || !L.ID_RE.test(b.jobId) || typeof b.token !== 'string') {
      return L.send(res, 400, { error: 'bad_request' });
    }
    const job = await L.getJob(b.jobId);
    if (!job) return L.send(res, 404, { error: 'not_found' });
    if (job.status !== 'pending' || !job.tokenHash) return L.send(res, 409, { error: 'already_closed' });
    if (!L.safeEqual(L.sha(b.token), job.tokenHash)) return L.send(res, 403, { error: 'forbidden' });
    // Closed exactly once: a second callback, or one racing the timeout, stops here.
    if (!(await L.claim('sc:closed:' + job.id, '1', c.jobTtl))) return L.send(res, 409, { error: 'already_closed' });

    const result = L.validateScan(b.result, job.domain, c);
    job.status = 'done';
    job.tokenHash = null;
    const good = Boolean(result && result.type !== 'error');
    if (result) {
      job.result = result;
      if (!good) job.reason = 'agent_error';
    } else {
      job.result = L.errorResult();
      job.reason = 'invalid';
    }
    // Only a full scan is kept, so a failed one never becomes "the saved result".
    if (good) await L.redis(['SET', 'sc:dom:' + job.domain, JSON.stringify(result), 'EX', c.keepSeconds]);
    await L.putJob(job);
    await L.redis(['DEL', 'sc:pend:' + job.domain]);
    return L.send(res, 200, { ok: true, accepted: good });
  } catch (e) {
    return L.send(res, 503, { error: 'unavailable' });
  }
};
