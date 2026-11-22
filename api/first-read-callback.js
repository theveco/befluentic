'use strict';
// First Read relay: the agent posts its finished JSON here.
//   POST /api/first-read-callback  { jobId, token, result }
// The token is issued per job, sent only to the agent, and works once.
const L = require('./_lib/first-read');

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
    if (!(await L.claim('fr:closed:' + job.id, c.jobTtl))) return L.send(res, 409, { error: 'already_closed' });

    const result = L.validateResult(b.result, c);
    job.status = 'done';
    job.tokenHash = null;
    if (result) {
      job.result = result;
    } else {
      job.result = L.errorResult();
      job.reason = 'invalid';
    }
    await L.putJob(job);
    return L.send(res, 200, { ok: true, accepted: Boolean(result) });
  } catch (e) {
    return L.send(res, 503, { error: 'unavailable' });
  }
};
