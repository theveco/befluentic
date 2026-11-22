'use strict';
// First Read relay.
//   POST /api/first-read  { input }            start a read
//   POST /api/first-read  { id, reply }        correction, or answer to a question
//   GET  /api/first-read?id=...                poll for the result
// The booking button is a plain link. Nothing is sent anywhere on that click.
const L = require('./_lib/first-read');

async function start(req, res) {
  const c = L.cfg();
  if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
  if (!L.allowed(req, c)) return L.send(res, 403, { error: 'closed' });
  if (!L.sameOrigin(req)) return L.send(res, 403, { error: 'forbidden' });

  const b = L.body(req);
  if (!b) return L.send(res, 400, { error: 'bad_request' });

  let input = null;
  let previous = null;
  let reply = null;
  let turn = 1;

  if (b.id !== undefined) {
    if (typeof b.id !== 'string' || !L.ID_RE.test(b.id)) return L.send(res, 400, { error: 'bad_request' });
    reply = L.cleanStr(b.reply, 500);
    if (!reply) return L.send(res, 400, { error: 'bad_request' });
    const prev = await L.getJob(b.id);
    if (!prev || prev.status !== 'done' || !prev.result) return L.send(res, 404, { error: 'not_found' });
    turn = (prev.turn || 1) + 1;
    if (turn > c.maxTurns) return L.send(res, 429, { error: 'too_many_turns' });
    input = prev.input;
    previous = prev.result;
  } else {
    input = L.cleanStr(b.input, 500);
    if (!input || input.length < 3) return L.send(res, 400, { error: 'bad_request' });
  }

  // Nothing with obvious personal identifiers is stored or sent on.
  if (L.personal(reply !== null ? reply : input)) {
    return L.send(res, 422, { error: 'personal_details' });
  }

  // Limits are checked before anything is spent. If the store is down the
  // relay refuses, so a run can never start without the cap in force.
  const who = L.clientKey(req, c);
  const day = new Date().toISOString().slice(0, 10);
  const hour = new Date().toISOString().slice(0, 13);
  if ((await L.hit('fr:ip:h:' + hour + ':' + who, 3700)) > c.perIpHour) {
    return L.send(res, 429, { error: 'rate_limited' });
  }
  if ((await L.hit('fr:ip:d:' + day + ':' + who, 90000)) > c.perIpDay) {
    return L.send(res, 429, { error: 'rate_limited' });
  }
  if ((await L.hit('fr:cap:' + day, 90000)) > c.dailyCap) {
    return L.send(res, 429, { error: 'daily_cap' });
  }

  const id = L.newId();
  const token = L.newToken();
  const job = {
    id, status: 'pending', created: Date.now(), turn,
    input, previous, reply, tokenHash: L.sha(token), result: null, reason: null,
  };
  await L.putJob(job);

  let ok = false;
  try {
    const r = await fetch(c.webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Hyperagent-Webhook-Secret': c.webhookSecret,
      },
      body: JSON.stringify({
        jobId: id,
        token,
        callbackUrl: c.baseUrl + '/api/first-read-callback',
        input,
        previous,
        reply,
      }),
    });
    ok = r.status === 202 || r.status === 200;
  } catch (e) {
    ok = false;
  }

  if (!ok) {
    job.status = 'done';
    job.result = L.errorResult();
    job.reason = 'upstream';
    job.tokenHash = null;
    await L.putJob(job);
    return L.send(res, 502, { id, status: 'done', result: job.result, reason: 'upstream' });
  }
  return L.send(res, 202, { id, status: 'pending' });
}

async function poll(req, res) {
  const c = L.cfg();
  if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
  // While closed, strangers cannot make the relay touch the store at all.
  if (!L.allowed(req, c)) return L.send(res, 403, { error: 'closed' });
  const id = req.query && req.query.id;
  if (typeof id !== 'string' || !L.ID_RE.test(id)) return L.send(res, 400, { error: 'bad_request' });
  const job = await L.getJob(id);
  if (!job) return L.send(res, 404, { error: 'not_found' });
  if (job.status === 'pending') {
    if (Date.now() - job.created > c.timeoutMs) {
      job.status = 'done';
      job.result = L.errorResult();
      job.reason = 'timeout';
      job.tokenHash = null;
      await L.putJob(job);
    } else {
      return L.send(res, 200, { id, status: 'pending' });
    }
  }
  const out = { id, status: 'done', result: job.result };
  if (job.reason) out.reason = job.reason;
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
