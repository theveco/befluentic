'use strict';
// First Read relay: records a booking click.
//   POST /api/first-read-lead  { id }
// Sends the visitor's input and the read to the existing Formspree form, once
// per read. No email address is collected and nothing is sent to the visitor.
const L = require('./_lib/first-read');

function readAsText(r) {
  const lines = [r.company, '', r.description, '', 'Likely bottlenecks'];
  r.bottlenecks.forEach((x, i) => lines.push((i + 1) + '. ' + x.name + ': ' + x.text));
  lines.push('', 'What we could do');
  r.actions.forEach((x, i) => lines.push((i + 1) + '. ' + x.name + ': ' + x.text));
  return lines.join('\n');
}

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return L.send(res, 405, { error: 'method_not_allowed' });
    }
    const c = L.cfg();
    if (!L.configured(c)) return L.send(res, 503, { error: 'not_configured' });
    if (!L.sameOrigin(req)) return L.send(res, 403, { error: 'forbidden' });

    const b = L.body(req);
    if (!b || typeof b.id !== 'string' || !L.ID_RE.test(b.id)) return L.send(res, 400, { error: 'bad_request' });
    const job = await L.getJob(b.id);
    if (!job || job.status !== 'done' || !job.result || job.result.type !== 'read') {
      return L.send(res, 404, { error: 'not_found' });
    }

    const first = await L.redis(['SET', 'fr:lead:' + job.id, '1', 'NX', 'EX', 86400]);
    if (first !== 'OK') return L.send(res, 200, { ok: true, duplicate: true });

    let ok = false;
    try {
      const r = await fetch(c.formspreeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          _subject: 'First Read: booking click (' + job.result.company + ')',
          source: 'First Read, booking click',
          input: job.input,
          read: readAsText(job.result),
          timestamp: new Date().toISOString(),
        }),
      });
      ok = r.ok;
    } catch (e) {
      ok = false;
    }
    if (!ok) {
      await L.redis(['DEL', 'fr:lead:' + job.id]);
      return L.send(res, 502, { error: 'lead_not_sent' });
    }
    return L.send(res, 200, { ok: true });
  } catch (e) {
    return L.send(res, 503, { error: 'unavailable' });
  }
};
