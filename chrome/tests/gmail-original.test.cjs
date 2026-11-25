const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness(location, fetch) {
  const context = vm.createContext({ location, fetch, Uint8Array, TextDecoder, atob });
  for (const file of ['original-mime.js', 'gmail-original.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context);
  }
  return context.PixelGuardGmailOriginal;
}
function bodyWith(attrs) {
  return { parentElement: { closest: selector => {
    assert.equal(selector, '[data-legacy-message-id], [data-message-id]');
    return { getAttribute: key => attrs[key] || null };
  } } };
}
const account = new URL('https://mail.google.com/mail/u/2/#inbox/threadOnly');
const id = '1f0102040a0c0001';
const eml = 'Content-Type: text/html; charset=utf-8\r\n\r\n<p>Prueba ☃</p>';

test('uses an individual message from the active Gmail account, preserving all 64 bits', () => {
  const api = harness(account);
  assert.equal(api.messageId(bodyWith({'data-legacy-message-id': id.toUpperCase()})), id);
  assert.equal(api.messageId(bodyWith({'data-message-id': '#msg-f:' + BigInt('0x' + id)})), id);
  assert.equal(api.messageId(bodyWith({'data-message-id': '#msg-f:18446744073709551616'})), null);
  assert.equal(api.messageId(bodyWith({'data-message-id': '#thread-f:123', 'data-thread-id': id})), null);
  for (const location of [new URL('https://mail.google.com/mail/'), new URL('https://example.test/mail/u/2/')]) {
    assert.equal(harness(location).messageId(bodyWith({'data-legacy-message-id': id})), null);
  }
});

test('retrieves only Gmail’s own original as bytes, with cancellation and no referrer', async () => {
  const signal = new AbortController().signal;
  let requests = 0;
  const api = harness(account, async (url, options) => {
    requests++;
    assert.equal(url, 'https://mail.google.com/mail/u/2?view=att&th=' + id + '&attid=0&disp=comp&safe=1&zw');
    assert.equal(options.mode, 'same-origin');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.redirect, 'error');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.signal, signal);
    return new Response(eml, { headers: { 'content-type': 'message/rfc822' } });
  });
  assert.equal(await api.read(id, signal), '<p>Prueba ☃</p>');
  await assert.rejects(api.read('123&th=456', signal), /Invalid/);
  assert.equal(requests, 1);
});

test('rejects a login page, incomplete response or oversized stream before MIME analysis', async () => {
  for (const response of [
    new Response(eml, { headers: { 'content-type': 'text/html; charset=utf-8' } }),
    new Response(eml, { status: 206 }),
    new Response(eml, { headers: { 'content-length': String(8 * 1024 * 1024 + 1) } })
  ]) {
    await assert.rejects(harness(account, async () => response).read(id));
  }
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(4 * 1024 * 1024)); },
    cancel() { cancelled = true; }
  });
  await assert.rejects(harness(account, async () => new Response(stream)).read(id), /too large/);
  assert.equal(cancelled, true);
});
