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

test('tries only the corresponding Gmail original view when the download is unavailable', async () => {
  const signal = new AbortController().signal;
  const native = 'https://mail.google.com/mail/u/2/?view=om&permmsgid=msg-f:' + BigInt('0x' + id);
  for (const download of [
    () => new Response('<html>Sign in</html>', { headers: { 'content-type': 'text/html' } }),
    () => new Response(eml, { status: 206 }),
    () => { throw new TypeError('Network error'); }
  ]) {
    const requests = [];
    const api = harness(account, async (url, options) => {
      requests.push(url);
      if (requests.length === 1) return download();
      assert.equal(url, native);
      assert.equal(options.mode, 'same-origin');
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.redirect, 'error');
      assert.equal(options.referrerPolicy, 'no-referrer');
      assert.equal(options.signal, signal);
      return new Response('Not a Gmail original page', { headers: { 'content-type': 'text/plain' } });
    });
    await assert.rejects(api.read(id, signal), /Gmail original unavailable/);
    assert.equal(requests.length, 2);
  }
});

test('does not request the original again after a size limit, cancellation, or unsupported MIME', async () => {
  const ctrl = new AbortController();
  for (const [download, expected] of [
    [() => new Response(eml, { headers: { 'content-length': String(8 * 1024 * 1024 + 1) } }), /too large/],
    [() => new Response('Content-Type: text/plain\r\n\r\nA plain message'), /no HTML/],
    [() => { ctrl.abort(); throw new Error('Cancelled'); }, /Cancelled/]
  ]) {
    let requests = 0;
    const api = harness(account, async () => { requests++; return download(); });
    await assert.rejects(api.read(id, ctrl.signal), expected);
    assert.equal(requests, 1);
  }
  let requests = 0;
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(4 * 1024 * 1024)); },
    cancel() { cancelled = true; }
  });
  const api = harness(account, async () => { requests++; return new Response(stream); });
  await assert.rejects(api.read(id), /too large/);
  assert.equal(cancelled, true);
  assert.equal(requests, 1);
});
