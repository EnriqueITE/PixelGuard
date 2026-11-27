const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness(location, fetch, anchors = [], runtime, implementation) {
  const document = { querySelectorAll: () => anchors, implementation };
  const context = vm.createContext({ location, fetch, document, chrome: {runtime}, URL, URLSearchParams, Uint8Array, TextDecoder, atob });
  for (const file of ['original-mime.js', 'gmail-original.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context);
  }
  return context.PixelGuardGmailOriginal;
}
function bodyWith(attrs) {
  return { isConnected: true, parentElement: { closest: selector => {
    assert.equal(selector, '[data-legacy-message-id], [data-message-id]');
    return { getAttribute: key => attrs[key] || null };
  } } };
}
const account = new URL('https://mail.google.com/mail/u/2/#inbox/threadOnly');
const id = '1f0102040a0c0001';
const eml = 'Content-Type: text/html; charset=utf-8\r\n\r\n<p>Prueba ☃</p>';
function assertReadBody(original) {
  assert.equal(original.partial, false);
  assert.equal(original.parts.length, 1);
  assert.equal(original.parts[0].type, 'text/html');
  assert.equal(original.parts[0].content, '<p>Prueba ☃</p>');
}

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
    assert.equal(url, 'https://mail.google.com/mail/u/2/?view=att&th=' + id + '&attid=0&disp=comp&safe=1&zw');
    assert.equal(options.mode, 'same-origin');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.redirect, 'error');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.signal, signal);
    return new Response(eml, { headers: { 'content-type': 'message/rfc822' } });
  });
  assertReadBody(await api.read(id, signal));
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

test('a full scan uses the permanent ID from the message wrapper, independently of the legacy ID', async () => {
  const permanent = 'msg-a:r-12345678';
  const body = bodyWith({'data-legacy-message-id': id, 'data-message-id': '#' + permanent});
  const urls = [];
  const api = harness(account, async url => {
    urls.push(new URL(url));
    return new Response(eml, { headers: { 'content-type': 'message/rfc822' } });
  });
  assertReadBody(await api.read(id, undefined, body));
  assert.equal(urls[0].pathname, '/mail/u/2/');
  assert.equal(urls[0].searchParams.get('view'), 'att');
  assert.equal(urls[0].searchParams.get('permmsgid'), permanent);
  assert.equal(urls[0].searchParams.has('th'), false);
  assert.equal(api.messageId(bodyWith({'data-message-id': '#' + permanent})), permanent);
  await assert.rejects(api.read('beda', undefined, body), /changed/);
  await assert.rejects(api.read('msg-a:1&th=bad'), /Invalid/);
  assert.equal(urls.length, 1);
});

test('falls back to the actual legacy download only when the permanent download and source view are unavailable', async () => {
  const permanent = 'msg-a:r-12345678';
  const body = bodyWith({'data-legacy-message-id': id, 'data-message-id': '#' + permanent});
  const permDownload = 'view=att&permmsgid=' + permanent;
  const nativeView = 'view=om&permmsgid=' + permanent;
  const legacyDownload = 'view=att&th=' + id;
  for (const hint of ['', '123abc1234']) {
    const observed = [];
    const runtime = {sendMessage: async () => ({ok: true, hint})};
    const api = harness(account, async url => {
      const params = new URL(url).searchParams;
      const key = params.has('th') ? 'th' : 'permmsgid';
      observed.push('view=' + params.get('view') + '&' + key + '=' + params.get(key));
      assert.equal(params.get('ik'), hint || null);
      return params.get('th') === id ? new Response(eml) : new Response('Unavailable', {status: 404});
    }, [], runtime);
    assertReadBody(await api.read(id, undefined, body));
    assert.deepEqual(observed, hint ? [nativeView, permDownload, legacyDownload] : [permDownload, nativeView, legacyDownload]);
  }
});

test('only forwards an existing Gmail mailbox hint from this message on the same account', async () => {
  const permId = 'msg-f:' + BigInt('0x' + id);
  const native = '?view=om&permmsgid=' + permId;
  const anchor = (href, inBody = false) => ({ getAttribute: () => href, closest: () => inBody ? {} : null });
  const anchors = [
    anchor(native + '&ik=0000000011', true),
    anchor('https://example.test/mail/u/2/' + native + '&ik=0000000022'),
    anchor('/mail/u/1/' + native + '&ik=0000000033'),
    anchor('?view=om&permmsgid=msg-f:42&ik=0000000044'),
    anchor(native + '&ik=safe%26extra%3Dwrong'),
    anchor(native + '&ik=0000000055&extra=ignored')
  ];
  for (const [location, nodes, expected] of [
    [account, anchors.slice(0, -1), null],
    [account, anchors, '0000000055'],
    [new URL('?ik=0000000066', account), anchors, '0000000066']
  ]) {
    let observed;
    const api = harness(location, async url => {
      observed = new URL(url);
      return new Response(eml);
    }, nodes);
    await api.read(id);
    assert.equal(observed.origin + observed.pathname, account.origin + account.pathname);
    assert.equal(observed.searchParams.get('ik'), expected);
    assert.equal(observed.searchParams.has('extra'), false);
  }
});

test('the default scan reads the native source view on the first request when Gmail supplies its mailbox hint', async () => {
  let lookups = 0;
  const runtime = { sendMessage: async msg => {
    assert.deepEqual(Object.keys(msg), ['type']);
    assert.equal(msg.type, 'pg:gmail:mailboxHint');
    lookups++;
    return {ok: true, hint: '123abc0000'};
  } };
  const views = [];
  const implementation = { createHTMLDocument: () => ({ createElement: () => ({
    content: { querySelectorAll: sel => sel === 'pre.raw_message_text' ? [{textContent: eml}] : [] }
  }) }) };
  const api = harness(account, async url => {
    const params = new URL(url).searchParams;
    views.push(params.get('view'));
    assert.equal(params.get('ik'), '123abc0000');
    assert.equal(params.get('permmsgid'), 'msg-f:' + BigInt('0x' + id));
    return new Response('<pre class="raw_message_text"></pre>', {headers: {'content-type': 'text/html'}});
  }, [], runtime, implementation);
  assertReadBody(await api.read(id));
  assert.equal(lookups, 1);
  assert.deepEqual(views, ['om']);
});

test('tries one download after a rejected native source, and ignores malformed or unavailable worker hints', async () => {
  for (const [reply, order] of [
    [{ok: true, hint: '123abc1234'}, ['om', 'att']],
    [{ok: true, hint: 'abcd1234&x=0'}, ['att']],
    [{ok: true, hint: 'a'.repeat(33)}, ['att']],
    [{ok: false, hint: 'abcd1234'}, ['att']],
    [null, ['att']]
  ]) {
    const views = [];
    const api = harness(account, async url => {
      const params = new URL(url).searchParams;
      views.push(params.get('view'));
      assert.equal(params.get('ik'), order.length === 2 ? reply.hint : null);
      return params.get('view') === 'om' ? new Response('Unavailable', {status: 404}) : new Response(eml);
    }, [], {sendMessage: async () => { if (!reply) throw Error('Worker unavailable'); return reply; }});
    assertReadBody(await api.read(id));
    assert.deepEqual(views, order);
  }
});

test('does not request the message after it closes or the request aborts during a mailbox lookup', async () => {
  for (const abort of [false, true]) {
    const body = bodyWith({'data-legacy-message-id': id});
    const cancel = new AbortController();
    let requests = 0;
    const api = harness(account, async () => { requests++; return new Response(eml); }, [], {sendMessage: async () => {
      if (abort) cancel.abort();
      else body.isConnected = false;
      return {ok: true, hint: '123abc0000'};
    }});
    await assert.rejects(api.read(id, cancel.signal, body), /cancelled|changed/);
    assert.equal(requests, 0);
  }
});

test('an extension reload during a download prevents another request from the old script', async () => {
  let active = true;
  const views = [];
  const api = harness(account, async url => {
    views.push(new URL(url).searchParams.get('view'));
    active = false;
    return new Response('Unavailable', {status: 404});
  });
  await assert.rejects(api.read(id, undefined, undefined, () => active), /cancelled/);
  assert.deepEqual(views, ['att']);
});

test('does not request the original again after a size limit, cancellation, or unsupported MIME', async () => {
  const ctrl = new AbortController();
  for (const [download, expected] of [
    [() => new Response(eml, { headers: { 'content-length': String(8 * 1024 * 1024 + 1) } }), /too large/],
    [() => new Response('Content-Type: application/octet-stream\r\n\r\nData'), /no displayable text body/],
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

test('reads only the selected native attachment, rejects partial or wrong files and never follows redirects', async () => {
  const body = bodyWith({'data-legacy-message-id': id});
  const target = {partId: '0.1', name: 'file.bin', limit: 32, hint: 'abcd1234'};
  const file = Uint8Array.from([0, 255, 13, 10]);
  const raw = 'Content-Type: multipart/mixed; boundary=eml\r\n\r\n--eml\r\nContent-Type: text/plain\r\n\r\ntext\r\n' +
    '--eml\r\nContent-Disposition: attachment; filename="file.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\nAP8NCg==\r\n--eml--\r\n';
  for (const outcome of ['exact', 'wrong', 'partial', 'too_large', 'redirect']) {
    const seen = [];
    const api = harness(account, async (input, options) => {
      const url = new URL(input);
      assert.equal(url.origin + url.pathname, account.origin + account.pathname);
      assert.equal(options.redirect, 'error');
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.referrerPolicy, 'no-referrer');
      const partId = url.searchParams.get('attid');
      seen.push(partId);
      if (partId === '0') return new Response(raw, {headers: {'content-type': 'message/rfc822'}});
      assert.equal(url.searchParams.get('th'), id);
      assert.equal(url.searchParams.get('ik'), 'abcd1234');
      const name = outcome === 'wrong' ? 'sign-in.html' : target.name;
      const headers = {'content-disposition': 'attachment; filename="' + name + '"'};
      if (outcome === 'partial') headers['content-range'] = 'bytes 0-3/10';
      if (outcome === 'too_large') headers['content-length'] = '33';
      if (outcome === 'redirect') throw TypeError('Redirect disallowed');
      return new Response(outcome === 'exact' ? file : 'bad', {headers});
    });
    const result = api.read(id, undefined, body, () => true, target);
    if (outcome === 'too_large') await assert.rejects(result, /too large/);
    else assert.deepEqual([...await result], [...file]);
    assert.deepEqual(seen, ['exact', 'too_large'].includes(outcome) ? ['0.1'] : ['0.1', '0']);
  }
});
