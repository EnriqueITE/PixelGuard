const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const { webcrypto, createHash } = require('node:crypto');

const ROOT = 'moz-extension://pixelguard-test/';
// Deliberately synthetic; never sent to a real service.
const TEST_KEY = 'test-key-placeholder-00000000000000000000000000000000000000000000';
const REPORT = 'https://www.virustotal.com/ui/widget/html/test-report-token';
const plain = value => JSON.parse(JSON.stringify(value));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
};
async function until(predicate) {
  for (let i = 0; i < 200; i++) {
    if (predicate()) return;
    await Promise.resolve();
  }
  assert.fail('Expected asynchronous operation did not start');
}
function loadModules(extra = {}) {
  const context = vm.createContext({ URL, AbortController, Uint8Array, console, ...extra });
  for (const file of ['virustotal/inventory.js', 'virustotal/service.js']) {
    vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });
  }
  return context;
}
function response(status = 200, data = { url: REPORT, detection_ratio: { detections: 2, total: 90 } }) {
  return { status, ok: status >= 200 && status < 300, json: async () => ({ data }) };
}
function harness(overrides = {}) {
  let time = 172800000, allowed = true, displayed = { id: 17 }, closed = false;
  const store = plain(overrides.stored || { vtConfig: { enabled: true, apiKey: TEST_KEY } });
  const calls = { fetch: [], writes: [], reads: [], files: [], tabs: [], external: [], permissionChecks: [] };
  const timers = new Map();
  let timerId = 0;
  const events = {};
  const event = name => ({ addListener(fn) { (events[name] ||= []).push(fn); } });
  const api = {
    runtime: { id: 'pixel-guard@test', getURL: path => ROOT + path, onMessage: event('message') },
    storage: { local: {
      get: async () => {
        if (overrides.getStorage) return overrides.getStorage(store);
        return plain(store);
      },
      set: async update => {
        calls.writes.push(plain(update));
        if (overrides.setStorage) await overrides.setStorage(update);
        Object.assign(store, plain(update));
      },
      remove: async key => { delete store[key]; }
    } },
    permissions: {
      contains: async value => { calls.permissionChecks.push(plain(value)); return allowed; },
      onRemoved: event('permissionsRemoved')
    },
    tabs: {
      query: async () => overrides.tabs || [{ id: 7 }],
      create: async details => { calls.tabs.push(plain(details)); return { id: 88 }; },
      onRemoved: event('tabRemoved')
    },
    windows: {
      getAll: async () => overrides.windows || [{ id: 5, focused: true, type: 'normal' }],
      openDefaultBrowser: async url => { calls.external.push(url); }
    },
    messageDisplay: {
      getDisplayedMessage: async tabId => {
        if (overrides.getDisplayed) return overrides.getDisplayed(tabId);
        if (closed) throw Error('tab closed');
        return displayed;
      },
      onMessageDisplayed: event('displayed'),
      onMessagesDisplayed: event('displayedMany')
    },
    messages: {
      getFull: async id => {
        calls.reads.push(id);
        return overrides.full || { contentType: 'text/plain', body: 'https://example.test/path?token=private https://second.test/ https://third.test/ https://fourth.test/ https://fifth.test/' };
      },
      listAttachments: async () => {
        if (overrides.attachmentsError) throw Error('not available');
        return overrides.attachments || [{ name: 'document.txt', size: 3, partName: '1.2' }];
      },
      getAttachmentFile: async (id, partName) => {
        calls.files.push({ id, partName });
        if (overrides.getFile) return overrides.getFile(id, partName);
        return new Blob(['abc']);
      }
    }
  };
  const deps = {
    crypto: overrides.crypto || webcrypto,
    now: () => time,
    setTimeout(fn, delay) { const id = ++timerId; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    parseHTML: overrides.parseHTML || (() => ({ hrefs: [], text: '' })),
    fetch: async (url, init) => {
      calls.fetch.push({ url, init });
      return overrides.fetch ? overrides.fetch(url, init) : response();
    }
  };
  const context = loadModules();
  const service = context.PixelGuardVT.createService(api, deps);
  const sender = { id: api.runtime.id, url: ROOT + 'popup/popup.html' };
  const options = { id: api.runtime.id, url: ROOT + 'options/options.html' };
  const send = (type, fields = {}, from = sender) => service.handle({ type: 'pg:vt:' + type, ...fields }, from);
  const inventory = () => send('getInventory');
  return {
    service, context, api, deps, calls, store, timers, events, send, inventory, sender, options,
    advance(ms) { time += ms; },
    allow(value) { allowed = value; },
    display(value) { displayed = value; service.messageDisplayed({ id: 7 }, value); },
    close() { closed = true; service.invalidate(7); }
  };
}
const lookup = (h, inv, fields = {}) => h.send('query', { sessionId: inv.sessionId, itemId: inv.links[0]?.id, kind: 'domain', ...fields });

test('VT inventory traverses the message envelope, skips attachments and nested messages', () => {
  const { PixelGuardVTInventory: inventory } = loadModules();
  const full = { contentType: 'message/rfc822', partName: '', parts: [
    { contentType: 'multipart/mixed', parts: [
      { contentType: 'text/plain', body: 'See https://example.test/path. Also (https://second.test/a(b)).' },
      { contentType: 'text/html', body: '<fixture>' },
      { contentType: 'text/plain', name: 'attached.txt', body: 'https://private.test/named' },
      { contentType: 'text/plain', headers: { 'content-disposition': ['attachment; filename="hidden.txt"'] }, body: 'https://private.test/disposition' },
      { contentType: 'message/rfc822', partName: '1.4', parts: [{ contentType: 'text/plain', body: 'https://private.test/forwarded' }] }
    ] }
  ] };
  const result = inventory.collectLinks(full, () => ({ hrefs: ['HTTPS://EXAMPLE.TEST:443/path', 'mailto:person@test', 'https://user:password@private.test/'], text: 'https://third.test/' }));
  assert.deepEqual(plain(result.links.map(x => x.url)), ['https://example.test/path', 'https://second.test/a(b)', 'https://third.test/']);
  assert.equal(result.truncated, false);
});

test('VT inventory caps unique links and preserves exact URL query and fragment', () => {
  const { PixelGuardVTInventory: inventory } = loadModules();
  const result = inventory.collectLinks({ contentType: 'text/plain', body: Array.from({ length: 1001 }, (_, i) => `https://example.test/${i}?id=a%2Fb#section`).join(' ') });
  assert.equal(result.links.length, 1000);
  assert.equal(result.truncated, true);
  assert.equal(result.links[0].url, 'https://example.test/0?id=a%2Fb#section');
});

test('VT HTML inventory does not concatenate adjacent blocks into an invented URL', () => {
  const html = '<p>https://example.invalid/text.</p><div>Box</div>';
  const body = { textContent: 'https://example.invalid/text.Box' };
  const textNodes = [{ nodeValue: 'https://example.invalid/text.' }, { nodeValue: 'Box' }];
  const doc = {
    body,
    querySelectorAll: () => [],
    createTreeWalker(root, whatToShow) {
      assert.equal(root, body);
      assert.equal(whatToShow, 4);
      let index = -1;
      return {
        get currentNode() { return textNodes[index]; },
        nextNode() { return textNodes[++index] || null; }
      };
    }
  };
  const { PixelGuardVTInventory: inventory } = loadModules({
    NodeFilter: { SHOW_TEXT: 4 },
    DOMParser: class {
      parseFromString(input, type) {
        assert.equal(input, html);
        assert.equal(type, 'text/html');
        return doc;
      }
    }
  });
  // Exercise the production HTML parser path, without a parseHTML override.
  const result = inventory.collectLinks({ contentType: 'text/html', body: html });
  assert.deepEqual(plain(result.links.map(item => item.url)), ['https://example.invalid/text']);
});

test('VT report URL validation rejects hostile origins, schemes and alternate paths', () => {
  const { PixelGuardVTInventory: inventory } = loadModules();
  assert.equal(inventory.reportUrl(REPORT), REPORT);
  assert.equal(inventory.reportUrl('https://virustotal.com/ui/widget/html/a_b-c='), 'https://virustotal.com/ui/widget/html/a_b-c=');
  for (const bad of [
    'http://www.virustotal.com/ui/widget/html/token', 'https://evil.test/ui/widget/html/token',
    'https://www.virustotal.com.evil.test/ui/widget/html/token', 'https://www.virustotal.com@evil.test/ui/widget/html/token',
    'https://person@www.virustotal.com/ui/widget/html/token', 'https://www.virustotal.com:444/ui/widget/html/token',
    'https://www.virustotal.com/ui/widget/html/token?query=secret', 'https://www.virustotal.com/ui/widget/html/token#fragment',
    'https://www.virustotal.com/ui/widget/html/', 'https://www.virustotal.com/ui/home', 'javascript:alert(1)'
  ]) assert.equal(inventory.reportUrl(bad), null, bad);
});

test('VT is off by default and no background requests occur while saving a key or opening inventory', async () => {
  const h = harness({ stored: {} });
  assert.equal((await h.send('getConfig')).enabled, false);
  assert.equal((await h.inventory()).error, 'disabled');
  const saved = await h.send('saveConfig', { enabled: true, apiKey: TEST_KEY, consent: true }, h.options);
  assert.equal(saved.enabled, true);
  assert.equal(JSON.stringify(saved).includes(TEST_KEY), false);
  const inv = await h.inventory();
  assert.equal(inv.ok, true);
  assert.equal(h.calls.files.length, 0);
  assert.equal(h.calls.fetch.length, 0);
  assert.equal(h.store.settings, undefined);
  assert.equal(h.store.vtConfig.apiKey, TEST_KEY);
});

test('VT command authorization requires exact extension page and restricts configuration to options', async () => {
  const h = harness();
  const senders = [
    {}, { id: 'other-extension', url: h.sender.url },
    { id: h.api.runtime.id, url: 'imap://message' },
    { id: h.api.runtime.id, url: 'https://example.test/' },
    { id: h.api.runtime.id, url: ROOT + 'popup/popup.html?fake=1' },
    { id: h.api.runtime.id, url: ROOT + 'content/scan.js' }
  ];
  for (const sender of senders) assert.equal((await h.send('getInventory', {}, sender)).error, 'unauthorized');
  assert.equal((await h.send('saveConfig', { enabled: false })).error, 'unauthorized');
  assert.equal((await h.send('getInventory', {}, h.options)).error, 'unauthorized');
  assert.equal(h.calls.fetch.length, 0);
  assert.equal(h.calls.reads.length, 0);
});

test('VT enable requires explicit consent, a key and both optional permissions', async () => {
  const h = harness({ stored: {} });
  assert.equal((await h.send('saveConfig', { enabled: true, apiKey: TEST_KEY }, h.options)).ok, false);
  assert.equal((await h.send('saveConfig', { enabled: true, consent: true }, h.options)).ok, false);
  h.allow(false);
  assert.equal((await h.send('saveConfig', { enabled: true, apiKey: TEST_KEY, consent: true }, h.options)).error, 'permission_denied');
  assert.deepEqual(h.calls.permissionChecks.at(-1), { permissions: ['sensitiveDataUpload'], origins: ['https://www.virustotal.com/*'] });
  assert.equal(h.calls.fetch.length, 0);
});

test('VT domain lookup sends only hostname to the fixed GET endpoint with no cookies', async () => {
  const h = harness();
  const inv = await h.inventory();
  const result = await lookup(h, inv);
  assert.equal(result.result.detections, 2);
  assert.equal(result.result.total, 90);
  const { url, init } = h.calls.fetch[0];
  assert.equal(new URL(url).origin + new URL(url).pathname, 'https://www.virustotal.com/api/v3/widget/url');
  assert.equal(new URL(url).searchParams.get('query'), 'example.test');
  assert.equal(init.method, 'GET');
  assert.equal(init.headers['x-apikey'], TEST_KEY);
  assert.equal(init.credentials, 'omit');
  assert.equal(init.redirect, 'error');
  assert.equal(init.referrerPolicy, 'no-referrer');
  assert.equal(init.body, undefined);
  assert.equal(JSON.stringify(result).includes(TEST_KEY), false);
  assert.equal(JSON.stringify(result).includes(REPORT), false);
  assert.equal(JSON.stringify(h.store.vtQuota).includes('example.test'), false);
});

test('VT full URL cannot be sent until the exact inventory URL is confirmed', async () => {
  const h = harness();
  const inv = await h.inventory();
  assert.equal((await lookup(h, inv, { kind: 'url' })).error, 'confirmation_required');
  assert.equal((await lookup(h, inv, { kind: 'url', confirmedUrl: 'https://other.test/' })).error, 'confirmation_required');
  assert.equal(h.calls.fetch.length, 0);
  const result = await lookup(h, inv, { kind: 'url', confirmedUrl: inv.links[0].url });
  assert.equal(result.ok, true);
  assert.equal(new URL(h.calls.fetch[0].url).searchParams.get('query'), inv.links[0].url);
});

test('VT attachment query reads selected part only and sends SHA-256 without bytes or filename', async () => {
  const h = harness();
  const inv = await h.inventory();
  const result = await lookup(h, inv, { itemId: inv.attachments[0].id, kind: 'file' });
  assert.equal(result.ok, true);
  assert.deepEqual(h.calls.files, [{ id: 17, partName: '1.2' }]);
  assert.equal(new URL(h.calls.fetch[0].url).searchParams.get('query'), createHash('sha256').update('abc').digest('hex'));
  assert.equal(h.calls.fetch[0].init.body, undefined);
  assert.equal(h.calls.fetch[0].url.includes('document.txt'), false);
});

test('VT can query the standard SHA-256 of an empty attachment', async () => {
  const h = harness({ attachments: [{ name: 'empty.txt', size: 0, partName: '1.2' }], getFile: async () => new Blob([]) });
  const inv = await h.inventory();
  assert.equal((await lookup(h, inv, { itemId: inv.attachments[0].id, kind: 'file' })).ok, true);
  assert.equal(new URL(h.calls.fetch[0].url).searchParams.get('query'), createHash('sha256').update('').digest('hex'));
});

test('VT rejects oversized or unavailable attachments without outgoing requests', async () => {
  const large = harness({ attachments: [{ name: 'large.zip', size: 50 * 1024 * 1024 + 1, partName: '1.2' }] });
  const inv = await large.inventory();
  assert.equal((await lookup(large, inv, { itemId: inv.attachments[0].id, kind: 'file' })).error, 'too_large');
  assert.equal(large.calls.files.length, 0);
  const missing = harness({ getFile: async () => { throw Error('deleted'); } });
  const inv2 = await missing.inventory();
  assert.equal((await lookup(missing, inv2, { itemId: inv2.attachments[0].id, kind: 'file' })).error, 'unavailable');
  assert.equal(large.calls.fetch.length + missing.calls.fetch.length, 0);
});

test('VT validates actual file size even if attachment metadata is smaller', async () => {
  let read = false;
  const h = harness({ getFile: async () => ({ size: 50 * 1024 * 1024 + 1, arrayBuffer() { read = true; } }) });
  const inv = await h.inventory();
  assert.equal((await lookup(h, inv, { itemId: inv.attachments[0].id, kind: 'file' })).error, 'too_large');
  assert.equal(read, false);
  assert.equal(h.calls.fetch.length, 0);
});

test('VT inventory keeps links available when attachment enumeration fails', async () => {
  const h = harness({ attachmentsError: true });
  const inv = await h.inventory();
  assert.equal(inv.ok, true);
  assert.equal(inv.attachmentError, 'unavailable');
  assert.equal(inv.links.length, 5);
  assert.equal(inv.attachments.length, 0);
});

test('VT validates item identity and kind instead of accepting arbitrary message parts or URLs', async () => {
  const h = harness();
  const inv = await h.inventory();
  for (const fields of [{ itemId: 'nonexistent', url: 'https://evil.test/' }, { kind: 'file' }, { itemId: 'file-0', kind: 'url' }, { kind: 'post' }]) {
    assert.equal((await lookup(h, inv, fields)).error, 'unavailable');
  }
  assert.equal(h.calls.fetch.length, 0);
  assert.equal(h.calls.files.length, 0);
});

test('VT deduplicates simultaneous clicks and reuses only a short-lived in-memory result', async () => {
  const pending = deferred();
  const h = harness({ fetch: () => pending.promise });
  const inv = await h.inventory();
  const first = lookup(h, inv);
  await until(() => h.calls.fetch.length === 1);
  const second = lookup(h, inv);
  assert.equal((await lookup(h, inv, { itemId: inv.links[1].id })).error, 'busy');
  pending.resolve(response());
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.result.id, b.result.id);
  assert.equal((await lookup(h, inv)).result.id, a.result.id);
  assert.equal(h.calls.fetch.length, 1);
  assert.equal(Object.keys(h.store).some(key => /report|result/i.test(key)), false);
});

test('VT enforces four requests per minute and resumes after the window', async () => {
  const h = harness();
  const inv = await h.inventory();
  for (const item of inv.links.slice(0, 4)) assert.equal((await lookup(h, inv, { itemId: item.id })).ok, true);
  const denied = await lookup(h, inv, { itemId: inv.links[4].id });
  assert.equal(denied.error, 'rate_limit');
  assert.equal(denied.retryAfter, 60);
  assert.equal(h.calls.fetch.length, 4);
  h.advance(60001);
  assert.equal((await lookup(h, inv, { itemId: inv.links[4].id })).ok, true);
});

test('VT persists the daily quota across sessions and refuses requests when saving it fails', async () => {
  const h = harness({ stored: { vtConfig: { enabled: true, apiKey: TEST_KEY }, vtQuota: Array(500).fill(172800000 - 120000) } });
  assert.equal((await lookup(h, await h.inventory())).error, 'daily_limit');
  assert.equal(h.calls.fetch.length, 0);
  const failing = harness({ setStorage: async update => { if (update.vtQuota) throw Error('disk unavailable'); } });
  assert.equal((await lookup(failing, await failing.inventory())).error, 'storage');
  assert.equal(failing.calls.fetch.length, 0);
});

test('VT returns safe distinct API errors without retries or response-body leakage', async () => {
  for (const [status, expected] of [[401, 'invalid_key'], [403, 'forbidden'], [429, 'rate_limit'], [503, 'network']]) {
    const h = harness({ fetch: async () => response(status) });
    const result = await lookup(h, await h.inventory());
    assert.equal(result.error, expected);
    assert.equal(h.calls.fetch.length, 1);
    assert.equal(JSON.stringify(result).includes(TEST_KEY), false);
  }
  const missing = harness({ fetch: async () => response(404) });
  assert.equal((await lookup(missing, await missing.inventory())).result.status, 'no_report');
  const network = harness({ fetch: async () => { throw Error(TEST_KEY); } });
  assert.deepEqual(plain(await lookup(network, await network.inventory())), { ok: false, error: 'network' });
});

test('VT refuses a malicious widget URL and does not turn an absent ratio into zero detections', async () => {
  const h = harness({ fetch: async () => response(200, { url: 'https://evil.test/ui/widget/html/token', detection_ratio: { detections: 0, total: 90 } }) });
  assert.equal((await lookup(h, await h.inventory())).error, 'invalid_response');
  const absent = harness({ fetch: async () => response(200, { url: REPORT }) });
  const result = await lookup(absent, await absent.inventory());
  assert.equal(result.result.detections, undefined);
  assert.equal(result.result.total, undefined);
  assert.equal(result.result.status, 'reported');
});

test('VT opens only a validated saved report in a normal window or the default browser', async () => {
  for (const windows of [[{ id: 23, focused: true, type: 'normal' }], []]) {
    const h = harness({ windows });
    const inv = await h.inventory();
    const res = await lookup(h, inv);
    assert.equal((await h.send('openReport', { sessionId: inv.sessionId, resultId: res.result.id, url: 'https://evil.test/' })).ok, true);
    if (windows.length) assert.deepEqual(h.calls.tabs, [{ windowId: 23, url: REPORT, active: true }]);
    else assert.deepEqual(h.calls.external, [REPORT]);
    assert.equal((await h.send('openReport', { sessionId: inv.sessionId, resultId: 'unknown' })).error, 'report_expired');
    h.advance(3 * 86400000);
    assert.equal((await h.send('openReport', { sessionId: inv.sessionId, resultId: res.result.id })).error, 'report_expired');
  }
});

test('VT old inventory cannot query a different message, even without display events', async () => {
  let messageId = 17;
  const h = harness({ getDisplayed: async () => ({ id: messageId }) });
  const inv = await h.inventory();
  messageId = 18;
  assert.equal((await lookup(h, inv)).error, 'stale_message');
  assert.equal(h.calls.fetch.length, 0);
});

test('VT tab closure during initial message lookup cannot restore inventory', async () => {
  const gate = deferred();
  let started = false;
  const h = harness({ getDisplayed: () => { started = true; return gate.promise; } });
  const pending = h.inventory();
  await until(() => started);
  h.close();
  gate.resolve({ id: 17 });
  assert.equal((await pending).error, 'stale_message');
  assert.equal(h.calls.reads.length, 0);
});

test('VT message change during hashing discards the digest without querying', async () => {
  const digest = deferred();
  let started = false;
  const h = harness({ crypto: { subtle: { digest() { started = true; return digest.promise; } } } });
  const inv = await h.inventory();
  const pending = lookup(h, inv, { itemId: inv.attachments[0].id, kind: 'file' });
  await until(() => started);
  h.display({ id: 18 });
  digest.resolve(new Uint8Array(32).buffer);
  assert.equal((await pending).error, 'stale_message');
  assert.equal(h.calls.fetch.length, 0);
});

test('VT message closure aborts network work and drops late reports', async () => {
  const gate = deferred();
  const h = harness({ fetch: () => gate.promise });
  const inv = await h.inventory();
  const pending = lookup(h, inv);
  await until(() => h.calls.fetch.length === 1);
  h.close();
  assert.equal(h.calls.fetch[0].init.signal.aborted, true);
  gate.resolve(response());
  assert.equal((await pending).error, 'stale_message');
  assert.equal(h.timers.size, 0);
});

test('VT revocation cancels work, disables configuration and clears report access', async () => {
  const gate = deferred();
  const h = harness({ fetch: () => gate.promise });
  const inv = await h.inventory();
  const pending = lookup(h, inv);
  await until(() => h.calls.fetch.length === 1);
  h.allow(false);
  h.service.permissionsRemoved({ permissions: ['sensitiveDataUpload'] });
  assert.equal(h.calls.fetch[0].init.signal.aborted, true);
  gate.resolve(response());
  assert.equal((await pending).error, 'stale_message');
  assert.equal((await h.send('getConfig')).enabled, false);
  assert.equal((await lookup(h, inv)).ok, false);
});

test('VT deleting the key invalidates previously obtained report tokens', async () => {
  const h = harness();
  const inv = await h.inventory();
  const res = await lookup(h, inv);
  const deleted = await h.send('deleteConfig', {}, h.options);
  assert.equal(deleted.configured, false);
  assert.equal(h.store.vtConfig, undefined);
  assert.equal((await h.send('openReport', { sessionId: inv.sessionId, resultId: res.result.id })).error, 'disabled');
  assert.equal(h.calls.tabs.length, 0);
});

test('VT timeout aborts the request at twenty seconds and never retries', async () => {
  const h = harness({ fetch: (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(Error('aborted')));
  }) });
  const pending = lookup(h, await h.inventory());
  await until(() => h.calls.fetch.length === 1);
  const timer = [...h.timers.values()][0];
  assert.equal(timer.delay, 20000);
  timer.fn();
  assert.equal((await pending).error, 'timeout');
  assert.equal(h.calls.fetch.length, 1);
  assert.equal(h.timers.size, 0);
});

test('VT startup storage failure is reported safely instead of enabling requests', async () => {
  const h = harness({ getStorage: async () => { throw Error(TEST_KEY); } });
  assert.deepEqual(plain(await h.send('getConfig')), { ok: false, error: 'storage' });
  assert.equal(h.calls.fetch.length, 0);
});

test('VT stale rejected lookup cannot invalidate a newer message inventory', async () => {
  const oldLookup = deferred();
  let currentId = 17, reads = 0;
  const h = harness({ getDisplayed: async () => {
    reads++;
    if (reads === 3) return oldLookup.promise;
    return { id: currentId };
  } });
  const oldInventory = await h.inventory();
  const pending = lookup(h, oldInventory);
  await until(() => reads === 3);
  currentId = 18;
  h.display({ id: currentId });
  const newInventory = await h.inventory();
  assert.equal(newInventory.ok, true);
  oldLookup.reject(Error('old tab lookup failed'));
  assert.equal((await pending).error, 'stale_message');
  assert.equal((await lookup(h, newInventory)).ok, true);
});

test('VT disabling aborts pending work before its configuration write completes', async () => {
  const network = deferred(), disk = deferred();
  let writing = false;
  const h = harness({
    fetch: () => network.promise,
    setStorage: async update => {
      if (update.vtConfig?.enabled === false) { writing = true; await disk.promise; }
    }
  });
  const inv = await h.inventory();
  const pending = lookup(h, inv);
  await until(() => h.calls.fetch.length === 1);
  const disabling = h.send('saveConfig', { enabled: false }, h.options);
  await until(() => writing);
  const abortedBeforeSave = h.calls.fetch[0].init.signal.aborted;
  network.resolve(response());
  const result = await pending;
  disk.resolve();
  assert.equal((await disabling).enabled, false);
  assert.equal(abortedBeforeSave, true);
  assert.equal(result.error, 'stale_message');
});

test('VT failed disable persistence still stops further requests in this session', async () => {
  const h = harness({ setStorage: async update => {
    if (update.vtConfig?.enabled === false) throw Error('disk full');
  } });
  const inv = await h.inventory();
  assert.equal((await h.send('saveConfig', { enabled: false }, h.options)).error, 'storage');
  assert.equal((await h.send('getConfig')).enabled, false);
  assert.equal((await lookup(h, inv)).ok, false);
  assert.equal(h.calls.fetch.length, 0);
});

test('VT malformed JSON reports invalid response without leaking server content', async () => {
  const h = harness({ fetch: async () => ({ status: 200, ok: true, json: async () => { throw new SyntaxError(TEST_KEY); } }) });
  assert.deepEqual(plain(await lookup(h, await h.inventory())), { ok: false, error: 'invalid_response' });
});

test('VT bootstrap only claims its message prefix and wires invalidation events', async () => {
  const h = harness();
  const calls = [];
  const stub = {
    handle: async (msg, sender) => { calls.push([msg.type, sender.id]); return { ok: true }; },
    invalidate: id => calls.push(['invalidate', id]),
    messageDisplayed: (tab, message) => calls.push(['displayed', tab.id, message.id]),
    permissionsRemoved: permissions => calls.push(['permissions', permissions])
  };
  const context = vm.createContext({ browser: h.api, PixelGuardVT: { createService: () => stub } });
  vm.runInContext(fs.readFileSync('virustotal/bootstrap.js', 'utf8'), context);
  const listener = h.events.message[0];
  assert.equal(listener({ type: 'pg:getState' }, h.sender, () => assert.fail('claimed unrelated message')), false);
  const received = deferred();
  assert.equal(listener({ type: 'pg:vt:getConfig' }, h.sender, received.resolve), true);
  assert.equal((await received.promise).ok, true);
  h.events.tabRemoved[0](7);
  h.events.displayed[0]({ id: 7 }, { id: 17 });
  h.events.displayedMany[0]({ id: 7 }, []);
  assert.deepEqual(calls.slice(1), [['invalidate', 7], ['displayed', 7, 17], ['invalidate', 7]]);
});
