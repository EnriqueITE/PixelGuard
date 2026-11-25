const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const root = path.resolve(__dirname, '../..');
const sample = 'only-for-the-local-worker-tests';
const report = 'https://www.virustotal.com/ui/widget/html/stub';
const clone = value => JSON.parse(JSON.stringify(value));
function harness(shared = { data: {} }) {
  const data = shared.data;
  const requests = [];
  const openedTabs = [];
  const broadcasts = [];
  const badges = new Map();
  function setBadge(tabId, patch) {
    assert.ok(Number.isInteger(tabId) && tabId >= 0);
    badges.set(tabId, { ...badges.get(tabId), ...patch });
  }
  const origin = 'chrome-extension://sample/';
  const popup = { id: 'sample', url: origin + 'popup.html' };
  const gmail = { id: 'sample', url: 'https://mail.google.com/mail/u/0/', frameId: 0, tab: { id: 1, windowId: 3 } };
  let handler, revoked, access, permission = false;
  const chrome = {
    scripting: shared.scripting,
    runtime: { id: 'sample', getURL: p => origin + p, getManifest: () => ({ name: 'PixelGuard for Gmail' }),
      onMessage: { addListener(fn) { handler = fn; } }, onInstalled: { addListener() {} }, onStartup: { addListener() {} } },
    action: {
      async setBadgeText({ tabId, text }) { setBadge(tabId, { text }); },
      async setBadgeBackgroundColor({ tabId, color }) { setBadge(tabId, { color }); },
      async setTitle({ tabId, title }) { setBadge(tabId, { title }); }
    },
    i18n: { getMessage(key, values) { assert.equal(key, 'badgeFindingsTitle'); return values.join(', '); } },
    storage: { local: {
      async setAccessLevel({ accessLevel }) { access = accessLevel; },
      async get(keys) {
        assert.equal(access, 'TRUSTED_CONTEXTS');
        return Object.fromEntries([].concat(keys).filter(k => k in data).map(k => [k, clone(data[k])]));
      },
      async set(update) {
        assert.equal(access, 'TRUSTED_CONTEXTS');
        if (shared.failSave) throw Error('Simulated storage failure');
        Object.assign(data, clone(update));
      },
      async remove(key) { assert.equal(access, 'TRUSTED_CONTEXTS'); delete data[key]; }
    } },
    tabs: {
      async query() { return [{ id: 1 }, { id: 2 }]; },
      async sendMessage(id, msg) { broadcasts.push(clone(msg)); },
      async create(options) { openedTabs.push(clone(options)); }
    },
    permissions: { async contains(p) {
      assert.deepEqual(clone(p), { origins: ['https://www.virustotal.com/*'] });
      return permission;
    }, onRemoved: { addListener(fn) { revoked = fn; } } }
  };
  const context = vm.createContext({
    chrome, URL, setTimeout, clearTimeout, AbortController, crypto: webcrypto, TextEncoder, TextDecoder, atob, btoa, navigator,
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ data: { url: report, detection_ratio: { detections: 1, total: 80 } } }) };
    },
    importScripts: (...names) => names.forEach(name => {
      const filename = path.join(root, name === 'virustotal/inventory.js' ? '' : 'chrome', name);
      vm.runInContext(fs.readFileSync(filename, 'utf8'), context);
      if (name === 'vault.js') {
        // Web Crypto and locks are real. A shared store stands in for IndexedDB
        // here; the browser smoke test uses native IndexedDB.
        const { create } = context.PixelGuardVault;
        context.PixelGuardVault.create = () => create({
          get: () => shared.wrappingKey,
          add: key => { assert.ok(!shared.wrappingKey); shared.wrappingKey = key; },
          remove: () => { delete shared.wrappingKey; }
        });
      }
    })
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'chrome/worker.js'), 'utf8'), context);
  const send = (type, fields = {}, sender = popup) => new Promise(resolve => {
    const asyncReply = handler({ type, ...fields }, sender, value => resolve(clone(value)));
    if (!asyncReply) resolve(undefined);
  });
  return { send, data, broadcasts, requests, gmail, badges, openedTabs,
    grant() { permission = true; },
    revoke() { permission = false; revoked({ origins: ['https://www.virustotal.com/*'] }); }
  };
}

test('the Gmail page only receives visibility, including when settings change', async () => {
  const h = harness();
  assert.deepEqual(await h.send('pg:panel', {}, h.gmail), { ok: true, showPanel: true });
  for (const type of ['pg:settings', 'pg:lookup', 'pg:state']) {
    assert.equal((await h.send(type, { apiKey: sample }, h.gmail)).error, 'unauthorized');
  }
  await h.send('pg:settings', { showPanel: false, apiKey: sample });
  assert.deepEqual(await h.send('pg:panel', {}, h.gmail), { ok: true, showPanel: false });
  assert.deepEqual(h.broadcasts, [1, 2].map(() => ({ type: 'pg:panelChanged', showPanel: false })));
  assert.deepEqual(await h.send('pg:state'), { ok: true, hasKey: true, vtEnabled: false, showPanel: false });
  assert.equal(h.requests.length, 0);
});

test('the Gmail toolbar badge shows counts and the highest-priority color for each tab', async () => {
  const h = harness();
  const otherTab = { ...h.gmail, tab: { id: 2 } };
  const send = (suspicious, externals, links, sender = h.gmail) =>
    h.send('pg:badge', { suspicious, externals, links, tabId: 999 }, sender);
  assert.ok((await send(3, 1, 0)).ok);
  assert.deepEqual(h.badges.get(1), { text: '310', title: '3, 1, 0', color: '#e53935' });
  await Promise.all([send(0, 9, 0), send(11, 0, 29, otherTab)]);
  assert.deepEqual(h.badges.get(1), { text: '090', title: '0, 9, 0', color: '#00bfa5' });
  assert.deepEqual(h.badges.get(2), { text: '+0+', title: '11, 0, 29', color: '#e53935' });
  await send(1, 24, 25, otherTab);
  assert.equal(h.badges.get(2).text, '1++');
  assert.equal(h.badges.get(2).color, '#e53935');
  await send(0, 24, 1, otherTab);
  assert.equal(h.badges.get(2).color, '#ff9800');
  await send(0, 0, 0, otherTab);
  assert.equal(h.badges.get(2).text, '');
  assert.equal(h.badges.get(2).title, 'PixelGuard for Gmail');
  assert.equal(h.badges.get(1).text, '090');
  assert.equal(h.badges.has(999), false);
});

test('only an active top-level Gmail document can publish valid badge counts', async () => {
  const h = harness();
  const counts = { suspicious: 1, externals: 0, links: 0 };
  assert.equal((await h.send('pg:badge', counts)).error, 'unauthorized');
  for (const override of [
    { id: 'other' }, { frameId: 2 }, { tab: { id: -1 } }, { documentLifecycle: 'cached' },
    { url: 'https://mail.google.com.example/mail/' }
  ]) {
    assert.equal((await h.send('pg:badge', counts, { ...h.gmail, ...override })).error, 'unauthorized');
  }
  for (const bad of [-1, 0.5, '1', Infinity]) {
    assert.equal((await h.send('pg:badge', { ...counts, links: bad }, h.gmail)).error, 'unavailable');
  }
  assert.equal(h.badges.size, 0);
});

test('ignores requests from older content scripts to open the original in another tab', async () => {
  const h = harness();
  assert.equal(await h.send('pg:openOriginal', { messageId: 'fedcbafeedac1234' }, h.gmail), undefined);
  assert.deepEqual(h.openedTabs, []);
});

test('reads only the native routing hint from the requesting Gmail account and document', async () => {
  const shared = {data: {}, scripting: {}};
  const h = harness(shared);
  const sender = {...h.gmail, documentId: 'active-doc', documentLifecycle: 'active'};
  const calls = [];
  let page = new URL(sender.url);
  let value = '0fabc12345';
  let resultDocument = sender.documentId;
  let resultFrame = 0;
  const field = new Proxy({}, {
    get(target, key) { assert.equal(key, '9'); return value; }
  });
  shared.scripting.executeScript = async ({func, args, target, world}) => {
    calls.push(clone(target));
    assert.equal(world, 'MAIN');
    const read = vm.runInNewContext('(' + func.toString() + ')', {window: {GLOBALS: field}, location: page});
    return [{result: read(...args), frameId: resultFrame, documentId: resultDocument}];
  };
  const request = (senderOverride = {}) => h.send('pg:gmail:mailboxHint', {tabId: 99, path: '/mail/u/100/'}, {...sender, ...senderOverride});
  assert.deepEqual(await request(), {ok: true, hint: value});
  assert.deepEqual(calls[0], {tabId: sender.tab.id, documentIds: [sender.documentId]});
  assert.deepEqual(await request({documentId: undefined}), {ok: true, hint: value});
  assert.deepEqual(calls[1], {tabId: sender.tab.id, frameIds: [0]});
  const blank = {ok: true, hint: ''};
  for (const invalid of [undefined, 12345678, {}, '1234', '1234567890abcdef0', 'abcdefgh', 'deadbeef&extra=1']) {
    value = invalid;
    assert.deepEqual(await request(), blank);
  }
  value = 'fe123456';
  for (const destination of ['https://mail.google.com/mail/u/8/', 'https://example.test/mail/u/0/']) {
    page = new URL(destination);
    assert.deepEqual(await request(), blank);
  }
  page = new URL(sender.url);
  resultDocument = 'different-doc';
  assert.deepEqual(await request(), blank);
  resultDocument = sender.documentId;
  resultFrame = 1;
  assert.deepEqual(await request(), blank);
  const injections = calls.length;
  for (const override of [
    {id: 'other'}, {frameId: 1}, {documentLifecycle: 'cached'}, {tab: {id: -1}},
    {url: 'https://example.test/mail/u/0/'}, {url: 'https://mail.google.com/mail/u/not-a-mailbox/'}
  ]) assert.deepEqual(await request(override), {ok: false, error: 'unauthorized'});
  assert.deepEqual(await h.send('pg:gmail:mailboxHint'), {ok: false, error: 'unauthorized'});
  assert.equal(calls.length, injections);
  assert.deepEqual(h.data, {});
  assert.deepEqual(h.requests, []);
  assert.deepEqual(h.openedTabs, []);
});

test('saving a key stays offline, and enabling requires separate permission', async () => {
  const h = harness();
  const saved = await h.send('pg:settings', { apiKey: sample });
  assert.equal(saved.vtEnabled, false);
  assert.equal(saved.hasKey, true);
  assert.equal(Object.hasOwn(h.data.vtConfig, 'apiKey'), false);
  assert.equal(JSON.stringify(h.data).includes(sample), false);
  const firstIV = h.data.vtConfig.sealedKey.iv;
  assert.equal((await h.send('pg:settings', { vtEnabled: true })).error, 'permission_denied');
  assert.equal((await h.send('pg:lookup', { kind: 'domain', value: 'example.test' })).error, 'disabled');
  assert.equal(h.requests.length, 0);
  h.grant();
  assert.equal((await h.send('pg:settings', { vtEnabled: true })).vtEnabled, true);
  assert.equal((await h.send('pg:settings', { apiKey: sample + '-replaced' })).vtEnabled, true);
  assert.notEqual(h.data.vtConfig.sealedKey.iv, firstIV);
  assert.equal(JSON.stringify(h.data).includes(sample), false);
  assert.equal((await h.send('pg:settings', { apiKey: '' })).hasKey, false);
  assert.equal('vtConfig' in h.data, false);
  assert.equal((await h.send('pg:lookup', { kind: 'domain', value: 'example.test' })).error, 'disabled');
  assert.equal(h.requests.length, 0);
});

test('two workers serialize new-key saves and keep the wrapping key across restarts', async () => {
  const shared = { data: {} };
  const first = harness(shared), second = harness(shared);
  const replies = await Promise.all([first, second].map(h => h.send('pg:settings', { apiKey: sample, onlyIfMissing: true })));
  assert.equal(replies.filter(r => r.ok).length, 1);
  assert.equal(replies.filter(r => r.error === 'key_exists').length, 1);
  assert.equal(shared.wrappingKey.extractable, false);
  assert.equal(shared.wrappingKey.algorithm.name, 'AES-GCM');
  assert.equal(shared.wrappingKey.algorithm.length, 256);
  const restarted = harness(shared);
  restarted.grant();
  assert.equal((await restarted.send('pg:settings', { vtEnabled: true })).vtEnabled, true);
  assert.equal((await restarted.send('pg:lookup', { kind: 'domain', value: 'example.test' })).ok, true);
  assert.ok(restarted.requests[0].options.headers['x-apikey'] === sample);
  delete shared.wrappingKey;
  const lost = harness(shared);
  lost.grant();
  assert.equal((await lost.send('pg:lookup', { kind: 'domain', value: 'example.test' })).error, 'storage');
  assert.equal(lost.requests.length, 0);
  assert.equal(shared.wrappingKey, undefined);
  assert.equal(shared.data.vtConfig.sealedKey.version, 1);
});

test('migration preserves the original record on failure and replaces it atomically on retry', async () => {
  const shared = { failSave: true, data: { vtConfig: { apiKey: sample, enabled: true } } };
  const h = harness(shared);
  h.grant();
  assert.equal((await h.send('pg:state')).error, 'storage');
  assert.ok(shared.data.vtConfig.apiKey === sample);
  assert.equal(shared.data.vtConfig.sealedKey, undefined);
  shared.failSave = false;
  assert.equal((await h.send('pg:state')).vtEnabled, true);
  assert.equal('apiKey' in shared.data.vtConfig, false);
  assert.equal(JSON.stringify(shared.data).includes(sample), false);
  assert.equal((await h.send('pg:settings', { onlyIfMissing: true, apiKey: sample })).error, 'key_exists');
  assert.equal((await h.send('pg:lookup', { kind: 'domain', value: 'example.test' })).ok, true);
  assert.ok(h.requests[0].options.headers['x-apikey'] === sample);
  await h.send('pg:settings', { apiKey: '' });
  assert.equal(shared.data.vtConfig, undefined);
  assert.equal(shared.wrappingKey, undefined);
});

test('only explicit, validated observables reach the VirusTotal widget via GET', async () => {
  const h = harness();
  h.grant();
  assert.equal((await h.send('pg:settings', { vtEnabled: true, apiKey: sample })).vtEnabled, true);
  const url = 'https://example.test/path?unique=abc';
  for (const [kind, value, error] of [
    ['url', url, 'confirmation_required'], ['domain', url, 'invalid_url'],
    ['url', 'https://user:pass@example.test/', 'invalid_url'], ['hash', 'nope', 'unavailable']
  ]) assert.equal((await h.send('pg:lookup', { kind, value })).error, error);
  assert.equal(h.requests.length, 0);
  for (const [kind, value] of [['domain', 'example.test'], ['url', url], ['hash', 'a'.repeat(64)]]) {
    const reply = await h.send('pg:lookup', { kind, value, confirmed: true });
    assert.equal(reply.result.reportUrl, report);
    assert.equal(reply.result.detections, 1);
    const { url: endpoint, options } = h.requests.at(-1);
    assert.equal(new URL(endpoint).searchParams.get('query'), value);
    assert.equal(new URL(endpoint).origin, 'https://www.virustotal.com');
    assert.equal(options.method, 'GET');
    assert.equal(options.headers['x-apikey'], sample);
    assert.equal(options.redirect, 'error');
    assert.equal(options.body, undefined);
    assert.equal(JSON.stringify(reply).includes(sample), false);
  }
  h.revoke();
  assert.equal((await h.send('pg:state')).vtEnabled, false);
  assert.equal((await h.send('pg:settings', { apiKey: '' })).hasKey, false);
  assert.equal(h.requests.length, 3);
});

test('quota survives a closed popup and blocks excess queries', async () => {
  const h = harness();
  h.grant();
  await h.send('pg:settings', { vtEnabled: true, apiKey: sample });
  for (let i = 0; i < 4; i++) {
    assert.equal((await h.send('pg:lookup', { kind: 'domain', value: 'example' + i + '.test' })).ok, true);
  }
  assert.equal((await h.send('pg:lookup', { kind: 'domain', value: 'example.test' })).error, 'rate_limit');
  assert.equal(h.requests.length, 4);
  assert.ok(h.data.vtQuota.every(Number.isFinite));
});
