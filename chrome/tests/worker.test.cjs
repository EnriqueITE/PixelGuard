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
  const session = shared.session ??= {};
  const requests = [];
  const openedTabs = [];
  const openedPopups = [];
  const openedWindows = [];
  const broadcasts = [];
  const badges = new Map();
  function setBadge(tabId, patch) {
    assert.ok(Number.isInteger(tabId) && tabId >= 0);
    badges.set(tabId, { ...badges.get(tabId), ...patch });
  }
  const origin = 'chrome-extension://sample/';
  const popup = { id: 'sample', url: origin + 'popup.html' };
  const gmailUrl = 'https://mail.google.com/mail/u/0/';
  const gmail = { id: 'sample', url: gmailUrl, frameId: 0, tab: { id: 1, windowId: 3, url: gmailUrl } };
  let handler, revoked, access, permission = false;
  const chrome = {
    scripting: shared.scripting,
    runtime: { id: 'sample', getURL: p => origin + p, getManifest: () => ({ name: 'PixelGuard for Gmail' }),
      onMessage: { addListener(fn) { handler = fn; } }, onInstalled: { addListener() {} }, onStartup: { addListener() {} } },
    action: {
      async openPopup(options) { openedPopups.push(clone(options)); },
      async setBadgeText({ tabId, text }) { setBadge(tabId, { text }); },
      async setBadgeBackgroundColor({ tabId, color }) { setBadge(tabId, { color }); },
      async setTitle({ tabId, title }) {
        if (tabId === undefined) shared.defaultTitle = title;
        else setBadge(tabId, { title });
      }
    },
    i18n: { getUILanguage: () => shared.browserLanguage || 'en-US' },
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
    }, session: {
      async get(key) { return key in session ? {[key]: clone(session[key])} : {}; },
      async set(update) { Object.assign(session, clone(update)); },
      async remove(key) { delete session[key]; }
    } },
    tabs: {
      async get(id) { assert.equal(id, gmail.tab.id); return { ...gmail.tab, url: gmail.url, active: true }; },
      async query() { return [{ id: 1 }, { id: 2 }]; },
      async sendMessage(id, msg) { broadcasts.push(clone(msg)); },
      async create(options) { openedTabs.push(clone(options)); }
    },
    windows: { async create(options) { openedWindows.push(clone(options)); } },
    permissions: { async contains(p) {
      assert.deepEqual(clone(p), { origins: ['https://www.virustotal.com/*'] });
      return permission;
    }, onRemoved: { addListener(fn) { revoked = fn; } } }
  };
  const context = vm.createContext({
    chrome, URL, Blob, FormData, setTimeout, clearTimeout, AbortController, crypto: webcrypto, TextEncoder, TextDecoder, atob, btoa, navigator,
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (shared.fetch) return shared.fetch(url, options);
      return { ok: true, status: 200, json: async () => ({ data: { url: report, detection_ratio: { detections: 1, total: 80 } } }) };
    },
    importScripts: (...names) => names.forEach(name => {
      if (name === 'i18n-catalogs.js') {
        context.PixelGuardCatalogs = {
          'en-US': {gmailExtensionName: 'PixelGuard for Gmail', gmailFullScanRunning: 'Analyzing the message', badgeFindingsTitle: '$1, $2, $3'},
          es: {gmailExtensionName: 'PixelGuard para Gmail', gmailFullScanRunning: 'Analizando el mensaje', badgeFindingsTitle: 'Resultados: $1, $2, $3'}
        };
        return;
      }
      const filename = path.join(root, 'chrome', name);
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
  return { send, data, broadcasts, requests, gmail, popup, badges, openedTabs, openedPopups, openedWindows, chrome,
    grant() { permission = true; },
    revoke() { permission = false; revoked({ origins: ['https://www.virustotal.com/*'] }); }
  };
}

test('the Gmail page only receives display preferences, including when settings change', async () => {
  const h = harness();
  assert.deepEqual(await h.send('pg:panel', {}, h.gmail), { ok: true, showPanel: true, theme: 'light', language: 'auto' });
  for (const type of ['pg:settings', 'pg:lookup', 'pg:state']) {
    assert.equal((await h.send(type, { apiKey: sample }, h.gmail)).error, 'unauthorized');
  }
  await h.send('pg:settings', { showPanel: false, apiKey: sample });
  assert.deepEqual(await h.send('pg:panel', {}, h.gmail), { ok: true, showPanel: false, theme: 'light', language: 'auto' });
  assert.deepEqual(h.broadcasts, [1, 2].map(() => ({ type: 'pg:panelChanged', showPanel: false, theme: 'light', language: 'auto' })));
  assert.deepEqual(await h.send('pg:state'), { ok: true, hasKey: true, vtEnabled: false, showPanel: false, theme: 'light', language: 'auto' });
  assert.equal(h.requests.length, 0);
});

const sampleFile = new Blob(['Adjunto de prueba\n']);
const sampleBlobUrl = 'blob:chrome-extension://sample/5c5bcfa9-8ddb-463e-8b87-c8bed46eeaf0';
const filesApi = 'https://www.virustotal.com/api/v3/files';
const miss = () => Response.json({error: {code: 'NotFoundError'}}, {status: 404});
const accepted = () => Response.json({data: {type: 'analysis', id: 'sample-analysis'}});
async function fileHash(file) {
  return Buffer.from(await webcrypto.subtle.digest('SHA-256', await file.arrayBuffer())).toString('hex');
}
async function configuredAttachmentHarness(fetch) {
  const shared = {data: {}, fetch};
  const h = harness(shared);
  h.grant();
  assert.equal((await h.send('pg:settings', {vtEnabled: true, apiKey: sample})).ok, true);
  return {h, shared};
}

test('file reports send only a SHA-256 from the trusted popup and distinguish verdicts, misses, and API errors', async () => {
  const hash = await fileHash(sampleFile);
  const hit = {data: {type: 'file', id: hash, attributes: {last_analysis_stats: {
    malicious: 2, suspicious: 1, harmless: 20, undetected: 37, timeout: 4
  }}}};
  const cases = [
    [() => Response.json(hit), 'reported'], [miss, 'no_report'],
    [() => Response.json({...hit, data: {...hit.data, id: '0'.repeat(64)}}), 'invalid_response'],
    [() => Response.json({error: {code: 'WrongCode'}}, {status: 404}), 'invalid_response'],
    [() => new Response('Not Found', {status: 404}), 'invalid_response'],
    [() => Response.json({}, {status: 401}), 'invalid_key'], [() => Response.json({}, {status: 403}), 'forbidden'],
    [() => Response.json({}, {status: 429}), 'rate_limit'], [() => Response.json({}, {status: 500}), 'network']
  ];
  for (const [response, expected] of cases) {
    const {h} = await configuredAttachmentHarness(response);
    assert.equal((await h.send('pg:attachmentReport', {hash}, h.gmail)).error, 'unauthorized');
    assert.equal((await h.send('pg:attachmentReport', {hash}, {...h.popup, documentLifecycle: 'cached'})).error, 'unauthorized');
    assert.equal((await h.send('pg:attachmentReport', {hash: 'no-hash'})).error, 'unavailable');
    const reply = await h.send('pg:attachmentReport', {hash: hash.toUpperCase(), name: 'private.pdf', blobUrl: sampleBlobUrl});
    assert.equal(reply.result?.status || reply.error, expected);
    assert.equal(!!reply.uploadToken, expected === 'no_report');
    if (expected === 'reported') {
      assert.equal(reply.result.detections, 3);
      assert.equal(reply.result.total, 60);
      assert.equal(reply.result.reportUrl, 'https://www.virustotal.com/gui/file/' + hash);
    }
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].url, filesApi + '/' + hash);
    const {method, body, credentials, redirect, headers} = h.requests[0].options;
    assert.deepEqual([method, body, credentials, redirect, headers['x-apikey']], ['GET', undefined, 'omit', 'error', sample]);
    assert.equal(JSON.stringify(headers).includes('private.pdf'), false);
  }
});

test('a confirmed missing attachment can be uploaded only once by its popup, even across worker restarts', async () => {
  const hash = await fileHash(sampleFile);
  const {h, shared} = await configuredAttachmentHarness((url, options) => {
    if (url === filesApi + '/' + hash) return miss();
    if (url === sampleBlobUrl) return new Response(sampleFile);
    if (url === filesApi && options.method === 'POST') return accepted();
    throw Error('Unexpected request: ' + url);
  });
  const sender = {...h.popup, documentId: 'popup1'};
  const {uploadToken} = await h.send('pg:attachmentReport', {hash}, sender);
  const msg = {hash, name: 'prueba.txt', blobUrl: sampleBlobUrl, uploadToken, confirmed: true};
  const reopened = harness(shared);
  reopened.grant();
  assert.equal((await reopened.send('pg:uploadAttachment', msg, h.gmail)).error, 'unauthorized');
  assert.equal((await reopened.send('pg:uploadAttachment', {...msg, confirmed: false}, sender)).error, 'upload_confirmation_required');
  assert.equal((await reopened.send('pg:uploadAttachment', msg, {...sender, documentId: 'popup2'})).error, 'report_expired');
  assert.equal((await reopened.send('pg:uploadAttachment', {...msg, hash: '0'.repeat(64)}, sender)).error, 'report_expired');
  for (const blobUrl of ['https://other.example/file', 'blob:https://mail.google.com/value', sampleBlobUrl + '?extra',
    sampleBlobUrl.replace('sample/', 'sample.else/')]) {
    assert.equal((await reopened.send('pg:uploadAttachment', {...msg, blobUrl}, sender)).error, 'unavailable');
  }
  assert.equal(reopened.requests.length, 0);
  const [first, simultaneous] = await Promise.all([
    reopened.send('pg:uploadAttachment', msg, sender), reopened.send('pg:uploadAttachment', msg, sender)
  ]);
  assert.deepEqual(first, {ok: true, analysisId: 'sample-analysis'});
  assert.equal(simultaneous.error, 'busy');
  assert.equal((await reopened.send('pg:uploadAttachment', msg, sender)).error, 'report_expired');
  assert.deepEqual(reopened.requests.map(x => x.url), [sampleBlobUrl, filesApi]);
  assert.equal(reopened.requests[0].options.headers, undefined);
  const options = reopened.requests[1].options;
  assert.deepEqual([options.method, options.credentials, options.redirect], ['POST', 'omit', 'error']);
  assert.equal(options.body.get('file').name, 'prueba.txt');
  assert.equal(await options.body.get('file').text(), await sampleFile.text());
  assert.equal(shared.data.vtQuota.length, 2);
});

test('expired consent, changed bytes, disabled settings and revoked permissions prevent sending file contents', async () => {
  const hash = await fileHash(sampleFile);
  for (const reason of ['expired', 'bytes', 'disabled', 'permission', 'quota', 'oversize']) {
    const {h, shared} = await configuredAttachmentHarness(url => url === sampleBlobUrl ?
      new Response(new Blob(['other bytes']), {headers: {'content-length': reason === 'oversize' ? '53000000' : '11'}}) : miss());
    const {uploadToken} = await h.send('pg:attachmentReport', {hash});
    const msg = {hash, name: 'test.txt', uploadToken, confirmed: true, blobUrl: sampleBlobUrl};
    if (reason === 'expired') shared.session.vtUploadGrants[0].expiresAt = Date.now() - 1;
    if (reason === 'disabled') {
      assert.equal((await h.send('pg:settings', {vtEnabled: false})).ok, true);
      assert.equal((await h.send('pg:settings', {vtEnabled: true})).ok, true);
    }
    if (reason === 'permission') h.revoke();
    if (reason === 'quota') {
      shared.data.vtQuota = Array(4).fill(Date.now());
      shared.fetch = () => new Response(sampleFile);
    }
    const reply = await h.send('pg:uploadAttachment', msg);
    assert.equal(reply.error, {permission: 'disabled', quota: 'rate_limit', oversize: 'too_large'}[reason] || 'report_expired');
    assert.equal(h.requests.some(r => r.options.method === 'POST'), false);
  }
});

test('large attachments use an HTTPS single-use upload URL on the permitted host and charge both API requests', async () => {
  const file = new Blob([new Uint8Array(32 * 1024 * 1024 + 1)]);
  const hash = await fileHash(file);
  const path = 'www.virustotal.com/_ah/upload/single-use/';
  for (const valid of [true, false]) {
    const {h} = await configuredAttachmentHarness(url => {
      if (url === filesApi + '/' + hash) return miss();
      if (url === sampleBlobUrl) return new Response(file);
      if (url === filesApi + '/upload_url') return Response.json({data: valid ? 'http://' + path : 'https://elsewhere.example/_ah/upload/x'});
      if (url === 'https://' + path) return accepted();
      throw Error('Unexpected request: ' + url);
    });
    const {uploadToken} = await h.send('pg:attachmentReport', {hash});
    const result = await h.send('pg:uploadAttachment', {hash, blobUrl: sampleBlobUrl, name: 'big.txt', uploadToken, confirmed: true});
    assert.equal(valid ? result.analysisId : result.error, valid ? 'sample-analysis' : 'invalid_response');
    assert.deepEqual(h.requests.map(r => r.url), [
      filesApi + '/' + hash, sampleBlobUrl, filesApi + '/upload_url', ...(valid ? ['https://' + path] : [])
    ]);
    assert.equal(h.data.vtQuota.length, valid ? 3 : 2);
  }
});

test('changing theme preserves other preferences and remains local across worker restarts', async () => {
  const shared = { data: { showPanel: false, theme: 'unknown' } };
  const h = harness(shared);
  assert.equal((await h.send('pg:state')).theme, 'light');
  assert.equal((await h.send('pg:settings', { theme: 'dark' }, h.gmail)).error, 'unauthorized');
  assert.equal((await h.send('pg:settings', { theme: 'system', showPanel: true })).ok, false);
  assert.deepEqual(h.broadcasts, []);
  assert.equal((await h.send('pg:settings', { theme: 'dark' })).theme, 'dark');
  assert.deepEqual(h.broadcasts, [1, 2].map(() => ({ type: 'pg:panelChanged', showPanel: false, theme: 'dark', language: 'auto' })));
  const reopened = harness(shared);
  assert.deepEqual(await reopened.send('pg:panel', {}, reopened.gmail), {ok: true, showPanel: false, theme: 'dark', language: 'auto'});
  assert.equal((await reopened.send('pg:settings', {showPanel: true})).theme, 'dark');
  assert.equal((await reopened.send('pg:settings', {theme: 'light'})).showPanel, true);
  assert.deepEqual(reopened.requests, []);
});

test('toolbar titles follow the browser by default and restore the selected language after worker restart', async () => {
  const shared = {data: {language: 'unknown'}, browserLanguage: 'es-MX'};
  const h = harness(shared);
  const counts = {suspicious: 3, externals: 1, links: 2};
  assert.equal((await h.send('pg:state')).language, 'auto');
  await h.send('pg:badge', counts, h.gmail);
  assert.equal(h.badges.get(1).title, 'Resultados: 3, 1, 2');
  for (const language of ['invalid', ['es'], null, {}]) {
    assert.equal((await h.send('pg:settings', {language})).error, 'unavailable');
  }
  assert.equal((await h.send('pg:settings', {language: 'en-US'})).language, 'en-US');
  assert.equal(shared.defaultTitle, 'PixelGuard for Gmail');
  const restarted = harness(shared);
  await restarted.send('pg:badge', counts, restarted.gmail);
  assert.equal(restarted.badges.get(1).title, '3, 1, 2');
  await restarted.send('pg:settings', {language: 'auto'});
  await restarted.send('pg:badge', {...counts, scanning: true}, restarted.gmail);
  assert.equal(restarted.badges.get(1).title, 'Analizando el mensaje');
  assert.equal(shared.defaultTitle, 'PixelGuard para Gmail');
  assert.deepEqual(restarted.requests, []);
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
  for (const scanning of [null, 0, 'true']) {
    assert.equal((await h.send('pg:badge', { ...counts, scanning }, h.gmail)).error, 'unavailable');
  }
  assert.equal(h.badges.size, 0);
});

test('a scanning tab shows a neutral badge until its findings are ready', async () => {
  const h = harness();
  const counts = { suspicious: 2, externals: 1, links: 0 };
  const scan = { text: '…', title: 'Analyzing the message', color: '#49616a' };
  const otherTab = { ...h.gmail, tab: { id: 2 } };
  await h.send('pg:badge', { ...counts, scanning: true }, h.gmail);
  await h.send('pg:badge', { suspicious: 0, externals: 0, links: 0, scanning: true }, otherTab);
  assert.deepEqual(h.badges.get(1), scan);
  assert.deepEqual(h.badges.get(2), scan);
  await h.send('pg:badge', { ...counts, scanning: false }, h.gmail);
  assert.deepEqual(h.badges.get(1), { text: '210', title: '2, 1, 0', color: '#e53935' });
  assert.deepEqual(h.badges.get(2), scan);
  await h.send('pg:badge', { suspicious: 0, externals: 0, links: 0 }, otherTab);
  assert.equal(h.badges.get(2).text, '');
  assert.equal(h.badges.get(2).title, 'PixelGuard for Gmail');
});

test('ignores requests from older content scripts to open the original in another tab', async () => {
  const h = harness();
  assert.equal(await h.send('pg:openOriginal', { messageId: 'fedcbafeedac1234' }, h.gmail), undefined);
  assert.deepEqual(h.openedTabs, []);
});

test('the Gmail row opens its own toolbar widget without sending or storing a URL', async () => {
  const h = harness();
  for (const sender of [h.popup, ...[
    {id: 'other'}, {frameId: 1}, {documentLifecycle: 'cached'}, {url: 'https://mail.google.com.example/mail/'},
    {tab: {id: -1, windowId: 3}}, {tab: {id: 1, windowId: -1}}, {tab: {id: 1}}
  ].map(override => ({...h.gmail, ...override}))]) {
    assert.equal((await h.send('pg:gmail:openVirusTotal', {}, sender)).error, 'unauthorized');
  }
  assert.deepEqual(h.openedPopups, []);
  const reply = await h.send('pg:gmail:openVirusTotal', {tabId: 99, windowId: 77, url: 'https://ignored.test/path'}, h.gmail);
  assert.deepEqual(reply, {ok: true});
  assert.deepEqual(h.openedPopups, [{windowId: 3}]);
  assert.deepEqual(h.openedWindows, []);
  assert.deepEqual(h.broadcasts, []);
  assert.deepEqual(h.requests, []);
  assert.deepEqual(h.data, {});
});

test('the fallback popup receives only the source tab ID and retains private browsing', async () => {
  const h = harness();
  const sender = {...h.gmail, tab: {...h.gmail.tab, incognito: true}};
  for (const open of [undefined, async () => { throw Error('Toolbar popup unavailable'); }]) {
    h.chrome.action.openPopup = open;
    assert.deepEqual(await h.send('pg:gmail:openVirusTotal', {}, sender), {ok: true});
    assert.deepEqual(h.openedWindows.at(-1), {
      type: 'popup', url: h.popup.url + '#tab=1', width: 410, height: 560, incognito: true
    });
  }
  const hasState = url => h.send('pg:state', {}, {...h.popup, url});
  assert.equal((await hasState(h.popup.url + '#tab=0')).ok, true);
  assert.equal((await hasState(h.openedWindows[0].url)).ok, true);
  for (const suffix of ['?tab=1', '/#tab=1', '#tab=-1', '#tab=01', '#tab=1.0', '#tab=1&url=x', '#tab=99999999999999999']) {
    assert.equal((await hasState(h.popup.url + suffix)).error, 'unauthorized');
  }
  assert.deepEqual(h.requests, []);
  assert.deepEqual(h.data, {});
});

test('tab switches, navigations and closed tabs cancel the widget handoff', async () => {
  const h = harness();
  const original = h.chrome.tabs.get;
  for (const change of [{active: false}, {windowId: 4}, {url: h.gmail.url + '#other'}, {pendingUrl: 'https://elsewhere.test/'}]) {
    h.chrome.tabs.get = async id => ({...await original(id), ...change});
    assert.equal((await h.send('pg:gmail:openVirusTotal', {}, h.gmail)).error, 'unavailable');
  }
  h.chrome.tabs.get = original;
  h.chrome.action.openPopup = async () => {
    h.chrome.tabs.get = async () => { throw Error('Tab removed'); };
    throw Error('Toolbar popup unavailable');
  };
  assert.equal((await h.send('pg:gmail:openVirusTotal', {}, h.gmail)).error, 'unavailable');
  assert.deepEqual(h.openedPopups, []);
  assert.deepEqual(h.openedWindows, []);
  assert.deepEqual(h.requests, []);
});

test('Gmail can change a thread fragment before a click and keep the same sending document', async () => {
  const h = harness();
  const clicked = h.gmail.url + '#inbox/clicked';
  const original = h.chrome.tabs.get;
  h.chrome.tabs.get = async id => ({...await original(id), url: clicked});
  const sender = {...h.gmail, url: h.gmail.url + '#inbox/first', tab: {...h.gmail.tab, url: clicked}};
  assert.equal((await h.send('pg:gmail:openVirusTotal', {}, sender)).ok, true);
  delete sender.tab.url;
  assert.equal((await h.send('pg:gmail:openVirusTotal', {}, sender)).ok, true);
  h.chrome.action.openPopup = async () => {
    h.chrome.tabs.get = async id => ({...await original(id), url: h.gmail.url + '#inbox/next'});
    throw Error('Toolbar cannot open');
  };
  assert.equal((await h.send('pg:gmail:openVirusTotal', {}, sender)).error, 'unavailable');
  h.chrome.tabs.get = async id => ({...await original(id), url: 'https://mail.google.com/mail/u/1/#inbox/other-account'});
  assert.equal((await h.send('pg:gmail:openVirusTotal', {}, sender)).error, 'unavailable');
  assert.deepEqual(h.openedWindows, []);
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
