const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Small eventful DOM harness: verifies the user's consent flow, not browser rendering.
function harness(file, responder, permission = true) {
  const elements = new Map();
  const calls = [];
  let storedLanguage = 'auto';
  const storageListeners = [];
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attributes = new Set(); this.value = ''; this.checked = false; }
    set textContent(text) { this.text = text; this.children = []; }
    get textContent() { return this.text || ''; }
    appendChild(child) { child.parent = this; this.children.push(child); return child; }
    append(...children) { children.forEach(child => this.appendChild(child)); }
    insertBefore(child, before) { child.parent = this; this.children.splice(this.children.indexOf(before), 0, child); }
    setAttribute(name) { this.attributes.add(name); }
    removeAttribute(name) { this.attributes.delete(name); }
    addEventListener(type, listener) { this.events[type] = listener; }
    remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
    focus() { this.focused = true; }
    fire(type) { return this.events[type]?.({ preventDefault() {} }); }
  }
  const descendants = element => [element, ...element.children.flatMap(descendants)];
  const document = {
    documentElement: {},
    querySelectorAll(selector) {
      const attr = selector.slice(1, -1);
      return [...elements.values()].flatMap(descendants).filter(el => el.attributes.has(attr));
    },
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element(id)); return elements.get(id); },
    createElement: tag => new Element(tag)
  };
  const context = vm.createContext({ document, Date, Number, String,
    fetch: async path => ({ ok: true, json: async () => JSON.parse(fs.readFileSync(path, 'utf8')) }),
    browser: {
    i18n: { getMessage: key => key, getUILanguage: () => 'en-US' },
    runtime: {
      getURL: path => path,
      sendMessage: async msg => { calls.push(msg); return responder(msg); },
      openOptionsPage: async () => {}
    },
    storage: {
      local: {
        get: async () => ({ uiLanguage: storedLanguage }),
        set: async ({ uiLanguage }) => {
          storedLanguage = uiLanguage;
          storageListeners.forEach(listener => listener({ uiLanguage: { newValue: uiLanguage } }, 'local'));
        }
      },
      onChanged: { addListener(listener) { storageListeners.push(listener); } }
    },
    permissions: {
      request: async data => { calls.push({ type: 'permission', ...data }); return permission; },
      onRemoved: { addListener() {} }
    }
  } });
  vm.runInContext(fs.readFileSync('i18n.js', 'utf8'), context);
  // popup.js / options.js translate the whole page when a locale is selected.
  context.PixelGuardI18n.onChange(() => context.PixelGuardI18n.translatePage(document));
  vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });
  return { calls, el: id => document.getElementById(id), descendants,
    changeLanguage: context.PixelGuardI18n.setLanguage, t: context.PixelGuardI18n.get };
}
async function flush() { for (let n = 0; n < 30; n++) await Promise.resolve(); }
const config = { ok: true, enabled: true, configured: true, granted: true };
const data = { ok: true, sessionId: 'session', links: [{ id: 'link', host: 'example.com', url: 'https://example.com/private?token=secret' }], attachments: [] };

test('collapsed and disabled VirusTotal never loads message inventory or queries', async () => {
  const h = harness('popup/vt.js', () => ({ ...config, enabled: false }));
  await flush();
  assert.equal(h.calls.length, 0);
  h.el('vtSection').open = true;
  h.el('vtSection').fire('toggle');
  await flush();
  assert.deepEqual(h.calls.map(x => x.type), ['pg:vt:getConfig']);
  assert.equal(h.el('vtSetup').hidden, false);
});

test('full URL requires preview plus explicit confirmation; cancel sends no query', async () => {
  const h = harness('popup/vt.js', msg => msg.type.endsWith('getConfig') ? config : msg.type.endsWith('getInventory') ? data : { ok: true, result: { status: 'no_report', queriedAt: 1 } });
  h.el('vtSection').open = true;
  h.el('vtSection').fire('toggle');
  await flush();
  const find = text => h.descendants(h.el('vtInventory')).find(el => el.tagName === 'button' && el.textContent === text);
  find('vt_queryUrl').fire('click');
  const code = h.descendants(h.el('vtInventory')).find(el => el.tagName === 'code');
  assert.equal(code.textContent, data.links[0].url);
  find('vt_cancel').fire('click');
  assert.equal(h.calls.filter(x => x.type.endsWith(':query')).length, 0);
  find('vt_queryUrl').fire('click');
  await find('vt_confirmUrl').fire('click');
  await flush();
  const queries = h.calls.filter(x => x.type.endsWith(':query'));
  assert.equal(queries.length, 1);
  assert.equal(queries[0].confirmedUrl, data.links[0].url);
  assert.equal(queries[0].kind, 'url');
  assert.equal(queries[0].sessionId, 'session');
});

test('attachment action sends only selected item identity, never file contents', async () => {
  const h = harness('popup/vt.js', msg => msg.type.endsWith('getConfig') ? config : msg.type.endsWith('getInventory') ? { ...data, links: [], attachments: [{ id: 'att', name: 'private.pdf', size: 123 }] } : { ok: false, error: 'unavailable' });
  h.el('vtSection').open = true; h.el('vtSection').fire('toggle'); await flush();
  const lookup = h.descendants(h.el('vtInventory')).find(el => el.textContent === 'vt_queryHash');
  await lookup.fire('click'); await flush();
  const query = h.calls.find(x => x.type.endsWith(':query'));
  assert.deepEqual(JSON.parse(JSON.stringify(query)), { type: 'pg:vt:query', sessionId: 'session', itemId: 'att', kind: 'file' });
});

test('a report without detection totals offers official details without inventing a ratio', async () => {
  const h = harness('popup/vt.js', msg => msg.type.endsWith('getConfig') ? config : msg.type.endsWith('getInventory') ? data : { ok: true, result: { status: 'reported', id: 'report', queriedAt: 1 } });
  h.el('vtSection').open = true; h.el('vtSection').fire('toggle'); await flush();
  const find = text => h.descendants(h.el('vtInventory')).find(el => el.textContent === text);
  await find('vt_queryDomain').fire('click'); await flush();
  assert.ok(find('vt_noSummary'));
  assert.ok(find('vt_openReport'));
  assert.equal(find('vt_ratio'), undefined);
});

test('changing language preserves expanded VT rows, unconfirmed URLs and in-flight reports', async () => {
  const links = Array.from({ length: 6 }, (_, n) => ({ ...data.links[0], id: String(n), url: `https://example.com/${n}` }));
  let finishQuery;
  const pending = new Promise(resolve => { finishQuery = resolve; });
  const h = harness('popup/vt.js', msg => {
    if (msg.type.endsWith('getConfig')) return config;
    if (msg.type.endsWith('getInventory')) return { ...data, links };
    if (msg.type.endsWith('openReport')) return { ok: true };
    assert.equal(msg.type, 'pg:vt:query');
    return pending;
  });
  await h.changeLanguage('de');
  assert.equal(h.calls.length, 0);
  h.el('vtSection').open = true; h.el('vtSection').fire('toggle'); await flush();
  const rendered = () => h.descendants(h.el('vtInventory'));
  const find = text => rendered().find(el => el.textContent === text);
  const more = find(h.t('vt_more'));
  more.fire('click');
  const urls = rendered().filter(el => el.textContent === h.t('vt_queryUrl'));
  assert.equal(urls.length, 6);
  urls[5].fire('click');
  const preview = rendered().find(el => el.tagName === 'code' && el.textContent === links[5].url);
  assert.ok(preview);
  const cancel = find(h.t('vt_cancel'));
  const domain = find(h.t('vt_queryDomain'));
  const query = domain.fire('click');
  await h.changeLanguage('fr');
  assert.equal(find(h.t('vt_cancel')), cancel);
  assert.ok(cancel.focused);
  assert.ok(rendered().includes(preview));
  assert.ok(more.hidden);
  assert.equal(rendered().filter(el => el.textContent === h.t('vt_queryUrl')).length, 6);
  assert.ok(find(h.t('vt_querying')));
  assert.ok(domain.disabled);
  finishQuery({ ok: true, result: { id: 'r1', status: 'reported', detections: 3, total: 90, queriedAt: 10 } });
  await query;
  const open = find(h.t('vt_openReport'));
  assert.ok(open);
  await h.changeLanguage('it');
  assert.equal(find(h.t('vt_openReport')), open);
  assert.ok(find(h.t('vt_ratio', '3', '90')));
  assert.ok(find(h.t('vt_queriedAt', new Date(10).toLocaleString('it'))));
  assert.deepEqual(h.calls.map(call => call.type), ['pg:vt:getConfig', 'pg:vt:getInventory', 'pg:vt:query']);
  await open.fire('click');
  assert.equal(h.calls.at(-1).resultId, 'r1');
  assert.equal(h.calls.at(-1).sessionId, data.sessionId);
});

test('settings require consent and permissions before saving, then clear entered key', async () => {
  const h = harness('options/vt.js', msg => msg.type.endsWith('getConfig') ? { ...config, enabled: false, configured: false } : config);
  await flush();
  assert.equal(h.el('vtEnable').disabled, true);
  assert.equal(h.el('vtKeySaved').hidden, true);
  assert.equal(h.el('vtKey').placeholder, 'vt_keyPlaceholder');
  assert.equal(h.el('vtKeyHint').textContent, 'vt_keyEmptyHint');
  h.el('vtKey').value = 'a'.repeat(64);
  await h.el('vtEnable').fire('click');
  assert.equal(h.calls.length, 1);
  h.el('vtConsent').checked = true; h.el('vtConsent').fire('change');
  await h.el('vtEnable').fire('click');
  assert.deepEqual(h.calls.map(x => x.type), ['pg:vt:getConfig', 'permission', 'pg:vt:saveConfig']);
  assert.equal(h.calls[2].consent, true);
  assert.equal(h.el('vtKey').value, '');
  assert.equal(h.el('vtKeySaved').hidden, false);
  assert.equal(h.el('vtKeySaved').textContent, 'vt_keySaved');
  assert.equal(h.el('vtKey').placeholder, 'vt_keyReplacePlaceholder');
  assert.equal(h.el('vtKeyHint').textContent, 'vt_keyHint');
});

test('reopening settings identifies a saved key even when disabled, without reading it back', async () => {
  for (const enabled of [true, false]) {
    const h = harness('options/vt.js', () => ({ ...config, enabled }));
    await flush();
    assert.equal(h.el('vtKeySaved').hidden, false);
    assert.equal(h.el('vtKey').placeholder, 'vt_keyReplacePlaceholder');
    assert.equal(h.el('vtKey').value, '');
    assert.deepEqual(h.calls.map(x => x.type), ['pg:vt:getConfig']);
  }
});

test('disabling keeps saved-key feedback; deleting returns the field to first setup', async () => {
  const h = harness('options/vt.js', msg => msg.type.endsWith('deleteConfig')
    ? { ...config, enabled: false, configured: false }
    : { ...config, enabled: msg.type.endsWith('getConfig') });
  await flush();
  await h.el('vtDisable').fire('click');
  assert.equal(h.el('vtKeySaved').hidden, false);
  assert.equal(h.el('vtKey').placeholder, 'vt_keyReplacePlaceholder');
  await h.el('vtDelete').fire('click');
  assert.equal(h.el('vtKeySaved').hidden, true);
  assert.equal(h.el('vtKey').placeholder, 'vt_keyPlaceholder');
  assert.equal(h.el('vtKeyHint').textContent, 'vt_keyEmptyHint');
  assert.equal(h.el('vtKey').value, '');
});

test('a failed save does not claim that a new key was stored', async () => {
  const h = harness('options/vt.js', msg => msg.type.endsWith('getConfig')
    ? { ...config, enabled: false, configured: false }
    : { ok: false, error: 'storage' });
  await flush();
  h.el('vtKey').value = 'a'.repeat(64); h.el('vtConsent').checked = true;
  await h.el('vtEnable').fire('click');
  assert.equal(h.el('vtKeySaved').hidden, true);
  assert.equal(h.el('vtKey').value, '');
  assert.equal(h.el('vtKey').placeholder, 'vt_keyPlaceholder');
  assert.equal(h.el('vtConfigStatus').textContent, 'vt_error_storage');
});

test('denying optional permissions never saves or queries the key', async () => {
  const h = harness('options/vt.js', () => ({ ...config, enabled: false, configured: false }), false);
  await flush();
  h.el('vtKey').value = 'a'.repeat(64); h.el('vtConsent').checked = true;
  await h.el('vtEnable').fire('click');
  assert.deepEqual(h.calls.map(x => x.type), ['pg:vt:getConfig', 'permission']);
  assert.equal(h.el('vtKey').value, '');
  assert.equal(h.el('vtKeySaved').hidden, true);
});

test('all locales contain matching VT keys and placeholder definitions', () => {
  const base = JSON.parse(fs.readFileSync('_locales/en/messages.json', 'utf8'));
  const keys = Object.keys(base).filter(key => key.startsWith('vt_')).sort();
  for (const lang of fs.readdirSync('_locales')) {
    const translations = JSON.parse(fs.readFileSync(`_locales/${lang}/messages.json`, 'utf8'));
    assert.deepEqual(Object.keys(translations).filter(key => key.startsWith('vt_')).sort(), keys);
    for (const key of keys) {
      assert.ok(translations[key].message.trim(), `${lang}: ${key}`);
      assert.deepEqual(translations[key].placeholders, base[key].placeholders);
    }
  }
});
