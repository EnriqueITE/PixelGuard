const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const catalogs = Object.fromEntries(fs.readdirSync('_locales').map(language =>
  [language, JSON.parse(fs.readFileSync(`_locales/${language}/messages.json`, 'utf8'))]));
const root = 'moz-extension://pixelguard/';
const tick = () => new Promise(resolve => setImmediate(resolve));

function makeStorage(initial = {}) {
  const data = { ...initial };
  const listeners = [];
  const writes = [];
  const local = {
    async get(key) { return { [key]: data[key] }; },
    async set(object) {
      const changes = {};
      for (const [key, value] of Object.entries(object)) {
        changes[key] = { oldValue: data[key], newValue: value };
        data[key] = value;
      }
      writes.push(Object.keys(object));
      for (const listener of listeners) listener(changes, 'local');
    }
  };
  return { data, writes, local, onChanged: { addListener(fn) { listeners.push(fn); } } };
}

function settingsPage(storage, onFetch = async () => {}) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      dataset: {}, hidden: true, events: {},
      addEventListener(name, fn) { this.events[name] = fn; }
    });
    return elements.get(id);
  }
  const label = { dataset: { i18n: 'options_language' } };
  const input = { dataset: { i18nPlaceholder: 'vt_keyPlaceholder' } };
  const document = {
    documentElement: {}, getElementById: element,
    querySelectorAll(selector) {
      return selector === '[data-i18n]' ? [label] :
        selector === '[data-i18n-placeholder]' ? [input] : [];
    }
  };
  const requests = [];
  const calls = [];
  const context = vm.createContext({
    document,
    browser: {
      storage,
      i18n: { getUILanguage: () => 'en-GB', getMessage: key => catalogs.en[key].message },
      runtime: {
        getURL: path => root + path,
        async sendMessage({ type }) {
          calls.push(type);
          assert.equal(type, 'pg:getState');
          return storage.data.settings || {};
        }
      }
    },
    async fetch(url) {
      requests.push(url);
      const match = /^moz-extension:\/\/pixelguard\/_locales\/([\w-]+)\/messages\.json$/.exec(url);
      assert.ok(match && Object.hasOwn(catalogs, match[1]), url);
      await onFetch(match[1]);
      return { ok: true, json: async () => catalogs[match[1]] };
    }
  });
  const run = path => vm.runInContext(fs.readFileSync(path, 'utf8'), context, { filename: path });
  run('i18n.js');
  const ready = run('options/options.js');
  const picker = element('uiLanguage');
  async function choose(language) {
    picker.value = language;
    await picker.events.change();
  }
  return { ready, i18n: context.PixelGuardI18n, picker, label, input, document, requests,
    calls, choose, error: element('languageSaveError'), element };
}

test('language picker switches repeatedly, updates other views and persists across reopening', async () => {
  const settings = { debug: true, showInlineBanner: true };
  const storage = makeStorage({ settings, integrationState: { enabled: false } });
  const page = settingsPage(storage);
  await page.ready;
  assert.equal(page.picker.value, 'auto');
  assert.equal(page.document.documentElement.lang, 'en-GB');
  assert.equal(page.label.textContent, catalogs.en.options_language.message);
  assert.deepEqual(page.requests, []);

  for (const language of ['fr', 'de', 'it', 'fr']) {
    await page.choose(language);
    assert.equal(page.picker.disabled, false);
    assert.equal(page.error.hidden, true);
    assert.equal(storage.data.uiLanguage, language);
    assert.equal(page.document.documentElement.lang, language);
    assert.equal(page.label.textContent, catalogs[language].options_language.message);
    assert.equal(page.input.placeholder, catalogs[language].vt_keyPlaceholder.message);
  }
  assert.equal(page.requests.length, 3, 'Previously loaded catalogs are reused');

  const reopened = settingsPage(storage);
  await reopened.ready;
  assert.equal(reopened.picker.value, 'fr');
  await reopened.choose('auto');
  await tick();
  for (const view of [page, reopened]) {
    assert.equal(view.picker.value, 'auto');
    assert.equal(view.document.documentElement.lang, 'en-GB');
    assert.equal(view.label.textContent, catalogs.en.options_language.message);
    assert.deepEqual(view.calls, ['pg:getState']);
    assert.equal(view.element('inlineBannerToggle').checked, true);
  }
  assert.equal(storage.data.settings, settings);
  assert.deepEqual(storage.data.integrationState, { enabled: false });
  assert.ok(storage.writes.every(keys => keys.length === 1 && keys[0] === 'uiLanguage'));
});

test('bundled catalogs preserve named placeholders and render counts, image reasons and sizes', async () => {
  for (const [language, messages] of Object.entries(catalogs)) {
    const extraForms = language === 'ru' ? ['popup_label_alerts_few', 'popup_label_images_few', 'popup_label_links_few'] : [];
    assert.deepEqual(Object.keys(messages).sort(), [...Object.keys(catalogs.en), ...extraForms].sort(), language);
    for (const [key, entry] of Object.entries(catalogs.en)) {
      assert.ok(messages[key].message.trim(), language + '/' + key);
      assert.deepEqual(messages[key].placeholders, entry.placeholders, language + '/' + key);
      for (const name of Object.keys(entry.placeholders || {})) {
        assert.ok(messages[key].message.toLowerCase().includes('$' + name + '$'), language + '/' + key);
      }
    }
  }
  const page = settingsPage(makeStorage({ uiLanguage: 'fr' }));
  await page.ready;
  assert.match(page.i18n.get('vt_ratio', '2', '71'), /2 sur 71/);
  assert.equal(page.i18n.get('vt_attachmentSize', '1,25'), '1,25 Mio');
  const image = page.i18n.get('reason_tiny');
  assert.equal(page.i18n.get('reason_withRecipient', image),
    catalogs.fr.reason_withRecipient.message.replace('$IMAGE$', image));
});

test('non-English catalogs do not copy English UI text except for shared words and units', () => {
  // These exact strings really are identical in both languages. Keeping the
  // exceptions per locale catches a new untranslated label in any other one.
  const shared = {
    de: ['vt_attachmentSize'], el: ['vt_attachmentSize'], es: ['vt_attachmentSize'],
    fr: ['popup_label_image', 'popup_label_images'],
    it: ['vt_attachmentSize', 'popup_label_link', 'options_debugTitle'],
    ru: [], zh_CN: ['vt_attachmentSize']
  };
  for (const [language, messages] of Object.entries(catalogs)) {
    if (language.startsWith('en')) continue;
    const allowed = new Set(['extensionName', ...shared[language]]);
    for (const [key, english] of Object.entries(catalogs.en)) {
      if (!allowed.has(key)) assert.notEqual(messages[key].message, english.message, language + '/' + key);
    }
  }
});

test('malformed stored and selected language values never request a catalog', async () => {
  const storage = makeStorage({ uiLanguage: '../other' });
  const page = settingsPage(storage);
  await page.ready;
  for (const value of ['../other', 'https://example.invalid/messages.json', '__proto__']) {
    await page.choose(value);
    assert.equal(page.picker.value, 'auto');
    assert.equal(page.error.hidden, false);
  }
  assert.deepEqual(page.requests, []);
  assert.deepEqual(storage.writes, []);
});

test('a failed catalog load or save preserves the current language and permits retry', async () => {
  const storage = makeStorage({ uiLanguage: 'fr' });
  let failLoad = true;
  const page = settingsPage(storage, async lang => {
    if (lang === 'de' && failLoad) throw new Error('catalog unavailable');
  });
  await page.ready;
  const save = storage.local.set;
  await page.choose('de');
  assert.equal(page.picker.value, 'fr');
  assert.equal(page.error.hidden, false);
  assert.deepEqual(storage.writes, []);
  failLoad = false;
  storage.local.set = async () => { throw new Error('save failed'); };
  await page.choose('de');
  assert.equal(storage.data.uiLanguage, 'fr');
  assert.equal(page.document.documentElement.lang, 'fr');
  assert.equal(page.error.hidden, false);
  storage.local.set = save;
  await page.choose('de');
  assert.equal(page.picker.value, 'de');
  assert.equal(page.error.hidden, true);
  assert.equal(storage.data.uiLanguage, 'de');
});

test('a slow earlier catalog cannot replace a later committed language', async () => {
  const storage = makeStorage();
  let releaseFrench;
  const frenchPending = new Promise(resolve => { releaseFrench = resolve; });
  const page = settingsPage(storage, lang => lang === 'fr' ? frenchPending : Promise.resolve());
  await page.ready;
  await storage.local.set({ uiLanguage: 'fr' });
  await storage.local.set({ uiLanguage: 'it' });
  await tick();
  assert.equal(page.picker.value, 'it');
  releaseFrench();
  await tick();
  assert.equal(page.picker.value, 'it');
  assert.equal(page.label.textContent, catalogs.it.options_language.message);
});
