const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const runtime = fs.readFileSync(path.join(root, 'i18n.js'), 'utf8');
const sources = {'en-US': 'en', de: 'de', el: 'el', es: 'es', fr: 'fr', it: 'it', ru: 'ru', 'zh-CN': 'zh_CN'};

function readCatalog(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const catalogs = {};
const messages = {};
for (const [language, directory] of Object.entries(sources)) {
  const shared = readCatalog(path.join(root, '..', '_locales', directory, 'messages.json'));
  const gmail = readCatalog(path.join(root, 'messages.' + directory + '.json'));
  const entries = Object.fromEntries(Object.entries(shared).filter(([key]) =>
    key.startsWith('reason_') || key.startsWith('vt_') || key === 'ui_buyCoffee'));
  catalogs[language] = {...entries, ...gmail};
  messages[language] = {};
  for (const [key, entry] of Object.entries(catalogs[language])) {
    messages[language][key] = entry.message.replace(/\$(\w+)\$/g,
      (_, name) => entry.placeholders[name.toLowerCase()].content);
  }
}

function languageRuntime(browserLanguage, packagedMessages = messages) {
  const context = {
    chrome: {i18n: {getUILanguage: () => browserLanguage}},
    PixelGuardCatalogs: packagedMessages
  };
  vm.runInNewContext(runtime, context, {filename: 'i18n.js'});
  return context.PixelGuardI18n;
}

test('auto uses the browser UI language, regional variants and the Simplified Chinese script', () => {
  for (const [incoming, expected] of [
    ['en-GB', 'en-US'], ['de-CH', 'de'], ['el-GR', 'el'], ['es-MX', 'es'], ['fr_CA', 'fr'],
    ['it-IT', 'it'], ['ru-KZ', 'ru'], ['zh', 'zh-CN'], ['zh-Hans', 'zh-CN'], ['zh_SG', 'zh-CN'],
    ['zh-Hant-TW', 'en-US'], ['sv-SE', 'en-US'], ['?', 'en-US'], ['', 'en-US']
  ]) {
    const i18n = languageRuntime(incoming);
    assert.equal(i18n.locale, expected, incoming);
    assert.equal(i18n.t('pgLanguage'), messages[expected].pgLanguage, incoming);
  }
});

test('all eight manual choices override the browser and switching back to auto restores it', () => {
  const i18n = languageRuntime('fr-CA');
  assert.deepEqual(Object.keys(i18n.languages).sort(), Object.keys(sources).sort());
  assert.equal(i18n.validPreference('auto'), true);
  const labels = {
    'en-US': 'Language', de: 'Sprache', el: 'Γλώσσα', es: 'Idioma', fr: 'Langue',
    it: 'Lingua', ru: 'Язык', 'zh-CN': '语言'
  };
  for (const [language, label] of Object.entries(labels)) {
    assert.equal(i18n.validPreference(language), true);
    i18n.use(language);
    assert.equal(i18n.locale, language);
    assert.equal(i18n.t('pgLanguage'), label);
    assert.equal(i18n.t('ui_buyCoffee'), messages[language].ui_buyCoffee);
    assert.equal(i18n.t('reason_trackingHost'), messages[language].reason_trackingHost);
    assert.equal(i18n.t('vt_queryHash'), messages[language].vt_queryHash);
  }
  i18n.use('auto');
  assert.equal(i18n.locale, 'fr');
});

test('invalid stored preference values are rejected and fall back to the browser', () => {
  const i18n = languageRuntime('es');
  for (const value of [undefined, null, 2, 'sv', 'constructor', '__proto__', ['de'], {}, Object.create(null)]) {
    assert.equal(i18n.validPreference(value), false);
    i18n.use('ru');
    i18n.use(value);
    assert.equal(i18n.locale, 'es');
  }
});

test('message substitutions preserve translated order, literal dollars and user values', () => {
  const testMessages = {
    ...messages,
    fr: {...messages.fr, order: '$3 · $1 · $2 · $$'},
    'en-US': {...messages['en-US'], englishOnly: 'Default $1'}
  };
  const i18n = languageRuntime('fr', testMessages);
  assert.equal(i18n.t('order', '$2', 'b$&', 9), '9 · $2 · b$& · $');
  assert.equal(i18n.t('englishOnly', 'label'), 'Default label');
  assert.equal(i18n.t('unknownKey'), '');
});

test('Russian numeral forms work for units, teens and compound counts', () => {
  const i18n = languageRuntime('ru');
  for (const [count, pixelForm, imageForm, linkForm] of [
    [1, 'gmailPixel', 'gmailImage', 'gmailLink'], [2, 'gmailPixelsFew', 'gmailImagesFew', 'gmailLinksFew'],
    [5, 'gmailPixelsMany', 'gmailImagesMany', 'gmailLinksMany'], [11, 'gmailPixelsMany', 'gmailImagesMany', 'gmailLinksMany'],
    [21, 'gmailPixel', 'gmailImage', 'gmailLink'], [22, 'gmailPixelsFew', 'gmailImagesFew', 'gmailLinksFew']
  ]) {
    assert.equal(i18n.pluralKey('gmailPixel', 'gmailPixels', count), pixelForm);
    assert.equal(i18n.pluralKey('gmailImage', 'gmailImages', count), imageForm);
    assert.equal(i18n.pluralKey('gmailLink', 'gmailLinks', count), linkForm);
  }
  assert.equal(i18n.t(i18n.pluralKey('gmailExternalImage', 'gmailExternalImages', 22)), 'внешних изображения');
  assert.match(i18n.t(i18n.pluralKey(null, 'gmailUnavailableImages', 21), 21), /21/);
  i18n.use('zh-CN');
  for (const count of [1, 2, 11, 22]) {
    assert.equal(i18n.t(i18n.pluralKey('gmailImage', 'gmailImages', count)), '张可疑图片');
  }
  assert.equal(i18n.t('gmailImage'), '可疑图片');
});

test('every catalog covers the base messages and preserves their named placeholders', () => {
  const base = catalogs['en-US'];
  for (const [language, catalog] of Object.entries(catalogs)) {
    for (const key of Object.keys(base)) assert.ok(Object.hasOwn(catalog, key), language + ': ' + key);
    for (const [key, entry] of Object.entries(catalog)) {
      const reference = base[key] || base[key.replace(/(?:Few|Many)$/, '')];
      assert.ok(reference && entry.message.trim(), language + ': ' + key);
      const metadata = entry.placeholders || {};
      assert.deepEqual(metadata, reference.placeholders || {}, language + ': ' + key);
      const used = [...entry.message.matchAll(/\$(\w+)\$/g)].map(match => match[1].toLowerCase());
      assert.deepEqual([...new Set(used)].sort(), Object.keys(metadata).sort(), language + ': ' + key);
    }
  }
});
