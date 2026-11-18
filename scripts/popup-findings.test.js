const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Keep the scanner and popup on their normal entry points. Only the DOM and the
// Thunderbird messaging boundary are simulated.
async function renderFindings(locale, findings) {
  const catalog = JSON.parse(fs.readFileSync(`_locales/${locale}/messages.json`, 'utf8'));
  const getMessage = (key, args = []) => catalog[key].message.replace(/\$([A-Z]+)\$/g, (_, name) => {
    const slot = catalog[key].placeholders[name.toLowerCase()].content.slice(1);
    return args[Number(slot) - 1];
  });
  const elements = new Map();
  function element() {
    return {
      children: [],
      setAttribute() {},
      addEventListener() {},
      appendChild(child) { this.children.push(child); }
    };
  }
  function getElementById(id) {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  }
  const document = {
    documentElement: {}, createElement: element, getElementById,
    querySelector: getElementById, querySelectorAll: () => []
  };
  const browser = {
    i18n: { getMessage: key => `native fallback for ${key}`, getUILanguage: () => 'en-US' },
    storage: { local: { get: async () => ({ uiLanguage: locale }) }, onChanged: { addListener() {} } },
    runtime: {
      getURL: path => path,
      sendMessage: async msg => msg.type === 'pg:getFindings' ? { findings } : {}
    }
  };
  const context = vm.createContext({ browser, document, URL, fetch: async path => {
    assert.equal(path, `_locales/${locale}/messages.json`);
    return { ok: true, json: async () => catalog };
  } });
  vm.runInContext(fs.readFileSync('i18n.js', 'utf8'), context);
  vm.runInContext(fs.readFileSync('popup/popup.js', 'utf8'), context);
  await new Promise(resolve => setImmediate(resolve));
  const descendants = node => [node, ...node.children.flatMap(descendants)];
  const nodes = descendants(getElementById('detailsSections'));
  return {
    texts: className => nodes.filter(node => node.className === className).map(node => node.textContent),
    chipLabels: ['pixels', 'images', 'links'].map(type =>
      elements.get(`[data-i18n="popup_label_${type}"]`).textContent),
    getMessage
  };
}

test('the popup localizes scanner reasons and levels and keeps URL data intact', async () => {
  const context = vm.createContext({ URL });
  vm.runInContext(fs.readFileSync('content/scanner.js', 'utf8'), context);
  const scanner = context.PixelGuardScanner;
  const image = scanner.classifyImage('https://img.example/p.png?uid=123', {}, {
    getAttribute: name => ({ width: '1', height: '1' })[name] || ''
  });
  const hidden = scanner.classifyImage('https://img.example/open.png', {}, {
    getAttribute: name => name === 'style' ? 'display: none' : ''
  });
  const link = scanner.classifyLink('https://click.example/redirect');
  const ordinary = scanner.classifyImage('https://img.example/logo.png');
  const findings = { suspicious: [image, hidden], externals: [ordinary], links: [link] };
  for (const locale of ['en', 'de', 'el', 'es', 'fr', 'it', 'ru', 'zh_CN']) {
    const { texts, getMessage } = await renderFindings(locale, findings);
    assert.deepEqual(texts('finding-reason'), [
      getMessage('reason_withRecipient', [getMessage('reason_onePixel')]),
      getMessage('reason_withOpenPath', [getMessage('reason_displayNone')]),
      getMessage('reason_visibleRemote'),
      getMessage('reason_linkRedirectHost')
    ]);
    assert.deepEqual(texts('confidence high'), Array(2).fill(getMessage('popup_confidence_high')));
    assert.deepEqual(texts('confidence medium'), [getMessage('popup_confidence_medium')]);
    assert.deepEqual(texts('confidence low'), [getMessage('popup_confidence_low')]);
    assert.deepEqual(texts('finding-url'), ['/p.png?uid=123', '/open.png', '/logo.png', '/redirect']);
  }
});

test('Russian count labels in the popup agree with the actual number of findings', async () => {
  const one = ['предупреждение', 'изображение', 'ссылка'];
  const few = ['предупреждения', 'изображения', 'ссылки'];
  const many = ['предупреждений', 'изображений', 'ссылок'];
  for (const [count, expected] of [[0,many], [1,one], [2,few], [5,many], [11,many], [14,many], [21,one], [22,few]]) {
    const items = Array.from({ length: count }, () => ({ host: 'example.invalid' }));
    const popup = await renderFindings('ru', { suspicious: items, externals: items, links: items });
    assert.deepEqual(popup.chipLabels, expected, String(count));
  }
});

test('unknown or absent reasons fall back to translated classifications or the empty label', async () => {
  const findings = {
    suspicious: [{ reason: 'new reason', classification: 'tracking-pixel' }],
    externals: [{ classification: 'external-image' }, { reason: '__proto__', classification: 'unknown' }],
    links: []
  };
  const { texts, getMessage } = await renderFindings('de', findings);
  assert.deepEqual(texts('finding-reason'), [
    getMessage('reason_trackingPixel'), getMessage('reason_externalImage'), getMessage('popup_noDetails')
  ]);
});
