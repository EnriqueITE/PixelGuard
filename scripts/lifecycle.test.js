const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
};
const load = (file, context) => vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });

function clock() {
  let now = 0, id = 0;
  const timers = new Map();
  return {
    setTimeout(fn, delay) { timers.set(++id, { fn, time: now + delay }); return id; },
    clearTimeout(key) { timers.delete(key); },
    async advance(duration) {
      const end = now + duration;
      for (let step = 0; step < 100; step++) {
        await flush();
        const next = [...timers].sort((a, b) => a[1].time - b[1].time)[0];
        if (!next || next[1].time > end) { now = end; return; }
        now = next[1].time;
        timers.delete(next[0]);
        next[1].fn();
      }
      throw new Error('Timer work did not settle');
    },
    timers
  };
}

function contentHarness() {
  const time = clock();
  let observer, queued = false, records = [], onContext, scans = 0;
  const messages = [];
  function changed(record) {
    if (!observer) return;
    records.push(record);
    if (!queued) {
      queued = true;
      queueMicrotask(() => { const batch = records; records = []; queued = false; observer(batch); });
    }
  }
  class Node {
    constructor(tag = '', text = null) {
      this.tagName = tag; this.nodeType = text === null ? 1 : 3;
      this.nodeValue = text; this.children = []; this.parentNode = null;
      this.attrs = {}; this.style = {}; this.events = {}; this.ownerDocument = doc;
    }
    get isConnected() { return this === doc.body || !!this.parentNode?.isConnected; }
    get firstChild() { return this.children[0] || null; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] || ''; }
    addEventListener(k, fn) { this.events[k] = fn; }
    set textContent(value) {
      this.children = [];
      if (value) this.appendChild(new Node('', String(value)));
    }
    appendChild(node) { return this.insertBefore(node, null); }
    insertBefore(node, before) {
      const index = before ? this.children.indexOf(before) : this.children.length;
      this.children.splice(index, 0, node); node.parentNode = this;
      if (this.isConnected) changed({ target: this, addedNodes: [node], removedNodes: [] });
      return node;
    }
    remove() {
      const parent = this.parentNode;
      if (!parent) return;
      parent.children.splice(parent.children.indexOf(this), 1); this.parentNode = null;
      if (parent.isConnected) changed({ target: parent, addedNodes: [], removedNodes: [this] });
    }
  }
  const all = node => [node, ...node.children.flatMap(all)];
  const doc = {
    addEventListener() {},
    createElement: tag => new Node(tag),
    createTextNode: text => new Node('', text),
    querySelectorAll(selector) {
      return all(doc.body).filter(n => selector === 'img' ? n.tagName === 'img' :
        selector === 'a[href]' ? n.tagName === 'a' && n.attrs.href :
        selector === '[style*="url("]' ? n.attrs.style?.includes('url(') : false);
    },
    createTreeWalker(root, mask, filter) {
      const nodes = [];
      function visit(node) {
        const selected = mask & (node.nodeType === 3 ? 4 : 1);
        const decision = selected ? (filter?.acceptNode(node) ?? 1) : 3;
        if (decision === 2) return;
        if (decision === 1) nodes.push(node);
        node.children.forEach(visit);
      }
      root.children.forEach(visit);
      return { currentNode: null, nextNode() { this.currentNode = nodes.shift(); return !!this.currentNode; } };
    }
  };
  doc.body = new Node('body');
  function image(url = 'https://vendor.invalid/p.gif?uid=recipient') {
    const node = new Node('img');
    Object.assign(node.attrs, { src: url, width: '1', height: '1' });
    doc.body.appendChild(node); return node;
  }
  image();
  const context = vm.createContext({
    URL, console, document: doc, window: { addEventListener() {} },
    ...time, NodeFilter: { SHOW_ELEMENT: 1, SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3 },
    MutationObserver: class { constructor(fn) { observer = fn; } observe() {} },
    browser: { i18n: { getMessage: key => key }, runtime: {
      sendMessage: async msg => { messages.push(msg); return msg.type === 'pg:hello' ? { ok: false } : {}; },
      onMessage: { addListener: fn => { onContext = fn; } }
    } }
  });
  load('content/scanner.js', context);
  const scan = context.PixelGuardScanner.scanDocument;
  context.PixelGuardScanner.scanDocument = (...args) => { scans++; return scan(...args); };
  load('content/scan.js', context);
  return { time, doc, image, messages, context: onContext, scans: () => scans,
    injectAgain: () => load('content/scan.js', context),
    banner: () => doc.body.children.find(n => n.className === 'pixelguard-banner'),
    nodes: () => all(doc.body), scanner: context.PixelGuardScanner };
}

test('static message settles; own banner URLs are not rescanned as links', async () => {
  const h = contentHarness();
  await h.time.advance(5000);
  assert.ok(h.scans() <= 3, `Unexpected rescans: ${h.scans()}`);
  assert.equal(h.time.timers.size, 0);
  assert.ok(h.banner());
  assert.equal(h.messages.filter(m => m.type === 'pg:detectedCount').length, 0);
  // One suspicious section only: the displayed pixel URL must not become a tracking-link section.
  assert.equal(h.nodes().filter(n => n.className === 'pixelguard-extwrap').length, 1);
  const first = h.banner();
  h.doc.body.appendChild(h.doc.createTextNode('ordinary message update'));
  await h.time.advance(500);
  assert.equal(h.banner(), first, 'Unchanged findings preserve expanded details');
});

test('dismissal survives mutations/repeated context, resets for another message', async () => {
  const h = contentHarness();
  h.context({ type: 'pg:context', domain: 'example.com', messageId: 1 });
  await h.time.advance(2500);
  h.nodes().find(n => n.className === 'pg-close').events.click();
  h.image('https://vendor.invalid/new.gif');
  h.context({ type: 'pg:context', domain: 'example.com', messageId: 1 });
  await h.time.advance(1000);
  assert.equal(h.banner(), undefined);
  h.context({ type: 'pg:context', domain: 'example.com', messageId: 2 });
  await h.time.advance(1000);
  assert.ok(h.banner());
  assert.equal(h.time.timers.size, 0);
});

test('message-authored banner class does not bypass detection; new content rescans', async () => {
  const h = contentHarness();
  await h.time.advance(2500);
  const before = h.scans();
  const lookalike = h.doc.createElement('div'); lookalike.className = 'pixelguard-banner';
  const image = h.doc.createElement('img');
  Object.assign(image.attrs, { src: 'https://vendor.invalid/second.gif', width: '1', height: '1' });
  lookalike.appendChild(image); h.doc.body.appendChild(lookalike);
  await h.time.advance(1000);
  assert.equal(h.scans(), before + 1);
  const counts = h.nodes().filter(n => n.className === 'pg-badge');
  assert.equal(counts[0].children[0].nodeValue, '2');
});

test('duplicate script injection does not create competing banners or observers', async () => {
  const h = contentHarness(); h.injectAgain();
  await h.time.advance(5000);
  assert.ok(h.scans() <= 3);
  assert.equal(h.doc.body.children.filter(n => n.className === 'pixelguard-banner').length, 1);
  assert.equal(h.time.timers.size, 0);
});

test('ordinary URL text remains detected outside the excluded banner', async () => {
  const h = contentHarness();
  h.doc.body.appendChild(h.doc.createTextNode('Visit https://click.vendor.invalid/path?uid=abc'));
  await h.time.advance(2500);
  assert.equal(h.nodes().filter(n => n.className === 'pixelguard-extwrap').length, 2);
});

function backgroundHarness(overrides = {}) {
  const time = clock(), writes = [], badges = [], contexts = [];
  let display, close, runtime, current = { id: 1, author: 'a@example.com' };
  const browser = {
    storage: { local: { get: overrides.getSettings || (async () => ({})), set: async v => {
      if (overrides.setSettings) await overrides.setSettings(v);
      writes.push(v);
    } } },
    runtime: { getBrowserInfo: async () => ({ version: '115' }), onInstalled: { addListener() {} },
      onMessage: { addListener: fn => { runtime = fn; } } },
    messageDisplayScripts: { register: async () => {} },
    browserAction: { setBadgeText: async d => {
      if (overrides.setBadge) await overrides.setBadge(d);
      badges.push(d);
    }, setBadgeBackgroundColor: async () => {} },
    tabs: { sendMessage: overrides.sendContext || (async (id, msg) => { contexts.push({ id, msg }); }),
      query: async () => [{ id: 7 }], onRemoved: { addListener: fn => { close = fn; } } },
    messageDisplay: { onMessageDisplayed: { addListener: fn => { display = fn; } },
      getDisplayedMessage: overrides.getDisplayed || (async () => current) },
    messages: { getFull: overrides.getFull || (async id => ({ contentType: 'text/html', body: String(id) })) }
  };
  const context = vm.createContext({ browser, console, structuredClone, ...time,
    PixelGuardScanner: { scanHtml: html => ({ suspicious: [{ url: `https://vendor.invalid/${html}` }], externals: [], links: [] }) } });
  load('background.js', context);
  return { time, writes, badges, contexts,
    show(id = 1, tabId = 7) { current = { id, author: `a@sender${id}.invalid` }; return display({ id: tabId }, current); },
    close: id => close(id),
    send: (msg, tabId = 7) => new Promise(resolve => runtime(msg, { tab: { id: tabId } }, resolve))
  };
}

test('background counts a pixel once across repeat events/manual rescans and scopes badges', async () => {
  const h = backgroundHarness();
  await h.show(); await h.show();
  assert.equal((await h.send({ type: 'pg:rescanNow' })).ok, true);
  await h.send({ type: 'pg:detectedCount', count: 99 }); // obsolete content-script message
  assert.equal((await h.send({ type: 'pg:getState' })).counters.totalDetected, 1);
  assert.equal(h.writes.length, 1);
  assert.ok(h.badges.every(b => b.tabId === 7));
  await h.show(2);
  assert.equal((await h.send({ type: 'pg:getState' })).counters.totalDetected, 2);
});

test('slow old scan cannot overwrite new findings or increment counters', async () => {
  const old = deferred();
  const h = backgroundHarness({ getFull: id => id === 1 ? old.promise : Promise.resolve({ contentType: 'text/html', body: 'new' }) });
  const first = h.show(1); await flush();
  await h.show(2);
  old.resolve({ contentType: 'text/html', body: 'old' }); await first;
  const result = await h.send({ type: 'pg:getFindings', tabId: 7 });
  assert.equal(result.findings.suspicious[0].url, 'https://vendor.invalid/new');
  assert.equal(result.domain, 'sender2.invalid');
  assert.equal((await h.send({ type: 'pg:getState' })).counters.totalDetected, 1);
});

test('closing tab removes findings and cancels pending reads and context retries', async () => {
  const pending = deferred();
  let requests = 0;
  const h = backgroundHarness({ getFull: () => pending.promise, sendContext: async () => { requests++; throw new Error('not ready'); } });
  const scan = h.show(); await flush(); h.close(7);
  pending.resolve({ contentType: 'text/html', body: 'closed' }); await scan;
  await h.time.advance(5000);
  const result = await h.send({ type: 'pg:getFindings', tabId: 7 });
  assert.equal(result.findings.suspicious.length, 0); assert.equal(result.domain, '');
  assert.equal(requests, 1); assert.equal(h.writes.length, 0);
  const loaded = backgroundHarness(); await loaded.show(); loaded.close(7);
  assert.equal((await loaded.send({ type: 'pg:getFindings', tabId: 7 })).findings.suspicious.length, 0);
});

test('close during initialization and manual lookup cannot resurrect tab state', async () => {
  const settings = deferred();
  const h = backgroundHarness({ getSettings: () => settings.promise });
  const scan = h.show(); h.close(7); settings.resolve({}); await scan;
  assert.equal(h.contexts.length, 0); assert.equal(h.writes.length, 0);
  assert.equal((await h.send({ type: 'pg:getFindings', tabId: 7 })).domain, '');
  const lookup = deferred();
  const manual = backgroundHarness({ getDisplayed: () => lookup.promise });
  await manual.show();
  const rescan = manual.send({ type: 'pg:rescanNow' }); await flush(); manual.close(7);
  lookup.resolve({ id: 1, author: 'a@example.com' });
  assert.equal((await rescan).ok, false);
  assert.equal((await manual.send({ type: 'pg:getFindings', tabId: 7 })).domain, '');
});

test('only newly discovered URLs increase the count within a message view', async () => {
  let body = 'first';
  const h = backgroundHarness({ getFull: async () => ({ contentType: 'text/html', body }) });
  await h.show(); body = 'second';
  await h.send({ type: 'pg:rescanNow' });
  await h.send({ type: 'pg:rescanNow' }); body = 'first';
  await h.send({ type: 'pg:rescanNow' });
  assert.equal((await h.send({ type: 'pg:getState' })).counters.totalDetected, 2);
  assert.equal(h.writes.length, 2);
});

test('settings writes keep snapshots in order across concurrent tabs', async () => {
  const pending = deferred(); let calls = 0;
  const h = backgroundHarness({ setSettings: () => ++calls === 1 ? pending.promise : Promise.resolve() });
  const first = h.show(1, 7); await flush();
  const second = h.show(2, 8); await flush();
  assert.equal(calls, 1, 'Second persistence waits for the first');
  pending.resolve(); await Promise.all([first, second]);
  assert.deepEqual(h.writes.map(w => w.settings.counters.totalDetected), [1, 2]);
});

test('delayed badge from an older scan is followed by the current badge', async () => {
  const pending = deferred(); let calls = 0;
  const h = backgroundHarness({ setBadge: () => ++calls === 2 ? pending.promise : Promise.resolve() });
  const first = h.show(1); await flush();
  const second = h.show(2); await flush();
  assert.equal(calls, 2);
  pending.resolve(); await Promise.all([first, second]);
  assert.equal(h.badges.at(-1).text, '100');
  assert.equal((await h.send({ type: 'pg:getFindings', tabId: 7 })).domain, 'sender2.invalid');
  assert.ok(h.badges.every(b => b.tabId === 7));
});

test('context rejection after close cannot schedule another retry', async () => {
  const pending = deferred(); let sends = 0;
  const h = backgroundHarness({ sendContext: () => { sends++; return pending.promise; } });
  await h.show(); h.close(7);
  pending.reject(new Error('tab closed')); await flush(); await h.time.advance(5000);
  assert.equal(sends, 1); assert.equal(h.time.timers.size, 0);
});

test('manual scan works before any display event, but not after close during lookup', async () => {
  const h = backgroundHarness();
  assert.equal((await h.send({ type: 'pg:rescanNow' })).ok, true);
  assert.equal((await h.send({ type: 'pg:getFindings', tabId: 7 })).findings.suspicious.length, 1);
  const lookup = deferred();
  const closed = backgroundHarness({ getDisplayed: () => lookup.promise });
  const rescan = closed.send({ type: 'pg:rescanNow' }); await flush(); closed.close(7);
  lookup.resolve({ id: 1, author: 'a@example.com' });
  assert.equal((await rescan).ok, false);
  assert.equal(closed.writes.length, 0);
  assert.equal((await closed.send({ type: 'pg:getFindings', tabId: 7 })).domain, '');
});

test('failed counter persistence retries without double-counting or hiding badge', async () => {
  let attempts = 0;
  const h = backgroundHarness({ setSettings: async () => {
    if (++attempts === 1) throw new Error('temporary storage failure');
  } });
  assert.equal((await h.show()).ok, true);
  assert.equal(h.badges.at(-1).text, '100');
  assert.equal(h.writes.length, 0);
  assert.equal((await h.send({ type: 'pg:rescanNow' })).ok, true);
  assert.equal(h.writes.length, 1);
  assert.equal(h.writes[0].settings.counters.totalDetected, 1);
  await h.send({ type: 'pg:rescanNow' });
  assert.equal(attempts, 2);
  assert.equal((await h.send({ type: 'pg:getState' })).counters.totalDetected, 1);
});
