// Run the packaged Gmail attachment flow with a synthetic mailbox and VirusTotal responses.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const path = require('node:path');
const {chromium} = require('playwright-core');

const bundle = path.resolve(process.argv[2] || path.join(__dirname, '../../dist/chrome-gmail'));
const gmail = 'https://mail.google.com/mail/u/0/';
const filename = 'agenda.bin';
const known = Buffer.from([0, 13, 10, 255, 128, 1]);
const unknown = Buffer.alloc(400_000);
for (let i = 0; i < unknown.length; i++) unknown[i] = i % 251;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function card(part, id) {
  const href = gmail + '?ui=2&amp;view=att&amp;th=abcd&amp;attid=' + part + '&amp;disp=inline';
  const downloadUrl = part === '0.1' ? gmail + href : href;
  return '<span class="aZo" id="' + id + '" download_url="application/octet-stream:' + filename + ':' + downloadUrl +
    '"><a class="aQy" href="' + href + '"><span class="aQA"><span class="aV3">' + filename +
    '</span></span></a><span class="aQw"></span></span>';
}
const shell = '<!doctype html><main><article class="adn" data-legacy-message-id="abcd">' +
  '<div class="a3s"><p>Hello</p>' + card('0.3', 'sender-content') + '</div><div class="aQH">' +
  card('0.1', 'known') + card('0.2', 'unknown') +
  card('0.1', 'other-message').replaceAll('th=abcd', 'th=aaaa') +
  card('0.1', 'other-account').replaceAll('/u/0/', '/u/1/') +
  card('0.1', 'mixed-accounts').replace(gmail + gmail, gmail + gmail.replace('/u/0/', '/u/1/')) +
  '<span class="aZo"><a class="aQy" href="https://drive.google.com/open?id=test"><span class="aV3">Drive</span></a></span>' +
  '</div></article></main>';
const original = 'Content-Type: multipart/mixed; boundary="mail"\r\n\r\n--mail\r\n' +
  'Content-Type: text/html; charset=UTF-8\r\n\r\n<p>Hello</p>\r\n' +
  [known, unknown].map(file => '--mail\r\nContent-Type: application/octet-stream\r\n' +
    'Content-Disposition: attachment; filename="' + filename + '"\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' + file.toString('base64') + '\r\n').join('') + '--mail--\r\n';

async function main() {
  const ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium', executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, locale: 'en-US', ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--lang=en-US', '--enable-unsafe-extension-debugging', '--host-resolver-rules=MAP * ~NOTFOUND']
  });
  ctx.setDefaultTimeout(10000);
  try {
    const downloads = [], external = [];
    let sourceReads = 0;
    await ctx.route(/^https?:\/\//, route => {
      const url = new URL(route.request().url());
      if (url.origin + url.pathname === gmail) {
        if (route.request().isNavigationRequest() && !url.search) return route.fulfill({contentType: 'text/html', body: shell});
        if (url.searchParams.get('view') === 'att') {
          const part = url.searchParams.get('attid');
          if (part === '0') return route.fulfill({status: 404, body: ''});
          if (['0.1', '0.2'].includes(part)) {
            downloads.push(part);
            if (part === '0.2') return route.fulfill({status: 302, headers: {location: 'https://blocked.invalid/attachment'}});
            return route.fulfill({headers: {'content-type': 'application/octet-stream',
              'content-disposition': 'attachment; filename="' + filename + '"'}, body: known});
          }
        }
        if (url.searchParams.get('view') === 'om') {
          sourceReads++;
          const escaped = original.replaceAll('&', '&amp;').replaceAll('<', '&lt;');
          return route.fulfill({contentType: 'text/html', body: '<pre class="raw_message_text">' + escaped + '</pre>'});
        }
      }
      external.push(url.href);
      return route.abort();
    });
    const mail = await ctx.newPage();
    await mail.goto(gmail + '#inbox/test');
    const browser = await ctx.browser().newBrowserCDPSession();
    await browser.send('Extensions.loadUnpacked', {path: bundle});
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
    await worker.evaluate(knownHash => {
      chrome.permissions.contains = async p => p.origins?.join() === 'https://www.virustotal.com/*';
      const localFetch = self.fetch.bind(self);
      self.requests = [];
      self.fetch = async (input, options = {}) => {
        const url = new URL(input instanceof Request ? input.url : input);
        if (url.protocol === 'blob:') return localFetch(input, options);
        if (url.origin !== 'https://www.virustotal.com' || url.search ||
            !/^\/api\/v3\/files(?:\/[a-f0-9]{64})?$/.test(url.pathname)) throw Error('Unexpected remote request');
        const method = options.method || 'GET';
        const entry = {method, path: url.pathname};
        self.requests.push(entry);
        if (method === 'GET') {
          if (url.pathname === '/api/v3/files/' + knownHash) {
            return Response.json({data: {type: 'file', id: knownHash, attributes: {sha256: knownHash,
              last_analysis_stats: {malicious: 1, suspicious: 0, harmless: 2, undetected: 7}}}});
          }
          return Response.json({error: {code: 'NotFoundError', message: 'No report'}}, {status: 404});
        }
        const file = options.body.get('file');
        entry.name = file.name;
        entry.size = file.size;
        const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
        entry.hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
        return Response.json({data: {type: 'analysis', id: 'fixture-analysis-1'}});
      };
    }, hash(known));
    const requests = () => worker.evaluate(() => self.requests);
    const config = await ctx.newPage();
    await config.goto(new URL('popup.html', worker.url()).href);
    await config.locator('#panel-toggle:enabled').waitFor();
    const enabled = await config.evaluate(() => chrome.runtime.sendMessage({
      type: 'pg:settings', apiKey: 'attachment-fixture-only', vtEnabled: true
    }));
    assert.equal(enabled.vtEnabled, true);
    await mail.bringToFront();
    await mail.evaluate(() => { location.hash = 'inbox/thread'; });
    const buttons = mail.locator('.aQH button').filter({hasText: 'VirusTotal'});
    await buttons.nth(1).waitFor();
    assert.equal(await buttons.count(), 2);
    assert.equal(await mail.locator('#sender-content button').count(), 0);
    const [knownId, unknownId] = await config.evaluate(async () => {
      const [source] = await chrome.tabs.query({url: 'https://mail.google.com/*'});
      const inventory = await chrome.tabs.sendMessage(source.id, {type: 'pg:gmail:attachments'}, {frameId: 0});
      return inventory.attachments.map(item => item.id);
    });
    assert.notEqual(knownId, unknownId, 'The two cards have distinct IDs despite sharing a filename');
    assert.deepEqual(downloads, []);
    assert.deepEqual(await requests(), []);
    await buttons.first().click();
    // Chrome's toolbar widget may not be enumerated as a normal browser tab.
    await config.waitForFunction(id => chrome.extension.getViews({type: 'popup'}).some(view => {
      const doc = view.document;
      return doc.getElementById('attachments')?.value === id && !doc.getElementById('query-hash').disabled &&
        doc.getElementById('attachment-digest').hidden && doc.getElementById('result').hidden;
    }), knownId);
    assert.deepEqual(downloads, [], 'Clicking the Gmail card only selects its attachment');
    assert.deepEqual(await requests(), [], 'The native popup waits for the hash lookup button');
    await config.evaluate(() => chrome.extension.getViews({type: 'popup'})[0].document.getElementById('query-hash').click());
    await config.waitForFunction(expected => chrome.extension.getViews().some(view => {
      const result = view.document.getElementById('result');
      if (view === window || !result || result.hidden || view.document.getElementById('attachment-sha')?.textContent !== expected) return false;
      const bounds = result.getBoundingClientRect();
      return view.document.getElementById('upload-confirmation').hidden && bounds.top >= 0 && bounds.bottom <= view.innerHeight;
    }), hash(known));
    assert.deepEqual(await requests(), [{method: 'GET', path: '/api/v3/files/' + hash(known)}]);
    assert.ok(!downloads.includes('0.2'), 'Reading the first card must not download the second attachment');
    await config.evaluate(() => chrome.extension.getViews().find(view => view !== window && view.document.getElementById('result')).close());
    await config.waitForFunction(() => !chrome.extension.getViews({type: 'popup'}).length);
    await mail.bringToFront();
    // Opening the toolbar normally shows both selectors without retaining the last card.
    await worker.evaluate(() => chrome.action.openPopup());
    await config.waitForFunction(label => chrome.extension.getViews({type: 'popup'}).some(view => {
      const doc = view.document;
      const picker = doc.getElementById('attachments');
      return doc.getElementById('url')?.getClientRects().length && picker?.getClientRects().length &&
        !picker.disabled && picker.value === '' &&
        Array.from(picker.options).filter(option => option.textContent.startsWith(label)).length === 2;
    }), filename);
    assert.deepEqual(downloads, ['0.1']);
    assert.equal((await requests()).length, 1);
    await config.evaluate(() => chrome.extension.getViews({type: 'popup'})[0].close());
    await worker.evaluate(() => { chrome.action.openPopup = async () => { throw Error('Use the compatibility window in this test'); }; });
    await mail.bringToFront();
    const beforeFallback = sourceReads;
    const [popup] = await Promise.all([ctx.waitForEvent('page'), buttons.nth(1).click()]);
    const select = popup.locator('#attachments');
    await popup.waitForFunction(id => document.querySelectorAll('#attachments option').length === 3 &&
      document.getElementById('attachments').value === id && !document.getElementById('query-hash').disabled, unknownId);
    const ids = await select.locator('option').evaluateAll(opts => opts.map(o => o.value).filter(Boolean));
    assert.deepEqual(ids, [knownId, unknownId]);
    assert.deepEqual(downloads, ['0.1'], 'Opening the second card does not download its attachment');
    assert.deepEqual(await requests(), [{method: 'GET', path: '/api/v3/files/' + hash(known)}]);
    assert.equal(await popup.locator('#upload-confirmation').isVisible(), false);
    await popup.locator('#query-hash').click();
    await popup.locator('#confirm-upload').waitFor();
    assert.ok(sourceReads > beforeFallback, 'The selected attachment is recovered from the original when its download redirects');
    assert.equal(await popup.locator('#attachment-sha').textContent(), hash(unknown));
    assert.ok((await popup.locator('#upload-confirmation').innerText()).includes(filename));
    await popup.locator('#cancel-upload').click();
    const selected = await select.inputValue();
    await select.selectOption(ids.find(id => id !== selected));
    await select.selectOption(selected);
    assert.deepEqual((await requests()).map(r => r.method), ['GET', 'GET']);
    await popup.locator('#query-hash').click();
    await popup.locator('#confirm-upload').click();
    await popup.waitForFunction(() => !document.getElementById('result').hidden &&
      document.getElementById('result-title').textContent === chrome.i18n.getMessage('pgFileSubmitted'));
    assert.equal(await popup.locator('#report').getAttribute('href'), 'https://www.virustotal.com/gui/file/' + hash(unknown));
    const log = await requests();
    assert.deepEqual(log.map(r => r.method), ['GET', 'GET', 'GET', 'POST']);
    assert.deepEqual(log.at(-1), {method: 'POST', path: '/api/v3/files', name: filename, size: unknown.length, hash: hash(unknown)});
    await mail.bringToFront();
    const downloadCount = downloads.length;
    const cardOnly = body => '<article class="adn" data-legacy-message-id="abcd">' + body + '</article>';
    const emptyMessage = cardOnly('<div class="a3s" hidden></div><div class="aQH">' + card('0.1', 'only-file') + '</div>');
    const collapsed = '<div class="kv">' + cardOnly('<div class="aQH">' + card('0.1', 'collapsed') + '</div>') + '</div>';
    const draft = cardOnly('<div class="M9"><div contenteditable="true"></div><div class="aQH">' +
      card('0.1', 'draft') + '</div></div>');
    await mail.evaluate(markup => { document.querySelector('main').innerHTML = markup; }, emptyMessage + collapsed + draft);
    await mail.locator('#only-file button').waitFor();
    assert.equal(await mail.locator('.pixelguard-attachment-action').count(), 1);
    assert.equal(downloads.length, downloadCount);
    assert.deepEqual(external, [], 'Nothing should contact sender resources');
    console.log('PASS Gmail attachments: duplicate names, correct bytes, known/missing report, cancel and one confirmed upload', ctx.browser().version());
  } finally { await ctx.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
