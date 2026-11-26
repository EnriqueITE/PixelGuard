// Install the extension into an isolated browser. Every Gmail response and VT lookup is local.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');

const bundle = path.resolve(process.argv[2] || path.join(__dirname, '../../dist/chrome-gmail'));
const gmail = 'https://mail.google.com/mail/u/0/';
const pixel = 'https://events.example.test/open.gif?uid=demo&token=a%2Fb%3D#mail';
const link = 'https://click.example.test/redirect?campaign=demo&part=2';
const anchor = '<a href="' + link.replace(/&/g, '&amp;') + '">Ticket</a>';
const body = '<!doctype html><main><article id="full" class="adn" data-legacy-message-id="abcd">' +
  '<div class="a3s"><img alt="Images blocked">' + anchor + '</div></article>' +
  '<article id="partial" class="adn"><div class="a3s"><img alt="Unknown image"></div></article></main>';
const raw = 'Content-Type: text/html; charset=utf-8\r\n\r\n<img width="1" height="1" src="' +
  pixel.replace(/&/g, '&amp;') + '">' + anchor;

async function main() {
  const ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium', executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, locale: 'en-US', ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--lang=en-US', '--enable-unsafe-extension-debugging', '--host-resolver-rules=MAP * ~NOTFOUND']
  });
  ctx.setDefaultTimeout(8000);
  try {
    const external = [];
    await ctx.route(/^https?:\/\//, route => {
      const url = new URL(route.request().url());
      if (url.origin + url.pathname === gmail) {
        if (!url.search && route.request().isNavigationRequest()) return route.fulfill({contentType: 'text/html', body});
        if (url.searchParams.get('view') === 'att') return route.fulfill({contentType: 'message/rfc822', body: raw});
      }
      external.push(url.href);
      return route.abort();
    });
    const mail = await ctx.newPage();
    await mail.goto(gmail + '#inbox/row-test');
    const browser = await ctx.browser().newBrowserCDPSession();
    await browser.send('Extensions.loadUnpacked', {path: bundle});
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
    const source = await worker.evaluate(async () => {
      const [tab] = await chrome.tabs.query({url: 'https://mail.google.com/*'});
      chrome.permissions.contains = async p => p.origins?.join() === 'https://www.virustotal.com/*';
      self.testQueries = [];
      self.fetch = async (input, options) => {
        const url = new URL(input);
        if (url.origin + url.pathname !== 'https://www.virustotal.com/api/v3/widget/url' ||
            options.method !== 'GET' || options.headers['x-apikey'] !== 'row-test-placeholder') {
          throw Error('Unexpected widget request');
        }
        self.testQueries.push(url.searchParams.get('query'));
        return Response.json({data: {detection_ratio: {detections: 0, total: 20},
          url: 'https://www.virustotal.com/ui/widget/html/row-test'}});
      };
      return tab.id;
    });
    const queries = () => worker.evaluate(() => self.testQueries);
    const reader = await ctx.newPage();
    await reader.goto(new URL('popup.html', worker.url()).href);
    await reader.locator('#panel-toggle:enabled').waitFor();
    await reader.evaluate(async () => {
      const saved = await chrome.runtime.sendMessage({type: 'pg:settings', apiKey: 'row-test-placeholder', vtEnabled: true});
      if (!saved?.vtEnabled) throw Error('Failed to enable the local VT stub');
    });
    await mail.bringToFront();
    await mail.evaluate(() => { location.hash = 'inbox/next-thread'; });
    await mail.waitForURL(gmail + '#inbox/next-thread');
    await mail.locator('#full li[data-category="tracking-pixel"]').waitFor({state: 'attached'});
    await mail.locator('#full summary').click();
    await mail.locator('#partial summary').click();
    const imageRow = mail.locator('#full li[data-category="tracking-pixel"]');
    const linkRow = mail.locator('#full li[data-category="tracking-link"]');
    const rowButton = row => row.getByRole('button', {name: 'VirusTotal', exact: true});
    assert.equal(await imageRow.locator('.pg-url').innerText(), pixel);
    assert.equal(await linkRow.locator('.pg-url').innerText(), link);
    for (const row of [imageRow, linkRow]) {
      assert.ok(await row.getByRole('button', {name: 'Copy URL'}).isVisible());
      assert.ok(await rowButton(row).isVisible());
    }
    assert.equal(await mail.locator('#partial li[data-category="unavailable-image"] button').count(), 0);
    assert.equal(await mail.locator('.a3s img[src]').count(), 0);
    await rowButton(imageRow).evaluate(button => button.click());
    const take = () => reader.evaluate(id => chrome.tabs.sendMessage(id, {type: 'pg:gmail:takeVtSelection'}, {frameId: 0}), source);
    assert.ok(!(await take())?.url, 'Synthetic page clicks must not hand off a selection');

    // Inspect the new extension view from a same-origin helper. Chromium toolbar popups
    // are not guaranteed to appear as regular Playwright tabs.
    await rowButton(imageRow).click();
    await reader.waitForFunction(expected => chrome.extension.getViews().some(view => view !== window &&
      view.document.querySelector('#lookup[open]') && view.document.querySelector('#url')?.value === expected), pixel,
      {polling: 100});
    const firstPopup = await reader.evaluate(() => {
      const view = chrome.extension.getViews().find(other => other !== window && other.document.querySelector('#lookup[open]'));
      const mode = view.location.hash ? 'separate window' : 'toolbar popup';
      view.close();
      return mode;
    });
    assert.ok(!(await take())?.url, 'The selection must be consumed just once');
    assert.deepEqual(await queries(), [], 'Opening the widget on a tracking pixel must not query VT');

    // Exercise the compatibility window even on browsers where openPopup is available.
    await worker.evaluate(() => { chrome.action.openPopup = async () => { throw Error('Toolbar unavailable in test'); }; });
    await mail.bringToFront();
    const [popup] = await Promise.all([ctx.waitForEvent('page'), rowButton(imageRow).click()]);
    await popup.waitForURL(new URL('popup.html#tab=' + source, worker.url()).href);
    await popup.waitForFunction(value => document.querySelector('#lookup').open && document.querySelector('#url').value === value, pixel);
    const address = popup.locator('#url');
    assert.equal(await address.getAttribute('title'), pixel);
    assert.deepEqual(await queries(), []);
    await popup.locator('#show-links').click();
    await popup.getByRole('option', {name: link, exact: true}).click();
    assert.equal(await address.inputValue(), link);
    await popup.locator('#query-domain').click();
    await popup.locator('#result-title').filter({hasText: '0 / 20'}).waitFor();
    assert.deepEqual(await queries(), ['click.example.test']);
    await popup.locator('#show-links').click();
    await popup.getByRole('option', {name: pixel, exact: true}).click();
    await popup.locator('#preview-url').click();
    assert.equal(await popup.locator('#exact-url').innerText(), pixel);
    await popup.locator('#cancel-url').click();
    assert.deepEqual(await queries(), ['click.example.test']);
    await popup.locator('#preview-url').click();
    await popup.locator('#confirm-url').click();
    await popup.locator('#result-title').filter({hasText: '0 / 20'}).waitFor();
    assert.deepEqual(await queries(), ['click.example.test', pixel]);
    assert.deepEqual(external, [], 'No sender or image URL was requested');
    console.log('PASS Gmail row to', firstPopup, 'and compatibility window, exact selection, manual domain and confirmed URL', ctx.browser().version());
  } finally {
    await ctx.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
