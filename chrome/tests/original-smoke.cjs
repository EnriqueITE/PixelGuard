// Scan a synthetic Gmail original with the installed extension. Intercept every
// HTTP request in the browser context before it can reach a real server.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');

const bundle = path.resolve(__dirname, '../../dist/chrome-gmail');
const gmail = 'https://mail.google.com/mail/u/1/';
const firstId = '18b3e19bf9f5ab01';
const secondId = '18b3e19bf9f5ab02';
const pixel = 'https://mail.shop.app/_t/open/synthetic-test-image';
const click = 'https://mail.shop.app/_t/c/v3/UUE=';
const image = 'https://assets.example.test/product.png';
const visibleHtml = '<img alt="Product"><img style="display:none">' +
  '<a href="' + click + '">Go to cart</a>';
const shell = '<!doctype html><main role="main"><article class="adn" data-legacy-message-id="' + firstId +
  '" data-message-id="#msg-f:' + BigInt('0x' + firstId) + '">' +
  '<span class="gD" email="sender@example.test"></span><div class="a3s">' + visibleHtml + '</div></article></main>';
const sourceHtml = [
  '<html><head>',
  '<link rel="stylesheet" href="https://assets.example.test/mail.css">',
  '<style>@import url(https://assets.example.test/more.css);</style>',
  '</head><body>',
  '<img src="' + pixel + '" style="display:none">',
  '<img src="' + image + '" srcset="' + image + ' 1x" width="180" height="50" alt="Product">',
  '<div style="background-image:url(' + image + ')"></div>',
  '<a href="' + click + '">Go to cart</a>',
  '<iframe src="https://assets.example.test/frame"></iframe>',
  '<script src="https://assets.example.test/mail.js"></script>',
  '</body></html>'
].join('\r\n');
const raw = [
  'From: Fixture <sender@example.test>', 'To: QA <test@example.test>', 'Subject: Example cart',
  'MIME-Version: 1.0', 'Content-Type: text/html; charset=UTF-8',
  'Content-Transfer-Encoding: quoted-printable', '', sourceHtml.replace(/=/g, '=3D')
].join('\r\n');

async function waitForBadge(worker, tabId, text, color) {
  const observed = await worker.evaluate(async ({tabId, text, color}) => {
    const until = Date.now() + 5000;
    let state;
    do {
      const actual = await chrome.action.getBadgeText({tabId});
      const rgba = await chrome.action.getBadgeBackgroundColor({tabId});
      state = [actual, rgba];
      if (actual === text && rgba.join() === color.join()) return state;
      await new Promise(resolve => setTimeout(resolve, 30));
    } while (Date.now() < until);
    return state;
  }, {tabId, text, color});
  assert.deepEqual(observed, [text, color]);
}

async function main() {
  const ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium', executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, locale: 'en-US', ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--lang=en-US', '--enable-unsafe-extension-debugging', '--host-resolver-rules=MAP * ~NOTFOUND']
  });
  try {
    const originalRequests = [];
    const external = [];
    const thirdParty = url => /^https?:/.test(url) && new URL(url).origin !== new URL(gmail).origin;
    ctx.on('request', req => { if (thirdParty(req.url())) external.push(req.url()); });
    await ctx.route(/^https?:\/\//, async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (thirdParty(url.href)) {
        external.push(url.href);
        return route.abort();
      }
      if (url.pathname === '/mail/u/1/' && !url.search && request.isNavigationRequest()) {
        return route.fulfill({contentType: 'text/html', body: shell});
      }
      if (url.pathname === '/mail/u/1/' && url.searchParams.get('view') === 'om' && request.isNavigationRequest()) {
        const escaped = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return route.fulfill({contentType: 'text/html', body: '<pre class="raw_message_text">' + escaped + '</pre>'});
      }
      if (url.searchParams.get('view') === 'att') {
        const id = url.searchParams.get('th');
        originalRequests.push({path: url.pathname, params: Object.fromEntries(url.searchParams), method: request.method()});
        if (id !== firstId) return route.fulfill({status: 503, body: 'Unavailable'});
        return route.fulfill({contentType: 'message/rfc822', body: raw});
      }
      return route.abort();
    });
    const page = await ctx.newPage();
    await page.goto(gmail + '#inbox/example-1');
    const cdp = await ctx.browser().newBrowserCDPSession();
    await cdp.send('Extensions.loadUnpacked', {path: bundle});
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
    const tabId = await worker.evaluate(async () => (await chrome.tabs.query({active: true, lastFocusedWindow: true}))[0].id);
    const panel = page.locator('.pixelguard-gmail');
    const summary = panel.locator('summary');
    const analyze = panel.getByRole('button', {name: 'Analyze original', exact: true});
    await summary.click();
    await analyze.waitFor();
    assert.equal(originalRequests.length, 0);
    assert.match(await summary.innerText(), /2 images without a URL/);
    await analyze.click();
    const pixelRow = panel.locator('li[data-category="tracking-pixel"]');
    await pixelRow.waitFor();
    assert.equal(await pixelRow.locator('.pg-url').innerText(), pixel);
    await panel.getByText('Original analyzed', {exact: true}).waitFor();
    assert.match(await summary.innerText(), /1 possible tracking pixel/);
    assert.match(await summary.innerText(), /1 link with tracking indicators/);
    assert.doesNotMatch(await summary.innerText(), /images without a URL|partial scan/i);
    await waitForBadge(worker, tabId, '111', [229, 57, 53, 255]);
    assert.deepEqual(originalRequests, [{path: '/mail/u/1',
      params: {view: 'att', th: firstId, attid: '0', disp: 'comp', safe: '1', zw: ''}, method: 'GET'}]);
    assert.deepEqual(await page.locator('.a3s img').evaluateAll(imgs => imgs.map(i => i.getAttribute('src'))), [null, null]);
    assert.equal(await page.locator('.a3s iframe,.a3s script,.a3s style').count(), 0);

    // Gmail may reuse DOM nodes while the user switches messages.
    await page.locator('.adn').evaluate((el, id) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      location.hash = 'inbox/example-2';
      el.querySelector('.a3s').innerHTML =
        '<img alt="Unloaded"><a href="https://click.example.test/redirect">Second link</a>';
    }, secondId);
    await page.waitForFunction(() => document.querySelector('.pg-status')?.textContent.includes('1 image without a URL'));
    await waitForBadge(worker, tabId, '001', [255, 152, 0, 255]);
    if (!(await analyze.isVisible())) await summary.click();
    await analyze.click();
    await analyze.waitFor({state: 'visible'});
    await page.waitForLoadState('networkidle');
    assert.equal(originalRequests.at(-1)?.params.th, secondId);
    assert.match(await summary.innerText(), /1 link with tracking indicators/);
    assert.match(await summary.innerText(), /partial scan/i);
    assert.equal(await panel.locator('li[data-category="tracking-pixel"]').count(), 0);

    const requestsBeforeOriginalPage = originalRequests.length;
    const originalPage = await ctx.newPage();
    await originalPage.goto(gmail + '?ik=test&view=om&permmsgid=msg-f:' + BigInt('0x' + firstId));
    const sourcePanel = originalPage.locator('.pixelguard-gmail');
    const sourceSummary = sourcePanel.locator('summary');
    await sourceSummary.waitFor();
    if (await sourcePanel.getAttribute('open') === null) await sourceSummary.click();
    await sourcePanel.getByText('Original analyzed', {exact: true}).waitFor();
    assert.equal(await sourcePanel.locator('li[data-category="tracking-pixel"] .pg-url').innerText(), pixel);
    const sourceTabId = await worker.evaluate(async () =>
      (await chrome.tabs.query({url: 'https://mail.google.com/mail/u/1/*'})).find(t => t.url.includes('view=om')).id);
    await waitForBadge(worker, sourceTabId, '111', [229, 57, 53, 255]);
    await originalPage.waitForLoadState('networkidle');
    assert.equal(originalRequests.length, requestsBeforeOriginalPage, 'Use the original already displayed on this page');
    assert.deepEqual(external, [], 'The context must never request a sender, image or embedded resource URL');
    console.log('PASS original pixel, tab badge, failed fetch, Show original and zero external requests', ctx.browser().version());
  } finally {
    await ctx.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
