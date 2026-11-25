// Scan a synthetic Gmail original with the installed extension. Intercept every
// HTTP request in the browser context before it can reach a real server.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');

const bundle = path.resolve(__dirname, '../../dist/chrome-gmail');
const gmail = 'https://mail.google.com/mail/u/1/';
const firstId = '18b3e19bf9f5ab01';
const secondId = '18b3e19bf9f5ab02';
const delayedId = '18b3e19bf9f5ab03';
const nativeId = '18b3e19bf9f5ab04';
const threadIds = ['18b3e19bf9f5ab05', '18b3e19bf9f5ab06', '18b3e19bf9f5ab07'];
const pixel = 'https://mail.shop.app/_t/open/synthetic-test-image';
const click = 'https://mail.shop.app/_t/c/v3/UUE=';
const image = 'https://assets.example.test/product.png';
const visibleHtml = '<img alt="Product"><img style="display:none">' +
  '<a href="' + click + '">Go to cart</a>';
const shell = '<!doctype html><main role="main"><article hidden class="adn" data-legacy-message-id="' + firstId +
  '" data-message-id="#msg-f:' + BigInt('0x' + firstId) + '">' +
  '<div class="gE"><span class="gD" email="sender@example.test"></span>' +
  '<button id="message-options" aria-label="More message options" aria-haspopup="menu" ' +
  'aria-controls="message-menu" aria-expanded="false">More</button></div>' +
  '<div class="a3s">' + visibleHtml + '</div></article></main>' +
  '<div id="message-menu" role="menu" hidden>' +
  '<button role="menuitem" id="display-images">Display images below</button>' +
  '<a role="menuitem" id="show-original" target="_blank">Show original</a></div>';
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
const escaped = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const originalView = '<pre class="raw_message_text">' + escaped + '</pre>';

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
    const sourceViewRequests = [];
    const heldRoutes = new Map();
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
      if (url.pathname === '/mail/u/1/' && url.searchParams.get('view') === 'om') {
        if (request.isNavigationRequest()) return route.fulfill({contentType: 'text/html', body: originalView});
        const id = url.searchParams.get('permmsgid');
        sourceViewRequests.push({id, method: request.method()});
        if (id !== 'msg-f:' + BigInt('0x' + nativeId)) return route.fulfill({status: 503, body: 'Unavailable'});
        return route.fulfill({contentType: 'text/html', body: '<img src="' + image + '">' + originalView});
      }
      if (url.searchParams.get('view') === 'att') {
        const id = url.searchParams.get('th');
        originalRequests.push({path: url.pathname, params: Object.fromEntries(url.searchParams), method: request.method()});
        if (id === delayedId || threadIds.includes(id)) {
          heldRoutes.set(id, route);
          return;
        }
        if (id !== firstId) return route.fulfill({status: 503, body: 'Unavailable'});
        return route.fulfill({contentType: 'message/rfc822', body: raw});
      }
      return route.abort();
    });
    const page = await ctx.newPage();
    await page.goto(gmail + '#inbox/example-1');
    await page.evaluate(() => {
      const options = document.getElementById('message-options');
      const menu = document.getElementById('message-menu');
      options.addEventListener('click', () => {
        options.setAttribute('aria-expanded', 'true');
        menu.hidden = false;
        const id = document.querySelector('.adn').getAttribute('data-message-id').slice(1);
        document.getElementById('show-original').href = '?ik=test&view=om&permmsgid=' + id;
      });
      document.getElementById('display-images').addEventListener('click', () => {
        document.body.dataset.displayImagesClicked = 'true';
      });
    });
    const cdp = await ctx.browser().newBrowserCDPSession();
    await cdp.send('Extensions.loadUnpacked', {path: bundle});
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
    const tabId = await worker.evaluate(async () => (await chrome.tabs.query({active: true, lastFocusedWindow: true}))[0].id);
    const panel = page.locator('.pixelguard-gmail');
    const summary = panel.locator('summary');
    const popup = await ctx.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    const toggle = popup.locator('#panel-toggle');
    await toggle.uncheck();
    await page.bringToFront();
    assert.equal(originalRequests.length, 0, 'A collapsed message must not be fetched');
    await page.locator('.adn').evaluate(el => el.hidden = false);
    await waitForBadge(worker, tabId, '111', [229, 57, 53, 255]);
    assert.equal(await panel.count(), 0, 'The badge uses the original even with the panel hidden');
    await toggle.check();
    await popup.close();
    await page.bringToFront();
    await summary.click();
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
    assert.deepEqual(sourceViewRequests, [], 'Only use the second Gmail endpoint if the first is unavailable');
    assert.deepEqual(await page.locator('.a3s img').evaluateAll(imgs => imgs.map(i => i.getAttribute('src'))), [null, null]);
    assert.equal(await page.locator('.a3s iframe,.a3s script,.a3s style').count(), 0);

    await page.locator('.a3s').evaluate(el => el.append(' Updated by Gmail'));
    await page.waitForLoadState('networkidle');
    assert.equal(originalRequests.length, 1, 'Panel updates and Gmail mutations must not refetch a message');

    // A failed direct download can be recovered by reading Gmail's own original
    // view in the background. The browser must not navigate to or render that page.
    const nativeResponse = page.waitForResponse(res =>
      new URL(res.url()).searchParams.get('permmsgid') === 'msg-f:' + BigInt('0x' + nativeId));
    await page.locator('.adn').evaluate((el, id) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      el.querySelector('.a3s').textContent = 'No visible images or links';
    }, nativeId);
    await nativeResponse;
    await page.waitForFunction(() => document.querySelector('.pg-status')?.textContent.includes('1 possible tracking pixel'));
    assert.deepEqual(sourceViewRequests, [{id: 'msg-f:' + BigInt('0x' + nativeId), method: 'GET'}]);
    assert.equal(await page.locator('#message-options').getAttribute('aria-expanded'), 'false');
    assert.equal(new URL(page.url()).search, '');

    // Gmail can reuse the same DOM for a different message during a request.
    const delayedRequest = page.waitForRequest(req => new URL(req.url()).searchParams.get('th') === delayedId);
    await page.locator('.adn').evaluate((el, id) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      el.querySelector('.a3s').textContent = 'No visible images or links';
    }, delayedId);
    await delayedRequest;
    const pageCount = ctx.pages().length;
    await page.locator('.adn').evaluate((el, id) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      location.hash = 'inbox/example-2';
      el.querySelector('.a3s').innerHTML =
        '<img alt="Unloaded"><a href="https://click.example.test/redirect">Second link</a>';
    }, secondId);
    await page.waitForFunction(() => document.querySelector('.pg-status')?.textContent.includes('1 image without a URL'));
    await waitForBadge(worker, tabId, '001', [255, 152, 0, 255]);
    if (await panel.getAttribute('open') === null) await summary.click();
    const fallback = panel.getByRole('button', {name: 'Show original in Gmail', exact: true});
    await fallback.waitFor();
    await heldRoutes.get(delayedId).fulfill({contentType: 'message/rfc822', body: raw});
    await page.waitForLoadState('networkidle');
    assert.equal(ctx.pages().length, pageCount, 'An automatic failure must not open another tab');
    assert.equal(await page.locator('#message-options').getAttribute('aria-expanded'), 'false');
    assert.deepEqual(originalRequests.map(req => req.params.th), [firstId, nativeId, delayedId, secondId],
      'Each expanded message should be requested just once, including after failure');
    assert.deepEqual(sourceViewRequests.map(req => req.id), [nativeId, secondId].map(id => 'msg-f:' + BigInt('0x' + id)),
      'A replaced message must not fall back to the source view');
    assert.match(await summary.innerText(), /1 link with tracking indicators/);
    assert.match(await summary.innerText(), /partial scan/i);
    assert.equal(await panel.locator('li[data-category="tracking-pixel"]').count(), 0);

    const requestsBeforeOriginalPage = originalRequests.length;
    const [originalPage] = await Promise.all([page.waitForEvent('popup'), fallback.click()]);
    await originalPage.waitForURL(url => url.searchParams.get('view') === 'om');
    assert.equal(new URL(originalPage.url()).searchParams.get('permmsgid'), 'msg-f:' + BigInt('0x' + secondId));
    assert.equal(await page.locator('#message-options').getAttribute('aria-expanded'), 'true');
    assert.equal(await page.locator('body').getAttribute('data-display-images-clicked'), null);
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
    await originalPage.close();
    await page.bringToFront();

    // Three messages expand together; the third collapses while the first two
    // are still waiting for Gmail. Its queued download must never start.
    const firstTwo = threadIds.slice(0, 2);
    const firstTwoRequests = Promise.all(firstTwo.map(id =>
      page.waitForRequest(req => new URL(req.url()).searchParams.get('th') === id)));
    await page.locator('main').evaluate((main, ids) => {
      main.replaceChildren();
      for (const id of ids) {
        const article = document.createElement('article');
        article.dataset.legacyMessageId = id;
        article.innerHTML = '<div class="a3s">Open message</div>';
        main.append(article);
      }
    }, threadIds);
    await firstTwoRequests;
    await page.locator('article').last().evaluate(el => el.hidden = true);
    await page.locator('article').last().locator('.pixelguard-gmail').waitFor({state: 'detached'});
    await Promise.all(firstTwo.map(id => heldRoutes.get(id).fulfill({contentType: 'message/rfc822', body: raw})));
    await waitForBadge(worker, tabId, '222', [229, 57, 53, 255]);
    await page.waitForLoadState('networkidle');
    assert.deepEqual(originalRequests.slice(requestsBeforeOriginalPage).map(req => req.params.th).sort(), firstTwo);
    assert.deepEqual(external, [], 'The context must never request a sender, image or embedded resource URL');
    console.log('PASS automatic originals, hidden-panel badge, message switches, manual fallback and zero external requests', ctx.browser().version());
  } finally {
    await ctx.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
