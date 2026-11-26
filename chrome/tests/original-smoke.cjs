// Scan a synthetic Gmail original with the installed extension. Intercept every
// HTTP request in the browser context before it can reach a real server.
const assert = require('node:assert/strict');
const { EventEmitter, once } = require('node:events');
const path = require('node:path');
const { chromium } = require('playwright-core');

const bundle = path.resolve(__dirname, '../../dist/chrome-gmail');
const gmail = 'https://mail.google.com/mail/u/1/';
const firstId = '18b3e19bf9f5ab01';
const secondId = '18b3e19bf9f5ab02';
const delayedId = '18b3e19bf9f5ab03';
const nativeId = '18b3e19bf9f5ab04';
const threadIds = ['18b3e19bf9f5ab05', '18b3e19bf9f5ab06', '18b3e19bf9f5ab07'];
const unavailableId = '18b3e19bf9f5ab08';
const hintedId = '18b3e19bf9f5ab09';
const hintedKey = 'msg-f:' + BigInt('0x' + hintedId);
const syntheticHint = 'a012345678';
const pixel = 'https://mail.shop.app/_t/open/synthetic-test-image';
const click = 'https://mail.shop.app/_t/c/v3/UUE=';
const image = 'https://assets.example.test/product.png';
const visibleHtml = '<img alt="Product"><img style="display:none">' +
  '<a href="' + click + '">Go to cart</a>';
const shell = '<!doctype html><main role="main"><article hidden class="adn" data-legacy-message-id="' + firstId +
  '" data-message-id="#msg-f:' + BigInt('0x' + firstId) + '">' +
  '<div class="gE"><span class="gD" email="sender@example.test"></span>' +
  '<button id="message-options" aria-label="More message options" aria-haspopup="menu" ' +
  'aria-expanded="false">More</button></div>' +
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
    const sourceRequests = [];
    const requestsFor = id => sourceRequests.filter(request => request.id === id);
    const heldRoutes = new EventEmitter();
    // Wait for the intercept handler itself; Chromium emits the request event
    // before Playwright gives this test the route that can supply the reply.
    const nextRoute = id => once(heldRoutes, id, {signal: AbortSignal.timeout(10000)})
      .then(([route]) => route);
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
      const view = url.searchParams.get('view');
      if (url.pathname !== '/mail/u/1/' || !['om', 'att'].includes(view)) return route.abort();
      if (view === 'om' && request.isNavigationRequest()) {
        return route.fulfill({contentType: 'text/html', body: originalView});
      }
      assert.equal(request.isNavigationRequest(), false);
      assert.equal(request.method(), 'GET');
      const permanent = url.searchParams.get('permmsgid')?.match(/^msg-f:(\d+)$/);
      const id = permanent ? BigInt(permanent[1]).toString(16) : url.searchParams.get('th');
      sourceRequests.push({id, url: url.href});
      if (view === 'att') {
        if (heldRoutes.emit(id, route)) return;
        if (id !== firstId) return route.fulfill({status: 503, body: 'Unavailable'});
        return route.fulfill({contentType: 'message/rfc822', body: raw});
      }
      const hintedView = id === hintedId && url.searchParams.get('ik') === syntheticHint;
      if (id !== nativeId && !hintedView) return route.fulfill({status: 503, body: 'Unavailable'});
      return route.fulfill({contentType: 'text/html', body: '<img src="' + image + '">' + originalView});
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
    const summary = panel.locator('.pg-summary');
    const partialInfo = panel.getByRole('button', {name: 'About this partial scan', exact: true});
    const popup = await ctx.newPage();
    await popup.goto(new URL('popup.html', worker.url()).href);
    const toggle = popup.locator('#panel-toggle');
    await toggle.uncheck();
    await page.bringToFront();
    assert.equal(sourceRequests.length, 0, 'A collapsed message must not be fetched');
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
    assert.match(await summary.innerText(), /1 possible tracking pixel/);
    assert.match(await summary.innerText(), /1 link with tracking indicators/);
    assert.doesNotMatch(await summary.innerText(), /images without a URL|partial scan/i);
    assert.equal(await partialInfo.count(), 0, 'A complete original has no partial-scan help');
    await waitForBadge(worker, tabId, '111', [229, 57, 53, 255]);
    assert.equal(requestsFor(firstId).length, 1, 'A successful download needs no additional source request');
    assert.deepEqual(await page.locator('.a3s img').evaluateAll(imgs => imgs.map(i => i.getAttribute('src'))), [null, null]);
    assert.equal(await page.locator('.a3s iframe,.a3s script,.a3s style').count(), 0);

    await page.locator('.a3s').evaluate(el => el.append(' Updated by Gmail'));
    await page.waitForLoadState('networkidle');
    assert.equal(sourceRequests.length, 1, 'Panel updates and Gmail mutations must not refetch a message');

    // A failed direct download can be recovered by reading Gmail's own original
    // view in the background. The browser must not navigate to or render that page.
    const nativeResponse = page.waitForResponse(res => {
      const params = new URL(res.url()).searchParams;
      return params.get('view') === 'om' && params.get('permmsgid') === 'msg-f:' + BigInt('0x' + nativeId);
    });
    await page.locator('.adn').evaluate((el, id) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      el.querySelector('.a3s').textContent = 'No visible images or links';
    }, nativeId);
    await nativeResponse;
    await page.waitForFunction(() => document.querySelector('.pg-status')?.textContent.includes('1 possible tracking pixel'));
    assert.equal(await page.locator('#message-options').getAttribute('aria-expanded'), 'false');
    assert.equal(new URL(page.url()).search, '');

    // Hold the original so the visible message contains genuine preliminary
    // findings while we inspect the non-interactive scanning state.
    const delayedRequest = nextRoute(delayedId);
    await page.locator('.adn').evaluate((el, {id, html}) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      el.querySelector('.a3s').innerHTML = html;
    }, {id: delayedId, html: visibleHtml});
    const delayedRoute = await delayedRequest;
    const running = summary.getByText('Analyzing the message', {exact: true});
    const results = panel.locator('.pg-results');
    const sweep = () => summary.evaluate(el => getComputedStyle(el, '::after').animationName);
    await running.waitFor();
    assert.equal(await panel.getAttribute('open'), null);
    assert.equal(await summary.evaluate(el => el.matches('summary, [role="button"]')), false);
    assert.equal(await summary.locator('.pg-chevron:visible').count(), 0);
    assert.equal(await partialInfo.count(), 0, 'The scanning indicator has no partial-scan help');
    assert.notEqual(await panel.getAttribute('data-scanning'), null);
    assert.equal(await results.getAttribute('aria-busy'), 'true');
    assert.doesNotMatch(await summary.innerText(), /tracking indicators|partial scan|no tracking/i);
    assert.notEqual(await sweep(), 'none');
    await waitForBadge(worker, tabId, '…', [73, 97, 106, 255]);
    await page.emulateMedia({reducedMotion: 'reduce'});
    assert.equal(await sweep(), 'none');
    assert.equal(await running.isVisible(), true);
    await summary.click();
    assert.equal(await panel.getAttribute('open'), null, 'A click does not expand the scanning bar');
    assert.equal(await panel.locator('.pg-list li:visible, .pg-filter:visible, .pg-pager:visible').count(), 0,
      'The scanning bar must not reveal provisional results');
    await page.emulateMedia({reducedMotion: 'no-preference'});

    // Gmail can reuse the same DOM for a different message during a request.
    const pageCount = ctx.pages().length;
    await page.locator('.adn').evaluate((el, id) => {
      el.setAttribute('data-legacy-message-id', id);
      el.setAttribute('data-message-id', '#msg-f:' + BigInt('0x' + id));
      location.hash = 'inbox/example-2';
      el.querySelector('.a3s').innerHTML =
        '<img alt="Unloaded">'.repeat(5) + '<a href="https://click.example.test/redirect">Second link</a>';
    }, secondId);
    await page.waitForFunction(() =>
      document.querySelector('.pg-status')?.textContent === '1 link with tracking indicators · Partial scan');
    await waitForBadge(worker, tabId, '001', [255, 152, 0, 255]);
    const retry = panel.getByRole('button', {name: 'Retry scan', exact: true});
    assert.equal(await panel.getAttribute('open'), null, 'The panel starts collapsed for a new message');
    await retry.waitFor();
    const attemptsBeforeHelp = requestsFor(secondId).length;
    await partialInfo.focus();
    await panel.getByRole('tooltip').waitFor();
    await page.keyboard.press('Enter');
    assert.equal(await panel.getAttribute('open'), null, 'Using the help keeps the findings collapsed');
    assert.equal(requestsFor(secondId).length, attemptsBeforeHelp, 'Using the help does not retry the scan');
    assert.equal(await panel.getAttribute('data-scanning'), null);
    assert.notEqual(await results.getAttribute('aria-busy'), 'true');
    assert.equal(await sweep(), 'none');
    await delayedRoute.fulfill({contentType: 'message/rfc822', body: raw});
    await page.waitForLoadState('networkidle');
    assert.equal(ctx.pages().length, pageCount, 'An automatic failure must not open another tab');
    assert.equal(await page.locator('#message-options').getAttribute('aria-expanded'), 'false');
    assert.equal(requestsFor(delayedId).length, 1, 'Do not continue retrieving a replaced message');
    assert.equal(await panel.locator('.pg-note').count(), 0);
    assert.equal(await panel.locator('li[data-category="tracking-pixel"]').count(), 0);

    const unexpectedPages = [];
    ctx.on('page', tab => unexpectedPages.push(tab));
    const initialUrl = page.url();
    const messageKey = 'msg-f:' + BigInt('0x' + secondId);
    const secondRequestsBeforeRetry = requestsFor(secondId).length;
    const [manualRoute] = await Promise.all([nextRoute(secondId), retry.click()]);
    await running.waitFor();
    assert.equal(await retry.isDisabled(), true);
    assert.equal(await partialInfo.count(), 0, 'The help disappears while retrying');
    assert.doesNotMatch(await summary.innerText(), /tracking indicators|partial scan/i);
    assert.equal(await panel.locator('.pg-list li:visible, .pg-filter:visible').count(), 0);
    await manualRoute.fulfill({contentType: 'message/rfc822', body: raw});
    await pixelRow.waitFor();
    assert.doesNotMatch(await panel.innerText(), /full scan complete/i);
    assert.equal(await panel.getAttribute('data-scanning'), null);
    assert.notEqual(await results.getAttribute('aria-busy'), 'true');
    assert.equal(await sweep(), 'none');
    assert.notEqual(await panel.getAttribute('open'), null, 'The single click reveals the results');
    assert.equal(await pixelRow.locator('.pg-url').innerText(), pixel);
    assert.doesNotMatch(await summary.innerText(), /partial scan/i);
    assert.equal(await partialInfo.count(), 0, 'A successful retry clears the partial-scan help');
    assert.equal(await retry.count(), 0);
    await waitForBadge(worker, tabId, '111', [229, 57, 53, 255]);
    assert.equal(requestsFor(secondId).length, secondRequestsBeforeRetry + 1);
    assert.equal(page.url(), initialUrl);
    assert.equal(await page.locator('#message-options').getAttribute('aria-expanded'), 'false');
    assert.equal(await page.locator('#message-menu').isVisible(), false);
    assert.equal(await page.locator('body').getAttribute('data-display-images-clicked'), null);

    // A fast second click while Gmail is responding must not start another
    // scan. A permanent failure leaves the available findings in the same panel.
    await page.locator('.adn').evaluate((el, id) => {
      el.dataset.legacyMessageId = id;
      el.dataset.messageId = '#msg-f:' + BigInt('0x' + id);
    }, unavailableId);
    await retry.waitFor();
    assert.equal(await panel.getAttribute('open'), null);
    const failedRequestsBeforeRetry = requestsFor(unavailableId).map(req => req.url);
    const [failedRoute] = await Promise.all([nextRoute(unavailableId), retry.dblclick()]);
    await failedRoute.fulfill({status: 503, body: 'Unavailable'});
    await panel.getByText('Could not complete the scan. Showing partial results.', {exact: true}).waitFor();
    await page.waitForLoadState('networkidle');
    await retry.waitFor();
    assert.notEqual(await panel.getAttribute('open'), null, 'An inline failure should also be visible');
    assert.doesNotMatch(await panel.innerText(), /Full scan complete|⋮|menu/i);
    assert.match(await summary.innerText(), /1 link with tracking indicators · Partial scan/);
    const filter = panel.getByRole('combobox', {name: 'Filter by type', exact: false});
    assert.match(await filter.locator('option:checked').innerText(), /\(6\)/);
    await waitForBadge(worker, tabId, '001', [255, 152, 0, 255]);
    assert.deepEqual(requestsFor(unavailableId).slice(failedRequestsBeforeRetry.length).map(req => req.url),
      failedRequestsBeforeRetry, 'A double click must start only one retry');
    assert.equal(unexpectedPages.length, 0, 'No scan opens a new tab at any point');
    assert.equal(page.url(), initialUrl);
    assert.equal(await page.locator('#message-menu').isVisible(), false);
    assert.equal(await page.locator('body').getAttribute('data-display-images-clicked'), null);
    // Some Gmail accounts require the account hint for the source view. No
    // hint is published in the DOM here; only the Gmail page world has it.
    await page.locator('.adn').evaluate((el, {id, hint}) => {
      window.GLOBALS = [];
      window.GLOBALS[9] = hint;
      el.dataset.legacyMessageId = id;
      el.dataset.messageId = '#msg-f:' + BigInt('0x' + id);
    }, {id: hintedId, hint: syntheticHint});
    await waitForBadge(worker, tabId, '111', [229, 57, 53, 255]);
    assert.equal(await panel.getAttribute('open'), null, 'Completing the scan did not require opening the panel');
    assert.equal(await retry.count(), 0);
    assert.match(await summary.innerText(), /1 possible tracking pixel/);
    assert.deepEqual(await page.locator('.a3s img').evaluateAll(imgs => imgs.map(i => i.getAttribute('src'))),
      Array(5).fill(null), 'All five images must still be blocked');
    assert.equal(requestsFor(hintedId).length, 1);
    const wanted = new URL(requestsFor(hintedId)[0].url);
    assert.equal(wanted.searchParams.get('view'), 'om');
    assert.equal(wanted.searchParams.get('permmsgid'), hintedKey);
    assert.equal(wanted.searchParams.get('ik'), syntheticHint);
    await summary.click();
    await pixelRow.waitFor();
    assert.doesNotMatch(await panel.innerText(), /full scan complete/i);
    assert.equal(await pixelRow.locator('.pg-url').innerText(), pixel);
    assert.doesNotMatch(await panel.innerText(), new RegExp(syntheticHint));
    assert.equal(unexpectedPages.length, 0);
    assert.equal(page.url(), initialUrl);
    assert.equal(await page.locator('#message-menu').isVisible(), false);
    await page.evaluate(() => { delete window.GLOBALS; });
    const requestsBeforeThread = sourceRequests.length;

    // Three messages expand together; the third collapses while the first two
    // are still waiting for Gmail. Its queued download must never start.
    const firstTwo = threadIds.slice(0, 2);
    const firstTwoRequests = Promise.all(firstTwo.map(nextRoute));
    await page.locator('main').evaluate((main, ids) => {
      main.replaceChildren();
      for (const id of ids) {
        const article = document.createElement('article');
        article.dataset.legacyMessageId = id;
        article.innerHTML = '<div class="a3s">Open message</div>';
        main.append(article);
      }
    }, threadIds);
    const firstTwoRoutes = await firstTwoRequests;
    await page.locator('article').last().evaluate(el => el.hidden = true);
    await page.locator('article').last().locator('.pixelguard-gmail').waitFor({state: 'detached'});
    await Promise.all(firstTwoRoutes.map(route => route.fulfill({contentType: 'message/rfc822', body: raw})));
    await waitForBadge(worker, tabId, '222', [229, 57, 53, 255]);
    await page.waitForLoadState('networkidle');
    assert.deepEqual(sourceRequests.slice(requestsBeforeThread).map(req => req.id).sort(), firstTwo);

    // Gmail users can still choose its own source view independently. Analyze
    // the source already present there without performing another download.
    const requestCount = sourceRequests.length;
    await page.goto(gmail + '?view=om&permmsgid=' + messageKey);
    await panel.locator('summary').click();
    assert.equal(await pixelRow.locator('.pg-url').innerText(), pixel);
    await waitForBadge(worker, tabId, '111', [229, 57, 53, 255]);
    for (const [type, body, expected] of [
      ['text/html', '<p>A clean message</p>', 'No tracking indicators found'],
      ['text/plain', 'A plain message', 'Plain-text original']
    ]) {
      await page.locator('pre.raw_message_text').evaluate((node, source) => { node.textContent = source; },
        'Content-Type: ' + type + '; charset=UTF-8\r\n\r\n' + body);
      await summary.getByText(expected, {exact: true}).waitFor();
      assert.equal(await partialInfo.count(), 0, 'A clean HTML or plain-text original needs no partial-scan help');
      assert.equal(await summary.evaluate(el => el.matches('summary, [role="button"]')), false);
      assert.equal(await panel.locator('.pg-chevron:visible, .pg-results:visible').count(), 0);
      await summary.click();
      assert.equal(await panel.getAttribute('open'), null);
    }
    await page.waitForLoadState('networkidle');
    assert.equal(sourceRequests.length, requestCount);
    assert.deepEqual(external, [], 'The context must never request a sender, image or embedded resource URL');
    console.log('PASS automatic full scan while images stay blocked, retry after failure, and zero external requests', ctx.browser().version());
  } finally {
    await ctx.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
