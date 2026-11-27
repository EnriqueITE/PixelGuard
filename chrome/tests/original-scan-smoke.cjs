// Exercise inert HTML parsing and inline-style classification in real Chromium.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');

async function main() {
  const browser = await chromium.launch({
    channel: 'chromium', executablePath: process.env.CHROME_FOR_TESTING || undefined, headless: true
  });
  try {
    const page = await browser.newPage();
    const requests = [];
    await page.route('**/*', route => {
      requests.push(route.request().url());
      return route.abort();
    });
    const chromeDir = path.resolve(__dirname, '..');
    for (const file of ['original-mime.js', 'scanner.js', 'original-scan.js']) {
      await page.addScriptTag({path: path.join(chromeDir, file)});
    }
    const actual = await page.evaluate(() => {
      const {result, labels} = PixelGuardOriginalScan.scan(`
        <style>@import url("https://assets.example.test/sheet.css");</style>
        <link rel="stylesheet" href="https://assets.example.test/theme.css">
        <iframe src="https://assets.example.test/frame"></iframe>
        <div style="background-image:url(https://assets.example.test/pattern.png)"></div>
        <img src="https://mail.shop.app/_t/open/example" style="display: none !important">
        <img src="https://assets.example.test/logo.png" alt="Company logo" width="200" height="80">
        <a href="https://mail.shop.app/_t/c/v3/YQ==">A product</a>
      `, 'shop.app');
      return {
        pixels: result.suspicious.map(f => ({url:f.url, signals:f.signals})),
        externals: result.externals.map(f => f.url).sort(), links: result.links.map(f => f.url),
        labels: Object.fromEntries(labels), visibleImages: document.images.length
      };
    });
    await page.waitForLoadState('networkidle');
    assert.deepEqual(requests, []);
    assert.equal(actual.visibleImages, 0);
    assert.equal(actual.pixels.length, 1);
    assert.equal(actual.pixels[0].url, 'https://mail.shop.app/_t/open/example');
    assert.ok(actual.pixels[0].signals.includes('display:none image'));
    assert.deepEqual(actual.externals, ['https://assets.example.test/logo.png', 'https://assets.example.test/pattern.png']);
    assert.deepEqual(actual.links, ['https://mail.shop.app/_t/c/v3/YQ==']);
    assert.equal(actual.labels[actual.links[0]], 'A product');
    assert.equal(actual.labels[actual.externals[0]], 'Company logo');

    const mixed = await page.evaluate(() => {
      const source = [
        'Content-Type: multipart/mixed; boundary=parts', '',
        '--parts', 'Content-Type: text/html', '', '<div><textarea>First note',
        '--parts', 'Content-Type: text/html', '', '<img src="https://images.example.test/pixel" width="1" height="1">',
        '--parts', 'Content-Type: text/plain', '', 'https://click.example.test/redirect <img src="https://images.example.test/text">',
        '--parts', 'Content-Type: multipart/encrypted', '', 'Unavailable section', '--parts--'
      ].join('\r\n');
      const {result, plainText} = PixelGuardOriginalScan.scan(PixelGuardOriginalMime.bodyParts(source));
      return {pixels: result.suspicious.map(item => item.url), links: result.links.map(item => item.url),
        images: result.externals.length, partial: result.partial, plainText};
    });
    assert.deepEqual(mixed, {pixels: ['https://images.example.test/pixel'], links: ['https://click.example.test/redirect'],
      images: 0, partial: true, plainText: false});

    const sourcePage = '<pre class="raw_message_text">Content-Type: text/html; charset=UTF-8\n\n' +
      '&lt;img width="1" height="1" src="https://example.test/open"&gt;</pre>';
    let nativePage = '<!doctype html><img src="https://example.test/in-page">' +
      '<iframe src="https://example.test/frame"></iframe>' + sourcePage;
    const gmail = 'https://mail.google.com/mail/u/2/';
    await page.route('https://mail.google.com/**', route => {
      const url = new URL(route.request().url());
      if (url.href === gmail) return route.fulfill({contentType: 'text/html', body: '<main></main>'});
      if (url.searchParams.get('view') === 'att') return route.fulfill({status: 503});
      if (url.searchParams.get('view') === 'om') return route.fulfill({contentType: 'text/html', body: nativePage});
      throw new Error('Unexpected Gmail request ' + url);
    });
    await page.goto(gmail);
    for (const file of ['original-mime.js', 'gmail-original.js']) {
      await page.addScriptTag({path: path.join(chromeDir, file)});
    }
    const read = () => page.evaluate(() => PixelGuardGmailOriginal.read('abcd'));
    assert.deepEqual(await read(), {parts: [{type: 'text/html', content: '<img width="1" height="1" src="https://example.test/open">'}], partial: false});
    for (const invalidPage of ['<html>Sign in</html>', sourcePage + sourcePage]) {
      nativePage = invalidPage;
      await assert.rejects(read(), /Gmail original unavailable/);
    }
    await page.waitForLoadState('networkidle');
    assert.equal(await page.locator('img, iframe, pre').count(), 0);
    assert.deepEqual(requests, []);
    console.log('PASS original HTML and Gmail source view parsed with zero remote resource requests');
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
