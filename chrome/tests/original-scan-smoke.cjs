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
    for (const file of ['scanner.js', 'original-scan.js']) {
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
    console.log('PASS original HTML pixel, logo, labels and zero remote resource requests');
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
