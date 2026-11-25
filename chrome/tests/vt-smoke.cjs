// Exercise the packaged popup, worker and local hash in a disposable browser.
// The optional browser permission and remote VT response are simulated.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const path = require('node:path');
const { chromium } = require('playwright-core');

async function inspectVault(popup) {
  return popup.evaluate(async () => {
    const config = (await chrome.storage.local.get('vtConfig')).vtConfig;
    const key = await new Promise((resolve, reject) => {
      const open = indexedDB.open('pixelguard-vault');
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const read = db.transaction('keys').objectStore('keys').get('vt');
        read.onsuccess = () => { db.close(); resolve(read.result); };
        read.onerror = () => { db.close(); reject(read.error); };
      };
    });
    return { encrypted: config?.sealedKey?.version === 1, hasPlaintext: !!config && 'apiKey' in config,
      cipher: key?.algorithm.name ?? null, extractable: key?.extractable ?? null };
  });
}

async function main() {
  const bundle = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, '../../dist/chrome-gmail');
  const ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium', executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, locale: 'en-US',
    args: ['--lang=en-US', '--host-resolver-rules=MAP * ~NOTFOUND',
      '--load-extension=' + bundle, '--disable-extensions-except=' + bundle]
  });
  try {
    await ctx.route(/^https?:\/\//, route => route.abort());
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
    await worker.evaluate(() => {
      chrome.permissions.contains = async p => p.origins?.join() === 'https://www.virustotal.com/*';
      self.testQueries = [];
      self.fetch = async (input, options) => {
        const endpoint = new URL(input);
        if (endpoint.origin !== 'https://www.virustotal.com' || endpoint.pathname !== '/api/v3/widget/url' ||
            options.method !== 'GET' || options.body || options.headers['x-apikey'] !== 'dummy-browser-test-only') {
          throw Error('Unexpected simulated request');
        }
        self.testQueries.push(endpoint.searchParams.get('query'));
        return Response.json({ data: {
          detection_ratio: { detections: 2, total: 83 }, url: 'https://www.virustotal.com/ui/widget/html/test-only'
        } });
      };
    });
    const queries = () => worker.evaluate(() => self.testQueries);
    const popup = await ctx.newPage();
    popup.setDefaultTimeout(5000);
    await popup.goto(new URL('popup.html', worker.url()).href);
    await popup.evaluate(() => {
      self.permissionRequests = 0;
      chrome.permissions.request = async p => {
        self.permissionRequests++;
        return p.origins?.join() === 'https://www.virustotal.com/*';
      };
    });
    await popup.locator('#setup').click();
    await popup.locator('#key').fill('dummy-browser-test-only');
    await popup.locator('#save-key').click();
    await popup.locator('#key-bar').waitFor();
    assert.equal(await popup.locator('#vt-toggle').isChecked(), false);
    assert.equal(await popup.locator('#lookup').isVisible(), false);
    assert.deepEqual(await inspectVault(popup), { encrypted: true, hasPlaintext: false, cipher: 'AES-GCM', extractable: false });
    assert.equal(await popup.evaluate(() => self.permissionRequests), 0);
    assert.deepEqual(await queries(), []);
    await popup.locator('#vt-toggle').click();
    await popup.locator('#lookup > summary').click();
    assert.equal(await popup.evaluate(() => self.permissionRequests), 1);
    const url = 'https://example.test/path?token=demo';
    await popup.locator('#url').fill(url);
    assert.deepEqual(await queries(), []);
    await popup.locator('#query-domain').click();
    const result = popup.locator('#result-title');
    await result.filter({ hasText: '2 / 83' }).waitFor();
    assert.deepEqual(await queries(), ['example.test']);
    assert.equal(await popup.locator('#report').getAttribute('href'), 'https://www.virustotal.com/ui/widget/html/test-only');
    await popup.locator('#preview-url').click();
    assert.equal(await popup.locator('#exact-url').innerText(), url);
    await popup.locator('#cancel-url').click();
    assert.deepEqual(await queries(), ['example.test']);
    await popup.locator('#preview-url').click();
    await popup.locator('#confirm-url').click();
    await result.filter({ hasText: '2 / 83' }).waitFor();
    assert.deepEqual(await queries(), ['example.test', url]);
    const content = Buffer.from('test file contents');
    const hash = createHash('sha256').update(content).digest('hex');
    await popup.locator('#file-mode').click();
    await popup.locator('#file').setInputFiles({ name: 'test.txt', mimeType: 'text/plain', buffer: content });
    assert.deepEqual(await queries(), ['example.test', url]);
    await popup.locator('#query-hash').click();
    await result.filter({ hasText: '2 / 83' }).waitFor();
    assert.deepEqual(await queries(), ['example.test', url, hash]);
    await popup.locator('#vt-toggle').click();
    await popup.locator('#lookup').waitFor({ state: 'hidden' });
    await popup.reload();
    await popup.locator('#key-bar').waitFor();
    assert.equal(await popup.locator('#vt-toggle').isChecked(), false);
    await popup.locator('#manage').click();
    await popup.locator('#delete-key').click();
    await popup.locator('#setup').waitFor();
    assert.equal(await worker.evaluate(async () => 'vtConfig' in await chrome.storage.local.get('vtConfig')), false);
    assert.deepEqual(await inspectVault(popup), { encrypted: false, hasPlaintext: false, cipher: null, extractable: null });
    await popup.reload();
    await popup.locator('#setup').waitFor();
    assert.deepEqual(await queries(), ['example.test', url, hash]);
    console.log('PASS popup > worker > VT stub: private key setup, hostname, confirmed full URL, local SHA-256, report and disable', ctx.browser().version());
  } finally { await ctx.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
