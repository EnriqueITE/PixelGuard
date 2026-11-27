// Simulate an upgrade from the prototype with a synthetic old-format key.
// Exercise migration, restart and lookup using Chromium's native key store.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright-core');

async function run() {
  const bundle = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, '../../dist/chrome-gmail');
  const temp = fs.realpathSync(os.tmpdir());
  const profile = fs.mkdtempSync(path.join(temp, 'pixelguard-vault-test-'));
  const key = 'dummy-only-for-vault-restart';
  async function session(action) {
    const ctx = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', executablePath: process.env.CHROME_FOR_TESTING || undefined,
      headless: true, args: ['--host-resolver-rules=MAP * ~NOTFOUND', '--load-extension=' + bundle, '--disable-extensions-except=' + bundle]
    });
    try {
      await ctx.route(/^https?:\/\//, route => route.abort());
      const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
      const popup = await ctx.newPage();
      await popup.goto(new URL('popup.html', worker.url()).href);
      await action(popup, worker);
    } finally { await ctx.close(); }
  }
  try {
    await session(async popup => {
      await popup.locator('#setup').waitFor();
      await popup.evaluate(apiKey => chrome.storage.local.set({ vtConfig: { enabled: false, apiKey } }), key);
    });
    await session(async popup => {
      const state = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'pg:state' }));
      assert.ok(state.hasKey && !state.vtEnabled);
      assert.ok(await popup.evaluate(async () => {
        const { vtConfig } = await chrome.storage.local.get('vtConfig');
        return vtConfig?.sealedKey?.version === 1 && !('apiKey' in vtConfig);
      }));
    });
    await session(async (popup, worker) => {
      await worker.evaluate(expected => {
        chrome.permissions.contains = async () => true;
        self.fetch = async (_url, options) => {
          if (options.headers['x-apikey'] !== expected) throw Error('Decryption failed');
          return new Response(null, { status: 404 });
        };
      }, key);
      const reply = await popup.evaluate(async () => {
        await chrome.runtime.sendMessage({ type: 'pg:settings', vtEnabled: true });
        return chrome.runtime.sendMessage({ type: 'pg:lookup', kind: 'domain', value: 'example.test' });
      });
      assert.equal(reply.result?.status, 'no_report');
    });
    console.log('PASS migration and native IndexedDB decryption after two Chromium restarts');
  } finally {
    const target = fs.realpathSync(profile);
    assert.equal(path.dirname(target), temp);
    assert.match(path.basename(target), /^pixelguard-vault-test-[A-Za-z0-9]+$/);
    fs.rmSync(target, { recursive: true, force: true, maxRetries: 4 });
  }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
