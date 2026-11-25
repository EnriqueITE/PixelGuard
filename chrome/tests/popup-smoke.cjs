// Exercises the real popup in Chromium with a fake worker and optional permission prompt.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const extension = path.resolve(__dirname, "../../dist/chrome-gmail");
const catalog = JSON.parse(fs.readFileSync(path.join(extension, "_locales/es/messages.json"), "utf8"));
const sample = "https://example.test/account?test_id=sample";
async function run() {
  const browser = await chromium.launch({
    channel: "chromium", executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true
  });
  try {
    const page = await browser.newPage({ viewport: { width: 366, height: 590 }, colorScheme: "dark" });
    const errors = [];
    page.on("pageerror", err => errors.push(err.message));
    await page.route("**/*", route => {
      const url = new URL(route.request().url());
      if (url.origin !== "https://popup.example.test") return route.abort();
      return route.fulfill({ path: path.join(extension, url.pathname.slice(1)) });
    });
    await page.addInitScript(({ catalog, sample }) => {
      const state = { ok: true, hasKey: false, showPanel: true, vtEnabled: false };
      window.testState = { granted: false, lookups: [], permissionRequests: 0, settings: [], inventory: 0 };
      const test = window.testState;
      const api = {
        i18n: {
          getUILanguage: () => "es",
          getMessage(key, subs) {
            const entry = catalog[key];
            return entry?.message.replace(/\$(\w+)\$/g, (_, name) =>
              subs[Number(entry.placeholders[name.toLowerCase()].content.slice(1)) - 1]) || "";
          }
        },
        permissions: { request: async () => { test.permissionRequests++; return test.granted; } },
        tabs: {
          query: async () => [{ id: 1 }],
          sendMessage: async () => { test.inventory++; return { links: [{ url: sample, label: "Enlace de prueba" }] }; }
        },
        runtime: { async sendMessage(msg) {
          if (msg.type === "pg:settings") {
            test.settings.push({ fields: Object.keys(msg), onlyIfMissing: msg.onlyIfMissing });
            if ("showPanel" in msg && test.holdPanelSave) {
              await new Promise(resolve => { window.releasePanelSave = resolve; });
              return { ok: false, error: "storage" };
            }
            if (msg.onlyIfMissing && test.concurrentKey) {
              state.hasKey = true;
              return { ok: false, error: "key_exists" };
            }
            if ("apiKey" in msg) state.hasKey = !!msg.apiKey;
            for (const key of ["showPanel", "theme", "vtEnabled"]) if (key in msg) state[key] = msg[key];
          }
          if (msg.type === "pg:lookup") {
            test.lookups.push(msg);
            throw new Error("Unexpected lookup");
          }
          return { ...state };
        } }
      };
      Object.assign(window.chrome, api);
    }, {catalog, sample});
    await page.goto("https://popup.example.test/popup.html");
    const q = id => page.locator("#" + id);
    await q("setup").waitFor();
    const darkMode = page.getByRole("switch", { name: "Modo oscuro", exact: true });
    await page.getByRole("switch", { name: "Modo oscuro", checked: false, disabled: false }).waitFor();
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), "rgb(255, 255, 255)");
    await darkMode.click();
    await page.getByRole("switch", { name: "Modo oscuro", checked: true, disabled: false }).waitFor();
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), "rgb(23, 35, 40)");
    assert.deepEqual(await page.evaluate(() => testState.settings.at(-1).fields), ["type", "theme"]);
    await darkMode.press("Space");
    await page.getByRole("switch", { name: "Modo oscuro", checked: false, disabled: false }).waitFor();
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), "rgb(255, 255, 255)");
    await page.evaluate(() => { testState.holdPanelSave = true; });
    await q("panel-toggle").uncheck();
    assert.equal(await q("panel-toggle").isChecked(), false);
    assert.equal(await q("panel-toggle").isDisabled(), true);
    await page.evaluate(() => { testState.holdPanelSave = false; window.releasePanelSave(); });
    await q("status").filter({hasText: catalog.vt_error_storage.message}).waitFor();
    assert.equal(await q("panel-toggle").isChecked(), true);
    await q("panel-toggle").uncheck();
    await q("setup").click();
    assert.equal(await q("key").getAttribute("type"), "password");
    await q("key").fill("!".repeat(64));
    await q("save-key").click();
    await q("status").filter({hasText: catalog.vt_error_invalid_key.message}).waitFor();
    await q("key").fill("0123456789abcdef".repeat(4));
    await q("save-key").click();
    await q("manage").waitFor();
    assert.equal(await q("vt-toggle").isChecked(), false);
    assert.equal(await q("lookup").isVisible(), false);
    assert.equal(await q("key").inputValue(), "");
    const saved = await page.evaluate(() => testState);
    assert.deepEqual(saved.settings.at(-1), { fields: ["type", "apiKey", "onlyIfMissing"], onlyIfMissing: true });
    assert.equal(saved.permissionRequests, 0);
    await q("vt-toggle").click();
    await q("status").filter({hasText: catalog.vt_error_permission_denied.message}).waitFor();
    assert.equal(await q("vt-toggle").isChecked(), false);
    await page.evaluate(() => { testState.granted = true; });
    await q("vt-toggle").click();
    await q("lookup").locator("summary").click();
    await q("links").selectOption(sample);
    assert.equal(await q("url").inputValue(), sample);
    assert.equal(await q("panel-toggle").isChecked(), false);
    await q("preview-url").click();
    assert.equal(await q("exact-url").innerText(), sample);
    await q("cancel-url").click();
    assert.equal((await page.evaluate(() => testState.lookups)).length, 0);
    assert.ok(!await page.evaluate(() => document.documentElement.scrollWidth > innerWidth));
    await q("manage").click();
    await q("delete-key").click();
    await q("setup").waitFor();
    assert.equal(await q("lookup").isVisible(), false);
    await q("setup").click();
    await page.evaluate(() => { testState.concurrentKey = true; });
    await q("key").fill("0123456789abcdef".repeat(4));
    await q("save-key").click();
    await q("status").filter({hasText: catalog.pgKeyConflict.message}).waitFor();
    assert.equal(await q("key").inputValue(), "");
    assert.equal(await q("vt-toggle").isChecked(), false);
    await q("manage").click();
    await q("key").fill("abcdef0123456789".repeat(4));
    await q("save-key").click();
    await q("manage").waitFor();
    assert.deepEqual(await page.evaluate(() => testState.settings.at(-1).fields), ["type", "apiKey"]);
    assert.deepEqual(errors, []);
    console.log("PASS light default and dark mode switch with mouse and keyboard, manual key entry, separate activation, permission denial, hidden-bar inventory, URL cancellation and key deletion");
  } finally { await browser.close(); }
}
run().catch(err => { console.error(err); process.exitCode = 1; });
