// Exercises the real popup in Chromium with a fake worker and optional permission prompt.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const extension = path.resolve(__dirname, "../../dist/chrome-gmail");
const catalog = JSON.parse(fs.readFileSync(path.join(extension, "_locales/es/messages.json"), "utf8"));
const sample = "https://tracking.example.test/tickets/buy?campaign=summer&recipient=" + "abcdef12".repeat(30) + "#end";
async function run() {
  const browser = await chromium.launch({
    channel: "chromium", executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true
  });
  try {
    const page = await browser.newPage({ viewport: { width: 366, height: 590 }, colorScheme: "dark" });
    const errors = [];
    const outbound = [];
    page.on("pageerror", err => errors.push(err.message));
    await page.route("**/*", route => {
      const url = new URL(route.request().url());
      if (url.origin !== "https://popup.example.test") {
        outbound.push(url.href);
        return route.abort();
      }
      return route.fulfill({ path: path.join(extension, url.pathname.slice(1)) });
    });
    await page.addInitScript(({ catalog, sample }) => {
      const state = { ok: true, hasKey: false, showPanel: true, vtEnabled: false };
      window.testState = { granted: false, lookups: [], permissionRequests: 0, settings: [], inventory: 0 };
      const test = window.testState;
      test.links = [{ url: sample, label: "COMPRAR ENTRADAS" }, { url: "https://example.test/help", label: "Ayuda" }];
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
          sendMessage: async () => { test.inventory++; return { links: test.links }; }
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
            return { ok: true, result: { status: "no_report", queriedAt: Date.now() } };
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
    const address = page.getByRole("combobox", { name: catalog.pgLinkAddress.message, exact: true });
    const list = page.getByRole("listbox");
    assert.equal(await q("link-fields").locator("select:visible,textarea:visible,input:visible").count(), 1);
    await q("show-links").click();
    const longOption = list.getByRole("option", { name: sample, exact: true });
    assert.equal(await longOption.innerText(), sample);
    assert.ok(await longOption.evaluate(node => getComputedStyle(node).textOverflow === "ellipsis" &&
      node.scrollWidth > node.clientWidth), "Long options ellipsize within the popup");
    const helpUrl = "https://example.test/help";
    const helpOption = list.getByRole("option", { name: helpUrl, exact: true });
    const pickerLayout = () => page.locator("#url, .url-option, #query-domain, #preview-url").evaluateAll(nodes =>
      nodes.map(node => [node.offsetLeft, node.offsetTop, node.offsetWidth, node.offsetHeight]));
    const initialLayout = await pickerLayout();
    for (const [option, url] of [[longOption, sample], [helpOption, helpUrl]]) {
      await option.hover();
      assert.equal(await option.getAttribute("title"), url, "The native pointer hint belongs to the hovered row");
      assert.equal(await page.locator("#url-tip, [role=tooltip]").count(), 0, "No popup scroll panel is needed for hover");
      assert.deepEqual(await pickerLayout(), initialLayout, "Hovering must not move the options or lookup buttons");
    }
    await longOption.click();
    await list.waitFor({ state: "hidden" });
    assert.equal(await address.inputValue(), sample);
    const picked = q("picked-url");
    assert.ok(await picked.isVisible());
    assert.equal(await picked.innerText(), sample);
    assert.equal(await picked.getAttribute("aria-hidden"), "true");
    assert.ok(await picked.evaluate(node => getComputedStyle(node).textOverflow === "ellipsis" &&
      node.scrollWidth > node.clientWidth), "Show the ellipsis even while the selected field still has focus");
    await address.blur();
    assert.equal(await address.evaluate(node => getComputedStyle(node).textOverflow), "ellipsis");
    await address.hover();
    assert.equal(await address.getAttribute("title"), sample);

    await q("show-links").click();
    await list.waitFor();
    await address.press("Tab");
    await list.waitFor({ state: "hidden" });
    await address.fill("");
    assert.equal(await address.evaluate(node => node.title), "", "Clearing the field clears its previous URL hint");
    await address.press("Escape");
    await address.press("ArrowDown");
    await list.waitFor();
    await address.press("Enter");
    await list.waitFor({ state: "hidden" });
    assert.equal(await address.inputValue(), sample);
    assert.equal(await address.getAttribute("title"), sample, "Keyboard selection updates the same pointer hint");
    assert.equal(await q("panel-toggle").isChecked(), false);
    await q("preview-url").click();
    assert.equal(await q("exact-url").innerText(), sample);
    await q("cancel-url").click();
    assert.deepEqual(await page.evaluate(() => testState.lookups), [], "Selecting, hovering and cancelling stay local");
    await address.fill("https://tracking.example.test/tickets");
    assert.equal(await address.getAttribute("title"), "https://tracking.example.test/tickets");
    await longOption.waitFor();
    await q("query-domain").click();
    assert.deepEqual(await page.evaluate(() => testState.lookups), [
      { type: "pg:lookup", kind: "domain", value: "tracking.example.test", confirmed: false }
    ], "A single click must query the typed domain even while suggestions are open");
    assert.equal(await list.isVisible(), false, "Clicking the lookup button closes the suggestions");
    await q("result").waitFor();
    await q("show-links").click();
    await longOption.click();
    await q("preview-url").click();
    assert.equal(await q("exact-url").innerText(), sample);
    assert.equal((await page.evaluate(() => testState.lookups)).length, 1);
    await q("confirm-url").click();
    await q("result").waitFor();
    assert.deepEqual(await page.evaluate(() => testState.lookups.at(-1)),
      { type: "pg:lookup", kind: "url", value: sample, confirmed: true });

    await q("vt-toggle").click();
    await q("lookup").waitFor({ state: "hidden" });
    assert.equal(await q("url").evaluate(node => node.title), "", "Disabling VirusTotal clears the selected URL hint");
    await page.evaluate(() => { testState.links = []; });
    await q("vt-toggle").click();
    await q("lookup").locator("summary").click();
    await page.waitForFunction(() => testState.inventory === 2);
    const manual = "https://manual.example.test/path?item=42#details";
    await address.fill(manual);
    assert.equal(await address.getAttribute("title"), manual);
    await address.press("ArrowDown");
    assert.equal(await list.count(), 0, "Manual entry works without suggestions");
    await q("preview-url").click();
    assert.equal(await q("exact-url").innerText(), manual);
    await q("cancel-url").click();
    assert.equal((await page.evaluate(() => testState.lookups)).length, 2);
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
    assert.deepEqual(outbound, [], "The popup never opens a selected or hovered email URL");
    console.log("PASS theme and key settings, native URL hover hints, stable picker layout, keyboard selection, manual entry and explicit domain/URL lookups");
  } finally { await browser.close(); }
}
run().catch(err => { console.error(err); process.exitCode = 1; });
