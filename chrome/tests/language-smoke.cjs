// Run against an unpacked build using Chrome for Testing and playwright-core.
const assert = require("node:assert/strict");
const path = require("node:path");
const { chromium } = require("playwright-core");

const extension = path.resolve(process.argv[2] || path.join(__dirname, "../../dist/chrome-gmail"));
const locales = ["en-US", "de", "el", "es", "fr", "it", "ru", "zh-CN"];
const files = { "en-US": "en", "zh-CN": "zh_CN" };
const catalogs = Object.fromEntries(locales.map(locale => [
  locale, require("../messages." + (files[locale] || locale) + ".json")
]));
const gmailUrl = "https://mail.google.com/mail/u/0/";
const message = `<!doctype html><main role="main"><article class="adn"><div class="a3s">
  <a href="https://click.example.test/redirect?utm_campaign=demo">Newsletter</a>
  <img alt="Blocked image" width="80" height="30">
</div></article></main>`;

async function main() {
  const ctx = await chromium.launchPersistentContext("", {
    channel: "chromium", executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, locale: "en-US", ignoreDefaultArgs: ["--disable-extensions"],
    args: ["--lang=en-US", "--enable-unsafe-extension-debugging", "--host-resolver-rules=MAP * ~NOTFOUND"]
  });
  ctx.setDefaultTimeout(8000);
  try {
    await ctx.route(/^https?:\/\//, route => {
      const request = route.request();
      if (request.isNavigationRequest() && request.url().split("#")[0] === gmailUrl) {
        return route.fulfill({contentType: "text/html", body: message});
      }
      return route.abort();
    });
    const gmail = await ctx.newPage();
    await gmail.goto(gmailUrl + "#inbox/language-test");
    const cdp = await ctx.browser().newBrowserCDPSession();
    await cdp.send("Extensions.loadUnpacked", {path: extension});
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent("serviceworker");
    const {tabId, nativeLabel} = await worker.evaluate(async () => ({
      tabId: (await chrome.tabs.query({active: true, lastFocusedWindow: true}))[0].id,
      nativeLabel: chrome.i18n.getMessage("pgShowBar")
    }));
    const automatic = locales.find(locale => catalogs[locale].pgShowBar.message === nativeLabel);
    assert.ok(automatic, "The browser's native Gmail bar label must match a supported catalog");

    const panel = gmail.locator("details.pixelguard-gmail");
    await panel.locator("summary").click();
    const filter = panel.locator(".pg-filter");
    assert.equal(await panel.locator(".pg-list li").count(), 2);
    await filter.selectOption("tracking-link");
    const popupUrl = new URL("popup.html", worker.url()).href;
    async function openPopup() {
      const page = await ctx.newPage();
      await page.goto(popupUrl);
      await page.locator("#language:enabled").waitFor();
      return page;
    }
    let popup = await openPopup();
    const choices = await popup.locator("#language option").evaluateAll(options => options.map(option => option.value));
    assert.deepEqual(choices.sort(), ["auto", ...locales].sort());

    async function checkLanguage(preference, locale) {
      const expected = catalogs[locale];
      await popup.getByText(expected.pgShowBar.message, {exact: true}).waitFor();
      assert.equal(await popup.locator("#language").inputValue(), preference);
      assert.equal(await popup.locator("label[for=language]").textContent(), expected.pgLanguage.message);
      assert.equal(await popup.locator('#language option[value="auto"]').textContent(), expected.pgBrowserLanguage.message);
      await panel.getByRole("button", {name: expected.gmailCopy.message, exact: true}).waitFor();
      assert.equal(await panel.evaluate(element => element.open), true);
      assert.equal(await filter.inputValue(), "tracking-link");
      assert.equal(await filter.getAttribute("aria-label"), expected.gmailFilterLabel.message);
      assert.equal(await panel.locator(".pg-list li").count(), 1);
      assert.equal(await panel.locator(".pg-kind").textContent(), expected.gmailLink.message);
      assert.ok((await panel.locator(".pg-status").textContent()).includes(expected.gmailPartial.message));
      const counts = {S: "0", E: "0", L: "1"};
      const title = expected.badgeFindingsTitle.message.replace(/\$([SEL])\$/g, (_, key) => counts[key]);
      await popup.waitForFunction(async ({tabId, title}) => await chrome.action.getTitle({tabId}) === title, {tabId, title});
    }

    await checkLanguage("auto", automatic);
    for (const key of ["pgShowBar", "gmailCopy", "badgeFindingsTitle"]) {
      assert.equal(new Set(locales.map(locale => catalogs[locale][key].message)).size, locales.length, key);
    }
    for (const locale of locales) {
      await popup.locator("#language").selectOption(locale);
      await checkLanguage(locale, locale);
    }
    await popup.close();
    popup = await openPopup();
    await checkLanguage("zh-CN", "zh-CN");
    await popup.locator("#language").selectOption("auto");
    await checkLanguage("auto", automatic);
    console.log("Passed: eight languages, automatic browser language, expanded Gmail results, filter, toolbar titles and popup persistence.");
  } finally {
    await ctx.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
