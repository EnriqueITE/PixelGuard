// Reload the real unpacked extension over a Gmail fixture with an original read in flight.
const assert = require("node:assert/strict");
const path = require("node:path");
const {chromium} = require("playwright-core");

const extension = path.resolve(process.argv[2] || path.join(__dirname, "../../dist/chrome-gmail"));
const gmail = "https://mail.google.com/mail/u/0/";
const shell = '<!doctype html><main><article class="adn" id="ready"><div class="a3s">' +
  '<a href="https://click.example.test/redirect?token=demo">Newsletter</a></div></article>' +
  '<article class="adn" id="pending" data-legacy-message-id="abc"><div class="a3s">Message</div></article></main>';
const original = 'Content-Type: text/html; charset=UTF-8\r\n\r\n<img width="1" height="1" src="https://events.example.test/open?uid=demo">';

async function main() {
  const context = await chromium.launchPersistentContext("", {
    channel: "chromium", executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, ignoreDefaultArgs: ["--disable-extensions"],
    args: ["--enable-unsafe-extension-debugging", "--host-resolver-rules=MAP * ~NOTFOUND"]
  });
  try {
    let delayedRead;
    const errors = [];
    const external = [];
    await context.route(/^https?:\/\//, async route => {
      const url = new URL(route.request().url());
      if (!url.href.startsWith(gmail)) {
        external.push(url.href);
        return route.abort();
      }
      if (route.request().isNavigationRequest()) return route.fulfill({contentType: "text/html", body: shell});
      if (url.searchParams.get("view") === "att") {
        if (!delayedRead) { delayedRead = route; return; }
        return route.fulfill({contentType: "message/rfc822", body: original});
      }
      return route.abort();
    });
    const page = await context.newPage();
    const devtools = await context.newCDPSession(page);
    devtools.on("Runtime.exceptionThrown", ({exceptionDetails}) => {
      errors.push(exceptionDetails.exception?.description || exceptionDetails.text);
    });
    await devtools.send("Runtime.enable");
    await page.goto(gmail + "#inbox/test");
    const browser = await context.browser().newBrowserCDPSession();
    const pending = page.waitForRequest(request => new URL(request.url()).searchParams.get("view") === "att");
    await browser.send("Extensions.loadUnpacked", {path: extension});
    await Promise.all([
      pending,
      page.waitForSelector("#ready li[data-category='tracking-link']", {state: "attached"}),
      page.waitForSelector("#pending .pixelguard-gmail[data-scanning]")
    ]);
    await page.evaluate(() => {
      window.oldPanel = document.querySelector("#ready details");
    });
    await browser.send("Extensions.loadUnpacked", {path: extension});
    await page.waitForFunction(() => !window.oldPanel.isConnected &&
      document.querySelector("#pending li[data-category='tracking-pixel']"));
    // Chromium may already have cancelled the paused request with the old world.
    await delayedRead.abort().catch(() => {});
    const obsoleteControlKeptItsRows = await page.evaluate(() => {
      const filter = window.oldPanel.querySelector("select");
      const originalRow = window.oldPanel.querySelector("li");
      filter.value = "tracking-link";
      filter.dispatchEvent(new Event("change"));
      window.oldPanel.querySelector(".pg-pager button").click();
      window.dispatchEvent(new Event("hashchange"));
      document.dispatchEvent(new Event("visibilitychange"));
      return originalRow === window.oldPanel.querySelector("li");
    });
    const filter = page.locator("#ready details select");
    await page.locator("#ready summary").click();
    await filter.selectOption("tracking-link");
    assert.equal(await page.locator("#ready details li[data-category=tracking-link]").count(), 1);
    assert.equal(await page.locator("details.pixelguard-gmail").count(), 2);
    assert.deepEqual(errors, [], "Reload and interaction with orphaned controls must not throw");
    assert.ok(obsoleteControlKeptItsRows, "Orphaned controls must stop rendering");
    assert.deepEqual(external, [], "The scanner must not contact the sender");
    console.log("PASS extension reload with pending original and stale controls", context.browser().version());
  } finally {
    await context.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
