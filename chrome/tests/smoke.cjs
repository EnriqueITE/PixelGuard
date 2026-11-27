// Run against the unpacked build using Chrome for Testing and playwright-core.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const extension = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, "../../dist/chrome-gmail");
const gmail = "https://mail.google.com/mail/u/0/";
const names = ["pixel", "link", "logo"];
const samples = names.map(name => {
  const raw = fs.readFileSync(path.join(__dirname, "mail", name + ".eml"), "utf8");
  const body = raw.replace(/^[\s\S]*?\r?\n\r?\n/, "");
  return '<article class="adn" id="' + name + '"><div class="gD" email="lab@example.test"></div>' +
    '<div class="a3s">' + body + "</div></article>";
});
const shell = '<!doctype html><main role="main">' + samples.join("") +
  '<div contenteditable="true"><div class="adn"><div class="a3s">Draft</div></div></div></main>';

const badgeColors = { red: [229, 57, 53, 255], orange: [255, 152, 0, 255], teal: [0, 191, 165, 255] };
async function checkBadge(worker, tabId, text, color) {
  const actual = await worker.evaluate(async ({tabId, text, color}) => {
    const deadline = Date.now() + 6000;
    let current;
    do {
      current = { text: await chrome.action.getBadgeText({tabId}) };
      if (color) current.color = await chrome.action.getBadgeBackgroundColor({tabId});
      if (current.text === text && (!color || current.color.join() === color.join())) break;
      await new Promise(resolve => setTimeout(resolve, 40));
    } while (Date.now() < deadline);
    return current;
  }, {tabId, text, color});
  assert.deepEqual(actual, color ? {text, color} : {text}, "badge for tab " + tabId);
}

async function main() {
  const ctx = await chromium.launchPersistentContext("", {
    channel: "chromium", executablePath: process.env.CHROME_FOR_TESTING || undefined,
    headless: true, locale: "en-US", colorScheme: "dark",
    ignoreDefaultArgs: ["--disable-extensions"],
    args: ["--lang=en-US", "--enable-unsafe-extension-debugging", "--host-resolver-rules=MAP * ~NOTFOUND"]
  });
  try {
    // All page traffic, including the fixture navigation, stays inside the test.
    await ctx.route(/^https?:\/\//, route => {
      if (route.request().isNavigationRequest()) {
        const body = new URL(route.request().url()).searchParams.has("view")
          ? '<!doctype html><div role="dialog">' + samples[0] + "</div>" : shell;
        return route.fulfill({ contentType: "text/html", body });
      }
      return route.abort();
    });
    const page = await ctx.newPage();
    await ctx.grantPermissions(["clipboard-read", "clipboard-write"], {origin: new URL(gmail).origin});
    await page.goto(gmail + "#inbox/test-thread");
    await page.evaluate(() => { window.beforeInstall = true; });
    assert.equal(await page.locator(".pixelguard-gmail").count(), 0);
    // Install after the Gmail tab is already showing a thread, as on an unpacked
    // extension update. A forced reload here could discard an in-progress draft.
    const cdp = await ctx.browser().newBrowserCDPSession();
    await cdp.send("Extensions.loadUnpacked", {path: extension});
    const worker = ctx.serviceWorkers()[0] || await ctx.waitForEvent("serviceworker");
    const tabId = await worker.evaluate(async () => (await chrome.tabs.query({active:true, lastFocusedWindow:true}))[0].id);
    const panel = id => page.locator("#" + id + " > .pixelguard-gmail");
    const colorFor = {
      "tracking-pixel": "rgb(229, 57, 53)", "suspicious-image": "rgb(229, 57, 53)",
      "tracking-link": "rgb(255, 152, 0)", "external-image": "rgb(0, 191, 165)",
      "unavailable-image": "rgb(116, 129, 135)"
    };
    async function checkSummary(id, summary, color) {
      await page.waitForFunction(({id, summary}) =>
        [...document.querySelectorAll("#" + id + " .pg-summary")].some(header =>
          header.getClientRects().length && header.querySelector(".pg-status")?.textContent === summary), {id, summary});
      const accent = await panel(id).locator(".pg-summary:visible").evaluate(el => getComputedStyle(el).borderInlineStartColor);
      assert.equal(accent, color);
    }
    async function check(id, summary, reason, category) {
      await checkSummary(id, summary, colorFor[category]);
      assert.equal(await panel(id).locator("li").count(), 1);
      assert.match(await panel(id).locator("li").textContent(), reason);
    }
    // These fixtures expose the rendered body but have no original message ID.
    const logoSummary = "1 external image · Partial scan";
    const linkSummary = "1 link with tracking indicators · Partial scan";
    await check("pixel", "1 possible tracking pixel · Partial scan", /events\.vendor\.test.*1\s*[×x]\s*1/i, "tracking-pixel");
    await check("link", linkSummary, /click\.example\.test.*redirect/i, "tracking-link");
    await check("logo", logoSummary, /external image/i, "external-image");
    assert.equal(await page.locator(".pixelguard-gmail").count(), 3);
    assert.equal(await page.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches), true);
    const panelBackground = item => item.evaluate(node => getComputedStyle(node).backgroundColor);
    assert.equal(await panelBackground(panel("logo")), "rgb(255, 255, 255)", "White is the default even on a dark OS");
    assert.equal(await page.evaluate(() => window.beforeInstall), true);
    await checkBadge(worker, tabId, "111", badgeColors.red);
    const info = panel("pixel").getByRole("button", {name: "About this partial scan", exact: true});
    const tip = panel("pixel").getByRole("tooltip", {includeHidden: true});
    assert.equal(await tip.isVisible(), false);
    await info.hover();
    await tip.waitFor();
    assert.match(await tip.innerText(), /Gmail/);
    const tipId = await tip.getAttribute("id");
    assert.ok(tipId, "The tooltip has an ID for screen readers");
    assert.equal(await info.getAttribute("aria-describedby"), tipId);
    await info.click();
    assert.equal(await panel("pixel").getAttribute("open"), null, "Reading the help does not open the findings");
    await panel("pixel").locator("summary").focus();
    await page.mouse.move(0, 0);
    await tip.waitFor({state: "hidden"});
    for (const name of names) {
      await panel(name).locator("summary").click();
      assert.ok(await panel(name).locator("li").isVisible());
      console.log(name, await panel(name).innerText());
    }
    // Mutate the existing thread in place, as a single-page mail client does.
    await page.locator("#logo .a3s img").evaluate(img => img.removeAttribute("src"));
    await checkSummary("logo", "Partial scan", colorFor["unavailable-image"]);
    await panel("logo").getByText("Gmail hides the address of 1 image.", {exact: true}).waitFor();
    assert.equal(await panel("logo").getByRole("button", {name: "Retry scan"}).count(), 0);
    const unavailable = panel("logo").locator('li[data-category="unavailable-image"]');
    await panel("logo").getByRole("combobox").selectOption("unavailable-image");
    assert.equal(await unavailable.count(), 1);
    assert.match(await unavailable.innerText(), /Example shop/);
    assert.equal(await unavailable.locator(".pg-url,button").count(), 0);
    await checkBadge(worker, tabId, "101", badgeColors.red);
    await page.locator("#logo .a3s img").evaluate(img => img.src = "https://cdn.example.test/brand/logo.png");
    await panel("logo").getByRole("combobox").selectOption("all");
    await check("logo", logoSummary, /external image/i, "external-image");
    assert.equal(await panel("logo").locator(".pg-original").isVisible(), false);
    await page.locator("#pixel img[src^='https']").evaluate(img => {
      img.src = "https://ci3.googleusercontent.com/meips/example#" + img.src;
    });
    await page.locator("#pixel .a3s img").evaluate(img => img.removeAttribute("width"));
    await check("pixel", "1 suspicious image · Partial scan", /events\.vendor\.test/, "suspicious-image");
    await page.locator("#pixel .a3s img").evaluate(img => img.src = "https://ci3.googleusercontent.com/meips/opaque");
    await check("pixel", logoSummary, /ci3\.googleusercontent\.com/, "external-image");
    await page.locator("#link .a3s").evaluate(el => el.textContent = "https://click.example.test/plain");
    await check("link", linkSummary, /click\.example\.test/, "tracking-link");
    await page.locator("#link").evaluate(el => el.hidden = true);
    await panel("link").waitFor({ state: "detached" });
    await page.locator("#link").evaluate(el => el.hidden = false);
    await check("link", linkSummary, /click\.example\.test/, "tracking-link");
    const longUrl = "https://click.example.test/redirect?token=demo&campaign=" + "a".repeat(160);
    await page.locator("#link .a3s").evaluate((el, url) => {
      el.replaceChildren();
      for (let i = 1; i <= 5; i++) {
        const anchor = document.createElement("a");
        anchor.href = url + i;
        anchor.textContent = "Newsletter " + i;
        el.append(anchor);
      }
    }, longUrl);
    await panel("link").locator("summary").click();
    await panel("link").getByText("1–3 of 5").waitFor();
    assert.equal(await panel("link").locator("li").count(), 3);
    assert.equal(await panel("link").locator(".pg-url").first().innerText(), longUrl + 1);
    await panel("link").getByRole("button", {name: "Copy URL"}).first().click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), longUrl + 1);
    await panel("link").getByRole("button", {name: "Next"}).click();
    await panel("link").getByText("Newsletter 5").waitFor();
    assert.equal(await panel("link").locator(".pg-url").last().innerText(), longUrl + 5);
    await panel("link").getByRole("button", {name: "Previous"}).click();
    await panel("link").getByText("Newsletter 1").waitFor();

    // Combine all four categories in the same message so filtering and paging
    // cannot pass merely by matching a label elsewhere in the thread.
    await page.locator("#link .a3s").evaluate(el => {
      const addImage = (url, width, height) => {
        const img = document.createElement("img");
        img.src = url;
        img.width = width;
        img.height = height;
        el.append(img);
      };
      addImage("https://events.vendor.test/open?uid=mixed", 1, 1);
      addImage("https://events.vendor.test/open?uid=suspect", 48, 48);
      addImage("https://cdn.example.test/logo", 180, 48);
    });
    const mixed = panel("link");
    const select = mixed.getByRole("combobox", {name: "Filter by type", exact: true});
    await mixed.getByText("1–3 of 8").waitFor();
    assert.doesNotMatch(await mixed.innerText(), /Filter by type/i, "The filter label is only announced to assistive technology");
    await mixed.getByRole("button", {name:"Next"}).click();
    await checkSummary("link", "1 possible tracking pixel · 1 suspicious image · 5 links with tracking indicators · 1 external image · Partial scan", colorFor["tracking-pixel"]);
    for (const category of ["tracking-pixel", "suspicious-image", "tracking-link", "external-image"]) {
      await select.selectOption(category);
      const rows = mixed.locator(".pg-list > li");
      const types = await rows.evaluateAll(items => items.map(item => item.dataset.category));
      assert.deepEqual(types, Array(category === "tracking-link" ? 3 : 1).fill(category));
      const indicator = rows.first().locator(".pg-kind");
      assert.equal(await indicator.evaluate(el => getComputedStyle(el, "::before").backgroundColor), colorFor[category]);
      if (category === "tracking-link") {
        await mixed.getByText("1–3 of 5").waitFor();
        await mixed.getByRole("button", {name:"Next"}).click();
        await mixed.getByText("4–5 of 5").waitFor();
        assert.equal(await rows.count(), 2);
      }
    }
    await select.selectOption("all");
    await mixed.getByText("1–3 of 8").waitFor();
    await checkBadge(worker, tabId, "235", badgeColors.red);
    await page.locator("#link .a3s").evaluate(el => {
      for (let i = 0; i < 7; i++) {
        const a = document.createElement("a");
        a.href = "https://click.example.test/redirect?token=extra" + i;
        el.append(a);
      }
    });
    await checkBadge(worker, tabId, "23+", badgeColors.red);

    // A separate Gmail message window has its own count. Its reading dialog
    // has no role=main; unlike a draft it contains an expanded message.
    const popoutReady = ctx.waitForEvent("page");
    const popoutId = await worker.evaluate(async url => {
      const result = await chrome.windows.create({type:"popup", url});
      return result.tabs[0].id;
    }, gmail + "?view=pt#inbox/test-pixel");
    const popout = await popoutReady;
    await popout.locator("#pixel .pixelguard-gmail").waitFor();
    await checkBadge(worker, popoutId, "100", badgeColors.red);
    await checkBadge(worker, tabId, "23+", badgeColors.red);
    await popout.close();
    await page.bringToFront();
    const popup = await ctx.newPage();
    await popup.goto(new URL("popup.html", worker.url()).href);
    const darkMode = popup.getByRole("switch", {name: "Dark mode", exact: true});
    assert.equal(await darkMode.isChecked(), false);
    await darkMode.click();
    await page.waitForFunction(() => [...document.querySelectorAll(".pixelguard-gmail")].every(node =>
      getComputedStyle(node).colorScheme === "dark"));
    const darkBackground = await panelBackground(panel("link"));
    assert.notEqual(darkBackground, "rgb(255, 255, 255)");
    assert.notEqual(await mixed.getAttribute("open"), null, "Changing theme preserves the expanded results");
    assert.match(await mixed.locator("summary").innerText(), /tracking pixel/);
    const toggle = popup.getByRole("switch", {name: "Show", exact: false}).first();
    await toggle.uncheck();
    await panel("link").waitFor({state:"detached"});
    await checkBadge(worker, tabId, "23+", badgeColors.red);
    await page.reload();
    await page.locator("#link .a3s").waitFor();
    await checkBadge(worker, tabId, "111", badgeColors.red);
    assert.equal(await page.locator(".pixelguard-gmail").count(), 0);
    const activeLinks = await popup.evaluate(async () => {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        try {
          const response = await chrome.tabs.sendMessage(tab.id, {type:"pg:gmail:links"});
          if (response?.links) return response.links;
        } catch { /* Only Gmail tabs contain the adapter. */ }
      }
    });
    assert.ok(activeLinks.some(link => link.label === "November newsletter" && link.url.includes("utm_campaign=demo")));
    await toggle.check();
    await page.bringToFront();
    await panel("link").waitFor({state:"visible"});
    await popup.close();
    // Chromium can retain an old panel's DOM after unloading its content world.
    await page.locator(".pixelguard-gmail").evaluateAll(nodes => nodes.forEach(n => n.setAttribute("data-before-reload", "")));
    await cdp.send("Extensions.loadUnpacked", {path: extension});
    await page.waitForFunction(() => !document.querySelector(".pixelguard-gmail[data-before-reload]") &&
      document.querySelectorAll(".pixelguard-gmail").length === 3);
    const probe = await ctx.newPage();
    await probe.goto(new URL("popup.html", worker.url()).href);
    await checkBadge(probe, tabId, "111", badgeColors.red);
    assert.equal(await page.locator(".pixelguard-gmail").count(), 3, "exactly one panel per message after extension reload");
    const restoredDarkMode = probe.getByRole("switch", {name: "Dark mode", exact: true, checked: true});
    await restoredDarkMode.waitFor();
    assert.equal(await panelBackground(panel("logo")), darkBackground, "Panel theme survives an extension reload");
    await restoredDarkMode.click();
    await page.waitForFunction(() => [...document.querySelectorAll(".pixelguard-gmail")].every(node =>
      getComputedStyle(node).backgroundColor === "rgb(255, 255, 255)"));
    const reloadedToggle = probe.locator("#panel-toggle");
    await reloadedToggle.uncheck();
    await page.waitForFunction(() => !document.querySelector(".pixelguard-gmail"));
    await reloadedToggle.check();
    await page.bringToFront();
    await panel("logo").waitFor();
    // Gmail reuses the same document when returning to the inbox or opening
    // another thread. The toolbar must follow the active view in this tab.
    await page.locator("main").evaluate(el => { location.hash = "inbox"; el.replaceChildren(); });
    await page.locator(".pixelguard-gmail").waitFor({ state: "detached" });
    await checkBadge(probe, tabId, "");
    await page.locator("main").evaluate((el, html) => {location.hash = "inbox/logo"; el.innerHTML = html;}, samples[2]);
    await panel("logo").waitFor({state:"visible"});
    await checkBadge(probe, tabId, "010", badgeColors.teal);
    await page.locator("main").evaluate((el, html) => {location.hash = "inbox/link"; el.innerHTML = html;}, samples[1]);
    await panel("link").waitFor({state:"visible"});
    await checkBadge(probe, tabId, "001", badgeColors.orange);
    // A single possible pixel takes priority even when a newsletter contains
    // many more tracking links and ordinary remote images.
    await page.locator("#link .a3s").evaluate(body => {
      const original = body.querySelector("a");
      for (let i = 1; i <= 24; i++) {
        const link = original.cloneNode(true);
        link.href += "&item=" + i;
        const image = new Image(180, 48);
        image.src = "https://cdn.example.test/product-" + i + ".png";
        body.append(link, image);
      }
      const pixel = new Image(1, 1);
      pixel.src = "https://events.vendor.test/open.gif?uid=demo";
      body.append(pixel);
    });
    await checkSummary("link", "1 possible tracking pixel · 25 links with tracking indicators · 24 external images · Partial scan", colorFor["tracking-pixel"]);
    await checkBadge(probe, tabId, "1++", badgeColors.red);
    assert.equal(await probe.evaluate(tabId => chrome.action.getTitle({tabId}), tabId),
      "PixelGuard · Possible tracking pixels and suspicious images: 1 · External images: 24 · Links with tracking indicators: 25");
    // A blocked newsletter can still expose its click redirects in the DOM.
    await page.locator("#link .a3s").evaluate(body => {
      body.replaceChildren();
      for (let i = 0; i < 31; i++) {
        const encoded = btoa("example-item-" + String(i).padStart(2, "0") + "!");
        const token = i < 27 ? encoded : encoded.replace(/=+$/, "");
        const link = document.createElement("a");
        link.href = "https://mail.shop.app/_t/c/v3/" + token;
        link.textContent = "Item " + i;
        body.append(link);
      }
      const ordinary = document.createElement("a");
      ordinary.href = "https://shop.app/products/plain";
      ordinary.textContent = "Ordinary product link";
      body.append(ordinary);
      for (let i = 0; i < 23; i++) {
        const image = new Image();
        if (i === 0) image.style.display = "none";
        body.append(image);
      }
    });
    await checkSummary("link", "31 links with tracking indicators · Partial scan", colorFor["tracking-link"]);
    await checkBadge(probe, tabId, "00+", badgeColors.orange);
    const shop = panel("link");
    await shop.locator("summary").click();
    await shop.locator(".pg-original").getByText("Gmail hides the addresses of 23 images.", {exact: true}).waitFor();
    const filterBox = await shop.locator(".pg-filter").boundingBox();
    const noticeBox = await shop.locator(".pg-original").boundingBox();
    assert.ok(filterBox.x + filterBox.width <= noticeBox.x + 1, "The filter appears to the left of the partial-scan notice");
    await shop.getByRole("combobox").selectOption("unavailable-image");
    const hidden = shop.locator('li[data-category="unavailable-image"]').filter({hasText: /display:\s*none/i});
    assert.equal(await hidden.count(), 1);
    assert.equal(await hidden.locator(".pg-url,button").count(), 0);
    await page.locator("#link .a3s").evaluate(body => body.replaceChildren(document.createTextNode("Hello")));
    await checkSummary("link", "Partial scan", "rgb(214, 226, 226)");
    const header = shop.locator(".pg-summary:visible");
    assert.equal(await shop.locator("summary:visible, .pg-chevron:visible").count(), 0);
    await header.click();
    await page.keyboard.press("Enter");
    await page.keyboard.press("Space");
    assert.equal(await shop.getAttribute("open"), null, "An empty bar cannot expand");
    assert.equal(await shop.getByRole("combobox").count(), 0, "The previous filter disappears with the last finding");
    await shop.evaluate(node => {
      const before = document.createElement("button");
      const after = document.createElement("button");
      after.id = "after-clean-bar";
      node.before(before);
      node.after(after);
      before.focus();
    });
    await page.mouse.move(0, 0);
    await page.keyboard.press("Tab");
    const emptyInfo = shop.getByRole("button", {name: "About this partial scan", exact: true});
    const emptyTip = shop.getByRole("tooltip", {includeHidden: true});
    assert.equal(await emptyInfo.evaluate(el => document.activeElement === el), true);
    await emptyTip.waitFor();
    assert.equal(await shop.getAttribute("open"), null);
    await page.keyboard.press("Tab");
    assert.equal(await page.evaluate(() => document.activeElement.id), "after-clean-bar");
    await emptyTip.waitFor({state: "hidden"});

    await page.locator("#link .a3s").evaluate(body => {
      const img = new Image(180, 48);
      img.src = "https://cdn.example.test/logo.png";
      body.append(img);
    });
    await checkSummary("link", logoSummary, colorFor["external-image"]);
    assert.equal(await shop.getAttribute("open"), null, "New findings start collapsed");
    await shop.locator("summary").focus();
    await page.keyboard.press("Enter");
    await shop.locator('li[data-category="external-image"]').waitFor();
    await page.locator("#link .a3s img").evaluate(img => img.remove());
    await checkSummary("link", "Partial scan", "rgb(214, 226, 226)");
    assert.equal(await shop.locator("summary:visible, .pg-chevron:visible").count(), 0);
    assert.equal(await shop.getAttribute("open"), null, "The open list closes when Gmail removes its last row");
    await page.goto("https://example.test/");
    assert.equal(await page.locator(".pixelguard-gmail").count(), 0);
    await checkBadge(probe, tabId, "");
    console.log("PASS", ctx.browser().version());
  } finally {
    await ctx.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
