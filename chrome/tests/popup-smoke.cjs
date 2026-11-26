// Exercises the real popup in Chromium with a fake worker and optional permission prompt.
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
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
      const fixture = JSON.parse(sessionStorage.getItem("rowFixture") || "{}");
      const state = { ok: true, hasKey: false, showPanel: true, vtEnabled: false, ...fixture.state };
      window.testState = { granted: false, lookups: [], permissionRequests: 0, settings: [], inventory: 0, mail: [],
        reads: [], reports: [], uploads: [] };
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
          async sendMessage(id, {type}, target) {
            test.mail.push({type, id, frameId: target.frameId});
            if (type === "pg:gmail:takeVtSelection") {
              if (fixture.hold) await new Promise(resolve => { window.releaseRow = resolve; });
              return {url: fixture.url, attachment: fixture.attachment};
            }
            if (type === "pg:gmail:attachments") {
              if (fixture.holdInventory) await new Promise(resolve => { window.releaseInventory = resolve; });
              if (fixture.unavailable) throw new Error("Gmail content script unavailable");
              return {attachments: fixture.attachments || []};
            }
            if (type !== "pg:gmail:links") throw new Error("Unexpected Gmail message");
            test.inventory++;
            return { links: test.links };
          },
          connect(id, target) {
            const event = () => {
              const handlers = new Set();
              return {addListener: fn => handlers.add(fn), removeListener: fn => handlers.delete(fn),
                fire: value => handlers.forEach(fn => fn(value))};
            };
            const onMessage = event(), onDisconnect = event();
            let open = true;
            return {onMessage, onDisconnect, disconnect() { open = false; },
              postMessage(message) {
                test.reads.push({id: message.id, tab: id, ...target});
                const file = fixture.attachments.find(item => item.id === message.id);
                const deliver = () => {
                  if (!open) return;
                  onMessage.fire({name: file.name, size: file.body.length});
                  onMessage.fire({chunk: btoa(file.body)});
                  onMessage.fire({done: true});
                };
                if (file.hold) window.deliverFile = deliver;
                else queueMicrotask(deliver);
              }};
          }
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
          if (msg.type === "pg:attachmentReport") {
            test.reports.push(msg);
            const result = {status: fixture.report || "no_report", queriedAt: Date.now()};
            if (fixture.report === "error") return {ok: false, error: "network"};
            if (fixture.report === "reported") Object.assign(result, {detections: 1, total: 75});
            return {ok: true, result, uploadToken: result.status === "no_report" ? "fixture-grant" : undefined};
          }
          if (msg.type === "pg:uploadAttachment") {
            const bytes = await (await fetch(msg.blobUrl)).text();
            test.uploads.push({name: msg.name, hash: msg.hash, confirmed: msg.confirmed, token: msg.uploadToken, bytes});
            return {ok: true, analysisId: "fixture-accepted"};
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
    await q("lookup").waitFor();
    const address = page.getByRole("combobox", { name: catalog.pgLinkAddress.message, exact: true });
    const attachmentSelect = page.getByRole("combobox", {name: catalog.pgAttachments.message, exact: true});
    const localFileButton = q("choose-local-file");
    const list = page.getByRole("listbox");
    await attachmentSelect.locator("option").filter({hasText: catalog.pgNoAttachments.message}).waitFor({state: "attached"});
    assert.ok(await attachmentSelect.isVisible());
    assert.ok(await attachmentSelect.isDisabled());
    assert.ok(await localFileButton.isVisible());
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

    const rowImage = "https://pixel.example.test/open.gif?id=customer-42#image";
    let visit = 0;
    async function openWidget(fixture, hash = "") {
      await page.evaluate(fixture => sessionStorage.setItem("rowFixture", JSON.stringify(fixture)), fixture);
      await page.goto("https://popup.example.test/popup.html?visit=" + ++visit + hash);
    }
    await openWidget({url: rowImage, state: {hasKey: true, vtEnabled: true}}, "#tab=42");
    await page.waitForFunction(url => document.querySelector("#url").value === url, rowImage);
    assert.equal(await address.inputValue(), rowImage);
    assert.equal(await address.getAttribute("title"), rowImage);
    assert.equal(await picked.innerText(), rowImage);
    await q("show-links").click();
    await list.getByRole("option", {name: rowImage, exact: true}).waitFor();
    await list.getByRole("option", {name: sample, exact: true}).click();
    assert.equal(await address.inputValue(), sample, "The row handoff keeps the regular link picker");
    const mailCalls = await page.evaluate(() => testState.mail);
    assert.deepEqual(new Set(mailCalls.map(call => call.type)), new Set([
      "pg:gmail:takeVtSelection", "pg:gmail:links", "pg:gmail:attachments"
    ]));
    assert.ok(mailCalls.every(call => call.id === 42 && call.frameId === 0));
    await q("preview-url").click();
    assert.equal(await q("exact-url").innerText(), sample);
    assert.deepEqual(await page.evaluate(() => testState.lookups), []);

    const enabled = {hasKey: true, vtEnabled: true};
    const attachments = [
      {id: "a1", name: "document.pdf", body: "abc"},
      {id: "a2", name: "document.pdf", body: "second file"}
    ];
    const hash = file => createHash("sha256").update(file.body).digest("hex");
    const secondHash = hash(attachments[1]);
    await openWidget({state: enabled, attachments, holdInventory: true});
    await address.waitFor();
    await attachmentSelect.waitFor();
    assert.equal(await attachmentSelect.locator("option:checked").textContent(), catalog.pgLoadingAttachments.message);
    assert.ok(await attachmentSelect.isDisabled());
    await q("show-links").click();
    await list.getByRole("option", {name: sample, exact: true}).click();
    assert.equal(await address.inputValue(), sample, "Links work while the attachment list is loading");
    await page.evaluate(() => window.releaseInventory());
    await attachmentSelect.locator('option[value="a2"]').waitFor({state: "attached"});
    assert.deepEqual(await attachmentSelect.locator("option").allTextContents(),
      [catalog.pgChooseAttachment.message, "document.pdf (1)", "document.pdf (2)"]);
    const visibleWithoutScrolling = node => {
      const bounds = node.getBoundingClientRect();
      return bounds.height > 0 && bounds.top >= 0 && bounds.bottom <= innerHeight && scrollY === 0;
    };
    assert.ok(await address.evaluate(visibleWithoutScrolling) && await attachmentSelect.evaluate(visibleWithoutScrolling),
      "Both selectors are visible at launch without scrolling or switching modes");
    assert.equal(await attachmentSelect.inputValue(), "");
    assert.ok(await q("query-hash").isDisabled());
    await attachmentSelect.selectOption("a2");
    assert.deepEqual(await page.evaluate(() => [testState.reads, testState.reports, testState.lookups, testState.uploads]),
      [[], [], [], []], "Opening the toolbar and selecting suggestions stays local and does not read attachment bytes");
    await q("query-hash").click();
    await q("upload-confirmation").waitFor();
    assert.equal(await q("attachment-sha").innerText(), secondHash);
    assert.equal(await q("upload-file-name").innerText(), "document.pdf · 11 B");
    assert.deepEqual(await page.evaluate(() => testState.reports), [{type: "pg:attachmentReport", hash: secondHash}]);
    assert.deepEqual(await page.evaluate(() => testState.reads),
      [{id: "a2", tab: 1, name: "pg:gmail:attachment", frameId: 0}]);
    await q("cancel-upload").click();
    await q("upload-confirmation").waitFor({state: "hidden"});
    assert.deepEqual(await page.evaluate(() => testState.uploads), []);
    await q("query-hash").click();
    await q("confirm-upload").click();
    await q("result-title").filter({hasText: catalog.pgFileSubmitted.message}).waitFor();
    assert.deepEqual(await page.evaluate(() => testState.uploads),
      [{hash: secondHash, name: "document.pdf", confirmed: true, token: "fixture-grant", bytes: "second file"}]);
    assert.equal(await q("report").getAttribute("href"), "https://www.virustotal.com/gui/file/" + secondHash);

    await openWidget({state: enabled, unavailable: true});
    await attachmentSelect.locator("option").filter({hasText: catalog.pgAttachmentsUnavailable.message}).waitFor({state: "attached"});
    assert.ok(await attachmentSelect.isVisible() && await attachmentSelect.isDisabled());
    assert.ok(await address.isVisible() && await localFileButton.isVisible());
    assert.ok(await q("query-hash").isDisabled());
    assert.deepEqual(await page.evaluate(() => [testState.reads, testState.lookups, testState.reports]), [[], [], []]);

    const unusual = {id: "odd", name: "A/B\\C\u0003" + "x".repeat(501) + "📧".repeat(12) + ".pdf", body: "abc"};
    const uploadName = "A_B_C_" + "x".repeat(501) + ".pdf";
    await openWidget({state: enabled, attachment: unusual, attachments: [unusual]});
    await q("upload-confirmation").waitFor();
    assert.equal(await q("attachments").locator("option:checked").textContent(), unusual.name);
    assert.equal(await q("upload-file-name").innerText(), uploadName + " · 3 B");
    await q("confirm-upload").click();
    await q("result-title").filter({hasText: catalog.pgFileSubmitted.message}).waitFor();
    assert.equal(await page.evaluate(() => testState.uploads[0].name), uploadName);

    const handoff = {id: "a1", name: "document.pdf"};
    await openWidget({state: {hasKey: true}, attachments, attachment: handoff, report: "reported"});
    await q("status").filter({hasText: catalog.pgEnableAttachmentVT.message}).waitFor();
    assert.deepEqual(await page.evaluate(() => testState.reads), []);
    await page.evaluate(() => { testState.granted = true; });
    await q("vt-toggle").click();
    await q("report").waitFor();
    assert.equal(await q("attachments").inputValue(), "a1");
    assert.equal(await q("attachment-sha").innerText(), hash(attachments[0]));
    assert.equal(await q("upload-confirmation").isVisible(), false);

    await openWidget({state: enabled, attachments, attachment: handoff, report: "error"});
    await q("status").filter({hasText: catalog.vt_error_network.message}).waitFor();
    assert.equal(await q("upload-confirmation").isVisible(), false, "A failed lookup cannot offer upload");
    await openWidget({state: enabled, attachments: [{...attachments[0], hold: true}, attachments[1]], attachment: handoff});
    await page.waitForFunction(() => typeof window.deliverFile === "function");
    await attachmentSelect.selectOption("a2");
    await page.evaluate(() => window.deliverFile());
    assert.deepEqual(await page.evaluate(() => testState.reports), [], "Changing attachments cancels the previous read");
    assert.equal(await q("attachment-digest").isVisible(), false);
    const [localChooser] = await Promise.all([page.waitForEvent("filechooser"), localFileButton.click()]);
    await localChooser.setFiles({name: "local.txt", mimeType: "text/plain", buffer: Buffer.from("abc")});
    assert.equal(await attachmentSelect.inputValue(), "", "Choosing a local file replaces the previous Gmail attachment");
    assert.ok((await q("local-filename").innerText()).includes("local.txt"));
    await q("query-hash").click();
    await q("result").waitFor();
    assert.deepEqual(await page.evaluate(() => testState.lookups),
      [{type: "pg:lookup", kind: "hash", value: hash(attachments[0]), confirmed: false}]);
    assert.equal(await q("upload-confirmation").isVisible(), false, "Local files keep their hash-only path");
    await attachmentSelect.selectOption("a2");
    await q("query-hash").click();
    await q("upload-confirmation").waitFor();
    assert.equal(await q("attachment-sha").textContent(), secondHash, "Selecting Gmail again clears the local file");
    await address.fill(manual);
    await q("query-domain").click();
    await q("result").waitFor();
    assert.ok(!await q("upload-confirmation").isVisible(), "Changing the URL clears the attachment upload offer");
    assert.equal(await q("attachment-digest").isVisible(), false);
    assert.deepEqual(await page.evaluate(() => testState.lookups.at(-1)),
      {type: "pg:lookup", kind: "domain", value: "manual.example.test", confirmed: false});
    assert.deepEqual(await page.evaluate(() => testState.uploads), []);

    await openWidget({url: rowImage});
    await q("key-form").waitFor();
    assert.equal(await q("lookup").isVisible(), false);
    assert.equal(await q("status").innerText(), catalog.pgRowEnableVT.message);
    await q("key").fill("0123456789abcdef".repeat(4));
    await q("save-key").click();
    await q("manage").waitFor();
    assert.equal(await q("vt-toggle").isChecked(), false);
    assert.equal(await page.evaluate(() => testState.permissionRequests), 0);
    await page.evaluate(() => { testState.granted = true; });
    await q("vt-toggle").click();
    await address.waitFor();
    assert.equal(await address.inputValue(), rowImage, "Manual setup preserves the chosen URL");
    assert.deepEqual(await page.evaluate(() => testState.lookups), []);
    assert.equal(await page.evaluate(() => testState.mail[0].id), 1);

    await openWidget({url: rowImage, state: {hasKey: true, vtEnabled: true}, hold: true});
    await address.fill(manual);
    await page.evaluate(() => window.releaseRow());
    assert.equal(await address.inputValue(), manual, "A late row handoff can't replace an edit");
    assert.deepEqual(await page.evaluate(() => testState.lookups), []);

    assert.deepEqual(errors, []);
    assert.deepEqual(outbound, [], "The popup never opens a selected or hovered email URL");
    console.log("PASS settings, URL and attachment handoffs, hash checks, upload consent, stale reads and local files");
  } finally { await browser.close(); }
}
run().catch(err => { console.error(err); process.exitCode = 1; });
