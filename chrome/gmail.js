/* global chrome, PixelGuardScanner, PixelGuardVTInventory */
(() => {
  if (globalThis.pixelGuardGmailAttached || !location.pathname.startsWith("/mail/")) return;
  globalThis.pixelGuardGmailAttached = true;
  const messageSelector = ".adn, [data-message-id], [data-legacy-message-id]";
  const bodySelector = ".a3s";
  const messages = new Map();
  const dirty = new Set();
  const pageSize = 3;
  let showPanel = false;
  const t = (key, ...values) => chrome.i18n.getMessage(key, values);
  // Show the highest-priority group first, also used for the summary's accent.
  const categories = {
    "tracking-pixel": ["gmailPixel", "gmailPixels"],
    "suspicious-image": ["gmailImage", "gmailImages"],
    "tracking-link": ["gmailLink", "gmailLinks"],
    "external-image": ["gmailExternalImage", "gmailExternalImages"],
    "unavailable-image": ["gmailMissingImage", "gmailMissingImages"]
  };
  const filterLabels = {
    all: "gmailAllFindings",
    "tracking-pixel": "gmailFilterPixels",
    "suspicious-image": "gmailFilterSuspects",
    "tracking-link": "gmailFilterLinks",
    "external-image": "gmailFilterExternal",
    "unavailable-image": "gmailFilterUnavailable"
  };
  const signalKeys = {
    "explicit 1x1 image": "reason_onePixel", "tiny image": "reason_tiny",
    "display:none image": "reason_displayNone", "visibility:hidden image": "reason_visibilityHidden",
    "opacity:0 image": "reason_opacityZero", "explicit zero-size image": "reason_zeroSize",
    "recipient id parameter": "reason_recipient", "open tracking parameter": "reason_openParameter",
    "open path": "reason_openPath", "tracking path keyword": "reason_trackingPath",
    "tracking host keyword": "reason_trackingHost", "marketing campaign params only": "gmailCampaign",
    "marketing campaign params": "gmailCampaign", "sender-owned host": "reason_senderHost",
    "tracking/redirect path": "reason_redirectPath", "tracking link host": "reason_linkHost",
    "tracking parameter": "reason_trackingParameter"
  };

  function originalImage(raw) {
    // Gmail sometimes retains the original absolute URL after the proxy fragment.
    // Keep an opaque proxy URL intact. Never dereference it.
    if (!/^https:\/\/ci\d*\.googleusercontent\.com\/(?:meips|proxy)\//i.test(raw)) return raw;
    const fragment = raw.slice(raw.indexOf("#") + 1);
    return raw.includes("#") && /^https?:\/\//i.test(fragment) ? fragment : raw;
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function button(label) {
    const control = element("button", "", label);
    control.type = "button";
    return control;
  }

  function createPanel() {
    const panel = element("details", "pixelguard-gmail");
    const summary = element("summary");
    const logo = element("img");
    logo.alt = "";
    logo.src = chrome.runtime.getURL("assets/icon-48.png");
    const status = element("span", "pg-status");
    const chevron = element("i", "pg-chevron");
    chevron.setAttribute("aria-hidden", "true");
    summary.append(logo, element("strong", "", "PixelGuard"), status, chevron);
    const note = element("p", "pg-note");
    const filterBar = element("label", "pg-filter");
    const filter = element("select");
    for (const value of Object.keys(filterLabels)) {
      const option = element("option");
      option.value = value;
      filter.append(option);
    }
    filterBar.append(element("span", "", t("gmailFilterLabel")), filter);
    const list = element("ul", "pg-list");
    const empty = element("div", "pg-empty", t("gmailNoMatches"));
    empty.setAttribute("role", "status");
    const footer = element("div", "pg-pager");
    const prev = button(t("gmailPrevious"));
    const next = button(t("gmailNext"));
    const range = element("span", "pg-range");
    range.setAttribute("aria-live", "polite");
    footer.append(range, prev, next);
    panel.append(summary, note, filterBar, list, empty, footer);
    const state = {panel, summary, status, note, filterBar, filter, list, empty, footer, prev, next, range, entries: [], page: 0};
    filter.addEventListener("change", () => { state.page = 0; drawPage(state); });
    prev.addEventListener("click", () => { state.page--; drawPage(state); });
    next.addEventListener("click", () => { state.page++; drawPage(state); });
    return state;
  }

  function anchorLabel(anchor) {
    const text = anchor.textContent.trim() || anchor.querySelector("img[alt]")?.alt || anchor.getAttribute("aria-label") || "";
    return /^https?:\/\//i.test(text) ? "" : text.replace(/\s+/g, " ").trim().slice(0, 180);
  }

  function drawPage(state) {
    const {filter, list, footer, prev, next, range} = state;
    const entries = filter.value === "all" ? state.entries :
      state.entries.filter(({item}) => item.classification === filter.value);
    const pages = Math.max(1, Math.ceil(entries.length / pageSize));
    state.page = Math.max(0, Math.min(pages - 1, state.page));
    const start = state.page * pageSize;
    const rows = document.createDocumentFragment();
    for (const {item, label, reason} of entries.slice(start, start + pageSize)) {
      const li = element("li");
      li.dataset.category = item.classification;
      const head = element("div", "pg-row-head");
      const type = item.classification === "unavailable-image" ? "gmailUnavailableImage" :
        categories[item.classification]?.[0] || "reason_externalImage";
      head.append(element("small", "pg-kind", t(type)), element("b", "", label || item.host));
      li.append(head);
      if (!item.url) {
        if (reason) li.append(element("div", "pg-row-foot", reason));
        rows.append(li);
        continue;
      }
      const url = element("code", "pg-url", item.url);
      url.dir = "ltr";
      const copy = button(t("gmailCopy"));
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(item.url);
          copy.textContent = t("gmailCopied");
        } catch {
          const selection = window.getSelection();
          selection.selectAllChildren(url);
          copy.textContent = t("gmailSelected");
        }
      });
      const detail = element("div", "pg-row-foot");
      detail.append(element("span", "", reason), copy);
      li.append(url, detail);
      rows.append(li);
    }
    list.replaceChildren(rows);
    state.empty.hidden = entries.length > 0 || filter.value === "all";
    footer.hidden = pages === 1;
    prev.disabled = state.page === 0;
    next.disabled = state.page === pages - 1;
    if (pages > 1) range.textContent = t("gmailRange", String(start + 1), String(Math.min(start + pageSize, entries.length)), String(entries.length));
  }

  function render(state, body, result) {
    const items = [...result.suspicious, ...result.links, ...result.externals];
    const counts = new Map();
    for (const item of items) counts.set(item.classification, (counts.get(item.classification) || 0) + 1);
    // With images disabled Gmail may preserve the img and strip its source.
    const sources = ["src", "srcset", "data-src", "data-srcset", "data-original", "data-lazy", "data-lazy-src", "data-url"];
    const unavailable = [...body.querySelectorAll("img")].filter(img =>
      !sources.some(attr => img.getAttribute(attr)?.trim()));
    const missing = unavailable.length;
    counts.set("unavailable-image", missing);
    const totals = [];
    for (const [type, labels] of Object.entries(categories)) {
      const count = counts.get(type);
      if (!count) continue;
      const total = element("span", "pg-total", count + " " + t(labels[count === 1 ? 0 : 1]));
      total.dataset.category = type;
      totals.push(total);
    }
    state.summary.dataset.category = totals[0]?.dataset.category || "";
    if (!result.suspicious.length && !result.links.length && !missing) totals.unshift(t("gmailNoSignals"));
    if (missing) totals.push(element("span", "", t("gmailPartial")));
    state.status.replaceChildren(...totals.flatMap((total, index) => index ? [" · ", total] : [total]));
    state.note.textContent = missing ? t("gmailUnavailableImages", String(missing)) : "";
    for (const option of state.filter.options) {
      const count = option.value === "all" ? items.length + missing : counts.get(option.value) || 0;
      option.textContent = t(filterLabels[option.value]) + " (" + count + ")";
      option.disabled = count === 0 && option.value !== "all" && !option.selected;
      option.hidden = option.value === "unavailable-image" && !missing && !option.selected;
    }
    state.filterBar.hidden = !items.length && !missing && state.filter.value === "all";
    const labels = new Map();
    for (const a of body.querySelectorAll("a[href]")) {
      const label = anchorLabel(a);
      if (label) labels.set(a.getAttribute("href"), label);
    }
    for (const img of body.querySelectorAll("img[src][alt]")) {
      if (img.alt.trim()) labels.set(originalImage(img.getAttribute("src")), img.alt.trim().slice(0, 180));
    }
    state.entries = items.map(item => {
      const reasons = item.signals.filter(signal => signalKeys[signal]).map(signal => t(signalKeys[signal]));
      if (!reasons.length && item.classification === "external-image") reasons.push(t("reason_visibleRemote"));
      return {item, label: labels.get(item.url), reason: reasons.join(" · ")};
    });
    unavailable.forEach((img, index) => {
      const description = [img.alt, img.getAttribute("aria-label"), img.title].find(text => text?.trim());
      const label = description?.trim().slice(0, 180) || t("gmailUnnamedImage", String(index + 1));
      const width = img.getAttribute("width");
      const height = img.getAttribute("height");
      const reason = /^\d{1,5}$/.test(width) && /^\d{1,5}$/.test(height) ? width + " × " + height + " px" : "";
      state.entries.push({item: {classification: "unavailable-image"}, label, reason});
    });
    drawPage(state);
  }

  function visibleBodies() {
    return [...document.querySelectorAll(bodySelector)].filter(body =>
      body.closest(messageSelector) && !body.parentElement.closest(bodySelector) &&
      !body.closest('[contenteditable="true"], [g_editable="true"], [role="textbox"], [aria-hidden="true"]') &&
      body.getClientRects().length);
  }

  function linkInventory() {
    const parts = [];
    const labels = new Map();
    for (const body of visibleBodies()) {
      const hrefs = [];
      for (const a of body.querySelectorAll("a[href]")) {
        const url = PixelGuardVTInventory.validUrl(a.getAttribute("href"));
        if (!url) continue;
        hrefs.push(url.href);
        const label = anchorLabel(a);
        if (label) labels.set(url.href, label);
      }
      const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
      const text = [];
      while (walker.nextNode()) text.push(walker.currentNode.nodeValue);
      parts.push({contentType: "text/html", body: {hrefs, text: text.join("\n")}});
    }
    const inventory = PixelGuardVTInventory.collectLinks({parts}, parsed => parsed);
    return {links: inventory.links.map(({url}) => ({url, label: labels.get(url) || ""})), truncated: inventory.truncated};
  }

  let lastCounts = "";
  function updateBadge(suspicious, externals, links) {
    const counts = [suspicious, externals, links].join(",");
    if (counts === lastCounts) return;
    lastCounts = counts;
    chrome.runtime.sendMessage({type: "pg:badge", suspicious, externals, links}).catch(() => {
      if (lastCounts === counts) lastCounts = "";
    });
  }

  function refresh() {
    scheduled = false;
    if (!chrome.runtime.id) {
      observer.disconnect();
      return;
    }
    const visible = new Set(visibleBodies());
    let suspicious = 0, externals = 0, links = 0;
    for (const body of visible) {
      const message = body.closest(messageSelector);
      const sender = message.querySelector(".gD[email]");
      const senderDomain = sender && !body.contains(sender) ? sender.getAttribute("email").split("@").pop() : "";
      let entry = messages.get(body);
      if (!entry) {
        entry = {};
        messages.set(body, entry);
      }
      const updated = !entry.result || dirty.has(body) || entry.senderDomain !== senderDomain;
      if (updated) {
        entry.result = PixelGuardScanner.scanDocument(body, {senderDomain, resolveImageUrl: originalImage});
        entry.senderDomain = senderDomain;
      }
      suspicious += entry.result.suspicious.length;
      externals += entry.result.externals.length;
      links += entry.result.links.length;
      if (showPanel) {
        const mount = !entry.view;
        if (mount) entry.view = createPanel();
        if (entry.view.panel.parentElement !== body.parentElement) body.before(entry.view.panel);
        if (updated || mount) render(entry.view, body, entry.result);
      } else if (entry.view) {
        entry.view.panel.remove();
        entry.view = null;
      }
    }
    for (const [body, entry] of messages) {
      if (visible.has(body)) continue;
      entry.view?.panel.remove();
      messages.delete(body);
    }
    dirty.clear();
    updateBadge(suspicious, externals, links);
  }

  let scheduled = false;
  function scheduleRefresh() {
    if (scheduled) return;
    scheduled = true;
    setTimeout(refresh, 25);
  }
  const observer = new MutationObserver(records => {
    let changed = false;
    for (const record of records) {
      const el = record.target.nodeType === 1 ? record.target : record.target.parentElement;
      if (!el || el.closest(".pixelguard-gmail")) continue;
      const body = el.closest(bodySelector);
      if (body) dirty.add(body);
      changed = true;
    }
    if (changed) scheduleRefresh();
  });
  observer.observe(document.documentElement, {
    subtree: true, childList: true, characterData: true, attributes: true,
    attributeFilter: ["class", "hidden", "aria-hidden", "style", "src", "srcset", "data-src",
      "data-original", "data-lazy", "data-lazy-src", "data-url", "data-srcset", "href",
      "height", "width", "alt", "aria-label", "role", "data-message-id", "data-legacy-message-id", "email", "contenteditable", "g_editable"]
  });
  window.addEventListener("hashchange", scheduleRefresh);
  window.addEventListener("pageshow", event => {
    if (event.persisted) { lastCounts = ""; scheduleRefresh(); }
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scheduleRefresh();
  });
  // An extension reload invalidates the old script, but the page keeps its DOM.
  for (const panel of document.querySelectorAll("details.pixelguard-gmail")) {
    if (panel.querySelector("summary > img")?.getAttribute("src") === chrome.runtime.getURL("assets/icon-48.png")) panel.remove();
  }
  let receivedPreference = false;
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (sender.id !== chrome.runtime.id) return;
    if (message.type === "pg:gmail:ping") {
      reply({ready: true});
    } else if (message.type === "pg:gmail:links") {
      reply(linkInventory());
    } else if (message.type === "pg:panelChanged") {
      receivedPreference = true;
      showPanel = message.showPanel === true;
      refresh();
    }
  });
  async function loadPreference() {
    for (const wait of [0, 250, 1000, 4000]) {
      if (wait) await new Promise(resolve => setTimeout(resolve, wait));
      if (receivedPreference || !chrome.runtime.id) return;
      try {
        const result = await chrome.runtime.sendMessage({type: "pg:panel"});
        if (result?.ok && !receivedPreference) {
          receivedPreference = true;
          showPanel = result.showPanel === true;
          refresh();
          return;
        }
      } catch { /* A worker that is reloading may temporarily have no receiver. */ }
    }
  }
  loadPreference();
})();
