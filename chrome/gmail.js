/* global chrome, PixelGuardScanner, PixelGuardVTInventory, PixelGuardGmailOriginal, PixelGuardGmailAttachments, PixelGuardOriginalScan, PixelGuardOriginalMime */
(() => {
  if (globalThis.pixelGuardGmailAttached || !location.pathname.startsWith("/mail/")) return;
  globalThis.pixelGuardGmailAttached = true;
  const messageSelector = ".adn, [data-message-id], [data-legacy-message-id]";
  const bodySelector = ".a3s";
  const messages = new Map();
  const dirty = new Set();
  const lifetime = new AbortController();
  const extensionId = chrome.runtime.id;
  const iconUrl = chrome.runtime.getURL("assets/icon-48.png");
  const popupUrl = chrome.runtime.getURL("popup.html");
  let refreshTimer, preferenceTimer;
  let vtSelection, vtSelectionTimer;
  const originalPage = new URL(location.href).searchParams.get("view") === "om";
  let originalPageRecord;
  const maxOriginalReads = 2;
  let activeOriginalReads = 0;
  const pageSize = 3;
  let showPanel = false;
  let theme = "light";
  const attachments = PixelGuardGmailAttachments.create(openVirusTotal, contextActive);
  const t = (key, ...values) => chrome.i18n.getMessage(key, values);
  // Show the highest-priority group first, also used for the summary's accent.
  const categories = {
    "tracking-pixel": ["gmailPixel", "gmailPixels"],
    "suspicious-image": ["gmailImage", "gmailImages"],
    "tracking-link": ["gmailLink", "gmailLinks"],
    "external-image": ["gmailExternalImage", "gmailExternalImages"]
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

  function partialScanHelp() {
    const help = element("span", "pg-partial-help");
    help.hidden = true;
    const info = button("");
    info.className = "pg-partial-info";
    info.setAttribute("aria-label", t("gmailPartialInfo"));
    const tip = element("span", "pg-partial-tip");
    tip.hidden = true;
    tip.id = "pixelguard-tip-" + crypto.randomUUID();
    tip.setAttribute("role", "tooltip");
    info.setAttribute("aria-describedby", tip.id);
    help.append(info, tip);
    function show() {
      tip.hidden = false;
      const bar = help.closest(".pg-summary").getBoundingClientRect();
      const icon = info.getBoundingClientRect();
      const left = Math.min(icon.left, bar.right - tip.offsetWidth - 4);
      const above = icon.bottom + tip.offsetHeight > innerHeight && icon.top >= tip.offsetHeight;
      tip.style.left = Math.max(4, left - bar.left) + "px";
      tip.style.top = (above ? icon.top - tip.offsetHeight : icon.bottom) - bar.top + "px";
    }
    help.addEventListener("pointerenter", show);
    help.addEventListener("pointerleave", () => { if (!info.matches(":focus-visible")) tip.hidden = true; });
    info.addEventListener("focus", show);
    info.addEventListener("blur", () => { tip.hidden = true; });
    help.addEventListener("click", event => {
      event.preventDefault();
      event.stopPropagation();
      show();
    });
    return help;
  }

  function createPanel(onFullScan) {
    const panel = element("div", "pixelguard-gmail");
    panel.dataset.theme = theme;
    const summary = element("div", "pg-summary");
    const logo = element("img");
    logo.alt = "";
    logo.src = iconUrl;
    const status = element("span", "pg-status");
    status.setAttribute("role", "status");
    const statusGroup = element("span");
    const partialHelp = partialScanHelp();
    statusGroup.append(status, partialHelp);
    const chevron = element("i", "pg-chevron");
    chevron.setAttribute("aria-hidden", "true");
    const originalButton = button(t("gmailRetryScan"));
    originalButton.className = "pg-full-scan";
    originalButton.hidden = true;
    if (onFullScan) originalButton.addEventListener("click", event => {
      event.preventDefault();
      event.stopPropagation();
      if (event.isTrusted) onFullScan();
    });
    summary.append(logo, element("strong", "", "PixelGuard"), statusGroup, originalButton, chevron);
    const tools = element("div", "pg-tools");
    const originalBar = element("div", "pg-original");
    const originalStatus = element("span");
    originalStatus.setAttribute("role", "status");
    originalBar.append(originalStatus);
    originalBar.hidden = true;
    const filter = element("select", "pg-filter");
    filter.setAttribute("aria-label", t("gmailFilterLabel"));
    for (const value of Object.keys(filterLabels)) {
      const option = element("option");
      option.value = value;
      filter.append(option);
    }
    const list = element("ul", "pg-list");
    const empty = element("div", "pg-empty", t("gmailNoMatches"));
    empty.setAttribute("role", "status");
    const footer = element("div", "pg-pager");
    const prev = button(t("gmailPrevious"));
    const next = button(t("gmailNext"));
    const range = element("span", "pg-range");
    range.setAttribute("aria-live", "polite");
    footer.append(range, prev, next);
    tools.append(filter, originalBar);
    const results = element("div", "pg-results");
    results.hidden = true;
    results.append(tools, list, empty, footer);
    panel.append(summary, results);
    const state = {panel, summary, status, partialHelp, results, originalBar, originalButton, originalStatus, filter, list, empty, footer, prev, next, range, entries: [], page: 0};
    filter.addEventListener("change", () => { state.page = 0; drawPage(state); });
    prev.addEventListener("click", () => { state.page--; drawPage(state); });
    next.addEventListener("click", () => { state.page++; drawPage(state); });
    return state;
  }

  function setPartialHelp(state, explanation) {
    const tip = state.partialHelp.querySelector(".pg-partial-tip");
    state.partialHelp.hidden = !explanation;
    if (!explanation) tip.hidden = true;
    else if (tip.textContent !== explanation) tip.textContent = explanation;
  }

  function setExpandable(state, expandable) {
    if (state.panel.matches("details") === expandable) return;
    const panel = element(expandable ? "details" : "div", "pixelguard-gmail");
    panel.dataset.theme = theme;
    const summary = element(expandable ? "summary" : "div", "pg-summary");
    summary.append(...state.summary.childNodes);
    panel.append(summary, state.results);
    state.panel.replaceWith(panel);
    state.panel = panel;
    state.summary = summary;
  }

  function anchorLabel(anchor) {
    const text = anchor.textContent.trim() || anchor.querySelector("img[alt]")?.alt || anchor.getAttribute("aria-label") || "";
    return /^https?:\/\//i.test(text) ? "" : text.replace(/\s+/g, " ").trim().slice(0, 180);
  }

  function explicitHiddenReason(img) {
    if (img.style.display === "none") return t("reason_displayNone");
    if (img.style.visibility === "hidden") return t("reason_visibilityHidden");
    if (parseFloat(img.style.opacity) === 0) return t("reason_opacityZero");
    if (img.hasAttribute("hidden")) return t("gmailHiddenAttribute");
    return "";
  }

  function clearVtSelection() {
    clearTimeout(vtSelectionTimer);
    vtSelection = null;
  }

  async function openVirusTotal(event, payload, panel) {
    const control = event.currentTarget;
    if (!event.isTrusted || !contextActive() || !control.isConnected) return;
    if (control.nextElementSibling?.matches(".pg-vt-notice")) control.nextElementSibling.remove();
    clearVtSelection();
    const selection = {payload, panel, page: location.href};
    vtSelection = selection;
    // Only the opening widget can take this short-lived selection. The worker opens it without the URL.
    vtSelectionTimer = setTimeout(clearVtSelection, 30000);
    control.disabled = true;
    try {
      const result = await chrome.runtime.sendMessage({type: "pg:gmail:openVirusTotal"});
      if (!result?.ok) throw new Error("Widget unavailable");
    } catch {
      if (vtSelection === selection) clearVtSelection();
      if (contextActive() && control.isConnected) {
        const notice = element("span", "pg-vt-notice", t("gmailVtOpenFailed"));
        notice.setAttribute("role", "status");
        control.after(notice);
      }
    } finally {
      control.disabled = false;
    }
  }

  function drawPage(state) {
    if (!contextActive()) return;
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
        if (!contextActive() || !copy.isConnected) return;
        try {
          await navigator.clipboard.writeText(item.url);
        } catch {
          if (!contextActive() || !copy.isConnected) return;
          const selection = window.getSelection();
          selection.selectAllChildren(url);
          copy.textContent = t("gmailSelected");
          return;
        }
        if (contextActive() && copy.isConnected) copy.textContent = t("gmailCopied");
      });
      const detail = element("div", "pg-row-foot");
      const actions = element("div", "pg-row-actions");
      actions.append(copy);
      const target = PixelGuardVTInventory.validUrl(item.url);
      if (target) {
        const vt = button("VirusTotal");
        vt.title = t("gmailVtOpen");
        vt.addEventListener("click", event => openVirusTotal(event, {url: target.href}, state.panel));
        actions.append(vt);
      }
      detail.append(element("span", "", reason), actions);
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

  function render(state, body, result, original) {
    const onlyVisible = Boolean(body && !original);
    const partial = onlyVisible || result.partial;
    const items = [...result.suspicious, ...result.links, ...result.externals];
    const counts = new Map();
    for (const item of items) counts.set(item.classification, (counts.get(item.classification) || 0) + 1);
    // With images disabled Gmail may preserve the img and strip its source.
    const sources = ["src", "srcset", "data-src", "data-srcset", "data-original", "data-lazy", "data-lazy-src", "data-url"];
    const unavailable = body && (!original || original.result.partial) ? [...body.querySelectorAll("img")].filter(img =>
      !sources.some(attr => img.getAttribute(attr)?.trim())) : [];
    const missing = unavailable.length;
    const hasEntries = items.length + missing > 0;
    setExpandable(state, hasEntries);
    state.results.hidden = !hasEntries;
    if (!hasEntries) state.filter.value = "all";
    if (state.expandAfterRetry && hasEntries) state.panel.open = true;
    state.expandAfterRetry = false;
    state.missing = missing;
    counts.set("unavailable-image", missing);
    const totals = [];
    for (const [type, labels] of Object.entries(categories)) {
      const count = counts.get(type);
      if (!count) continue;
      const total = element("span", "pg-total", count + " " + t(labels[count === 1 ? 0 : 1]));
      total.dataset.category = type;
      totals.push(total);
    }
    state.summary.dataset.category = totals[0]?.dataset.category || (missing ? "unavailable-image" : "");
    setPartialHelp(state, partial && t(onlyVisible ? "gmailPartialExplanation" : "gmailPartialCoverage"));
    if (partial) totals.push(t("gmailPartial"));
    else if (!result.suspicious.length && !result.links.length) {
      totals.unshift(t(!body && original?.plainText ? "gmailPlainSource" : "gmailNoSignals"));
    }
    state.status.replaceChildren(...totals.flatMap((total, index) => index ? [" · ", total] : [total]));
    for (const option of state.filter.options) {
      const count = option.value === "all" ? items.length + missing : counts.get(option.value) || 0;
      option.textContent = t(filterLabels[option.value]) + " (" + count + ")";
      option.disabled = count === 0 && option.value !== "all" && !option.selected;
      option.hidden = option.value === "unavailable-image" && !missing && !option.selected;
    }
    state.filter.hidden = !hasEntries;
    const labels = new Map(original?.labels);
    const unlabeled = new Set(items.filter(item => !labels.has(item.url)).map(item => item.url));
    if (body && unlabeled.size) {
      for (const a of body.querySelectorAll("a[href]")) {
        const href = a.getAttribute("href");
        if (!unlabeled.has(href)) continue;
        const label = anchorLabel(a);
        if (label) {
          labels.set(href, label);
          unlabeled.delete(href);
        }
      }
      for (const img of body.querySelectorAll("img[src][alt]")) {
        const src = originalImage(img.getAttribute("src"));
        if (unlabeled.has(src) && img.alt.trim()) {
          labels.set(src, img.alt.trim().slice(0, 180));
          unlabeled.delete(src);
        }
      }
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
      const size = /^\d{1,5}$/.test(width) && /^\d{1,5}$/.test(height) ? width + " × " + height + " px" : "";
      const hiddenReason = explicitHiddenReason(img);
      const reason = [hiddenReason, size].filter(Boolean).join(" · ");
      state.entries.push({item: {classification: "unavailable-image"}, label, reason});
    });
    drawPage(state);
  }

  function visibleBodies() {
    return [...document.querySelectorAll(bodySelector)].filter(body =>
      body.closest(messageSelector) && !body.parentElement.closest(bodySelector) &&
      !body.closest('[contenteditable]:not([contenteditable="false"]), [g_editable="true"], [role="textbox"], [aria-hidden="true"], [hidden], [inert]') &&
      body.getClientRects().length && getComputedStyle(body).visibility === "visible");
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
      parts.push({hrefs, text: text.join("\n")});
    }
    const inventory = PixelGuardVTInventory.collectLinks(parts);
    return {links: inventory.links.map(({url}) => ({url, label: labels.get(url) || ""})), truncated: inventory.truncated};
  }

  let lastCounts = "";
  async function updateBadge(suspicious, externals, links, scanning = false) {
    const counts = scanning ? "scanning" : [suspicious, externals, links].join(",");
    if (counts === lastCounts) return;
    lastCounts = counts;
    try {
      await chrome.runtime.sendMessage({type: "pg:badge", suspicious, externals, links, scanning});
    } catch {
      if (lastCounts === counts) lastCounts = "";
      contextActive();
    }
  }

  function originalControls(entry) {
    if (!entry.view) return;
    const {originalBar, originalButton, originalStatus, missing} = entry.view;
    originalButton.hidden = !entry.failed;
    originalButton.disabled = entry.retryState === "pending";
    let text = "";
    if (entry.retryState === "failed") text = t("gmailFullScanFailed");
    else if (missing) text = missing === 1 ? t("gmailUnavailableImageAddress") : t("gmailUnavailableImages", String(missing));
    else if (entry.failed) text = t("gmailOriginalFailed");
    originalBar.hidden = !text;
    if (originalStatus.textContent !== text) originalStatus.textContent = text;
    if (text && !entry.view.panel.hasAttribute("data-scanning")) entry.view.results.hidden = false;
  }

  function requestFullScan(body, entry) {
    if (!contextActive() || !entry.failed || entry.request || entry.retryState === "pending" || messages.get(body) !== entry ||
        !body.isConnected || PixelGuardGmailOriginal.messageId(body) !== entry.id) return;
    entry.retryState = "pending";
    entry.view.expandAfterRetry = true;
    refresh();
  }

  function combineWithOriginal(visible, original) {
    return original ? PixelGuardScanner.mergeResults([original.result, visible]) : visible;
  }

  async function analyzeOriginal(body, entry) {
    const request = new AbortController();
    const retry = entry.retryState === "pending";
    activeOriginalReads++;
    entry.request = request;
    const timeout = setTimeout(() => request.abort(), 20000);
    try {
      const source = await PixelGuardGmailOriginal.read(entry.id, request.signal, body, contextActive);
      request.signal.throwIfAborted();
      if (!contextActive() || !body.isConnected || messages.get(body) !== entry ||
          PixelGuardGmailOriginal.messageId(body) !== entry.id) return;
      entry.original = PixelGuardOriginalScan.scan(source, entry.senderDomain);
      entry.result = combineWithOriginal(entry.result, entry.original);
      entry.failed = false;
      if (entry.view && (retry || entry.view.filter.value === "unavailable-image")) {
        entry.view.filter.value = "all";
        entry.view.page = 0;
      }
    } catch {
      if (!contextActive() || messages.get(body) !== entry) return;
      entry.failed = true;
    } finally {
      clearTimeout(timeout);
      entry.request = null;
      entry.retryState = retry && entry.failed ? "failed" : null;
      activeOriginalReads--;
      scheduleRefresh();
    }
  }

  // Gmail also exposes the full MIME as text on its own “Show original” page.
  function refreshOriginalPage() {
    const raw = document.querySelector("pre.raw_message_text");
    if (!raw) {
      originalPageRecord?.view?.panel.remove();
      originalPageRecord = null;
      updateBadge(0, 0, 0);
      return;
    }
    if (originalPageRecord?.node !== raw || originalPageRecord.needsScan) {
      originalPageRecord?.view?.panel.remove();
      originalPageRecord = {node: raw};
      try {
        const source = PixelGuardOriginalMime.bodyParts(raw.textContent);
        originalPageRecord.scan = PixelGuardOriginalScan.scan(source);
      } catch { /* The original view reports unsupported input below. */ }
    }
    const record = originalPageRecord;
    const result = record.scan?.result;
    updateBadge(result?.suspicious.length || 0, result?.externals.length || 0, result?.links.length || 0);
    if (showPanel && !record.view) {
      const view = createPanel();
      if (result) {
        render(view, null, result, record.scan);
      } else {
        view.status.textContent = t("gmailOriginalUnsupported");
        view.filter.hidden = view.footer.hidden = view.empty.hidden = true;
      }
      raw.before(view.panel);
      record.view = view;
    } else if (!showPanel && record.view) {
      record.view.panel.remove();
      record.view = null;
    }
  }

  function refresh() {
    clearTimeout(refreshTimer);
    refreshTimer = undefined;
    if (!contextActive()) return;
    if (originalPage) {
      refreshOriginalPage();
      return;
    }
    const visible = new Set(visibleBodies());
    attachments.refresh(theme);
    let suspicious = 0, externals = 0, links = 0;
    let tabScanning = false;
    for (const body of visible) {
      const message = body.closest(messageSelector);
      const sender = message.querySelector(".gD[email]");
      const senderDomain = sender && !body.contains(sender) ? sender.getAttribute("email").split("@").pop() : "";
      const id = PixelGuardGmailOriginal.messageId(body);
      let entry = messages.get(body);
      if (!entry || entry.id !== id) {
        entry?.request?.abort();
        entry?.view?.panel.remove();
        entry = {id};
        messages.set(body, entry);
      }
      const updated = !entry.result || dirty.has(body) || entry.senderDomain !== senderDomain;
      if (updated) {
        const visibleResult = PixelGuardScanner.scanDocument(body, {senderDomain, resolveImageUrl: originalImage});
        entry.result = combineWithOriginal(visibleResult, entry.original);
        entry.senderDomain = senderDomain;
      }
      const result = entry.result;
      const scanning = !!id && !entry.original && (!entry.failed || entry.retryState === "pending");
      if (scanning) tabScanning = true;
      suspicious += result.suspicious.length;
      externals += result.externals.length;
      links += result.links.length;
      if (showPanel) {
        const mount = !entry.view;
        if (mount) entry.view = createPanel(() => requestFullScan(body, entry));
        if (entry.view.panel.parentElement !== body.parentElement) body.before(entry.view.panel);
        const view = entry.view;
        if (updated || mount || scanning !== view.panel.hasAttribute("data-scanning")) {
          view.results.setAttribute("aria-busy", String(scanning));
          if (scanning) {
            setExpandable(view, false);
            view.results.hidden = true;
            setPartialHelp(view, false);
            view.summary.removeAttribute("data-category");
            const label = t("gmailFullScanRunning");
            if (view.status.textContent !== label) view.status.textContent = label;
          } else {
            render(view, body, result, entry.original);
          }
          view.panel.toggleAttribute("data-scanning", scanning);
          originalControls(entry);
        }
      } else if (entry.view) {
        entry.view.panel.remove();
        entry.view = null;
      }
    }
    for (const [body, entry] of messages) {
      if (visible.has(body)) continue;
      entry.request?.abort();
      entry.view?.panel.remove();
      messages.delete(body);
    }
    dirty.clear();
    updateBadge(suspicious, externals, links, tabScanning);

    if (document.hidden) return;
    for (const [body, entry] of messages) {
      if (activeOriginalReads >= maxOriginalReads) break;
      if (entry.id && !entry.request && !entry.original &&
          (!entry.failed || entry.retryState === "pending")) {
        analyzeOriginal(body, entry);
      }
    }
  }

  // Chromium can leave this world and its DOM handlers alive after an extension reload.
  function contextActive() {
    if (lifetime.signal.aborted) return false;
    try {
      if (chrome.runtime?.id === extensionId) return true;
    } catch { /* An invalidated context can also throw when accessing the API. */ }
    lifetime.abort();
    observer.disconnect();
    clearTimeout(refreshTimer);
    clearTimeout(preferenceTimer);
    clearVtSelection();
    attachments.clear();
    for (const entry of messages.values()) {
      entry.request?.abort();
      entry.view?.panel.remove();
    }
    originalPageRecord?.view?.panel.remove();
    originalPageRecord = null;
    messages.clear();
    dirty.clear();
    return false;
  }

  function scheduleRefresh() {
    if (contextActive() && refreshTimer === undefined) refreshTimer = setTimeout(refresh, 25);
  }
  const observer = new MutationObserver(records => {
    if (!contextActive()) return;
    let changed = false;
    for (const record of records) {
      const el = record.target.nodeType === 1 ? record.target : record.target.parentElement;
      if (!el || el.closest(".pixelguard-gmail")) continue;
      if (originalPageRecord?.node.contains(el) && record.type !== "attributes") {
        originalPageRecord.needsScan = true;
      }
      const body = el.closest(bodySelector);
      if (body) dirty.add(body);
      changed = true;
    }
    if (changed) scheduleRefresh();
  });
  observer.observe(document.documentElement, {
    subtree: true, childList: true, characterData: true, attributes: true,
    attributeFilter: ["class", "hidden", "inert", "aria-hidden", "style", "src", "srcset", "data-src",
      "data-original", "data-lazy", "data-lazy-src", "data-url", "data-srcset", "href",
      "download_url", "download", "height", "width", "alt", "aria-label", "role", "data-message-id", "data-legacy-message-id", "email", "contenteditable", "g_editable"]
  });
  const listenerOptions = {signal: lifetime.signal};
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    for (const {view} of messages.values()) {
      if (view && !view.partialHelp.hidden) {
        const tip = view.partialHelp.querySelector(".pg-partial-tip");
        if (!tip.hidden) {
          tip.hidden = true;
          event.stopPropagation();
        }
      }
    }
  }, {capture: true, signal: lifetime.signal});
  function clearMessageSelection() { clearVtSelection(); attachments.clear(); }
  window.addEventListener("hashchange", () => { clearMessageSelection(); scheduleRefresh(); }, listenerOptions);
  window.addEventListener("pagehide", clearMessageSelection, listenerOptions);
  window.addEventListener("pageshow", event => {
    if (event.persisted) { lastCounts = ""; scheduleRefresh(); }
  }, listenerOptions);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scheduleRefresh();
  }, listenerOptions);
  // An extension reload invalidates the old script, but the page keeps its DOM.
  for (const panel of document.querySelectorAll(".pixelguard-gmail")) {
    if (panel.querySelector(":scope > :is(summary, .pg-summary) > img")?.getAttribute("src") === iconUrl) panel.remove();
  }
  for (const control of document.querySelectorAll(".pixelguard-attachment-action")) {
    if (!control.closest(".a3s")) control.remove();
  }
  let receivedPreference = false;
  function applyPreferences(preferences) {
    receivedPreference = true;
    showPanel = preferences.showPanel === true;
    theme = preferences.theme === "dark" ? "dark" : "light";
    for (const entry of messages.values()) {
      if (entry.view) entry.view.panel.dataset.theme = theme;
    }
    if (originalPageRecord?.view) originalPageRecord.view.panel.dataset.theme = theme;
    refresh();
  }
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (!contextActive() || sender.id !== extensionId) return;
    if (message.type === "pg:gmail:ping") {
      reply({ready: true});
    } else if (message.type === "pg:gmail:links") {
      reply(linkInventory());
    } else if (message.type === "pg:gmail:attachments") {
      if (sender.url?.split("#")[0] !== popupUrl) return;
      attachments.refresh(theme);
      reply({attachments: attachments.list()});
    } else if (message.type === "pg:gmail:takeVtSelection") {
      if (sender.url?.split("#")[0] !== popupUrl) return;
      const selection = vtSelection;
      clearVtSelection();
      const valid = selection?.page === location.href && selection.panel.isConnected &&
        (!selection.payload.attachment || attachments.find(selection.payload.attachment.id));
      reply(valid ? selection.payload : {url: null});
    } else if (message.type === "pg:panelChanged") {
      applyPreferences(message);
    }
  });
  chrome.runtime.onConnect.addListener(port => {
    if (port.name !== "pg:gmail:attachment") return;
    if (!contextActive() || port.sender?.id !== extensionId || port.sender.url?.split("#")[0] !== popupUrl) {
      port.disconnect();
      return;
    }
    attachments.connect(port);
  });
  const preferenceRetries = [250, 1000, 4000];
  async function loadPreference(attempt = 0) {
    if (receivedPreference || !contextActive()) return;
    try {
      const result = await chrome.runtime.sendMessage({type: "pg:panel"});
      if (result?.ok && !receivedPreference && contextActive()) applyPreferences(result);
    } catch { /* A worker that is reloading may temporarily have no receiver. */ }
    if (!receivedPreference && contextActive() && attempt < preferenceRetries.length) {
      preferenceTimer = setTimeout(loadPreference, preferenceRetries[attempt], attempt + 1);
    }
  }
  loadPreference();
})();
