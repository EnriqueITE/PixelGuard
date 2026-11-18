/* global browser, messenger, PixelGuardScanner */
(() => {
  // Registration retries or manual injection must not create competing observers.
  if (globalThis.PixelGuardScanDocument === document) return;
  globalThis.PixelGuardScanDocument = document;
  const API = (typeof browser !== "undefined") ? browser : (typeof messenger !== "undefined" ? messenger : null);
  const THROTTLE_MS = 400;
  let currentDomain = "";
  let lastBanner = null;
  let debugEnabled = false;
  let dismissed = false;
  let lastActivityCount = null;
  let currentMessageId = null;
  let contextVersion = 0;
  const ownedBanners = new WeakSet();

  function isOwnNode(node) {
    for (let current = node; current; current = current.parentNode) {
      if (ownedBanners.has(current)) return true;
    }
    return false;
  }

  function debugLog(...args) {
    if (!debugEnabled) return;
    try { console.log(...args); } catch (_) {}
  }

  function t(key, ...subs) {
    try { return API?.i18n?.getMessage(key, subs) || key; } catch (_) { return key; }
  }

  function scan(doc) {
    if (!globalThis.PixelGuardScanner?.scanDocument) {
      return { suspicious: [], externals: [], links: [] };
    }
    return globalThis.PixelGuardScanner.scanDocument(doc, {
      senderDomain: currentDomain, excludeNode: isOwnNode
    });
  }

  function removeBanner() {
    if (lastBanner && lastBanner.isConnected) lastBanner.remove();
    lastBanner = null;
    lastActivityCount = null;
  }

  function renderBanner(activityCount, text) {
    if (!document.body) return;
    if (lastBanner?.isConnected && activityCount === lastActivityCount) return;
    removeBanner();

    const banner = document.createElement("div");
    ownedBanners.add(banner);
    banner.className = "pixelguard-banner";
    banner.setAttribute("role", "region");
    banner.setAttribute("aria-label", text?.title || t("banner_ariaLabel"));
    if (text?.lang) banner.setAttribute("lang", text.lang);
    // The host stays in the normal reading flow, even if the email styles divs.
    banner.style.cssText = [
      "all: initial !important",
      "position: static !important",
      "display: flex !important",
      "align-items: center !important",
      "gap: 6px !important",
      "box-sizing: border-box !important",
      "width: max-content !important",
      "max-width: 100% !important",
      "padding: 2px 6px !important",
      "margin: 0 0 4px !important",
      "border-inline-start: 2px solid GrayText !important",
      "background: Canvas !important",
      "color: CanvasText !important",
      "font: 13px/1.4 system-ui, sans-serif !important"
    ].join("; ");

    // Keep email styles away from the label and the dismiss button.
    const shadow = banner.attachShadow({ mode: "closed" });
    const label = document.createElement("span");
    label.textContent = t("extensionName") + ": " + (text ? text.label.replace('{count}', String(activityCount)) : t("banner_detected", String(activityCount)));
    label.style.cssText = "min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis";
    label.title = label.textContent;
    const closeBtn = document.createElement("button");
    closeBtn.className = "pg-close";
    closeBtn.type = "button";
    closeBtn.title = text?.dismiss || t("banner_dismiss");
    closeBtn.setAttribute("aria-label", closeBtn.title);
    closeBtn.textContent = "×";
    closeBtn.style.cssText = "flex: none; font: inherit; line-height: 1; min-width: 24px; min-height: 24px; cursor: pointer";
    closeBtn.addEventListener("click", () => {
      dismissed = true;
      removeBanner();
    });
    shadow.appendChild(label);
    shadow.appendChild(closeBtn);

    document.body.insertBefore(banner, document.body.firstChild);
    lastBanner = banner;
    lastActivityCount = activityCount;
  }

  function throttle(fn, wait) {
    let timer = null;
    return function (...args) {
      if (timer) return;
      timer = setTimeout(() => { timer = null; fn.apply(this, args); }, wait);
    };
  }

  const doScan = throttle(async () => {
    const version = contextVersion;
    const st = await (API?.runtime?.sendMessage ? API.runtime.sendMessage({ type: "pg:getState" }) : Promise.resolve({}));
    if (version !== contextVersion) return;
    const showBanner = st?.showInlineBanner === true && !dismissed;
    debugEnabled = !!st?.debug;
    if (!showBanner) {
      removeBanner();
      // The background independently computes the popup, badge and counters.
      if (!debugEnabled) return;
    }
    debugLog("[PG/cs] scanning...");
    const findings = scan(document);
    debugLog("[PG/cs] results", findings);
    const activityCount = findings.suspicious.length + findings.links.length;
    if (showBanner && activityCount > 0) renderBanner(activityCount, st.bannerText);
    else removeBanner();
  }, THROTTLE_MS);

  const mo = new MutationObserver(records => {
    const changed = records.some(record => {
      if (isOwnNode(record.target)) return false;
      // Insertion/removal records target the parent, often the message body.
      const nodes = [...record.addedNodes, ...record.removedNodes];
      return nodes.some(node => !isOwnNode(node));
    });
    if (changed) doScan();
  });
  mo.observe(document, { childList: true, subtree: true });

  (API?.runtime || browser.runtime).onMessage.addListener((msg) => {
    if (msg?.type === "pg:inlineBannerChanged") {
      contextVersion++;
      removeBanner();
      if (msg.value === true) doScan();
      return;
    }
    if (msg?.type === "pg:context") {
      if (msg.messageId != null && currentMessageId != null && msg.messageId !== currentMessageId) {
        dismissed = false;
        removeBanner();
      }
      currentMessageId = msg.messageId ?? currentMessageId;
      contextVersion++;
      currentDomain = msg.domain || "";
      debugLog("[PG/cs] context domain", currentDomain);
      doScan();
    }
  });

  document.addEventListener("DOMContentLoaded", doScan);
  window.addEventListener("load", doScan);
  setTimeout(doScan, 300);
  setTimeout(doScan, 900);
  setTimeout(doScan, 1800);
  debugLog("[PG/cs] loaded", { apiAlias: !!API });

  (async () => {
    try {
      const version = contextVersion;
      const res = await API.runtime.sendMessage({ type: "pg:hello" });
      if (res?.ok && version === contextVersion) {
        currentMessageId = res.messageId ?? currentMessageId;
        if (res.domain) {
          currentDomain = res.domain;
          debugLog("[PG/cs] hello->domain", currentDomain);
        }
        if (res.settings?.debug) {
          debugLog("[PG/cs] settings", res.settings);
        }
        doScan();
      }
    } catch (e) {
      debugLog("[PG/cs] hello failed", String(e));
    }
  })();
})();
