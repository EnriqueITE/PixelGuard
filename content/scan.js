/* global browser, messenger, PixelGuardScanner */
(() => {
  const API = (typeof browser !== "undefined") ? browser : (typeof messenger !== "undefined" ? messenger : null);
  const THROTTLE_MS = 400;
  let currentDomain = "";
  let lastBanner = null;
  let debugEnabled = false;

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
    return globalThis.PixelGuardScanner.scanDocument(doc, { senderDomain: currentDomain });
  }

  function removeBanner() {
    if (lastBanner && lastBanner.isConnected) lastBanner.remove();
    lastBanner = null;
  }

  function formatItem(it) {
    const host = it.host || "?";
    const reason = it.reason ? ` [${it.confidence || "low"}: ${it.reason}]` : "";
    const safe = (it.url || "").slice(0, 200);
    return `${host}${reason} - ${safe}`;
  }

  function addFindingsSection(banner, title, items, limit = 20) {
    if (!items || items.length === 0) return;
    const wrap = document.createElement("div");
    wrap.className = "pixelguard-extwrap";
    const details = document.createElement("details");
    details.className = "pixelguard-details";
    const summary = document.createElement("summary");
    const label = document.createElement("span");
    label.className = "pg-accent";
    label.textContent = title;
    const badge = document.createElement("span");
    badge.className = "pg-badge";
    badge.textContent = String(items.length);
    summary.appendChild(label);
    summary.appendChild(document.createTextNode(" "));
    summary.appendChild(badge);

    const list = document.createElement("ul");
    list.className = "pixelguard-list";
    for (const it of items.slice(0, limit)) {
      const li = document.createElement("li");
      li.textContent = formatItem(it);
      list.appendChild(li);
    }
    if (items.length > limit) {
      const li = document.createElement("li");
      li.textContent = `... +${items.length - limit} more`;
      list.appendChild(li);
    }
    details.appendChild(summary);
    details.appendChild(list);
    wrap.appendChild(details);
    banner.appendChild(wrap);
  }

  async function renderBanner(findings) {
    removeBanner();

    const banner = document.createElement("div");
    banner.className = "pixelguard-banner";
    banner.setAttribute("role", "region");
    banner.setAttribute("aria-label", t("banner_ariaLabel"));
    banner.style.cssText = [
      "position: sticky",
      "top: 0",
      "z-index: 2147483647",
      "background: #0b0d0f",
      "color: #e6f1ef",
      "border: 1px solid #1f2a2f",
      "border-left: 4px solid #00e676",
      "border-radius: 8px",
      "padding: 10px 12px",
      "margin: 8px 0",
      "box-shadow: 0 6px 18px rgba(0,0,0,0.35)"
    ].join("; ");

    const activityCount = findings.suspicious.length + findings.links.length;
    const header = document.createElement("div");
    header.className = "pg-header";
    const left = document.createElement("div");
    left.className = "pg-left";
    const icon = document.createElement("span");
    icon.className = "pg-icon";
    icon.textContent = "PG";
    const title = document.createElement("div");
    const strongName = document.createElement("strong");
    strongName.textContent = t("extensionName");
    title.appendChild(strongName);
    title.appendChild(document.createTextNode(`: ${t("banner_detected", String(activityCount))}`));
    left.appendChild(icon);
    left.appendChild(title);
    const closeBtn = document.createElement("button");
    closeBtn.className = "pg-close";
    closeBtn.setAttribute("aria-label", t("banner_dismiss"));
    closeBtn.textContent = "x";
    closeBtn.addEventListener("click", removeBanner);
    header.appendChild(left);
    header.appendChild(closeBtn);
    banner.appendChild(header);

    addFindingsSection(banner, t("banner_suspiciousImagesTitle"), findings.suspicious);
    addFindingsSection(banner, t("banner_externalImagesTitle"), findings.externals);
    addFindingsSection(banner, t("banner_trackingLinksTitle"), findings.links);

    const actions = document.createElement("div");
    actions.className = "pixelguard-actions";
    const moreBtn = document.createElement("button");
    moreBtn.className = "pixelguard-btn primary";
    moreBtn.style.borderRadius = "6px";
    moreBtn.style.border = "1px solid #0b7";
    moreBtn.style.padding = "6px 10px";
    moreBtn.style.background = "#0c8";
    moreBtn.style.color = "#082017";
    moreBtn.style.cursor = "pointer";
    moreBtn.textContent = t("banner_moreInfo");
    moreBtn.addEventListener("click", () => API.runtime.openOptionsPage());
    actions.appendChild(moreBtn);
    banner.appendChild(actions);

    const host = document.body || document.documentElement;
    host.insertBefore(banner, host.firstChild);
    lastBanner = banner;

    try { await API.runtime.sendMessage({ type: "pg:detectedCount", count: findings.suspicious.length }); } catch (_) {}
  }

  function throttle(fn, wait) {
    let timer = null;
    return function (...args) {
      if (timer) return;
      timer = setTimeout(() => { timer = null; fn.apply(this, args); }, wait);
    };
  }

  const doScan = throttle(async () => {
    const st = await (API?.runtime?.sendMessage ? API.runtime.sendMessage({ type: "pg:getState" }) : Promise.resolve({}));
    const debug = !!st?.debug;
    debugEnabled = debug;
    debugLog("[PG/cs] scanning...");
    const findings = scan(document);
    debugLog("[PG/cs] results", findings);
    if (findings.suspicious.length > 0 || findings.externals.length > 0 || findings.links.length > 0 || debug) await renderBanner(findings); else removeBanner();
  }, THROTTLE_MS);

  const mo = new MutationObserver(doScan);
  mo.observe(document, { childList: true, subtree: true });

  (API?.runtime || browser.runtime).onMessage.addListener((msg) => {
    if (msg?.type === "pg:context") {
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
      const res = await API.runtime.sendMessage({ type: "pg:hello" });
      if (res?.ok) {
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
