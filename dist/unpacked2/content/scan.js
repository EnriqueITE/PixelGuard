/* global browser */
(() => {
  const THROTTLE_MS = 400;
  let currentDomain = "";
  let lastBanner = null;

  function t(key, ...subs) {
    try { return browser.i18n.getMessage(key, subs) || key; } catch (_) { return key; }
  }

  function tryURL(u) { try { return new URL(u); } catch (_) { return null; } }

  function hasSuspiciousParams(u) {
    if (!u) return false;
    const keys = ["uid","token","open","track","pixel","beacon","campaign_id","recipient","subscriber","message_id","signature","rid","cid","utm_source","utm_medium","utm_campaign"]; 
    return keys.some(k => u.searchParams.has(k));
  }

  function looksTinyOrHidden(img) {
    const w = (img.getAttribute("width") || img.style.width || "");
    const h = (img.getAttribute("height") || img.style.height || "");
    const bb = img.getBoundingClientRect();
    const tinyAttr = (parseInt(w, 10) <= 2 && w !== "") || (parseInt(h, 10) <= 2 && h !== "");
    const tinyBox = (bb.width <= 2 && bb.height <= 2);
    const style = getComputedStyle(img);
    const hidden = style.display === "none" || style.visibility === "hidden" || parseFloat(style.opacity || "1") === 0;
    return tinyAttr || tinyBox || hidden;
  }

  function isRemote(img) {
    const src = img.getAttribute("src") || "";
    return /^https?:\/\//i.test(src);
  }

  function scan(doc) {
    const list = [];
    const imgs = doc.querySelectorAll("img");
    for (const img of imgs) {
      if (!isRemote(img)) continue;
      const src = img.getAttribute("src");
      const u = tryURL(src);
      if (!u) continue;
      const tinyHidden = looksTinyOrHidden(img);
      const suspicious = tinyHidden || hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname);
      if (suspicious) {
        list.push({ url: src, reason: tinyHidden ? "tiny/hidden" : hasSuspiciousParams(u) ? "tracking-param" : "path" });
      }
    }
    // dedupe by URL
    const seen = new Set();
    return list.filter(x => (seen.has(x.url) ? false : (seen.add(x.url), true)));
  }

  function removeBanner() {
    if (lastBanner && lastBanner.isConnected) lastBanner.remove();
    lastBanner = null;
  }

  async function renderBanner(findings) {
    removeBanner();

    const banner = document.createElement("div");
    banner.className = "pixelguard-banner";
    banner.setAttribute("role", "region");
    banner.setAttribute("aria-label", t("banner_ariaLabel"));

    const count = findings.length;
    const title = document.createElement("div");
    const name = t("extensionName");
    title.innerHTML = `<strong>${name}</strong>: ${t("banner_detected", String(count))}`;

    const actions = document.createElement("div");
    actions.className = "pixelguard-actions";

    const allowBtn = document.createElement("button");
    allowBtn.className = "pixelguard-btn";
    allowBtn.textContent = t("banner_allowDomain", currentDomain || t("unknownDomain"));
    allowBtn.addEventListener("click", async () => {
      if (!currentDomain) return;
      await browser.runtime.sendMessage({ type: "pg:addWhitelist", domain: currentDomain });
      removeBanner();
    });

    const blockToggle = document.createElement("button");
    blockToggle.className = "pixelguard-btn warn";
    blockToggle.textContent = t("banner_toggleBlock");
    blockToggle.addEventListener("click", async () => {
      const res = await browser.runtime.sendMessage({ type: "pg:toggleBlock" });
      blockToggle.textContent = res.blockMode ? t("banner_blockActive") : t("banner_blockInactive");
    });

    const moreBtn = document.createElement("button");
    moreBtn.className = "pixelguard-btn primary";
    moreBtn.textContent = t("banner_moreInfo");
    moreBtn.addEventListener("click", () => browser.runtime.openOptionsPage());

    actions.appendChild(allowBtn);
    actions.appendChild(blockToggle);
    actions.appendChild(moreBtn);

    banner.appendChild(title);
    banner.appendChild(actions);

    const host = document.body || document.documentElement;
    host.insertBefore(banner, host.firstChild);
    lastBanner = banner;

    // report detected count to background (for badge)
    try { await browser.runtime.sendMessage({ type: "pg:detectedCount", count }); } catch (_) {}
  }

  // Throttle helper
  function throttle(fn, wait) {
    let timer = null;
    return function (...args) {
      if (timer) return;
      timer = setTimeout(() => { timer = null; fn.apply(this, args); }, wait);
    };
  }

  const doScan = throttle(async () => {
    // skip scanning if current sender domain is whitelisted
    const st = await browser.runtime.sendMessage({ type: "pg:getState" });
    if (st?.whitelist?.includes((currentDomain || "").toLowerCase())) {
      removeBanner();
      return;
    }
    const findings = scan(document);
    if (findings.length > 0) await renderBanner(findings); else removeBanner();
  }, THROTTLE_MS);

  // React to message DOM changes (Thunderbird re-renders message DOM)
  const mo = new MutationObserver(doScan);
  mo.observe(document, { childList: true, subtree: true });

  // Receive context (sender domain) from background
  browser.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "pg:context") {
      currentDomain = msg.domain || "";
      doScan();
    }
  });

  // Initial scan
  document.addEventListener("DOMContentLoaded", doScan);
  window.addEventListener("load", doScan);
})();

