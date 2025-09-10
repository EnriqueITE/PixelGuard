/* global browser, messenger */
(() => {
  const API = (typeof browser !== 'undefined') ? browser : (typeof messenger !== 'undefined' ? messenger : null);
  const THROTTLE_MS = 400;
  let currentDomain = "";
  let lastBanner = null;

  function t(key, ...subs) {
    try { return API?.i18n?.getMessage(key, subs) || key; } catch (_) { return key; }
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
    const suspicious = [];
    const externals = [];
    const linkFindings = [];
    const imgs = doc.querySelectorAll("img");
    for (const img of imgs) {
      if (!isRemote(img)) continue;
      const src = img.getAttribute("src");
      const u = tryURL(src);
      if (!u) continue;
      const tinyHidden = looksTinyOrHidden(img);
      const isSuspicious = tinyHidden || hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname);
      if (isSuspicious) {
        suspicious.push({ url: src, reason: tinyHidden ? "tiny/hidden" : hasSuspiciousParams(u) ? "tracking-param" : "path" });
      } else {
        externals.push({ url: src, host: u.hostname });
      }

      // srcset candidates
      const srcset = img.getAttribute('srcset') || '';
      if (srcset) {
        const parts = srcset.split(',');
        for (const p of parts) {
          const cand = (p.trim().split(/\s+/)[0] || '').trim();
          if (!/^https?:\/\//i.test(cand)) continue;
          const cu = tryURL(cand);
          if (!cu) continue;
          const susp = hasSuspiciousParams(cu) || /\b(pixel|beacon|track|open)\b/i.test(cu.pathname);
          if (susp) suspicious.push({ url: cand, reason: 'srcset' }); else externals.push({ url: cand, host: cu.hostname });
        }
      }

      // Lazy-load data-* attributes
      const lazyAttrs = ['data-src','data-original','data-lazy','data-lazy-src','data-url','data-srcset'];
      for (const an of lazyAttrs) {
        const v = img.getAttribute(an);
        if (!v) continue;
        if (an.endsWith('srcset')) {
          const parts = v.split(',');
          for (const p of parts) {
            const cand = (p.trim().split(/\s+/)[0] || '').trim();
            if (!/^https?:\/\//i.test(cand)) continue;
            const cu = tryURL(cand);
            if (!cu) continue;
            const susp = hasSuspiciousParams(cu) || /\b(pixel|beacon|track|open)\b/i.test(cu.pathname);
            if (susp) suspicious.push({ url: cand, reason: 'data-srcset' }); else externals.push({ url: cand, host: cu.hostname });
          }
        } else if (/^https?:\/\//i.test(v)) {
          const cu = tryURL(v);
          if (cu) {
            const susp = hasSuspiciousParams(cu) || /\b(pixel|beacon|track|open)\b/i.test(cu.pathname);
            if (susp) suspicious.push({ url: v, reason: 'data-src' }); else externals.push({ url: v, host: cu.hostname });
          }
        }
      }
    }

    // Inline CSS background-image URLs
    const withStyle = doc.querySelectorAll('[style*="url("]');
    for (const el of withStyle) {
      const style = el.getAttribute('style') || '';
      const urls = Array.from(style.matchAll(/url\(([^)]+)\)/gi)).map(m => (m[1] || '').replace(/["']/g, '').trim());
      for (const raw of urls) {
        if (!/^https?:\/\//i.test(raw)) continue;
        const u = tryURL(raw);
        if (!u) continue;
        const susp = hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname);
        if (susp) suspicious.push({ url: raw, reason: 'css-bg' }); else externals.push({ url: raw, host: u.hostname });
      }
    }
    // Scan links for tracking patterns (unsubscribe/click/utm/trace etc.)
    const anchors = doc.querySelectorAll('a[href]');
    for (const a of anchors) {
      const href = a.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) continue;
      const u = tryURL(href);
      if (!u) continue;
      const host = u.hostname.toLowerCase();
      const path = u.pathname || '';
      const params = u.searchParams;
      const trackParamKeys = [
        // common marketing/tracking params
        'utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid','msclkid','mc_cid','mc_eid','mkt_tok','oly_anon_id','oly_enc_id','vero_id','hsenc','hsmi','spm','clickid','trace','tracelog','rid','cid','uid','token','signature'
      ];
      const hasTrackParam = trackParamKeys.some(k => params.has(k));
      const pathSuspicious = /\b(unsubscribe|click|track|redirect|trk|link)\b/i.test(path);
      const hostSuspicious = /\b(trk|click|email|link)\b/i.test(host);
      if (hasTrackParam || pathSuspicious || hostSuspicious) {
        linkFindings.push({ url: href, host, reason: hasTrackParam ? 'param' : pathSuspicious ? 'path' : 'host' });
      }
    }

    // Also scan plain text for URLs (marketing emails sometimes render raw URLs)
    try {
      const urlRegex = /(https?:\/\/[\w\-._~%!$&'()*+,;=:@/?#\[\]]+)/gi;
      let checked = 0;
      const walker = doc.createTreeWalker(doc.body || doc, NodeFilter.SHOW_TEXT, null);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        const text = node.nodeValue || '';
        if (!text || !/https?:\/\//i.test(text)) continue;
        // Safety limits
        if (checked++ > 500) break;
        const matches = text.match(urlRegex) || [];
        for (const raw of matches.slice(0, 50)) {
          const u = tryURL(raw);
          if (!u) continue;
          const host = u.hostname.toLowerCase();
          const path = u.pathname || '';
          const params = u.searchParams;
          const trackParamKeys = ['utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid','msclkid','mc_cid','mc_eid','mkt_tok','oly_anon_id','oly_enc_id','vero_id','hsenc','hsmi','spm','clickid','trace','tracelog','rid','cid','uid','token','signature'];
          const hasTrackParam = trackParamKeys.some(k => params.has(k));
          const pathSuspicious = /\b(unsubscribe|click|track|redirect|trk|link)\b/i.test(path);
          const hostSuspicious = /\b(trk|click|email|link)\b/i.test(host);
          if (hasTrackParam || pathSuspicious || hostSuspicious) {
            linkFindings.push({ url: raw, host, reason: hasTrackParam ? 'param' : pathSuspicious ? 'path' : 'host' });
          }
        }
      }
    } catch (_) { /* ignore walker errors */ }

    // dedupe by URL
    const dedupe = arr => {
      const seen = new Set();
      return arr.filter(x => (seen.has(x.url) ? false : (seen.add(x.url), true)));
    };
    return { suspicious: dedupe(suspicious), externals: dedupe(externals), links: dedupe(linkFindings) };
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
    // Theme-aware inline fallback to ensure it renders
    let theme = 'alert';
    try {
      const st = await browser.runtime.sendMessage({ type: 'pg:getState' });
      if (st && st.uiTheme === 'hacker') theme = 'hacker';
    } catch (_) {}
    if (theme === 'alert') {
      banner.classList.add('alert');
      banner.style.cssText = [
        "position: sticky",
        "top: 0",
        "z-index: 2147483647",
        "background: #ffeb3b",
        "color: #111",
        "border: 1px solid #d4c200",
        "border-left: 4px solid #bfa200",
        "border-radius: 0",
        "padding: 10px 12px",
        "margin: 0 0 8px 0",
        "box-shadow: inset 0 -1px 0 rgba(0,0,0,0.2)"
      ].join("; ");
    } else {
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
    }

    const count = findings.suspicious.length;
    const header = document.createElement("div");
    header.className = 'pg-header';
    const left = document.createElement('div');
    left.className = 'pg-left';
    const icon = document.createElement('span');
    icon.className = 'pg-icon';
    icon.textContent = '🛡️';
    const title = document.createElement("div");
    const name = t("extensionName");
    title.innerHTML = `<strong>${name}</strong>: ${t("banner_detected", String(count))}`;
    left.appendChild(icon);
    left.appendChild(title);
    const closeBtn = document.createElement('button');
    closeBtn.className = 'pg-close';
    closeBtn.setAttribute('aria-label', t('banner_dismiss'));
    closeBtn.textContent = '×';
    closeBtn.addEventListener('click', removeBanner);
    header.appendChild(left);
    header.appendChild(closeBtn);

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
    // button inline fallbacks
    [allowBtn, blockToggle, moreBtn].forEach((b) => {
      b.style.borderRadius = '6px';
      b.style.border = '1px solid #2b363c';
      b.style.padding = '6px 10px';
      b.style.background = '#121517';
      b.style.color = '#e6f1ef';
      b.style.cursor = 'pointer';
    });
    if (theme === 'alert') {
      [allowBtn, moreBtn].forEach((b)=>{ b.style.background = '#fff8b0'; b.style.color='#111'; b.style.borderColor='#c7b500'; });
      moreBtn.style.background = '#ffe15a';
      blockToggle.style.background = '#f44336';
      blockToggle.style.borderColor = '#b71c1c';
      blockToggle.style.color = '#fff';
    } else {
      moreBtn.style.background = '#0c8';
      moreBtn.style.borderColor = '#0b7';
      moreBtn.style.color = '#082017';
      blockToggle.style.background = '#e53935';
      blockToggle.style.borderColor = '#b71c1c';
    }
    moreBtn.textContent = t("banner_moreInfo");
    moreBtn.addEventListener("click", () => API.runtime.openOptionsPage());

    actions.appendChild(allowBtn);
    actions.appendChild(blockToggle);
    actions.appendChild(moreBtn);

    // External images section (collapsible)
    const extCount = findings.externals.length;
    if (extCount > 0) {
      const extWrap = document.createElement("div");
      extWrap.className = "pixelguard-extwrap";
      const details = document.createElement("details");
      details.className = "pixelguard-details";
      const summary = document.createElement("summary");
      summary.innerHTML = `<span class="pg-accent">${t("banner_externalImagesTitle")}</span> <span class="pg-badge">${extCount}</span>`;

      const list = document.createElement("ul");
      list.className = "pixelguard-list";
      for (const it of findings.externals.slice(0, 20)) {
        const li = document.createElement("li");
        const host = it.host || "?";
        const safe = (it.url || "").slice(0, 200);
        li.textContent = `${host} — ${safe}`;
        list.appendChild(li);
      }
      if (findings.externals.length > 20) {
        const li = document.createElement("li");
        li.textContent = `… +${findings.externals.length - 20} more`;
        list.appendChild(li);
      }
      details.appendChild(summary);
      details.appendChild(list);
      extWrap.appendChild(details);
      banner.appendChild(extWrap);
    }

    // Tracking links section
    const linkCount = findings.links.length;
    if (linkCount > 0) {
      const wrap = document.createElement('div');
      wrap.className = 'pixelguard-extwrap';
      const details = document.createElement('details');
      details.className = 'pixelguard-details';
      const summary = document.createElement('summary');
      summary.innerHTML = `<span class="pg-accent">${t('banner_trackingLinksTitle')}</span> <span class=\"pg-badge\">${linkCount}</span>`;
      const list = document.createElement('ul');
      list.className = 'pixelguard-list';
      for (const it of findings.links.slice(0, 20)) {
        const li = document.createElement('li');
        const safe = (it.url || '').slice(0, 200);
        li.textContent = `${it.host} — ${safe}`;
        list.appendChild(li);
      }
      if (findings.links.length > 20) {
        const li = document.createElement('li');
        li.textContent = `… +${findings.links.length - 20} more`;
        list.appendChild(li);
      }
      details.appendChild(summary);
      details.appendChild(list);
      wrap.appendChild(details);
      banner.appendChild(wrap);
    }

    banner.appendChild(header);
    banner.appendChild(actions);

    const host = document.body || document.documentElement;
    host.insertBefore(banner, host.firstChild);
    lastBanner = banner;

    // report detected count to background (for badge)
    try { await API.runtime.sendMessage({ type: "pg:detectedCount", count }); } catch (_) {}
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
    const st = await (API?.runtime?.sendMessage ? API.runtime.sendMessage({ type: "pg:getState" }) : Promise.resolve({}));
    const debug = !!st?.debug;
    if (debug) console.log('[PG/cs] scanning...');
    if (st?.whitelist?.includes((currentDomain || "").toLowerCase())) {
      if (debug) console.log('[PG/cs] domain whitelisted, removing banner');
      removeBanner();
      return;
    }
    const findings = scan(document);
    if (debug) console.log('[PG/cs] results', findings);
    if (findings.suspicious.length > 0 || findings.externals.length > 0 || findings.links.length > 0 || debug) await renderBanner(findings); else removeBanner();
  }, THROTTLE_MS);

  // React to message DOM changes (Thunderbird re-renders message DOM)
  const mo = new MutationObserver(doScan);
  mo.observe(document, { childList: true, subtree: true });

  // Receive context (sender domain) from background
  (API?.runtime || browser.runtime).onMessage.addListener((msg) => {
    if (msg?.type === "pg:context") {
      currentDomain = msg.domain || "";
      try { console.log('[PG/cs] context domain', currentDomain); } catch (_) {}
      doScan();
    }
  });

  // Initial scan
  document.addEventListener("DOMContentLoaded", doScan);
  window.addEventListener("load", doScan);
  // extra delayed scans in case the body renders late
  setTimeout(doScan, 300);
  setTimeout(doScan, 900);
  setTimeout(doScan, 1800);
  // Kick a first log ASAP so we see injection in debug
  try { console.log('[PG/cs] loaded', { apiAlias: !!API }); } catch (_) {}
  // Pull context from background as fallback
  (async () => {
    try {
      const res = await API.runtime.sendMessage({ type: 'pg:hello' });
      if (res?.ok) {
        if (res.domain) {
          currentDomain = res.domain;
          try { console.log('[PG/cs] hello->domain', currentDomain); } catch (_) {}
        }
        if (res.settings?.debug) {
          try { console.log('[PG/cs] settings', res.settings); } catch (_) {}
        }
        doScan();
      }
    } catch (e) {
      try { console.log('[PG/cs] hello failed', String(e)); } catch (_) {}
    }
  })();
})();
