/* global browser */
(() => {
  const DEFAULT_SETTINGS = {
    blockMode: false,
    blockAllResources: false,
    blockAllExternals: false,
    blockStylesheets: false,
    blockFonts: false,
    blockMedia: false,
    blockXHR: false,
    blockPings: true,
    whitelist: [], // allowed domains (no warn or block)
    uiTheme: "alert", // 'alert' (yellow) or 'hacker' (dark)
    debug: false,
    suspiciousHosts: [
      // base list of common tracking providers (editable in Options)
      "mailtrack.io",
      "mandrillapp.com",
      "sendgrid.net",
      "postmarkapp.com",
      "sparkpostmail.com",
      "customersend.com",
      "trkn.us",
      "emltrk.com",
      "sendibm1.com",
      "bnc.lt",
      "open.my.salesforce.com",
      "clicks.**",
      "trk.**",
      "email.**"
    ],
    trackingParams: [
      "uid",
      "token",
      "open",
      "track",
      "pixel",
      "beacon",
      "campaign_id",
      "recipient",
      "subscriber",
      "message_id",
      "signature",
      "rid",
      "cid",
      "utm_source",
      "utm_medium",
      "utm_campaign"
    ],
    counters: { totalDetected: 0, totalBlocked: 0 }
  };

  const state = {
    settings: null,
    currentSenderDomainByTab: new Map(), // tabId -> sender domain
    findingsByTab: new Map(), // tabId -> { findings, ts, domain }
    tbMajor: null,
    suspiciousByTab: new Map(), // tabId -> Set of suspicious URL strings (or hosts)
    lastSuspiciousGlobal: new Set()
  };

  function getRulesForExperiment() {
    const s = state.settings || {};
    return {
      blockMode: !!s.blockMode,
      blockAllResources: !!s.blockAllResources,
      blockAllExternals: !!s.blockAllExternals,
      blockStylesheets: !!s.blockStylesheets,
      blockFonts: !!s.blockFonts,
      blockMedia: !!s.blockMedia,
      blockXHR: !!s.blockXHR,
      blockPings: !!s.blockPings,
      whitelist: Array.isArray(s.whitelist) ? s.whitelist : [],
      suspicious: Array.from(state.lastSuspiciousGlobal || [])
    };
  }

  async function getTbMajor() {
    try {
      const info = await browser.runtime.getBrowserInfo();
      const v = parseInt(String(info.version).split(".")[0], 10);
      return Number.isFinite(v) ? v : null;
    } catch (_) { return null; }
  }

  async function registerMessageScripts() {
    try {
      if (browser.messageDisplayScripts && browser.messageDisplayScripts.register) {
        await browser.messageDisplayScripts.register({
          js: [{ file: "content/scan.js" }],
          css: [{ file: "content/banner.css" }],
          runAt: "document_end",
          allFrames: true
        });
        if (state.settings?.debug) console.log("[PG/bg] messageDisplayScripts.register OK");
      }
    } catch (e) {
      console.log("[PG/bg] messageDisplayScripts.register FAILED:", String(e));
    }
    // fallback: try contentScripts.register for about:message (may be ignored, but log it)
    try {
      if (browser.contentScripts?.register) {
        await browser.contentScripts.register({
          matches: ["about:message*"],
          js: [{ file: "content/scan.js" }],
          css: [{ file: "content/banner.css" }],
          runAt: "document_end", allFrames: true
        });
        if (state.settings?.debug) console.log("[PG/bg] contentScripts.register about:message OK");
      }
    } catch (e) {
      console.log("[PG/bg] contentScripts.register FAILED:", String(e));
    }
  }

  async function loadSettings() {
    const stored = await browser.storage.local.get("settings");
    state.settings = Object.assign({}, DEFAULT_SETTINGS, stored.settings || {});
    state.tbMajor = await getTbMajor();
    // Ensure scripts are registered for message display (avoid on TB >= 140 where MV2 path is flaky)
    if (!state.tbMajor || state.tbMajor < 140) {
      await registerMessageScripts();
      if (state.settings?.debug) console.log('[PG/bg] registered message scripts (tbMajor=', state.tbMajor, ')');
    } else if (state.settings?.debug) {
      console.log("[PG/bg] Skipping messageDisplayScripts on TB", state.tbMajor);
    }
    // Enable experiment-based hard blocker if available
    try {
      if (browser.pgPolicy?.enable) {
        await browser.pgPolicy.enable(getRulesForExperiment());
        if (state.settings?.debug) console.log('[PG/bg] experiment blocker enabled');
      }
    } catch (e) { console.log('[PG/bg] experiment enable failed:', String(e)); }
  }

  async function saveSettings() {
    await browser.storage.local.set({ settings: state.settings });
  }

  function parseDomainFromEmail(authorHeader) {
    // authorHeader often looks like "Name <user@domain.com>" or just the email
    try {
      const match = /<([^>]+)>/.exec(authorHeader);
      const email = (match ? match[1] : authorHeader).trim();
      const at = email.lastIndexOf("@");
      return at !== -1 ? email.slice(at + 1).toLowerCase() : "";
    } catch (_) {
      return "";
    }
  }

  function hostMatchesPattern(host, pattern) {
    if (!pattern) return false;
    if (pattern.includes("**")) {
      const esc = pattern.replace(/[-\/\\^$+?.()|[\]{}]/g, "\\$&").replace(/\\\*\\\*/g, ".*");
      return new RegExp(`^${esc}$`, "i").test(host);
    }
    return host === pattern;
  }

  function urlHasTrackingParam(url, keys) {
    try {
      const u = new URL(url);
      for (const k of keys) {
        if (u.searchParams.has(k)) return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function isSuspiciousUrl(url) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      if (state.settings.suspiciousHosts.some(p => hostMatchesPattern(host, p))) return true;
      if (urlHasTrackingParam(url, state.settings.trackingParams)) return true;
      // simple heuristic by path
      if (/\b(pixel|beacon|track|open)\b/i.test(u.pathname)) return true;
      return false;
    } catch (_) {
      return false;
    }
  }

  function isWhitelisted(domain) {
    if (!domain) return false;
    return state.settings.whitelist.some(d => d.toLowerCase() === domain.toLowerCase());
  }

  async function setBadge(text, tabId, color) {
    try {
      const details = tabId != null ? { text, tabId } : { text };
      await browser.browserAction.setBadgeText(details);
      if (color) {
        const cdet = tabId != null ? { color, tabId } : { color };
        await browser.browserAction.setBadgeBackgroundColor(cdet);
      }
    } catch (_) {
      /* some versions may not support tab-specific badges or color */
      try { await browser.browserAction.setBadgeText({ text }); } catch (_) {}
      if (color) { try { await browser.browserAction.setBadgeBackgroundColor({ color }); } catch (_) {} }
    }
  }

  async function setBadgeForFindings(tabId, findings) {
    const s = findings?.suspicious?.length || 0;
    const e = findings?.externals?.length || 0;
    const l = findings?.links?.length || 0;
    const txt = `${s}|${e}|${l}`;
    let color = l > 0 ? "#ff9800" : (s > 0 ? "#e53935" : (e > 0 ? "#00bfa5" : "#607d8b"));
    await setBadge(txt, tabId, color);
  }

  // Init
  loadSettings().then(() => setBadge(""));
  try {
    browser.runtime.onInstalled.addListener(() => {
      registerMessageScripts();
    });
  } catch (_) {}

  // When a message is displayed, store sender domain by tab
  browser.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
    const domain = parseDomainFromEmail(message.author || "");
    state.currentSenderDomainByTab.set(tab.id, domain);
    // clear badge when switching threads
    setBadge("");
    // notify the content script (with retry to wait injection)
    const dbg = !!state.settings?.debug;
    if (dbg) console.log("[PG/bg] onMessageDisplayed tab=", tab.id, "domain=", domain);
    const sendWithRetry = async (attempt = 1) => {
      try {
        await browser.tabs.sendMessage(tab.id, { type: "pg:context", domain });
        if (dbg) console.log(`[PG/bg] context sent on attempt ${attempt}`);
      } catch (e) {
        if (attempt < 12) {
          const delay = 150 * attempt; // up to ~2s
          if (dbg) console.log(`[PG/bg] retry ${attempt} in ${delay}ms:`, String(e));
          setTimeout(() => sendWithRetry(attempt + 1), delay);
        } else if (dbg) {
          console.log("[PG/bg] giving up sending context to tab", tab.id);
        }
      }
    };
    sendWithRetry();

    // Fallback: scan message HTML in background (works even if CS didn't inject)
    try {
      if (state.settings?.debug) console.log("[PG/bg] scanning message in background for tab", tab.id);
      const html = await getMessageHtml(message);
      const findings = scanHtml(html);
      state.findingsByTab.set(tab.id, { findings, ts: Date.now(), domain });
      // Store suspicious URLs for blocking decisions (per tab and global fallback)
      try {
        const arr = (findings?.suspicious || []).map(x => String(x.url || '')).filter(Boolean);
        const set = new Set(arr);
        state.suspiciousByTab.set(tab.id, set);
        state.lastSuspiciousGlobal = new Set(arr);
      } catch (_) { state.suspiciousByTab.set(tab.id, new Set()); state.lastSuspiciousGlobal = new Set(); }
      if (state.settings?.debug) console.log("[PG/bg] findings:", findings);
      await setBadgeForFindings(tab.id, findings);
      // Increment total detected counter so popup shows numbers even without CS
      try {
        const n = Number(findings?.suspicious?.length || 0);
        if (n > 0) {
          state.settings.counters.totalDetected += n;
          await saveSettings();
        }
      } catch (_) {}
      // Push updated suspicious set to experiment
      try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
    } catch (e) {
      if (state.settings?.debug) console.log("[PG/bg] background scan error:", String(e));
    }
  });

  // Blocking suspicious requests (block mode)
  const webRequestBlocker = details => {
      const { url, tabId, type } = details;
      const documentUrl = details.documentUrl || details.originUrl || '';
      if (!state.settings.blockMode) return {};
      const senderDomain = state.currentSenderDomainByTab.get(tabId) || "";
      if (isWhitelisted(senderDomain)) return {};

      const t = String(type || '').toLowerCase();
      const isImg = (t === 'image' || t === 'imageset');
      const isCSS = (t === 'stylesheet');
      const isFont = (t === 'font');
      const isXHR = (t === 'xmlhttprequest' || t === 'fetch');
      const isMedia = (t === 'media' || t === 'object');
      const isPing = (t === 'ping' || t === 'beacon');
      const isOther = (t === 'other');

      try { console.log('[PG/bg] webRequest', { type: t, tabId, url, senderDomain, documentUrl }); } catch (_) {}

      // Master switch: block all common external resource types
      if (state.settings.blockAllResources && (isImg || isCSS || isFont || isMedia || isXHR || isPing || isOther)) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] master blocked', t, url);
        return { cancel: true };
      }

      // Global blocks per-type
      if (state.settings.blockAllExternals && isImg) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] blocked image (all externals ON):', url);
        return { cancel: true };
      }
      if (state.settings.blockStylesheets && isCSS) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] blocked stylesheet:', url);
        return { cancel: true };
      }
      if (state.settings.blockFonts && isFont) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] blocked font:', url);
        return { cancel: true };
      }
      if (state.settings.blockMedia && isMedia) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] blocked media:', url);
        return { cancel: true };
      }
      if (state.settings.blockXHR && isXHR) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] blocked XHR/fetch:', url);
        return { cancel: true };
      }
      if (state.settings.blockPings && isPing) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        if (state.settings?.debug) console.log('[PG/bg] blocked ping/beacon:', url);
        return { cancel: true };
      }

      // Heuristic suspicious URL block
      if (isSuspiciousUrl(url)) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        return { cancel: true };
      }
      // Block URLs previously flagged as suspicious for this tab
      try {
        const tabSuspicious = (tabId != null && tabId >= 0) ? state.suspiciousByTab.get(tabId) : null;
        if (tabSuspicious && tabSuspicious.size > 0) {
          const u = new URL(url);
          const normalized = u.toString();
          let hit = tabSuspicious.has(normalized);
          if (!hit) {
            const originPath = `${u.origin}${u.pathname}`;
            for (const s of tabSuspicious) { if (normalized.startsWith(s) || originPath === s || originPath.startsWith(s)) { hit = true; break; } }
          }
          if (hit) {
            state.settings.counters.totalBlocked += 1;
            saveSettings();
            setBadge(String(state.settings.counters.totalBlocked));
            if (state.settings?.debug) console.log('[PG/bg] blocked suspicious-from-scan:', url);
            return { cancel: true };
          }
        }
        // Fallback for requests without tab association (about:message)
        const isAboutMsg = String(documentUrl).startsWith('about:message');
        if (isAboutMsg && state.lastSuspiciousGlobal && state.lastSuspiciousGlobal.size > 0) {
          const u = new URL(url);
          const normalized = u.toString();
          let hit = state.lastSuspiciousGlobal.has(normalized);
          if (!hit) {
            const originPath = `${u.origin}${u.pathname}`;
            for (const s of state.lastSuspiciousGlobal) { if (normalized.startsWith(s) || originPath === s || originPath.startsWith(s)) { hit = true; break; } }
          }
          if (hit) {
            state.settings.counters.totalBlocked += 1;
            saveSettings();
            setBadge(String(state.settings.counters.totalBlocked));
            if (state.settings?.debug) console.log('[PG/bg] blocked (global suspicious set):', url);
            return { cancel: true };
          }
        }
      } catch (_) {}
      return {};
  };

  try {
    browser.webRequest.onBeforeRequest.addListener(
      webRequestBlocker,
      { urls: ["http://*/*", "https://*/*"] },
      ["blocking"]
    );
  } catch (e) {
    console.log('[PG/bg] onBeforeRequest listener failed to add:', String(e));
  }

  // Fallback: try to cancel at headers stage as well (some channels might bypass early cancel)
  try {
    browser.webRequest.onBeforeSendHeaders.addListener(
      details => webRequestBlocker(details),
      { urls: ["http://*/*", "https://*/*"] },
      ["blocking", "requestHeaders"]
    );
  } catch (e) {
    console.log('[PG/bg] onBeforeSendHeaders listener failed to add:', String(e));
  }

  // Messaging with popup, options and content script
  browser.runtime.onMessage.addListener(async (msg, sender) => {
    switch (msg?.type) {
      case "pg:getState": {
        if (state.settings?.debug) console.log("[PG/bg] getState from", sender?.tab?.id);
        return state.settings;
      }
      case "pg:hello": {
        const tabId = sender?.tab?.id;
        const domain = (tabId != null) ? (state.currentSenderDomainByTab.get(tabId) || "") : "";
        if (state.settings?.debug) console.log("[PG/bg] hello from", tabId, "-> domain:", domain);
        return { ok: true, domain, settings: state.settings };
      }
      case "pg:getFindings": {
        let tabId = msg?.tabId;
        if (tabId == null) {
          try {
            const tabs = await browser.tabs.query({ active: true, currentWindow: true });
            if (tabs && tabs[0]) tabId = tabs[0].id;
          } catch (_) {}
        }
        const entry = tabId != null ? state.findingsByTab.get(tabId) : null;
        return entry || { findings: { suspicious: [], externals: [], links: [] }, ts: 0, domain: state.currentSenderDomainByTab.get(tabId || -1) || "" };
      }
      case "pg:rescanNow": {
        try {
          let tabId = sender?.tab?.id;
          if (tabId == null) {
            const tabs = await browser.tabs.query({ active: true, currentWindow: true });
            if (tabs && tabs[0]) tabId = tabs[0].id;
          }
          if (tabId == null) return { ok: false };
          const displayed = await browser.messageDisplay.getDisplayedMessage(tabId);
          if (!displayed) return { ok: false };
          const html = await getMessageHtml(displayed);
          const findings = scanHtml(html);
          const domain = state.currentSenderDomainByTab.get(tabId) || "";
          state.findingsByTab.set(tabId, { findings, ts: Date.now(), domain });
          // Update suspicious cache for this tab and global fallback
          try {
            const arr = (findings?.suspicious || []).map(x => String(x.url || '')).filter(Boolean);
            const set = new Set(arr);
            state.suspiciousByTab.set(tabId, set);
            state.lastSuspiciousGlobal = new Set(arr);
          } catch (_) { state.suspiciousByTab.set(tabId, new Set()); state.lastSuspiciousGlobal = new Set(); }
          await setBadgeForFindings(tabId, findings);
          // Increment totals based on detections
          try {
            const n = Number(findings?.suspicious?.length || 0);
            if (n > 0) { state.settings.counters.totalDetected += n; await saveSettings(); }
          } catch (_) {}
          try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
          if (state.settings?.debug) console.log('[PG/bg] manual rescan done', { tabId, counts: { s: findings.suspicious.length, e: findings.externals.length, l: findings.links.length } });
          return { ok: true, findings };
        } catch (e) {
          if (state.settings?.debug) console.log('[PG/bg] manual rescan error', String(e));
          return { ok: false, error: String(e) };
        }
      }
      case "pg:setTheme": {
        const theme = (msg.theme === 'hacker') ? 'hacker' : 'alert';
        state.settings.uiTheme = theme;
        await saveSettings();
        return { ok: true, uiTheme: theme };
      }
      case "pg:toggleBlock": {
        state.settings.blockMode = !state.settings.blockMode;
        await saveSettings();
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { blockMode: state.settings.blockMode };
      }
      case "pg:setBlockAllExternals": {
        state.settings.blockAllExternals = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockAllExternals:', state.settings.blockAllExternals);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockAllExternals: state.settings.blockAllExternals };
      }
      case "pg:setBlockStylesheets": {
        state.settings.blockStylesheets = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockStylesheets:', state.settings.blockStylesheets);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockStylesheets: state.settings.blockStylesheets };
      }
      case "pg:setBlockFonts": {
        state.settings.blockFonts = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockFonts:', state.settings.blockFonts);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockFonts: state.settings.blockFonts };
      }
      case "pg:setBlockMedia": {
        state.settings.blockMedia = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockMedia:', state.settings.blockMedia);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockMedia: state.settings.blockMedia };
      }
      case "pg:setBlockXHR": {
        state.settings.blockXHR = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockXHR:', state.settings.blockXHR);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockXHR: state.settings.blockXHR };
      }
      case "pg:setBlockPings": {
        state.settings.blockPings = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockPings:', state.settings.blockPings);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockPings: state.settings.blockPings };
      }
      case "pg:setBlockAllResources": {
        state.settings.blockAllResources = !!msg.value;
        await saveSettings();
        if (state.settings?.debug) console.log('[PG/bg] blockAllResources:', state.settings.blockAllResources);
        try { if (browser.pgPolicy?.update) await browser.pgPolicy.update(getRulesForExperiment()); } catch (_) {}
        return { ok: true, blockAllResources: state.settings.blockAllResources };
      }
      case "pg:setTheme": {
        const theme = (msg.theme === 'hacker') ? 'hacker' : 'alert';
        state.settings.uiTheme = theme;
        await saveSettings();
        if (state.settings?.debug) console.log("[PG/bg] setTheme:", theme);
        return { ok: true, uiTheme: theme };
      }
      case "pg:setDebug": {
        state.settings.debug = !!msg.value;
        await saveSettings();
        console.log("[PG/bg] debug:", state.settings.debug);
        return { ok: true, debug: state.settings.debug };
      }
      case "pg:addWhitelist": {
        const d = (msg.domain || "").toLowerCase();
        if (d && !state.settings.whitelist.includes(d)) {
          state.settings.whitelist.push(d);
          await saveSettings();
        }
        return { ok: true, whitelist: state.settings.whitelist };
      }
      case "pg:removeWhitelist": {
        const d = (msg.domain || "").toLowerCase();
        state.settings.whitelist = state.settings.whitelist.filter(x => x !== d);
        await saveSettings();
        return { ok: true, whitelist: state.settings.whitelist };
      }
      case "pg:export": {
        return state.settings;
      }
      case "pg:import": {
        try {
          const incoming = msg.payload || {};
          // basic structure validation & merge
          const merged = Object.assign({}, DEFAULT_SETTINGS, incoming);
          state.settings = merged;
          await saveSettings();
          return { ok: true };
        } catch (e) {
          return { ok: false, error: String(e) };
        }
      }
      case "pg:detectedCount": {
        // used by content-script to update badge with detections in thread
        const n = Number(msg.count || 0);
        state.settings.counters.totalDetected += n;
        await saveSettings();
        await setBadge(`${n}|0|0`);
        return { ok: true };
      }
      default:
        return {};
    }
  });

  // ----- Helpers: message HTML and scanning in background -----

  async function getMessageHtml(message) {
    const full = await browser.messages.getFull(message.id);
    function findHtml(part) {
      if (!part) return null;
      if (part.contentType && /text\/html/i.test(part.contentType) && part.body) return part.body;
      if (part.parts) {
        for (const p of part.parts) {
          const h = findHtml(p);
          if (h) return h;
        }
      }
      return null;
    }
    const html = findHtml(full) || "";
    return html;
  }

  function scanHtml(html) {
    const res = { suspicious: [], externals: [], links: [] };
    if (!html) return res;
    let doc;
    try {
      const parser = new DOMParser();
      doc = parser.parseFromString(html, 'text/html');
    } catch (e) {
      return res;
    }

    const tryURL = (u) => { try { return new URL(u); } catch (_) { return null; } };
    const hasSuspiciousParams = (u) => {
      if (!u) return false;
      const keys = ["uid","token","open","track","pixel","beacon","campaign_id","recipient","subscriber","message_id","signature","rid","cid","utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid","msclkid","clickid","trace","tracelog"]; 
      return keys.some(k => u.searchParams.has(k));
    };
    const isRemote = (s) => /^https?:\/\//i.test(s || "");

    // Images
    doc.querySelectorAll('img').forEach(img => {
      const src = img.getAttribute('src') || '';
      if (isRemote(src)) {
        const u = tryURL(src);
        const tinyAttr = ['width','height','style'].some(k => (img.getAttribute(k)||'').toString().includes('1px') || (img.getAttribute(k)||'').toString().includes('2px'));
        const hidden = (img.getAttribute('style')||'').match(/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i);
        const susp = tinyAttr || hidden || (u && (hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname)));
        if (susp) res.suspicious.push({ url: src, reason: tinyAttr? 'tiny/hidden': 'url' }); else res.externals.push({ url: src, host: u?.hostname||'' });
      }
      const srcset = img.getAttribute('srcset') || '';
      if (srcset) srcset.split(',').forEach(p => {
        const cand = (p.trim().split(/\s+/)[0]||'').trim();
        if (!isRemote(cand)) return;
        const u = tryURL(cand);
        const susp = u && (hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname));
        if (susp) res.suspicious.push({ url: cand, reason: 'srcset' }); else res.externals.push({ url: cand, host: u?.hostname||'' });
      });
      ['data-src','data-original','data-lazy','data-lazy-src','data-url'].forEach(an => {
        const v = img.getAttribute(an);
        if (isRemote(v)) {
          const u = tryURL(v);
          const susp = u && (hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname));
          if (susp) res.suspicious.push({ url: v, reason: 'data-src' }); else res.externals.push({ url: v, host: u?.hostname||'' });
        }
      });
    });

    // CSS background-image
    doc.querySelectorAll('[style*="url("]').forEach(el => {
      const style = el.getAttribute('style') || '';
      const urls = Array.from(style.matchAll(/url\(([^)]+)\)/gi)).map(m => (m[1]||'').replace(/["']/g,'').trim());
      urls.forEach(raw => {
        if (!isRemote(raw)) return;
        const u = tryURL(raw);
        const susp = u && (hasSuspiciousParams(u) || /\b(pixel|beacon|track|open)\b/i.test(u.pathname));
        if (susp) res.suspicious.push({ url: raw, reason: 'css-bg' }); else res.externals.push({ url: raw, host: u?.hostname||'' });
      });
    });

    // Links
    doc.querySelectorAll('a[href]').forEach(a => {
      const href = a.getAttribute('href') || '';
      if (!isRemote(href)) return;
      const u = tryURL(href);
      const host = u?.hostname.toLowerCase() || '';
      const path = u?.pathname || '';
      const params = u?.searchParams;
      const keys = ['utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','fbclid','msclkid','mc_cid','mc_eid','mkt_tok','hsenc','hsmi','spm','clickid','trace','tracelog','rid','cid','uid','token','signature'];
      const hasKey = params && keys.some(k => params.has(k));
      const pathSusp = /\b(unsubscribe|click|track|redirect|trk|link)\b/i.test(path);
      const hostSusp = /\b(trk|click|email|link)\b/i.test(host);
      if (hasKey || pathSusp || hostSusp) res.links.push({ url: href, host, reason: hasKey? 'param' : pathSusp? 'path':'host' });
    });

    // Deduplicate
    function dedupe(arr){ const s = new Set(); return arr.filter(x=> (s.has(x.url)? false : (s.add(x.url), true))); }
    res.suspicious = dedupe(res.suspicious);
    res.externals = dedupe(res.externals);
    res.links = dedupe(res.links);
    return res;
  }
})();
