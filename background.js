/* global browser */
(() => {
  const DEFAULT_SETTINGS = {
    uiTheme: "hacker", // 'alert' (yellow) or 'hacker' (dark)
    debug: false,
    trackingParams: [
      "uid", "token", "open", "track", "pixel", "beacon", "campaign_id",
      "recipient", "subscriber", "message_id", "signature", "rid", "cid",
      "utm_source", "utm_medium", "utm_campaign"
    ],
    counters: { totalDetected: 0 }
  };

  const state = {
    settings: null,
    currentSenderDomainByTab: new Map(),
    findingsByTab: new Map(),
    tbMajor: null,
    messageScriptsRegistered: false,
  };

  async function getTbMajor() {
    try {
      const info = await browser.runtime.getBrowserInfo();
      const v = parseInt(String(info.version).split(".")[0], 10);
      return Number.isFinite(v) ? v : null;
    } catch (_) { return null; }
  }

  async function registerMessageScripts(force = false) {
    if (state.messageScriptsRegistered && !force) {
      return true;
    }

    let registered = false;
    try {
      if (browser.messageDisplayScripts?.register) {
        await browser.messageDisplayScripts.register({
          js: [{ file: "content/scan.js" }],
          css: [{ file: "content/banner.css" }],
          runAt: "document_end",
          allFrames: true,
        });
        registered = true;
        if (state.settings?.debug) console.log("[PG/bg] messageDisplayScripts.register OK");
      } else if (state.settings?.debug) {
        console.log("[PG/bg] messageDisplayScripts API unavailable on this build");
      }
    } catch (e) {
      console.log("[PG/bg] messageDisplayScripts.register FAILED:", String(e));
    }

    if (registered) {
      state.messageScriptsRegistered = true;
    }
    return state.messageScriptsRegistered;
  }

  async function loadSettings() {
    const stored = await browser.storage.local.get("settings");
    state.settings = Object.assign({}, DEFAULT_SETTINGS, stored.settings || {});
    state.tbMajor = await getTbMajor();
    const registered = await registerMessageScripts();
    if (state.settings?.debug) {
      const tbInfo = state.tbMajor != null ? state.tbMajor : "unknown";
      console.log(
        registered
          ? `[PG/bg] message scripts active (tbMajor=${tbInfo})`
          : `[PG/bg] message scripts unavailable (tbMajor=${tbInfo})`
      );
    }
  }

  async function saveSettings() {
    await browser.storage.local.set({ settings: state.settings });
  }

  function parseDomainFromEmail(authorHeader) {
    try {
      const match = /<([^>]+)>/.exec(authorHeader);
      const email = (match ? match[1] : authorHeader).trim();
      const at = email.lastIndexOf("@");
      return at !== -1 ? email.slice(at + 1).toLowerCase() : "";
    } catch (_) {
      return "";
    }
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
      try { await browser.browserAction.setBadgeText({ text }); } catch (_) {}
      if (color) { try { await browser.browserAction.setBadgeBackgroundColor({ color }); } catch (_) {} }
    }
  }

  async function setBadgeForFindings(tabId, findings) {
    const s = findings?.suspicious?.length || 0;
    const e = findings?.externals?.length || 0;
    const l = findings?.links?.length || 0;

    if (s === 0 && e === 0 && l === 0) {
      await setBadge("", tabId);
      return;
    }

    // Abbreviate numbers if needed to fit in the badge
    const format = n => (n > 9 ? '+' : String(n));
    const txt = `${format(s)}${format(e)}${format(l)}`;

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

  const handleMessageDisplayed = async (tab, message) => {
    const domain = parseDomainFromEmail(message.author || "");
    state.currentSenderDomainByTab.set(tab.id, domain);
    setBadge("");
    const dbg = !!state.settings?.debug;
    if (dbg) console.log("[PG/bg] onMessageDisplayed tab=", tab.id, "domain=", domain);
    const sendWithRetry = async (attempt = 1) => {
      try {
        await browser.tabs.sendMessage(tab.id, { type: "pg:context", domain });
        if (dbg) console.log(`[PG/bg] context sent on attempt ${attempt}`);
      } catch (e) {
        if (attempt < 12) {
          const delay = 150 * attempt;
          if (dbg) console.log(`[PG/bg] retry ${attempt} in ${delay}ms:`, String(e));
          setTimeout(() => sendWithRetry(attempt + 1), delay);
        } else if (dbg) {
          console.log("[PG/bg] giving up sending context to tab", tab.id);
        }
      }
    };
    sendWithRetry();

    try {
      if (state.settings?.debug) console.log("[PG/bg] scanning message in background for tab", tab.id);
      const html = await getMessageHtml(message);
      const findings = scanHtml(html);
      state.findingsByTab.set(tab.id, { findings, ts: Date.now(), domain });
      if (state.settings?.debug) console.log("[PG/bg] findings:", findings);
      await setBadgeForFindings(tab.id, findings);
      const n = Number(findings?.suspicious?.length || 0);
      if (n > 0) {
        state.settings.counters.totalDetected += n;
        await saveSettings();
      }
    } catch (e) {
      if (state.settings?.debug) console.log("[PG/bg] background scan error:", String(e));
    }
  };

  if (browser.messageDisplay?.onMessageDisplayed?.addListener) {
    browser.messageDisplay.onMessageDisplayed.addListener(handleMessageDisplayed);
  } else {
    console.warn("[PG/bg] messageDisplay API unavailable; real-time message detection disabled.");
  }

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
        if (!browser.messageDisplay?.getDisplayedMessage) {
          if (state.settings?.debug) console.log("[PG/bg] rescan skipped: messageDisplay.getDisplayedMessage unavailable");
          return { ok: false, error: "messageDisplay.getDisplayedMessage unsupported" };
        }
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
          await setBadgeForFindings(tabId, findings);
          const n = Number(findings?.suspicious?.length || 0);
          if (n > 0) { state.settings.counters.totalDetected += n; await saveSettings(); }
          if (state.settings?.debug) console.log('[PG/bg] manual rescan done', { tabId, counts: { s: findings.suspicious.length, e: findings.externals.length, l: findings.links.length } });
          return { ok: true, findings };
        } catch (e) {
          if (state.settings?.debug) console.log('[PG/bg] manual rescan error', String(e));
          return { ok: false, error: String(e) };
        }
      }

      case "pg:setDebug": {
        state.settings.debug = !!msg.value;
        await saveSettings();
        console.log("[PG/bg] debug:", state.settings.debug);
        return { ok: true, debug: state.settings.debug };
      }
      case "pg:export": {
        // Filter out non-essential keys for export
        const { uiTheme, debug, counters } = state.settings;
        return { uiTheme, debug, counters };
      }
      case "pg:import": {
        try {
          const incoming = msg.payload || {};
          const sanitized = {
            uiTheme: 'hacker',
            debug: !!incoming.debug,
            counters: { totalDetected: incoming.counters?.totalDetected || 0 }
          };
          state.settings = Object.assign({}, DEFAULT_SETTINGS, sanitized);
          await saveSettings();
          return { ok: true };
        } catch (e) {
          return { ok: false, error: String(e) };
        }
      }
      case "pg:detectedCount": {
        const n = Number(msg.count || 0);
        if (n > 0) {
            state.settings.counters.totalDetected += n;
            await saveSettings();
        }
        await setBadge(n > 0 ? String(n) : "");
        return { ok: true };
      }
      default:
        return {};
    }
  });

  async function getMessageHtml(message) {
    if (!browser.messages?.getFull) {
      throw new Error("messages.getFull unsupported in this build");
    }
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
    return findHtml(full) || "";
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

    function dedupe(arr){ const s = new Set(); return arr.filter(x=> (s.has(x.url)? false : (s.add(x.url), true))); }
    res.suspicious = dedupe(res.suspicious);
    res.externals = dedupe(res.externals);
    res.links = dedupe(res.links);
    return res;
  }
})();
