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
          js: [{ file: "content/scanner.js" }, { file: "content/scan.js" }],
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
      const findings = scanHtml(html, domain);
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

  async function handleRuntimeMessage(msg, sender) {
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
          const domain = state.currentSenderDomainByTab.get(tabId) || "";
          const findings = scanHtml(html, domain);
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
  }

  browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    handleRuntimeMessage(msg, sender)
      .then(response => sendResponse(response))
      .catch(e => {
        if (state.settings?.debug) console.log("[PG/bg] runtime message error:", String(e));
        sendResponse({ ok: false, error: String(e) });
      });
    return true;
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

  function scanHtml(html, senderDomain) {
    if (!globalThis.PixelGuardScanner?.scanHtml) {
      return { suspicious: [], externals: [], links: [] };
    }
    return globalThis.PixelGuardScanner.scanHtml(html, { senderDomain });
  }
})();
