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
    messagesByTab: new Map(),
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

  let settingsWrite = Promise.resolve();
  let settingsRevision = 0;
  let settingsDirty = false;
  function saveSettings() {
    settingsDirty = true;
    const revision = ++settingsRevision;
    const snapshot = structuredClone(state.settings);
    settingsWrite = settingsWrite.catch(() => {}).then(async () => {
      await browser.storage.local.set({ settings: snapshot });
      if (revision === settingsRevision) settingsDirty = false;
    });
    return settingsWrite;
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

  let badgeWrite = Promise.resolve();
  function setBadge(text, tabId, color, isCurrent = () => true) {
    badgeWrite = badgeWrite.catch(() => {}).then(async () => {
      if (!isCurrent()) return;
      try {
        const details = tabId != null ? { text, tabId } : { text };
        await browser.browserAction.setBadgeText(details);
        if (color && isCurrent()) {
          const cdet = tabId != null ? { color, tabId } : { color };
          await browser.browserAction.setBadgeBackgroundColor(cdet);
        }
      } catch (_) {
        // A closed/unavailable tab must not change every other tab's badge.
        if (tabId != null || !isCurrent()) return;
        try { await browser.browserAction.setBadgeText({ text }); } catch (_) {}
        if (color) { try { await browser.browserAction.setBadgeBackgroundColor({ color }); } catch (_) {} }
      }
    });
    return badgeWrite;
  }

  async function setBadgeForFindings(tabId, findings, isCurrent) {
    const s = findings?.suspicious?.length || 0;
    const e = findings?.externals?.length || 0;
    const l = findings?.links?.length || 0;

    if (s === 0 && e === 0 && l === 0) {
      await setBadge("", tabId, undefined, isCurrent);
      return;
    }

    // Abbreviate numbers if needed to fit in the badge
    const format = n => (n > 9 ? '+' : String(n));
    const txt = `${format(s)}${format(e)}${format(l)}`;

    let color = l > 0 ? "#ff9800" : (s > 0 ? "#e53935" : (e > 0 ? "#00bfa5" : "#607d8b"));
    await setBadge(txt, tabId, color, isCurrent);
  }

  // Init
  const ready = loadSettings();
  try {
    browser.runtime.onInstalled.addListener(() => {
      registerMessageScripts();
    });
  } catch (_) {}

  async function scanMessage(tabId, message) {
    let session = state.messagesByTab.get(tabId);
    if (session?.messageId !== message.id) {
      if (session?.retryTimer) clearTimeout(session.retryTimer);
      session = { messageId: message.id, countedUrls: new Set(), retryTimer: null };
      state.messagesByTab.set(tabId, session);
    }
    if (session.retryTimer) clearTimeout(session.retryTimer);
    const token = {};
    session.token = token;
    const isCurrent = () => state.messagesByTab.get(tabId) === session && session.token === token;
    const domain = parseDomainFromEmail(message.author || "");
    state.currentSenderDomainByTab.set(tabId, domain);
    state.findingsByTab.delete(tabId);
    await ready;
    if (!isCurrent()) return { ok: false };
    await setBadge("", tabId, undefined, isCurrent);
    if (!isCurrent()) return { ok: false };
    const dbg = !!state.settings?.debug;
    if (dbg) console.log("[PG/bg] scanning tab=", tabId, "domain=", domain);
    const sendWithRetry = async (attempt = 1) => {
      if (!isCurrent()) return;
      try {
        await browser.tabs.sendMessage(tabId, { type: "pg:context", domain, messageId: message.id });
        if (dbg) console.log(`[PG/bg] context sent on attempt ${attempt}`);
      } catch (e) {
        if (isCurrent() && attempt < 12) {
          const delay = 150 * attempt;
          if (dbg) console.log(`[PG/bg] retry ${attempt} in ${delay}ms:`, String(e));
          session.retryTimer = setTimeout(() => sendWithRetry(attempt + 1), delay);
        } else if (dbg) {
          console.log("[PG/bg] giving up sending context to tab", tabId);
        }
      }
    };
    sendWithRetry();

    try {
      const html = await getMessageHtml(message);
      if (!isCurrent()) return { ok: false };
      const findings = scanHtml(html, domain);
      state.findingsByTab.set(tabId, { findings, ts: Date.now(), domain });
      if (state.settings?.debug) console.log("[PG/bg] findings:", findings);
      let n = 0;
      for (const item of findings.suspicious) {
        if (!session.countedUrls.has(item.url)) {
          session.countedUrls.add(item.url);
          n++;
        }
      }
      if (n > 0) {
        state.settings.counters.totalDetected += n;
      }
      if (n > 0 || settingsDirty) {
        try { await saveSettings(); } catch (e) {
          // Keep the in-memory total and retry persistence on the next scan.
          // A storage failure must not suppress the current findings/badge.
          if (state.settings?.debug) console.log("[PG/bg] counter persistence error:", String(e));
        }
      }
      if (!isCurrent()) return { ok: false };
      await setBadgeForFindings(tabId, findings, isCurrent);
      return { ok: isCurrent(), findings };
    } catch (e) {
      if (state.settings?.debug) console.log("[PG/bg] background scan error:", String(e));
      return { ok: false, error: String(e) };
    }
  }

  const handleMessageDisplayed = (tab, message) => scanMessage(tab.id, message);

  browser.tabs.onRemoved.addListener(tabId => {
    const session = state.messagesByTab.get(tabId);
    if (session?.retryTimer) clearTimeout(session.retryTimer);
    state.messagesByTab.delete(tabId);
    state.currentSenderDomainByTab.delete(tabId);
    state.findingsByTab.delete(tabId);
  });

  if (browser.messageDisplay?.onMessageDisplayed?.addListener) {
    browser.messageDisplay.onMessageDisplayed.addListener(handleMessageDisplayed);
  } else {
    console.warn("[PG/bg] messageDisplay API unavailable; real-time message detection disabled.");
  }

  async function handleRuntimeMessage(msg, sender) {
    await ready;
    switch (msg?.type) {
      case "pg:getState": {
        if (state.settings?.debug) console.log("[PG/bg] getState from", sender?.tab?.id);
        return state.settings;
      }
      case "pg:hello": {
        const tabId = sender?.tab?.id;
        const domain = (tabId != null) ? (state.currentSenderDomainByTab.get(tabId) || "") : "";
        if (state.settings?.debug) console.log("[PG/bg] hello from", tabId, "-> domain:", domain);
        return { ok: true, domain, messageId: state.messagesByTab.get(tabId)?.messageId, settings: state.settings };
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
        let tabId = sender?.tab?.id;
        let placeholder = null;
        try {
          if (tabId == null) {
            const tabs = await browser.tabs.query({ active: true, currentWindow: true });
            if (tabs && tabs[0]) tabId = tabs[0].id;
          }
          if (tabId == null) return { ok: false };
          let session = state.messagesByTab.get(tabId);
          if (!session) {
            // A manual scan can initialize a message already open at startup.
            // Reserve identity before the lookup so closing the tab invalidates it.
            placeholder = { messageId: null, token: {}, countedUrls: new Set(), retryTimer: null };
            session = placeholder;
            state.messagesByTab.set(tabId, session);
          }
          const token = session.token;
          const displayed = await browser.messageDisplay.getDisplayedMessage(tabId);
          if (!displayed || state.messagesByTab.get(tabId) !== session || session.token !== token || (session.messageId != null && displayed.id !== session.messageId)) return { ok: false };
          return scanMessage(tabId, displayed);
        } catch (e) {
          if (state.settings?.debug) console.log('[PG/bg] manual rescan error', String(e));
          return { ok: false, error: String(e) };
        } finally {
          if (placeholder && state.messagesByTab.get(tabId) === placeholder) state.messagesByTab.delete(tabId);
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
      default:
        return {};
    }
  }

  browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // VT has a separate authenticated handler and must never reach debug logging.
    if (String(msg?.type || '').startsWith('pg:vt:')) return false;
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
