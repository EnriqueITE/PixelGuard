/* global browser */
(() => {
  const DEFAULT_SETTINGS = {
    blockMode: false,
    whitelist: [], // allowed domains (no warn or block)
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
    currentSenderDomainByTab: new Map() // tabId -> sender domain
  };

  async function loadSettings() {
    const stored = await browser.storage.local.get("settings");
    state.settings = Object.assign({}, DEFAULT_SETTINGS, stored.settings || {});
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

  async function setBadge(text) {
    try {
      await browser.browserAction.setBadgeText({ text });
      await browser.browserAction.setBadgeBackgroundColor({ color: "#d00" });
    } catch (_) {
      /* some versions may not support badge color */
    }
  }

  // Init
  loadSettings().then(() => setBadge(""));

  // When a message is displayed, store sender domain by tab
  browser.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
    const domain = parseDomainFromEmail(message.author || "");
    state.currentSenderDomainByTab.set(tab.id, domain);
    // clear badge when switching threads
    setBadge("");
    // notify the content script
    try { await browser.tabs.sendMessage(tab.id, { type: "pg:context", domain }); } catch (_) {}
  });

  // Blocking suspicious requests (block mode)
  browser.webRequest.onBeforeRequest.addListener(
    details => {
      const { url, tabId, type } = details;
      if (!state.settings.blockMode) return {};
      if (type !== "image" && type !== "xmlhttprequest" && type !== "other") return {};
      const senderDomain = state.currentSenderDomainByTab.get(tabId) || "";
      if (isWhitelisted(senderDomain)) return {};
      if (isSuspiciousUrl(url)) {
        state.settings.counters.totalBlocked += 1;
        saveSettings();
        setBadge(String(state.settings.counters.totalBlocked));
        return { cancel: true };
      }
      return {};
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
  );

  // Messaging with popup, options and content script
  browser.runtime.onMessage.addListener(async (msg, sender) => {
    switch (msg?.type) {
      case "pg:getState": {
        return state.settings;
      }
      case "pg:toggleBlock": {
        state.settings.blockMode = !state.settings.blockMode;
        await saveSettings();
        return { blockMode: state.settings.blockMode };
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
        await setBadge(String(n));
        return { ok: true };
      }
      default:
        return {};
    }
  });
})();

