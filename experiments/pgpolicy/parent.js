/* global ExtensionAPI */
"use strict";

const Ci = Components.interfaces;
const Cr = Components.results;

function lazyBool(v) { return v === true; }

function makeSet(arr) {
  const s = new Set();
  if (Array.isArray(arr)) for (const v of arr) { if (v) s.add(String(v)); }
  return s;
}

function hasTrackingParam(u) {
  try {
    const url = new URL(u);
    const keys = [
      "uid","token","open","track","pixel","beacon","campaign_id","recipient","subscriber","message_id","signature","rid","cid",
      "utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid","msclkid","clickid","trace","tracelog"
    ];
    return keys.some(k => url.searchParams.has(k));
  } catch (_) {
    return false;
  }
}

function pathLooksSuspicious(u) {
  try { return /\b(pixel|beacon|track|open)\b/i.test(new URL(u).pathname); } catch (_) { return false; }
}

function contentTypeToStr(t) {
  switch (t) {
    case Ci.nsIContentPolicy.TYPE_IMAGE:
    case Ci.nsIContentPolicy.TYPE_IMAGESET:
      return "image";
    case Ci.nsIContentPolicy.TYPE_STYLESHEET:
      return "stylesheet";
    case Ci.nsIContentPolicy.TYPE_FONT:
      return "font";
    case Ci.nsIContentPolicy.TYPE_MEDIA:
    case Ci.nsIContentPolicy.TYPE_OBJECT:
      return "media";
    case Ci.nsIContentPolicy.TYPE_XMLHTTPREQUEST:
    case Ci.nsIContentPolicy.TYPE_FETCH:
      return "xhr";
    case Ci.nsIContentPolicy.TYPE_PING:
      return "ping";
    default:
      return "other";
  }
}

var pgPolicy = class extends ExtensionAPI {
  onStartup() {
    // nothing
  }

  onShutdown(isAppShutdown) {
    try { if (this._enabled) this._detach(); } catch (_) {}
  }

  getAPI(context) {
    const self = this;
    this._enabled = false;
    this._rules = {};
    this._suspicious = new Set();

    this._observer = (subject, topic, data) => {
      if (!self._enabled) return;
      if (topic !== "http-on-modify-request") return;
      try {
        const chan = subject.QueryInterface(Ci.nsIHttpChannel);
        const url = chan.URI.spec;
        const li = chan.loadInfo;
        const ctype = contentTypeToStr(li && li.externalContentPolicyType);
        // Only care about http/https
        if (!/^https?:/i.test(url)) return;

        // Determine whitelist by sender domain is not reliable here, so only use explicit user whitelist
        const wl = new Set((self._rules.whitelist || []).map(s => String(s).toLowerCase()));
        const host = chan.URI.host ? String(chan.URI.host).toLowerCase() : "";
        if (host && wl.has(host)) return;

        const r = self._rules;
        if (!lazyBool(r.blockMode)) return;

        let shouldBlock = false;
        // Master switch: block all common resource types
        if (lazyBool(r.blockAllResources)) {
          shouldBlock = (ctype === 'image' || ctype === 'stylesheet' || ctype === 'font' || ctype === 'media' || ctype === 'xhr' || ctype === 'ping' || ctype === 'other');
        }
        if (!shouldBlock && lazyBool(r.blockAllExternals) && ctype === 'image') shouldBlock = true;
        if (!shouldBlock && lazyBool(r.blockStylesheets) && ctype === 'stylesheet') shouldBlock = true;
        if (!shouldBlock && lazyBool(r.blockFonts) && ctype === 'font') shouldBlock = true;
        if (!shouldBlock && lazyBool(r.blockMedia) && ctype === 'media') shouldBlock = true;
        if (!shouldBlock && lazyBool(r.blockXHR) && ctype === 'xhr') shouldBlock = true;
        if (!shouldBlock && lazyBool(r.blockPings) && ctype === 'ping') shouldBlock = true;

        // Suspicious set from last scan
        if (!shouldBlock && self._suspicious && self._suspicious.size > 0) {
          try {
            const u = new URL(url);
            const normalized = u.toString();
            if (self._suspicious.has(normalized)) shouldBlock = true;
            if (!shouldBlock) {
              const originPath = `${u.origin}${u.pathname}`;
              for (const s of self._suspicious) { if (normalized.startsWith(s) || originPath === s || originPath.startsWith(s)) { shouldBlock = true; break; } }
            }
          } catch (_) {}
        }

        // Heuristic by URL
        if (!shouldBlock && (hasTrackingParam(url) || pathLooksSuspicious(url))) shouldBlock = true;

        if (shouldBlock) {
          try { chan.cancel(Cr.NS_BINDING_ABORTED); } catch (_) { chan.cancel(Cr.NS_ERROR_ABORT); }
          try { Services.console.logStringMessage(`[PixelGuard/exp] blocked ${ctype}: ${url}`); } catch (_) {}
        }
      } catch (e) {
        try { Services.console.logStringMessage(`[PixelGuard/exp] observer error: ${e}`); } catch (_) {}
      }
    };

    this._attach = () => {
      if (this._enabled) return;
      Services.obs.addObserver(this._observer, "http-on-modify-request");
      this._enabled = true;
    };

    this._detach = () => {
      if (!this._enabled) return;
      Services.obs.removeObserver(this._observer, "http-on-modify-request");
      this._enabled = false;
    };

    this._applyRules = (newRules) => {
      this._rules = Object.assign({}, this._rules, newRules || {});
      this._suspicious = makeSet(this._rules.suspicious || []);
    };

    return {
      pgPolicy: {
        enable: (rules) => {
          self._applyRules(rules);
          self._attach();
        },
        update: (rules) => {
          self._applyRules(rules);
        },
        disable: () => {
          self._detach();
        }
      }
    };
  }
};

