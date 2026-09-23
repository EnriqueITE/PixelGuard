/* global DOMParser, NodeFilter */
(function (root) {
  const IMAGE_ID_PARAMS = [
    "uid", "token", "recipient", "subscriber", "message_id", "signature",
    "rid", "cid", "user_id", "email", "e", "mid"
  ];
  const IMAGE_EVENT_PARAMS = ["open", "track", "pixel", "beacon"];
  const MARKETING_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "campaign_id", "gclid", "fbclid", "msclkid", "mc_cid", "spm"
  ];
  const LINK_TRACKING_PARAMS = [
    ...MARKETING_PARAMS,
    "mc_eid", "mkt_tok", "oly_anon_id", "oly_enc_id", "vero_id", "hsenc",
    "hsmi", "clickid", "trace", "tracelog", "rid", "cid", "uid", "token",
    "signature"
  ];

  const TRACKING_PATH_RE = /(^|[\/._-])(pixel|beacon|tracking?|trk|open)([\/._-]|$)/i;
  const TRACKING_HOST_RE = /(^|[.-])(pixel|beacon|tracking?|trk|analytics|events)([.-]|$)/i;
  const LINK_PATH_RE = /(^|[\/._-])(unsubscribe|click|tracking?|redirect|redir|trk|link)([\/._-]|$)/i;
  const LINK_HOST_RE = /(^|[.-])(click|tracking?|trk|links?)([.-]|$)/i;

  function tryURL(raw) {
    try { return new URL(raw); } catch (_) { return null; }
  }

  function isRemote(raw) {
    return /^https?:\/\//i.test(raw || "");
  }

  function hasAnyParam(u, keys) {
    if (!u) return false;
    return keys.some(k => u.searchParams.has(k));
  }

  function matchingParams(u, keys) {
    if (!u) return [];
    return keys.filter(k => u.searchParams.has(k));
  }

  function sameSenderHost(host, senderDomain) {
    const h = String(host || "").toLowerCase();
    const sender = String(senderDomain || "").toLowerCase();
    if (!h || !sender) return false;
    return h === sender || h.endsWith(`.${sender}`);
  }

  function parseCssNumber(value) {
    const match = String(value || "").match(/(\d+(?:\.\d+)?)(?:\s*px)?/i);
    return match ? Number(match[1]) : null;
  }

  function parseStyle(styleText) {
    const result = {};
    String(styleText || "").split(";").forEach(part => {
      const idx = part.indexOf(":");
      if (idx === -1) return;
      result[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
    });
    return result;
  }

  function getComputedStyleSafe(el) {
    try {
      const view = el?.ownerDocument?.defaultView || root;
      if (view?.getComputedStyle) return view.getComputedStyle(el);
    } catch (_) {}
    return parseStyle(el?.getAttribute?.("style") || "");
  }

  function explicitImageMetrics(el) {
    const attrs = {
      width: parseCssNumber(el?.getAttribute?.("width")),
      height: parseCssNumber(el?.getAttribute?.("height"))
    };
    const inlineStyle = parseStyle(el?.getAttribute?.("style") || "");
    const styled = {
      width: parseCssNumber(inlineStyle.width),
      height: parseCssNumber(inlineStyle.height)
    };
    return { attrs, styled };
  }

  function hasTinyPair(size) {
    return size.width != null && size.height != null && size.width <= 2 && size.height <= 2;
  }

  function hasZeroDimension(size) {
    return size.width === 0 || size.height === 0;
  }

  function getVisibilitySignals(el) {
    if (!el) return [];
    const signals = [];
    const { attrs, styled } = explicitImageMetrics(el);
    const style = getComputedStyleSafe(el);
    const displayNone = style.display === "none";
    const visibilityHidden = style.visibility === "hidden";
    const opacityZero = Number(style.opacity ?? 1) === 0;
    const tiny = hasTinyPair(attrs) || hasTinyPair(styled);
    const zero = hasZeroDimension(attrs) || hasZeroDimension(styled);
    const tinySize = hasTinyPair(attrs) ? attrs : styled;

    if (tiny) signals.push(tinySize.width <= 1 && tinySize.height <= 1 ? "explicit 1x1 image" : "tiny image");
    if (displayNone) signals.push("display:none image");
    if (visibilityHidden) signals.push("visibility:hidden image");
    if (opacityZero) signals.push("opacity:0 image");
    if (zero) signals.push("explicit zero-size image");
    return signals;
  }

  function describeSignals(signals) {
    if (!signals || signals.length === 0) return "external resource";
    return signals.slice(0, 3).join(", ");
  }

  function hasSignal(signals, value) {
    return signals.includes(value);
  }

  function hasAnySignal(signals, values) {
    return values.some(value => hasSignal(signals, value));
  }

  function describeImageSignals(signals, classification) {
    if (!signals || signals.length === 0) return "visible remote image";

    const hasRecipient = hasSignal(signals, "recipient id parameter");
    const hasOpenPath = hasSignal(signals, "open path");
    const hasTrackingPath = hasSignal(signals, "tracking path keyword");
    const hasTrackingHost = hasSignal(signals, "tracking host keyword");
    const hiddenSignal = ["display:none image", "visibility:hidden image", "opacity:0 image"]
      .find(signal => hasSignal(signals, signal));

    if (hiddenSignal && hasRecipient) return `${hiddenSignal} with recipient id`;
    if (hiddenSignal && hasOpenPath) return `${hiddenSignal} with open path`;
    if (hiddenSignal) return hiddenSignal;
    if (hasSignal(signals, "explicit 1x1 image") && hasRecipient) return "explicit 1x1 image with recipient id";
    if (hasSignal(signals, "explicit 1x1 image") && hasOpenPath) return "explicit 1x1 image with open path";
    if (hasSignal(signals, "explicit 1x1 image")) return "explicit 1x1 image";
    if (hasSignal(signals, "tiny image") && hasOpenPath) return "tiny image with open path";
    if (hasSignal(signals, "tiny image")) return "tiny image";
    if (hasSignal(signals, "explicit zero-size image") && hasRecipient) return "explicit zero-size image with recipient id";
    if (hasSignal(signals, "explicit zero-size image")) return "explicit zero-size image";
    if (hasRecipient && hasOpenPath) return "recipient id with open path";
    if (hasRecipient) return "recipient id parameter";
    if (hasOpenPath) return classification === "external-image" ? "visible image with open path" : "open path";
    if (hasTrackingPath && hasTrackingHost) return "tracking path and host keywords";
    if (hasTrackingPath) return "tracking path keyword";
    if (hasTrackingHost) return "tracking host keyword";
    if (hasSignal(signals, "marketing campaign params only")) return "marketing campaign params only";
    if (hasSignal(signals, "sender-owned host")) return "sender-owned host";
    if (hasAnySignal(signals, ["srcset", "data-src", "data-original", "data-lazy", "data-lazy-src", "data-url", "data-srcset", "css background"])) {
      return "image from alternate source attribute";
    }
    return describeSignals(signals);
  }

  function describeLinkSignals(signals) {
    if (!signals || signals.length === 0) return "external link";
    if (hasSignal(signals, "tracking link host") && hasSignal(signals, "tracking/redirect path")) return "tracking link host with redirect path";
    if (hasSignal(signals, "tracking link host")) return "tracking link host";
    if (hasSignal(signals, "tracking/redirect path")) return "tracking/redirect path";
    if (hasSignal(signals, "tracking parameter")) return "tracking parameter";
    if (hasSignal(signals, "marketing campaign params")) return "marketing campaign params only";
    return describeSignals(signals);
  }

  function classifyImage(rawUrl, options = {}, el = null, source = "src") {
    if (!isRemote(rawUrl)) return null;
    const u = tryURL(rawUrl);
    if (!u) return null;

    const signals = [];
    const visibilitySignals = getVisibilitySignals(el);
    signals.push(...visibilitySignals);

    const idParams = matchingParams(u, IMAGE_ID_PARAMS);
    const eventParams = matchingParams(u, IMAGE_EVENT_PARAMS);
    const marketingParams = matchingParams(u, MARKETING_PARAMS);
    const pathSignal = TRACKING_PATH_RE.test(u.pathname);
    const hostSignal = TRACKING_HOST_RE.test(u.hostname);
    const sameSender = sameSenderHost(u.hostname, options.senderDomain);

    if (idParams.length) signals.push("recipient id parameter");
    if (eventParams.length) signals.push("open tracking parameter");
    if (pathSignal) signals.push(/(^|[\/._-])open([\/._-]|$)/i.test(u.pathname) ? "open path" : "tracking path keyword");
    if (hostSignal) signals.push("tracking host keyword");
    if (marketingParams.length) signals.push("marketing campaign params only");
    if (sameSender) signals.push("sender-owned host");
    if (source !== "src") signals.push(source);

    const hiddenOrTiny = visibilitySignals.length > 0;
    const strongUrlSignals = Number(idParams.length > 0) + Number(eventParams.length > 0) + Number(pathSignal) + Number(hostSignal);
    let classification = "external-image";
    let confidence = "low";

    if (hiddenOrTiny) {
      classification = "tracking-pixel";
      confidence = strongUrlSignals > 0 ? "high" : "medium";
    } else if (!sameSender && strongUrlSignals >= 2) {
      classification = "suspicious-image";
      confidence = "medium";
    }

    return {
      url: rawUrl,
      host: u.hostname,
      reason: describeImageSignals(signals, classification),
      signals,
      confidence,
      classification
    };
  }

  function classifyLink(rawUrl) {
    if (!isRemote(rawUrl)) return null;
    const u = tryURL(rawUrl);
    if (!u) return null;
    const params = matchingParams(u, LINK_TRACKING_PARAMS);
    const pathSuspicious = LINK_PATH_RE.test(u.pathname);
    const hostSuspicious = LINK_HOST_RE.test(u.hostname);
    if (!params.length && !pathSuspicious && !hostSuspicious) return null;

    const signals = [];
    if (params.length) signals.push(params.some(k => k.startsWith("utm_")) ? "marketing campaign params" : "tracking parameter");
    if (pathSuspicious) signals.push("tracking/redirect path");
    if (hostSuspicious) signals.push("tracking link host");

    const confidence = (pathSuspicious || hostSuspicious || params.some(k => !k.startsWith("utm_"))) ? "medium" : "low";
    return {
      url: rawUrl,
      host: u.hostname.toLowerCase(),
      reason: describeLinkSignals(signals),
      signals,
      confidence,
      classification: "tracking-link"
    };
  }

  function addFinding(result, finding) {
    if (!finding) return;
    if (finding.classification === "tracking-link") {
      result.links.push(finding);
    } else if (finding.classification === "tracking-pixel" || finding.classification === "suspicious-image") {
      result.suspicious.push(finding);
    } else {
      result.externals.push(finding);
    }
  }

  function srcsetCandidates(value) {
    return String(value || "")
      .split(",")
      .map(part => (part.trim().split(/\s+/)[0] || "").trim())
      .filter(Boolean);
  }

  function scanDocument(doc, options = {}) {
    const result = { suspicious: [], externals: [], links: [] };
    if (!doc?.querySelectorAll) return result;

    doc.querySelectorAll("img").forEach(img => {
      addFinding(result, classifyImage(img.getAttribute("src") || "", options, img, "src"));
      srcsetCandidates(img.getAttribute("srcset")).forEach(url => {
        addFinding(result, classifyImage(url, options, img, "srcset"));
      });
      ["data-src", "data-original", "data-lazy", "data-lazy-src", "data-url"].forEach(attr => {
        addFinding(result, classifyImage(img.getAttribute(attr), options, img, attr));
      });
      srcsetCandidates(img.getAttribute("data-srcset")).forEach(url => {
        addFinding(result, classifyImage(url, options, img, "data-srcset"));
      });
    });

    doc.querySelectorAll('[style*="url("]').forEach(el => {
      const urls = Array.from(String(el.getAttribute("style") || "").matchAll(/url\(([^)]+)\)/gi))
        .map(m => (m[1] || "").replace(/["']/g, "").trim());
      urls.forEach(url => addFinding(result, classifyImage(url, options, null, "css background")));
    });

    doc.querySelectorAll("a[href]").forEach(a => {
      addFinding(result, classifyLink(a.getAttribute("href") || ""));
    });

    try {
      const walker = doc.createTreeWalker(doc.body || doc, NodeFilter.SHOW_TEXT, null);
      const urlRegex = /(https?:\/\/[\w\-._~%!$&'()*+,;=:@/?#\[\]]+)/gi;
      let checked = 0;
      while (walker.nextNode()) {
        if (checked++ > 500) break;
        const text = walker.currentNode?.nodeValue || "";
        if (!/https?:\/\//i.test(text)) continue;
        (text.match(urlRegex) || []).slice(0, 50).forEach(url => addFinding(result, classifyLink(url)));
      }
    } catch (_) {}

    return normalize(result);
  }

  function scanHtml(html, options = {}) {
    if (!html) return { suspicious: [], externals: [], links: [] };
    try {
      const parser = new DOMParser();
      return scanDocument(parser.parseFromString(html, "text/html"), options);
    } catch (_) {
      return { suspicious: [], externals: [], links: [] };
    }
  }

  function normalize(result) {
    const confidenceRank = { high: 0, medium: 1, low: 2 };
    const dedupe = arr => {
      const seen = new Set();
      return arr
        .filter(item => item?.url && (seen.has(item.url) ? false : (seen.add(item.url), true)))
        .sort((a, b) => (confidenceRank[a.confidence] ?? 9) - (confidenceRank[b.confidence] ?? 9));
    };
    return {
      suspicious: dedupe(result.suspicious),
      externals: dedupe(result.externals),
      links: dedupe(result.links)
    };
  }

  root.PixelGuardScanner = {
    classifyImage,
    classifyLink,
    scanDocument,
    scanHtml,
    rules: {
      imageIdParams: IMAGE_ID_PARAMS.slice(),
      imageEventParams: IMAGE_EVENT_PARAMS.slice(),
      marketingParams: MARKETING_PARAMS.slice(),
      linkTrackingParams: LINK_TRACKING_PARAMS.slice()
    }
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
