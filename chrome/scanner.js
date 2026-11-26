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
  const MAX_SCAN_NODES = 20000;
  const MAX_SCAN_URLS = 4096;
  const MAX_SCAN_CHARS = 4 * 1024 * 1024;
  const MAX_ATTRIBUTE_CHARS = 65536;
  const MAX_URL_CHARS = 16384;
  const MAX_ELEMENT_IMAGES = 128;
  const MAX_TEXT_NODES = 501;
  const MAX_LINKS_PER_TEXT = 50;
  const AMAZON_STORES = new Set([
    "amazon.ae", "amazon.ca", "amazon.co.jp", "amazon.co.uk", "amazon.co.za",
    "amazon.com", "amazon.com.au", "amazon.com.be", "amazon.com.br", "amazon.com.mx",
    "amazon.com.tr", "amazon.de", "amazon.eg", "amazon.es", "amazon.fr", "amazon.ie",
    "amazon.in", "amazon.it", "amazon.nl", "amazon.pl", "amazon.sa", "amazon.se", "amazon.sg"
  ]);

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
    const result = Object.create(null);
    String(styleText || "").split(";").forEach(part => {
      const idx = part.indexOf(":");
      if (idx === -1) return;
      result[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
    });
    return result;
  }

  function getComputedStyleSafe(el, inlineStyle) {
    try {
      const view = el?.ownerDocument?.defaultView;
      if (view?.getComputedStyle) return view.getComputedStyle(el);
      // Template contents have no window or computed layout. Their inline
      // declarations still record an explicit display:none or opacity:0.
      if (el?.style) return el.style;
    } catch (_) {}
    return inlineStyle;
  }

  function hasTinyPair(size) {
    return size.width != null && size.height != null && size.width <= 2 && size.height <= 2;
  }

  function hasZeroDimension(size) {
    return size.width === 0 || size.height === 0;
  }

  function boundedAttribute(value) {
    return value && value.length > MAX_ATTRIBUTE_CHARS ? null : value || "";
  }

  function getVisibilitySignals(el, readField = boundedAttribute, styleText = readField(el?.getAttribute?.("style"))) {
    if (!el) return [];
    const signals = [];
    const inlineStyle = parseStyle(styleText);
    const attrs = {
      width: parseCssNumber(readField(el.getAttribute?.("width"))),
      height: parseCssNumber(readField(el.getAttribute?.("height")))
    };
    const styled = {width: parseCssNumber(inlineStyle.width), height: parseCssNumber(inlineStyle.height)};
    // null means the style exceeded a budget. Do not ask CSSOM to evaluate it.
    const style = styleText === null ? inlineStyle : getComputedStyleSafe(el, inlineStyle);
    const displayNone = style.display === "none";
    const visibilityHidden = style.visibility === "hidden";
    const opacityZero = style.opacity !== "" && Number(style.opacity ?? 1) === 0;
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

  function classifyImage(rawUrl, options = {}, el = null, source = "src", cachedVisibility) {
    if (options.resolveImageUrl) rawUrl = options.resolveImageUrl(rawUrl);
    if (!isRemote(rawUrl)) return null;
    const u = tryURL(rawUrl);
    if (!u) return null;

    const signals = [];
    const visibilitySignals = cachedVisibility ?? getVisibilitySignals(el);
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

  function isAmazonClickRedirect(u) {
    if (!["/gp/f.html", "/gp/r.html"].includes(u.pathname) || !AMAZON_STORES.has(u.hostname.replace(/^www\./, ""))) return false;
    const params = u.searchParams;
    if (params.get("T") !== "C" || !params.get("M") || !params.get("R")) return false;
    const destination = params.get("U");
    return isRemote(destination) && tryURL(destination) !== null;
  }

  function isShopClickRedirect(u) {
    return u.origin === "https://mail.shop.app" && /^\/_t\/c\/v3\/[A-Za-z0-9_-]+={0,2}$/.test(u.pathname);
  }

  function classifyLink(rawUrl) {
    if (!isRemote(rawUrl)) return null;
    const u = tryURL(rawUrl);
    if (!u) return null;
    const params = matchingParams(u, LINK_TRACKING_PARAMS);
    const pathSuspicious = LINK_PATH_RE.test(u.pathname) || isAmazonClickRedirect(u) || isShopClickRedirect(u);
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

  function* imageCandidates(el, style, readField) {
    if (el.localName === "img") {
      for (const source of ["src", "srcset", "data-src", "data-original", "data-lazy", "data-lazy-src", "data-url", "data-srcset"]) {
        const value = readField(el.getAttribute(source));
        if (!value) continue;
        if (source.endsWith("srcset")) {
          for (const match of value.matchAll(/(?:^|,)\s*([^,\s]+)/g)) yield [match[1], source];
        } else {
          yield [value, source];
        }
      }
    }
    if (!style) return;
    // Advance past each complete value. An unclosed value consumes the tail once.
    const start = /url\(/gi;
    while (start.exec(style)) {
      const end = style.indexOf(")", start.lastIndex);
      if (end < 0) break;
      const url = style.slice(start.lastIndex, end).replace(/["']/g, "").trim();
      start.lastIndex = end + 1;
      if (url) yield [url, "css background"];
    }
  }

  function emptyResult(partial = false) {
    return { suspicious: [], externals: [], links: [], partial };
  }

  function scanDocument(doc, options = {}) {
    const result = emptyResult();
    let remainingChars = MAX_SCAN_CHARS;
    let urls = 0;
    let nodes = 0;
    let textNodes = 0;

    function readField(value, limit = MAX_ATTRIBUTE_CHARS) {
      if (!value) return "";
      if (value.length > limit || value.length > remainingChars) {
        result.partial = true;
        return null;
      }
      remainingChars -= value.length;
      return value;
    }
    function acceptUrl(url) {
      if (++urls > MAX_SCAN_URLS || url.length > MAX_URL_CHARS) {
        result.partial = true;
        return false;
      }
      return true;
    }
    function scanElement(el) {
      const style = readField(el.getAttribute("style"));
      let visibility, images = 0;
      for (const [url, source] of imageCandidates(el, style, readField)) {
        if (++images > MAX_ELEMENT_IMAGES) {
          result.partial = true;
          break;
        }
        if (acceptUrl(url)) {
          visibility ??= getVisibilitySignals(el, readField, style);
          addFinding(result, classifyImage(url, options, el, source, visibility));
        }
        if (urls > MAX_SCAN_URLS) return;
      }
      if (el.localName === "a") {
        const href = readField(el.getAttribute("href"), MAX_URL_CHARS);
        if (href && acceptUrl(href)) addFinding(result, classifyLink(href));
      }
    }
    function scanText(node) {
      if (++textNodes > MAX_TEXT_NODES) {
        result.partial = true;
        return;
      }
      const text = readField(node.nodeValue, MAX_SCAN_CHARS);
      if (!text) return;
      let count = 0;
      for (const [url] of text.matchAll(/https?:\/\/[\w\-._~%!$&'()*+,;=:@/?#\[\]]+/gi)) {
        if (++count > MAX_LINKS_PER_TEXT) {
          result.partial = true;
          break;
        }
        if (acceptUrl(url)) addFinding(result, classifyLink(url));
        if (urls > MAX_SCAN_URLS) return;
      }
    }

    try {
      const owner = doc.ownerDocument || doc;
      const filter = options.excludeNode && {acceptNode: node =>
        options.excludeNode(node) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT};
      const walker = owner.createTreeWalker(doc.body || doc, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, filter);
      while (walker.nextNode()) {
        if (++nodes > MAX_SCAN_NODES) {
          result.partial = true;
          break;
        }
        const node = walker.currentNode;
        if (node.nodeType === 3) scanText(node);
        else scanElement(node);
        if (urls > MAX_SCAN_URLS) break;
      }
    } catch (_) {
      result.partial = true;
    }
    return mergeResults([result]);
  }

  function scanHtml(html, options = {}) {
    if (!html) return emptyResult();
    try {
      const parser = new DOMParser();
      return scanDocument(parser.parseFromString(html, "text/html"), options);
    } catch (_) {
      return emptyResult(true);
    }
  }

  function mergeResults(results) {
    const severity = {"tracking-pixel": 3, "suspicious-image": 2, "external-image": 1, "tracking-link": 1};
    const confidence = {high: 3, medium: 2, low: 1};
    const images = new Map(), links = new Map();
    const merged = emptyResult();
    for (const result of results) {
      if (result.partial) merged.partial = true;
      for (const group of [result.suspicious, result.externals, result.links]) {
        for (const item of group) {
          const items = item.classification === "tracking-link" ? links : images;
          const previous = items.get(item.url);
          if (!previous || severity[item.classification] > severity[previous.classification] ||
              (item.classification === previous.classification && confidence[item.confidence] > confidence[previous.confidence])) {
            items.set(item.url, item);
          }
        }
      }
    }
    for (const item of images.values()) addFinding(merged, item);
    merged.links = [...links.values()];
    for (const group of [merged.suspicious, merged.externals, merged.links]) {
      group.sort((a, b) => confidence[b.confidence] - confidence[a.confidence]);
    }
    return merged;
  }

  root.PixelGuardScanner = {
    classifyImage,
    classifyLink,
    mergeResults,
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
