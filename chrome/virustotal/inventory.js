/* Gmail supplies visible links and plain text. Read their addresses without opening them. */
(() => {
  const MAX_FILE_BYTES = 50 * 1024 * 1024;
  const MAX_URL_LENGTH = 16384;
  const MAX_LINKS = 1000;
  const closingFor = {'(': ')', '[': ']', '{': '}'};

  function validUrl(raw) {
    if (typeof raw !== 'string' || raw.length > MAX_URL_LENGTH) return null;
    try {
      const url = new URL(raw);
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return null;
      return url;
    } catch { return null; }
  }

  function trimTextUrl(raw) {
    if (raw.length > MAX_URL_LENGTH) return null;
    // Keep balanced delimiters in addresses such as Wikipedia article URLs.
    const balance = {')': 0, ']': 0, '}': 0};
    for (const character of raw) {
      if (character in closingFor) balance[closingFor[character]]++;
      else if (character in balance) balance[character]--;
    }
    let end = raw.length;
    while (end > 0) {
      const tail = raw[end - 1];
      if (balance[tail] < 0) balance[tail]++;
      else if (!'.,;!?'.includes(tail)) break;
      end--;
    }
    return raw.slice(0, end);
  }

  function* candidates(parts) {
    for (const {hrefs, text} of parts) {
      yield* hrefs;
      for (const match of text.matchAll(/https?:\/\/[^\s<>"\u0000-\u001f]+/gi)) {
        yield trimTextUrl(match[0]);
      }
    }
  }

  function collectLinks(parts) {
    const addresses = new Set();
    let truncated = false;
    for (const candidate of candidates(parts)) {
      const url = validUrl(candidate);
      if (!url || addresses.has(url.href)) continue;
      if (addresses.size === MAX_LINKS) {
        truncated = true;
        break;
      }
      addresses.add(url.href);
    }
    return {links: Array.from(addresses, url => ({url})), truncated};
  }

  function reportUrl(raw) {
    const url = validUrl(raw);
    if (!url || url.protocol !== 'https:' || !['www.virustotal.com', 'virustotal.com'].includes(url.hostname) ||
        url.port || url.search || url.hash || !/^\/ui\/widget\/html\/[A-Za-z0-9_=-]+$/.test(url.pathname)) return null;
    return url.href;
  }

  globalThis.PixelGuardVTInventory = {collectLinks, validUrl, reportUrl, MAX_FILE_BYTES};
})();
