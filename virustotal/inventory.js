/* Local-only message inventory. No resource is loaded or followed. */
(() => {
  const MAX_FILE_BYTES = 50 * 1024 * 1024;
  const MAX_LINKS = 1000;
  function validUrl(raw) {
    try {
      if (typeof raw !== 'string' || raw.length > 16384) return null;
      const u = new URL(raw);
      if (!['https:', 'http:'].includes(u.protocol) || u.username || u.password) return null;
      return u;
    } catch (_) { return null; }
  }
  function htmlParts(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script,style,template,noscript').forEach(node => node.remove());
    // textContent concatenates adjacent blocks, potentially inventing a URL.
    const text = [];
    const walker = doc.createTreeWalker(doc.body || doc, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) text.push(walker.currentNode.nodeValue || '');
    return {
      hrefs: Array.from(doc.querySelectorAll('a[href],area[href]'), a => a.getAttribute('href')),
      text: text.join('\n')
    };
  }
  function collectLinks(full, parseHTML = htmlParts) {
    const urls = new Map();
    let truncated = false;
    function add(raw) {
      const u = validUrl(raw);
      if (!u || urls.has(u.href)) return;
      if (urls.size >= MAX_LINKS) { truncated = true; return; }
      urls.set(u.href, { id: `link-${urls.size}`, url: u.href, host: u.hostname });
    }
    function textUrls(text) {
      for (const match of String(text || '').matchAll(/https?:\/\/[^\s<>"\u0000-\u001f]+/gi)) {
        let raw = match[0].replace(/[.,;!?]+$/, '');
        for (const [open, close] of [['(', ')'], ['[', ']'], ['{', '}']]) {
          while (raw.endsWith(close) && raw.split(close).length > raw.split(open).length) raw = raw.slice(0, -1);
        }
        add(raw);
      }
    }
    function visit(part, root = false) {
      if (!part) return;
      const type = String(part.contentType || '').split(';')[0].toLowerCase();
      const disposition = part.headers?.['content-disposition'];
      const value = Array.isArray(disposition) ? disposition.join(';') : String(disposition || '');
      if (part.name || /^attachment\b/i.test(value) || /\bfilename\s*=/i.test(value) || (!root && type === 'message/rfc822')) return;
      if (type === 'text/html' && part.body) {
        const parsed = parseHTML(part.body);
        parsed.hrefs.forEach(add);
        textUrls(parsed.text);
      } else if (type === 'text/plain') textUrls(part.body);
      for (const child of part.parts || []) visit(child);
    }
    visit(full, true);
    return { links: [...urls.values()], truncated };
  }
  function reportUrl(raw) {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'https:' || !['www.virustotal.com', 'virustotal.com'].includes(u.hostname) ||
          u.port || u.username || u.password || u.search || u.hash || !/^\/ui\/widget\/html\/[A-Za-z0-9_=-]+$/.test(u.pathname)) return null;
      return u.href;
    } catch (_) { return null; }
  }
  globalThis.PixelGuardVTInventory = { collectLinks, validUrl, reportUrl, MAX_FILE_BYTES };
})();
