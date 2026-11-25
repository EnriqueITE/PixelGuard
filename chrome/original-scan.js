/* global PixelGuardScanner */
(() => {
  function scan(html, senderDomain) {
    // Parse in the extension's isolated world. Template contents belong to a
    // document with no browsing context, so remote resources stay inert.
    const doc = document.implementation.createHTMLDocument("");
    const template = doc.createElement("template");
    template.innerHTML = html;
    const fragment = template.content;
    for (const element of fragment.querySelectorAll("script, style, title, iframe, object, embed")) {
      element.remove();
    }

    const result = PixelGuardScanner.scanDocument(fragment, { senderDomain });
    const labels = new Map();
    for (const element of fragment.querySelectorAll("a[href], img[src][alt]")) {
      const anchor = element.localName === "a";
      const url = element.getAttribute(anchor ? "href" : "src");
      if (!/^https?:\/\//i.test(url)) continue;
      const text = anchor
        ? element.textContent.trim() || element.querySelector("img[alt]")?.getAttribute("alt") || element.getAttribute("aria-label")
        : element.getAttribute("alt");
      if (text?.trim() && !/^https?:\/\//i.test(text.trim())) {
        labels.set(url, text.trim().replace(/\s+/g, " ").slice(0, 180));
      }
    }
    return { result, labels };
  }

  globalThis.PixelGuardOriginalScan = { scan };
})();
