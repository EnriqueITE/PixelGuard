/* global PixelGuardScanner */
(() => {
  function scan(body, senderDomain) {
    const parts = typeof body === "string" ? [{type: "text/html", content: body}] : body.parts;
    // Parse each HTML part independently. An unfinished element in one body
    // cannot consume the next one. All nodes remain in inert template contents.
    const doc = document.implementation.createHTMLDocument("");
    const template = doc.createElement("template");
    const fragment = doc.createElement("template").content;
    for (const part of parts) {
      if (part.type === "text/plain") {
        fragment.append(doc.createTextNode(part.content));
      } else {
        template.innerHTML = part.content;
        fragment.append(template.content);
      }
    }
    for (const element of fragment.querySelectorAll("script, style, title, iframe, object, embed")) {
      element.remove();
    }

    // All selected parts share one scan budget.
    const result = PixelGuardScanner.scanDocument(fragment, { senderDomain });
    result.partial ||= body.partial === true;
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
    return {result, labels, plainText: parts.every(part => part.type === "text/plain")};
  }

  globalThis.PixelGuardOriginalScan = { scan };
})();
