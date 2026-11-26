/* global PixelGuardGmailOriginal, PixelGuardVTInventory */
(() => {
  const hiddenOrDraft = '[contenteditable]:not([contenteditable="false"]), [g_editable="true"], ' +
    '[role="textbox"], [aria-hidden="true"], [hidden], [inert]';
  const excluded = '.a3s, .pixelguard-gmail, .M9, .adB, [data-draft-id], .kv, .ky, .kQ, .kx, ' + hiddenOrDraft;
  const wrapperSelector = '[data-legacy-message-id], [data-message-id]';
  const partPattern = /^0(?:\.\d{1,4}){1,16}$/;

  function messageAnchor(card) {
    const wrapper = card.parentElement.closest(wrapperSelector);
    const container = card.closest('.adn');
    if (!container) return wrapper?.querySelector('.a3s') ? card : null;
    // An attachment-only message can have an empty, hidden or absent body.
    if (wrapper && container.contains(wrapper)) return card;
    // Some views put the message ID on a sibling around the text instead.
    return [...container.querySelectorAll('.a3s')].find(body => {
      const owner = body.parentElement.closest(wrapperSelector);
      return owner && container.contains(owner) && body.closest('.adn') === container &&
        !body.parentElement.closest('.a3s, .M9, .adB, [contenteditable], [role="textbox"]');
    });
  }

  function describe(card) {
    if (!card.isConnected || card.closest(excluded) || !card.getClientRects().length ||
        getComputedStyle(card).visibility !== 'visible') return null;
    const source = messageAnchor(card);
    if (!source) return null;
    const wrapper = source.parentElement.closest(wrapperSelector);
    const messageId = PixelGuardGmailOriginal.messageId(source);
    if (!messageId) return null;
    const account = /^\/mail\/u\/(\d+)(?=\/|$)/.exec(location.pathname);
    if (!account) return null;

    const anchor = card.matches('a') ? card : card.querySelector('a.aQy, a[href]');
    const rawDownload = card.getAttribute('download_url') || anchor?.getAttribute('download_url') || '';
    const download = /^[^:]*:([\s\S]*?):(https?:\/\/[\s\S]+)$/i.exec(rawDownload);
    const name = download?.[1] || card.querySelector('.aV3, .aQA > span')?.textContent?.trim() ||
      anchor?.getAttribute('download');
    if (!name || name.length > 1024) return null;
    const href = anchor?.getAttribute('href');
    const urls = [download?.[2], href && !href.startsWith('#') ? href : null].filter(Boolean);
    let partId = '';
    let hint = '';
    const owner = (wrapper.getAttribute('data-message-id') || '').replace(/^#/, '') ||
      (/^[a-f0-9]+$/i.test(messageId) ? 'msg-f:' + BigInt('0x' + messageId) : messageId);
    for (const raw of urls) {
      let url;
      try { url = new URL(raw, location.href); } catch { return null; }
      if (url.username || url.password || url.protocol !== 'https:') return null;
      // Signed resource URLs are hints only. Never contact their origin.
      const signed = url.origin === 'https://mail-attachment.googleusercontent.com' &&
        (url.pathname === '/attachment/' || url.pathname.startsWith('/attachment/u/' + account[1] + '/'));
      const path = url.pathname.replace(/\/$/, '');
      // Some Gmail cards prepend the account URL twice in download_url, while
      // their preview href uses it once. Only recognize the same account twice.
      const nativePath = path === account[0] || (raw === download?.[2] &&
        path === account[0] + '/' + location.origin + account[0]);
      if (!signed && (url.origin !== 'https://mail.google.com' || !nativePath || url.searchParams.get('view') !== 'att')) return null;
      const legacy = url.searchParams.get('th');
      const permanent = url.searchParams.get('permmsgid');
      if ((legacy && legacy.toLowerCase() !== messageId) || (permanent && permanent !== owner) ||
          (!signed && !legacy && !permanent)) return null;
      const part = url.searchParams.get('attid');
      if (signed && (!part || (!legacy && !permanent))) continue;
      if (!partPattern.test(part || '') || (partId && partId !== part)) return null;
      partId = part;
      hint = url.searchParams.get('ik') || hint;
    }
    // For preview-only native cards, resolve the filename in this message's MIME.
    // Unknown or ambiguous parts will be refused by the MIME reader.
    if (!urls.length && (!card.closest('.aQH') || !card.querySelector('.aQw'))) return null;
    return {source, name, messageId, partId, hint: /^[\da-f]{8,32}$/i.test(hint) ? hint : ''};
  }

  function create(open, contextActive) {
    const records = new Map();
    const transfers = new Set();
    function current(record) {
      if (!contextActive() || record.page !== location.href || records.get(record.card) !== record) return false;
      const metadata = describe(record.card);
      return metadata?.source === record.source && metadata.name === record.name &&
        metadata.messageId === record.messageId && metadata.partId === record.partId;
    }
    function publicItem({id, name}) { return {id, name}; }
    function refresh(theme) {
      const keep = new Set();
      for (const card of document.querySelectorAll('.aZo')) {
        const data = describe(card);
        if (!data) continue;
        let record = records.get(card);
        if (!record || record.page !== location.href || record.source !== data.source || record.messageId !== data.messageId ||
            record.partId !== data.partId || record.name !== data.name) {
          record?.button.remove();
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'pixelguard-attachment-action';
          button.textContent = 'VirusTotal';
          button.setAttribute('aria-label', 'VirusTotal · ' + data.name);
          record = {...data, id: crypto.randomUUID(), page: location.href, card, button};
          records.set(card, record);
          button.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
            if (event.isTrusted && current(record)) open(event, {attachment: publicItem(record)}, card);
          });
        }
        if (record.button.dataset.theme !== theme) record.button.dataset.theme = theme;
        if (card.matches('a, button, [role="button"], [role="link"]')) {
          if (card.nextElementSibling !== record.button) card.after(record.button);
        } else if (record.button.parentNode !== card) {
          // Keep our action outside the preview link but in the same wrapping card.
          card.append(record.button);
        }
        keep.add(card);
      }
      for (const [card, record] of records) {
        if (!keep.has(card)) { record.button.remove(); records.delete(card); }
      }
    }
    function find(id) {
      for (const record of records.values()) if (record.id === id && current(record)) return record;
      return null;
    }
    function connect(port) {
      const controller = new AbortController();
      transfers.add(controller);
      port.onDisconnect.addListener(() => {
        controller.abort();
        transfers.delete(controller);
      });
      let started = false;
      port.onMessage.addListener(async request => {
        if (started) return;
        started = true;
        try {
          const record = find(request?.id);
          if (!record) throw Error('Gmail attachment unavailable');
          const valid = () => !controller.signal.aborted && current(record);
          const duplicateName = [...records.values()].some(other => other !== record &&
            other.messageId === record.messageId && other.name === record.name);
          const bytes = await PixelGuardGmailOriginal.read(record.messageId, controller.signal, record.source, valid, {
            name: record.name, partId: record.partId, hint: record.hint, duplicateName, limit: PixelGuardVTInventory.MAX_FILE_BYTES
          });
          if (!valid()) throw Error('Gmail attachment changed');
          port.postMessage({name: record.name, size: bytes.length});
          const chunkSize = 96 * 1024;
          for (let offset = 0; offset < bytes.length; offset += chunkSize) {
            if (controller.signal.aborted) return;
            let chunk = '';
            const end = Math.min(offset + chunkSize, bytes.length);
            for (let i = offset; i < end; i += 8192) {
              chunk += String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, end)));
            }
            port.postMessage({chunk: btoa(chunk)});
            // Yield between batches so closing the popup or navigating cancels delivery.
            if ((offset / chunkSize) % 8 === 7) {
              await new Promise(resolve => setTimeout(resolve, 0));
              if (!valid()) throw Error('Gmail attachment changed');
            }
          }
          port.postMessage({done: true});
        } catch (error) {
          if (!controller.signal.aborted) {
            try { port.postMessage({error: error instanceof RangeError ? 'too_large' : 'unavailable'}); } catch {}
          }
        } finally {
          transfers.delete(controller);
          port.disconnect();
        }
      });
    }
    function clear() {
      for (const record of records.values()) record.button.remove();
      records.clear();
      for (const controller of transfers) controller.abort();
      transfers.clear();
    }
    return {refresh, clear, find, connect, list: () => [...records.values()].filter(current).map(publicItem)};
  }

  globalThis.PixelGuardGmailAttachments = {create};
})();
