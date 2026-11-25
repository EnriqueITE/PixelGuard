/* global PixelGuardOriginalMime */
(() => {
  const SOURCE_LIMIT = 8 * 1024 * 1024;
  const HEX_ID = /^[\da-f]{1,16}$/i;
  const MESSAGE_WRAPPER = '[data-legacy-message-id], [data-message-id]';
  const EXCLUDED_UI = '.a3s, .pixelguard-gmail, [role="textbox"], [contenteditable]:not([contenteditable="false"]), [g_editable="true"]';
  const MENU_LABELS = new Set(['More message options', 'More options for this message', 'Más opciones de mensajes']);
  const ORIGINAL_LABELS = new Set(['Show original', 'Mostrar original']);

  function accountPath() {
    if (location.origin !== 'https://mail.google.com') return null;
    return /^\/mail\/u\/\d+(?=\/|$)/.exec(location.pathname)?.[0] || null;
  }

  function messageId(body) {
    if (!accountPath()) return null;
    // Gmail puts these identifiers outside the sender-controlled message HTML.
    const wrapper = body.parentElement?.closest(MESSAGE_WRAPPER);
    if (!wrapper) return null;
    const legacy = wrapper.getAttribute('data-legacy-message-id') || '';
    if (HEX_ID.test(legacy)) return legacy.toLowerCase();
    const modern = /^#?msg-f:(\d{1,20})$/.exec(wrapper.getAttribute('data-message-id') || '');
    if (!modern) return null;
    const hex = BigInt(modern[1]).toString(16);
    return HEX_ID.test(hex) ? hex : null;
  }

  function visibleControl(node) {
    if (node.closest(EXCLUDED_UI) || node.closest('[hidden], [inert], [aria-hidden="true"]') ||
        node.matches(':disabled, [aria-disabled="true"]') || !node.getClientRects().length) return false;
    return getComputedStyle(node).visibility === 'visible';
  }

  function visibleMenus() {
    return [...document.querySelectorAll('[role="menu"]')].filter(visibleControl);
  }

  function originalItem(menu, id) {
    const items = [...menu.querySelectorAll('[role="menuitem"]')].filter(node =>
      node.closest('[role="menu"]') === menu && visibleControl(node) &&
      ORIGINAL_LABELS.has((node.getAttribute('aria-label') || node.innerText || '').trim()));
    if (items.length !== 1) return null;
    const item = items[0];
    // An anchor is eligible only when it points to Gmail's source view for
    // this exact message and this account. Otherwise leave the choice to the user.
    const anchors = [item.closest('a[href]'), ...item.querySelectorAll('a[href]')].filter(Boolean);
    for (const anchor of anchors) {
      if (anchor.hasAttribute('ping') || anchor.hasAttribute('attributionsrc') || anchor.hasAttribute('download')) return null;
      let url;
      try { url = new URL(anchor.getAttribute('href'), location.href); } catch { return null; }
      if (url.origin !== location.origin || url.username || url.password || url.pathname.replace(/\/$/, '') !== accountPath() ||
          url.searchParams.get('view') !== 'om' ||
          url.searchParams.get('permmsgid') !== 'msg-f:' + BigInt('0x' + id).toString()) return null;
    }
    return item;
  }

  async function openNative(body) {
    const id = messageId(body);
    const message = body.parentElement?.closest(MESSAGE_WRAPPER);
    if (!id || !body.isConnected || !message || body.parentElement.closest(EXCLUDED_UI) || visibleMenus().length) return false;
    const buttons = [...message.querySelectorAll('button[aria-label], [role="button"][aria-label]')].filter(node =>
      node.closest(MESSAGE_WRAPPER) === message && !node.closest('a[href], form') && visibleControl(node) &&
      (node.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING) &&
      MENU_LABELS.has(node.getAttribute('aria-label')));
    if (buttons.length !== 1) return false;
    const control = buttons[0];
    if (control.getAttribute('aria-expanded') === 'true') return false;
    control.click();

    // Gmail sometimes attaches a menu to the document asynchronously. Only
    // select an item when the menu belongs to the original header control or
    // the same message. Unassociated popovers stay open for manual selection.
    const deadline = Date.now() + 700;
    do {
      if (!body.isConnected || messageId(body) !== id || document.hidden) return false;
      const menus = visibleMenus();
      if (menus.length) {
        if (menus.length !== 1) return false;
        const menu = menus[0];
        const owned = [control.getAttribute('aria-controls'), control.getAttribute('aria-owns')]
          .filter(Boolean).join(' ').split(/\s+/).filter(Boolean);
        const labelled = (menu.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean);
        const wrapper = menu.closest(MESSAGE_WRAPPER);
        if (wrapper && wrapper !== message) return false;
        if (owned.length && !owned.includes(menu.id)) return false;
        if (labelled.length && !labelled.includes(control.id)) return false;
        if (!owned.length && !labelled.length && wrapper !== message) return false;
        const item = originalItem(menu, id);
        if (!item) return false;
        item.click();
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 40));
    } while (Date.now() < deadline);
    return false;
  }

  async function read(id, signal) {
    const account = accountPath();
    if (!account || typeof id !== 'string' || !HEX_ID.test(id)) throw Error('Invalid Gmail message');
    // Same request as Gmail's own Download original link. In this view "th"
    // takes the individual message ID, including inside a conversation.
    const url = location.origin + account + '?view=att&th=' + id + '&attid=0&disp=comp&safe=1&zw';
    const response = await fetch(url, {
      credentials: 'same-origin', mode: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer',
      cache: 'no-store', signal
    });
    if (!response.body) throw Error('Gmail original unavailable');
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    try {
      const type = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
      if (response.status !== 200 || type === 'text/html' || type === 'application/xhtml+xml') {
        throw Error('Gmail original unavailable');
      }
      if (Number(response.headers.get('content-length')) > SOURCE_LIMIT) throw Error('Original too large');
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > SOURCE_LIMIT) throw Error('Original too large');
        chunks.push(value);
      }
    } catch (error) {
      await reader.cancel().catch(() => {});
      throw error;
    } finally {
      reader.releaseLock();
    }
    const source = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      source.set(chunk, offset);
      offset += chunk.length;
    }
    return PixelGuardOriginalMime.html(source);
  }

  globalThis.PixelGuardGmailOriginal = { messageId, read, openNative };
})();
