/* global PixelGuardOriginalMime */
(() => {
  const SOURCE_LIMIT = 8 * 1024 * 1024;
  const HEX_ID = /^[\da-f]{1,16}$/i;
  const MAILBOX_HINT = /^[\da-f]{8,32}$/i;
  const PERM_ID = /^(?:msg-f:\d{1,20}|msg-a:[\w-]{1,64})$/;
  const MESSAGE_WRAPPER = '[data-legacy-message-id], [data-message-id]';
  function accountPath(page) {
    if (page.origin !== 'https://mail.google.com') return null;
    return /^\/mail\/u\/\d+(?=\/|$)/.exec(page.pathname)?.[0] || null;
  }

  function permanentId(wrapper) {
    const id = (wrapper?.getAttribute('data-message-id') || '').replace(/^#/, '');
    return PERM_ID.test(id) ? id : '';
  }

  function messageId(body) {
    if (!accountPath(location)) return null;
    // Gmail puts these identifiers outside the sender-controlled message HTML.
    const wrapper = body.parentElement?.closest(MESSAGE_WRAPPER);
    if (!wrapper) return null;
    const legacy = wrapper.getAttribute('data-legacy-message-id') || '';
    if (HEX_ID.test(legacy)) return legacy.toLowerCase();
    const modern = permanentId(wrapper);
    if (!modern) return null;
    if (modern.startsWith('msg-a:')) return modern;
    const hex = BigInt(modern.slice(6)).toString(16);
    return HEX_ID.test(hex) ? hex : null;
  }

  function sourceLinkHint(account, id, permId) {
    // Reuse Gmail's mailbox hint only when it is already in this account's
    // address bar or an original-message link for this specific message.
    const own = new URL(location.href);
    const hint = own.searchParams.get('ik') || '';
    if (MAILBOX_HINT.test(hint)) return hint;
    for (const anchor of document.querySelectorAll('a[href*="ik="][href*="view="]')) {
      if (anchor.closest('.a3s, .pixelguard-gmail, [role="textbox"], [contenteditable]')) continue;
      let url;
      try { url = new URL(anchor.getAttribute('href'), own); } catch { continue; }
      if (url.origin !== own.origin || url.pathname.replace(/\/$/, '') !== account) continue;
      const params = url.searchParams;
      const view = params.get('view');
      if (view !== 'om' && !(view === 'att' && params.get('attid') === '0' && params.get('disp') === 'comp')) continue;
      if (params.has('permmsgid') ? params.get('permmsgid') !== permId : params.get('th') !== id) continue;
      const value = params.get('ik') || '';
      if (MAILBOX_HINT.test(value)) return value;
    }
    return '';
  }

  async function readSource(url, signal, expectHtmlPage) {
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
      const isHtmlPage = type === 'text/html' || type === 'application/xhtml+xml';
      if (Number(response.headers.get('content-length')) > SOURCE_LIMIT) throw new RangeError('Original too large');
      if (response.status !== 200 || isHtmlPage !== expectHtmlPage) {
        throw Error('Gmail original unavailable');
      }
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > SOURCE_LIMIT) throw new RangeError('Original too large');
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
    return source;
  }

  async function read(id, signal, body) {
    const account = accountPath(location);
    if (!account || typeof id !== 'string' || !(HEX_ID.test(id) || PERM_ID.test(id))) throw Error('Invalid Gmail message');
    const wrapper = body?.parentElement?.closest(MESSAGE_WRAPPER);
    const nativeId = permanentId(wrapper);
    const permId = nativeId || (HEX_ID.test(id) ? 'msg-f:' + BigInt('0x' + id).toString() : id);
    const hasLegacy = HEX_ID.test(wrapper ? wrapper.getAttribute('data-legacy-message-id') || '' : id);
    function checkCurrent() {
      if (signal?.aborted) throw Error('Gmail read cancelled');
      if (accountPath(location) !== account || (body && (!body.isConnected || messageId(body) !== id ||
          permanentId(body.parentElement?.closest(MESSAGE_WRAPPER)) !== nativeId))) throw Error('Gmail message changed');
    }
    checkCurrent();
    let hint = sourceLinkHint(account, id, permId);
    if (!hint) {
      try {
        const reply = await globalThis.chrome?.runtime?.sendMessage({type: 'pg:gmail:mailboxHint'});
        if (reply?.ok && typeof reply.hint === 'string' && MAILBOX_HINT.test(reply.hint)) hint = reply.hint;
      } catch { /* The same-account, hint-free download still works for some messages. */ }
    }
    const base = location.origin + account + '/?';
    const suffix = hint ? '&ik=' + hint : '';
    const view = base + 'view=om&permmsgid=' + permId + suffix;
    const download = param => base + 'view=att&' + param + '&attid=0&disp=comp&safe=1&zw' + suffix;
    const preferred = download(nativeId || !hasLegacy ? 'permmsgid=' + permId : 'th=' + id);
    const routes = hint ? [view, preferred] : [preferred, view];
    // Some Gmail views accept only the legacy message ID when downloading.
    if (nativeId && hasLegacy) routes.push(download('th=' + id));
    for (const url of routes) {
      checkCurrent();
      let source;
      try {
        source = await readSource(url, signal, url === view);
        if (url === view) {
          // Keep the entire Gmail page inert. Only its escaped source text enters the MIME reader.
          const template = document.implementation.createHTMLDocument('').createElement('template');
          template.innerHTML = new TextDecoder('utf-8').decode(source);
          const raw = template.content.querySelectorAll('pre.raw_message_text');
          if (raw.length !== 1) throw Error('Gmail original unavailable');
          source = raw[0].textContent;
        }
      } catch (error) {
        if (url === routes[routes.length - 1] || signal?.aborted || error.name === 'AbortError' || error instanceof RangeError) throw error;
        continue;
      }
      checkCurrent();
      return PixelGuardOriginalMime.html(source);
    }
  }

  globalThis.PixelGuardGmailOriginal = { messageId, read };
})();
