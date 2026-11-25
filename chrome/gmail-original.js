/* global PixelGuardOriginalMime */
(() => {
  const SOURCE_LIMIT = 8 * 1024 * 1024;
  const HEX_ID = /^[\da-f]{1,16}$/i;

  function accountPath() {
    if (location.origin !== 'https://mail.google.com') return null;
    return /^\/mail\/u\/\d+(?=\/|$)/.exec(location.pathname)?.[0] || null;
  }

  function messageId(body) {
    if (!accountPath()) return null;
    // Gmail puts these identifiers outside the sender-controlled message HTML.
    const wrapper = body.parentElement?.closest('[data-legacy-message-id], [data-message-id]');
    if (!wrapper) return null;
    const legacy = wrapper.getAttribute('data-legacy-message-id') || '';
    if (HEX_ID.test(legacy)) return legacy.toLowerCase();
    const modern = /^#?msg-f:(\d{1,20})$/.exec(wrapper.getAttribute('data-message-id') || '');
    if (!modern) return null;
    const hex = BigInt(modern[1]).toString(16);
    return HEX_ID.test(hex) ? hex : null;
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

  globalThis.PixelGuardGmailOriginal = { messageId, read };
})();
