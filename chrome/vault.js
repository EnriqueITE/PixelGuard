/* The caller serializes changes with an origin-wide Web Lock. */
(() => {
  async function keyRecord(mode, operation) {
    const db = await new Promise((resolve, reject) => {
      const open = indexedDB.open('pixelguard-vault', 1);
      open.onupgradeneeded = () => open.result.createObjectStore('keys');
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction('keys', mode);
        const request = operation(tx.objectStore('keys'));
        tx.oncomplete = () => resolve(request.result);
        tx.onabort = () => reject(tx.error || new Error('Key storage unavailable'));
      });
    } finally { db.close(); }
  }
  const persistentKeys = {
    get: () => keyRecord('readonly', store => store.get('vt')),
    add: key => keyRecord('readwrite', store => store.add(key, 'vt')),
    remove: () => keyRecord('readwrite', store => store.delete('vt'))
  };
  function create(keys = persistentKeys) {
    const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
    const decode = base64 => Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    async function seal(text) {
      let key = await keys.get();
      if (!key) {
        key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        await keys.add(key);
      }
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
      return { version: 1, iv: encode(iv), data: encode(data) };
    }
    async function unseal(record) {
      const key = await keys.get();
      if (!key || record.version !== 1) throw new Error('Key unavailable');
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(record.iv) }, key, decode(record.data));
      return new TextDecoder().decode(plaintext);
    }
    return { seal, unseal, remove: keys.remove };
  }
  globalThis.PixelGuardVault = { create };
})();
