/* VT Augment: explicit, user-initiated enrichment only. */
(() => {
  const PERMISSIONS = { permissions: ['sensitiveDataUpload'], origins: ['https://www.virustotal.com/*'] };
  const PREFIX = 'pg:vt:';
  function createService(api, deps = {}) {
    const request = deps.fetch || globalThis.fetch;
    const crypt = deps.crypto || globalThis.crypto;
    const now = deps.now || Date.now;
    const later = deps.setTimeout || globalThis.setTimeout;
    const cancelTimer = deps.clearTimeout || globalThis.clearTimeout;
    const inventory = globalThis.PixelGuardVTInventory;
    const sessions = new Map();
    let config = { enabled: false, apiKey: '' }, revision = 0, quota = [], sequence = 0;
    let writes = Promise.resolve();
    const fail = (error, extra = {}) => ({ ok: false, error, ...extra });
    const ready = api.storage.local.get(['vtConfig', 'vtQuota']).then(stored => {
      const key = stored.vtConfig?.apiKey;
      config = { enabled: stored.vtConfig?.enabled === true, apiKey: typeof key === 'string' ? key : '' };
      quota = Array.isArray(stored.vtQuota) ? stored.vtQuota.filter(Number.isFinite) : [];
    });
    // Handle startup storage rejection immediately; requests will return a safe error.
    ready.catch(() => {});
    function serialize(fn) {
      const task = writes.catch(() => {}).then(fn);
      writes = task;
      return task;
    }
    function invalidate(tabId) {
      const session = sessions.get(tabId);
      if (session) {
        session.controller?.abort();
        session.results.clear();
        sessions.delete(tabId);
      }
    }
    function clear() { for (const tabId of sessions.keys()) invalidate(tabId); }
    function messageDisplayed(tab, message) {
      const current = sessions.get(tab.id);
      if (current && current.messageId !== message?.id) invalidate(tab.id);
    }
    function permissionsRemoved(removed) {
      if ((removed.permissions || []).includes('sensitiveDataUpload') || (removed.origins || []).some(p => p.includes('virustotal.com') || p === '<all_urls>')) {
        revision++;
        clear();
        serialize(async () => {
          config = { ...config, enabled: false };
          await api.storage.local.set({ vtConfig: config });
        }).catch(() => {});
      }
    }
    const granted = () => api.permissions.contains(PERMISSIONS);
    function authorized(sender, action) {
      const pages = action === 'saveConfig' || action === 'deleteConfig' ? ['options/options.html'] :
        action === 'getConfig' ? ['options/options.html', 'popup/popup.html'] : ['popup/popup.html'];
      return sender?.id === api.runtime.id && pages.some(page => sender.url === api.runtime.getURL(page));
    }
    async function publicConfig() {
      const allowed = await granted();
      return { ok: true, enabled: config.enabled && !!config.apiKey && allowed, configured: !!config.apiKey, granted: allowed };
    }
    async function enabled() {
      if (!config.enabled || !config.apiKey) return fail('disabled');
      if (!await granted()) return fail('permission_denied');
      return null;
    }
    async function getInventory() {
      const blocked = await enabled();
      if (blocked) return blocked;
      const generation = revision;
      const tabs = await api.tabs.query({ active: true, currentWindow: true });
      const tabId = tabs[0]?.id;
      if (tabId == null) return fail('no_message');
      let session = sessions.get(tabId);
      if (!session) {
        session = { id: `vt-${++sequence}`, tabId, messageId: null, results: new Map(), items: new Map(), pending: null };
        sessions.set(tabId, session);
      }
      const displayed = await api.messageDisplay.getDisplayedMessage(tabId);
      if (generation !== revision || sessions.get(tabId) !== session) return fail('stale_message');
      if (!displayed) { invalidate(tabId); return fail('no_message'); }
      if (session.messageId != null && session.messageId !== displayed.id) {
        invalidate(tabId);
        return fail('stale_message');
      }
      session.messageId = displayed.id;
      if (session.view) return { ok: true, ...session.view };
      if (session.building) return session.building;
      session.building = (async () => {
        const full = await api.messages.getFull(displayed.id);
        let attachments = [], attachmentError;
        try { attachments = await api.messages.listAttachments(displayed.id); }
        catch (_) { attachmentError = 'unavailable'; }
        if (!await current(session, generation)) return fail('stale_message');
        const collected = inventory.collectLinks(full, deps.parseHTML);
        for (const item of collected.links) session.items.set(item.id, { ...item, type: 'link' });
        const files = attachments.map((file, index) => {
          const item = { id: `file-${index}`, name: file.name || 'attachment', size: file.size, partName: file.partName, type: 'file' };
          session.items.set(item.id, item);
          return { id: item.id, name: item.name, size: item.size };
        });
        session.view = { sessionId: session.id, links: collected.links, attachments: files, truncated: collected.truncated, attachmentError };
        return { ok: true, ...session.view };
      })().finally(() => { session.building = null; });
      return session.building;
    }
    async function current(session, generation) {
      if (generation !== revision || sessions.get(session.tabId) !== session) return false;
      try {
        const displayed = await api.messageDisplay.getDisplayedMessage(session.tabId);
        const valid = displayed?.id === session.messageId && generation === revision && sessions.get(session.tabId) === session;
        if (!valid && sessions.get(session.tabId) === session) invalidate(session.tabId);
        return valid;
      } catch (_) {
        if (sessions.get(session.tabId) === session) invalidate(session.tabId);
        return false;
      }
    }
    async function reserve(session, generation) {
      return serialize(async () => {
        if (!await current(session, generation)) return fail('stale_message');
        const time = now();
        quota = quota.filter(t => t > time - 86400000 && t <= time);
        const minute = quota.filter(t => t > time - 60000);
        if (minute.length >= 4) return fail('rate_limit', { retryAfter: Math.ceil((minute[0] + 60000 - time) / 1000) });
        if (quota.length >= 500) return fail('daily_limit');
        const next = [...quota, time];
        await api.storage.local.set({ vtQuota: next });
        quota = next;
        return null;
      });
    }
    function sessionFor(id) { return [...sessions.values()].find(s => s.id === id); }
    async function query(msg) {
      const generation = revision;
      const blocked = await enabled();
      if (blocked) return blocked;
      const session = sessionFor(msg.sessionId);
      if (!session || !await current(session, generation)) return fail('stale_message');
      const item = session.items.get(msg.itemId);
      if (!item) return fail('unavailable');
      if (!['domain', 'url', 'file'].includes(msg.kind) || (item.type === 'file') !== (msg.kind === 'file')) return fail('unavailable');
      if (msg.kind === 'url' && msg.confirmedUrl !== item.url) return fail('confirmation_required');
      const key = `${item.id}:${msg.kind}`;
      const cached = session.results.get(key);
      if (cached && now() - cached.queriedAt < 600000) return { ok: true, result: cached.public };
      if (session.pending) return session.pending.key === key ? session.pending.promise : fail('busy');
      const promise = execute(session, item, msg.kind, key, generation);
      session.pending = { key, promise };
      try { return await promise; } finally { if (session.pending?.promise === promise) session.pending = null; }
    }
    async function execute(session, item, kind, cacheKey, generation) {
      let observable;
      if (kind === 'file') {
        if (item.size > inventory.MAX_FILE_BYTES) return fail('too_large');
        let file;
        try { file = await api.messages.getAttachmentFile(session.messageId, item.partName); }
        catch (_) { return fail('unavailable'); }
        if (!await current(session, generation)) return fail('stale_message');
        if (!file || typeof file.size !== 'number') return fail('unavailable');
        if (file.size > inventory.MAX_FILE_BYTES) return fail('too_large');
        try {
          const buffer = await file.arrayBuffer();
          if (buffer.byteLength > inventory.MAX_FILE_BYTES) return fail('too_large');
          if (!await current(session, generation)) return fail('stale_message');
          const digest = await crypt.subtle.digest('SHA-256', buffer);
          observable = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
        } catch (_) { return fail('unavailable'); }
      } else {
        const u = inventory.validUrl(item.url);
        if (!u) return fail('invalid_url');
        observable = kind === 'domain' ? u.hostname : u.href;
      }
      if (!await current(session, generation)) return fail('stale_message');
      const block = await enabled();
      if (block) return block;
      let reserved;
      try { reserved = await reserve(session, generation); } catch (_) { return fail('storage'); }
      if (reserved) return reserved;
      if (!await current(session, generation)) return fail('stale_message');
      const controller = new AbortController();
      session.controller = controller;
      let timedOut = false;
      const timer = later(() => { timedOut = true; controller.abort(); }, 20000);
      try {
        const endpoint = new URL('https://www.virustotal.com/api/v3/widget/url');
        endpoint.searchParams.set('query', observable);
        const response = await request(endpoint.href, {
          method: 'GET', headers: { 'x-apikey': config.apiKey, accept: 'application/json' },
          credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal: controller.signal
        });
        if (!await current(session, generation)) return fail('stale_message');
        if (response.status === 401) return fail('invalid_key');
        if (response.status === 403) return fail('forbidden');
        if (response.status === 429) return fail('rate_limit');
        if (response.status === 404) return remember(session, cacheKey, { status: 'no_report' });
        if (!response.ok) return fail(response.status === 400 ? 'unavailable' : 'network');
        let body;
        try { body = await response.json(); }
        catch (error) {
          if (error?.name === 'SyntaxError') return fail('invalid_response');
          throw error;
        }
        if (!await current(session, generation)) return fail('stale_message');
        const url = inventory.reportUrl(body?.data?.url);
        if (!url) return fail('invalid_response');
        const ratio = body.data.detection_ratio;
        const hasRatio = Number.isInteger(ratio?.detections) && Number.isInteger(ratio?.total) && ratio.detections >= 0 && ratio.total > 0 && ratio.detections <= ratio.total;
        return remember(session, cacheKey, { status: 'reported', detections: hasRatio ? ratio.detections : undefined, total: hasRatio ? ratio.total : undefined }, url);
      } catch (_) {
        if (!await current(session, generation)) return fail('stale_message');
        return fail(timedOut ? 'timeout' : 'network');
      } finally {
        cancelTimer(timer);
        if (session.controller === controller) session.controller = null;
      }
    }
    function remember(session, cacheKey, result, url) {
      const queriedAt = now();
      const value = { ...result, id: `report-${++sequence}`, queriedAt };
      session.results.set(cacheKey, { public: value, queriedAt, url });
      return { ok: true, result: value };
    }
    async function openReport(msg) {
      const generation = revision;
      const blocked = await enabled();
      if (blocked) return blocked;
      const session = sessionFor(msg.sessionId);
      if (!session || !await current(session, generation)) return fail('stale_message');
      const result = [...session.results.values()].find(r => r.public.id === msg.resultId);
      if (!result?.url || now() - result.queriedAt >= 3 * 86400000) return fail('report_expired');
      const url = inventory.reportUrl(result.url);
      if (!url) return fail('invalid_response');
      const windows = await api.windows.getAll({ windowTypes: ['normal'] });
      if (!await current(session, generation)) return fail('stale_message');
      const normal = windows.find(w => w.focused) || windows[0];
      if (normal) {
        await api.tabs.create({ windowId: normal.id, url, active: true });
      } else await api.windows.openDefaultBrowser(url);
      return { ok: true };
    }
    async function handle(msg, sender) {
      const action = String(msg?.type || '').slice(PREFIX.length);
      if (!String(msg?.type || '').startsWith(PREFIX) || !authorized(sender, action)) return fail('unauthorized');
      try { await ready; } catch (_) { return fail('storage'); }
      try {
        if (action === 'getConfig') return await publicConfig();
        if (action === 'saveConfig' || action === 'deleteConfig') {
          let next = { enabled: false, apiKey: '' };
          if (action === 'saveConfig') {
            if (typeof msg.enabled !== 'boolean') return fail('unavailable');
            const key = typeof msg.apiKey === 'string' && msg.apiKey.trim() ? msg.apiKey.trim() : config.apiKey;
            if (msg.enabled && key && !/^[A-Za-z0-9_-]{16,256}$/.test(key)) return fail('invalid_key');
            if (msg.enabled && (!key || msg.consent !== true)) return fail('invalid_key');
            if (msg.enabled && !await granted()) return fail('permission_denied');
            next = { enabled: msg.enabled, apiKey: key };
          }
          // Stop work immediately, even if an earlier quota/config write is slow.
          const operation = ++revision;
          clear();
          config = { enabled: false, apiKey: action === 'deleteConfig' ? '' : config.apiKey };
          return await serialize(async () => {
            if (operation !== revision) return fail('busy');
            if (action === 'deleteConfig') {
              await api.storage.local.remove('vtConfig');
            } else {
              await api.storage.local.set({ vtConfig: next });
            }
            if (operation === revision) config = next;
            return publicConfig();
          });
        }
        if (action === 'getInventory') return await getInventory();
        if (action === 'query') return await query(msg);
        if (action === 'openReport') return await openReport(msg);
        return fail('unavailable');
      } catch (_) { return fail(action === 'saveConfig' || action === 'deleteConfig' ? 'storage' : 'unavailable'); }
    }
    return { handle, invalidate, messageDisplayed, permissionsRemoved, clear };
  }
  globalThis.PixelGuardVT = { createService, PERMISSIONS };
})();
