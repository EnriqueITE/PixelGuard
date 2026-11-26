/* global chrome, importScripts, PixelGuardVTInventory, PixelGuardVTWidget, PixelGuardVTAttachments, PixelGuardVault */
importScripts('virustotal/inventory.js', 'virustotal/widget.js', 'virustotal/attachments.js', 'vault.js');

const VT_PERMISSION = { origins: ['https://www.virustotal.com/*'] };
const storage = chrome.storage.local;
const vault = PixelGuardVault.create();
// Only the popup and service worker need storage access. Gmail receives the
// panel preferences over messaging, never storage events or the VT key.
const ready = storage.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
// Migrate on worker startup, even if the user never opens the popup again.
// A transient storage failure is retried on the next config operation.
ready.then(() => withConfig(() => {})).catch(() => {});
const fail = error => ({ ok: false, error });
let writes = Promise.resolve();
let pending;

function serialize(change) {
  const next = writes.then(change);
  writes = next.catch(() => {});
  return next;
}

function withConfig(operation) {
  return navigator.locks.request('pixelguard-vt-config', async () => {
    let { vtConfig = {} } = await storage.get('vtConfig');
    if ('apiKey' in vtConfig) {
      const sealedKey = vtConfig.apiKey ? await vault.seal(vtConfig.apiKey) : undefined;
      const migrated = sealedKey ? { enabled: vtConfig.enabled === true, sealedKey } : { enabled: false };
      // The IDB key has committed and encryption has succeeded. Replacing the
      // single local-storage item now drops the legacy value atomically.
      await storage.set({ vtConfig: migrated });
      vtConfig = migrated;
    }
    return operation(vtConfig);
  });
}

async function panelPreferences() {
  const { showPanel, theme } = await storage.get(['showPanel', 'theme']);
  return {showPanel: showPanel !== false, theme: theme === 'dark' ? 'dark' : 'light'};
}

async function state() {
  return withConfig(async config => {
    const panel = await panelPreferences();
    const hasKey = !!config.sealedKey;
    const vtEnabled = hasKey && config.enabled === true && await chrome.permissions.contains(VT_PERMISSION);
    return { ok: true, ...panel, hasKey, vtEnabled };
  });
}

async function notifyPanels({showPanel, theme}) {
  // Tab IDs are available without the broad tabs permission. Only our Gmail
  // content scripts receive this message; other tabs have no listener.
  const tabs = await chrome.tabs.query({});
  await Promise.allSettled(tabs.map(tab => chrome.tabs.sendMessage(tab.id, { type: 'pg:panelChanged', showPanel, theme })));
}

async function settings(msg) {
  return serialize(async () => {
    const update = {};
    if ('showPanel' in msg) {
      if (typeof msg.showPanel !== 'boolean') return fail('unavailable');
      update.showPanel = msg.showPanel;
    }
    if ('theme' in msg) {
      if (msg.theme !== 'light' && msg.theme !== 'dark') return fail('unavailable');
      update.theme = msg.theme;
    }
    const panelChanged = 'showPanel' in update || 'theme' in update;
    if ('vtEnabled' in msg || 'apiKey' in msg) {
      if (('apiKey' in msg && typeof msg.apiKey !== 'string') ||
          ('vtEnabled' in msg && typeof msg.vtEnabled !== 'boolean')) return fail('unavailable');
      const apiKey = msg.apiKey?.trim();
      if (apiKey && !/^[A-Za-z0-9_-]{16,256}$/.test(apiKey)) return fail('invalid_key');
      const error = await withConfig(async config => {
        if (msg.onlyIfMissing === true && config.sealedKey) return fail('key_exists');
        const hasKey = apiKey === undefined ? !!config.sealedKey : !!apiKey;
        if (!hasKey && msg.vtEnabled === true) return fail('invalid_key');
        const enabled = hasKey && (msg.vtEnabled ?? config.enabled) === true;
        if (enabled && !await chrome.permissions.contains(VT_PERMISSION)) return fail('permission_denied');
        pending?.abort();
        await chrome.storage.session.remove('vtUploadGrants');
        if (hasKey) {
          const sealedKey = apiKey ? await vault.seal(apiKey) : config.sealedKey;
          await storage.set({ ...update, vtConfig: { enabled, sealedKey } });
        } else {
          await storage.remove('vtConfig');
          await vault.remove();
          if (panelChanged) await storage.set(update);
        }
      });
      if (error) return error;
    } else if (panelChanged) {
      await storage.set(update);
    }
    const updated = await state();
    if (panelChanged) await notifyPanels(updated);
    return updated;
  });
}

function observable(msg) {
  const input = msg.value;
  if (typeof input !== 'string') return null;
  if (msg.kind === 'hash') return /^[a-f0-9]{64}$/i.test(input) ? input.toLowerCase() : null;
  if (msg.kind === 'url') return PixelGuardVTInventory.validUrl(input)?.href;
  if (msg.kind !== 'domain' || /[\s/%@?#\\]/.test(input)) return null;
  const url = PixelGuardVTInventory.validUrl('https://' + input);
  return url && url.hostname === input.toLowerCase() ? url.hostname : null;
}

async function reserve() {
  const { vtQuota = [] } = await storage.get('vtQuota');
  const time = Date.now();
  const quota = vtQuota.filter(stamp => Number.isFinite(stamp) && stamp > time - 86400000);
  if (quota.filter(stamp => stamp > time - 60000).length >= 4) return fail('rate_limit');
  if (quota.length >= 500) return fail('daily_limit');
  await storage.set({ vtQuota: [...quota, time] });
  return null;
}

async function withVirusTotal(operation, timeoutMs = 20000) {
  if (pending) return fail('busy');
  const controller = new AbortController();
  pending = controller;
  let timeout;
  try {
    await writes;
    const ticket = await withConfig(async config => {
      if (!config.enabled || !config.sealedKey) return fail('disabled');
      if (!await chrome.permissions.contains(VT_PERMISSION)) return fail('permission_denied');
      if (controller.signal.aborted) return fail('disabled');
      const apiKey = await vault.unseal(config.sealedKey);
      return {ok: true, apiKey, keyId: config.sealedKey.iv};
    });
    if (!ticket.ok) return ticket;
    if (controller.signal.aborted) return fail('disabled');
    timeout = setTimeout(() => controller.abort('timeout'), timeoutMs);
    const charge = () => withConfig(async config => {
      if (controller.signal.aborted || !config.enabled || config.sealedKey?.iv !== ticket.keyId) return fail('disabled');
      if (!await chrome.permissions.contains(VT_PERMISSION)) return fail('permission_denied');
      return reserve();
    }).catch(() => fail('storage'));
    try {
      const reply = await operation(ticket.apiKey, controller.signal, charge);
      if (controller.signal.aborted) return fail(controller.signal.reason === 'timeout' ? 'timeout' : 'disabled');
      return reply;
    } catch (_) {
      if (controller.signal.aborted) return fail(controller.signal.reason === 'timeout' ? 'timeout' : 'disabled');
      return fail('network');
    }
  } finally {
    clearTimeout(timeout);
    pending = undefined;
  }
}

async function lookup(msg) {
  const value = observable(msg);
  if (!value) return fail(msg.kind === 'hash' ? 'unavailable' : 'invalid_url');
  if (msg.kind === 'url' && msg.confirmed !== true) return fail('confirmation_required');
  return withVirusTotal(async (apiKey, signal, charge) => {
    const limit = await charge();
    if (limit) return limit;
    const reply = await PixelGuardVTWidget.lookup(value, apiKey, signal);
    if (!reply.ok) return reply;
    return {ok: true, result: {...reply.result, queriedAt: Date.now(), reportUrl: reply.reportUrl}};
  });
}

// A report miss and the ensuing confirmation may span MV3 worker lifetimes.
// Session storage is restricted to trusted extension contexts by default.
async function updateUploadGrant(owner, signal, operation) {
  return withConfig(async () => {
    if (signal.aborted) return fail('disabled');
    const {vtUploadGrants = []} = await chrome.storage.session.get('vtUploadGrants');
    const active = vtUploadGrants.filter(grant => grant.expiresAt > Date.now());
    const {grant, reply} = operation(active.find(item => item.owner === owner));
    const others = active.filter(item => item.owner !== owner);
    if (grant) others.push(grant);
    await chrome.storage.session.set({vtUploadGrants: others});
    return reply;
  }).catch(() => fail('storage'));
}

async function attachmentAction(msg, sender) {
  const hash = observable({kind: 'hash', value: msg.hash});
  if (!hash) return fail('unavailable');
  const owner = sender.documentId || sender.url + '#' + (sender.tab?.id ?? '');
  if (msg.type === 'pg:attachmentReport') {
    return withVirusTotal(async (key, signal, charge) => {
      const cleared = await updateUploadGrant(owner, signal, () => ({reply: null}));
      if (cleared) return cleared;
      const limit = await charge();
      if (limit) return limit;
      const reply = await PixelGuardVTAttachments.report(hash, key, signal);
      if (reply.result?.status !== 'no_report') return reply;
      const token = crypto.randomUUID();
      return updateUploadGrant(owner, signal, () => ({
        grant: {owner, hash, token, expiresAt: Date.now() + 10 * 60000},
        reply: {...reply, uploadToken: token}
      }));
    });
  }
  if (msg.confirmed !== true) return fail('upload_confirmation_required');
  if (typeof msg.uploadToken !== 'string' || !msg.uploadToken) return fail('report_expired');
  if (!PixelGuardVTAttachments.localBlobUrl(msg.blobUrl, chrome.runtime.getURL('')) ||
      typeof msg.name !== 'string' || !msg.name.trim() || msg.name.length > 512 || /[\\/\x00-\x1f\x7f]/.test(msg.name)) {
    return fail('unavailable');
  }
  return withVirusTotal(async (key, signal, charge) => {
    const allowed = await updateUploadGrant(owner, signal, grant => {
      if (grant?.token === msg.uploadToken && grant.hash === hash) return {reply: {ok: true}};
      return {grant, reply: fail('report_expired')};
    });
    if (!allowed.ok) return allowed;
    return PixelGuardVTAttachments.upload({hash, name: msg.name, blobUrl: msg.blobUrl}, key, signal, charge);
  }, 120000);
}

async function updateBadge(tabId, { suspicious, externals, links, scanning = false }) {
  const counts = [suspicious, externals, links];
  if (typeof scanning !== 'boolean' || !counts.every(count => Number.isSafeInteger(count) && count >= 0)) return fail('unavailable');
  let text = '';
  let title = chrome.runtime.getManifest().name;
  let color;
  if (scanning) {
    text = '…';
    title = chrome.i18n.getMessage('gmailFullScanRunning');
    color = '#49616a';
  } else if (counts.some(count => count > 0)) {
    text = counts.map(count => count > 9 ? '+' : String(count)).join('');
    title = chrome.i18n.getMessage('badgeFindingsTitle', counts.map(String));
    color = suspicious > 0 ? '#e53935' : links > 0 ? '#ff9800' : '#00bfa5';
  }
  // Issue the tab-scoped updates together, in delivery order, even when the
  // service worker is waking up or an earlier request is still resolving.
  const updates = [chrome.action.setBadgeText({ tabId, text }), chrome.action.setTitle({ tabId, title })];
  if (color) updates.push(chrome.action.setBadgeBackgroundColor({ tabId, color }));
  await Promise.all(updates);
  return { ok: true };
}

async function mailboxHint(sender) {
  const path = new URL(sender.url).pathname;
  if (!/^\/mail\/u\/\d+\/?$/.test(path)) return fail('unauthorized');
  const target = {tabId: sender.tab.id};
  if (sender.documentId) target.documentIds = [sender.documentId];
  else target.frameIds = [0];
  const [injection] = await chrome.scripting.executeScript({
    target, world: 'MAIN', args: [path],
    func: expectedPath => {
      if (location.origin !== 'https://mail.google.com' || location.pathname !== expectedPath) return '';
      // This one field is the mailbox identifier on Gmail's original-message URLs.
      const hint = window.GLOBALS?.[9];
      return typeof hint === 'string' && /^[a-f\d]{8,16}$/i.test(hint) ? hint : '';
    }
  });
  const hint = injection?.result;
  if (injection?.frameId !== 0 || (sender.documentId && injection.documentId !== sender.documentId)) return {ok: true, hint: ''};
  return {ok: true, hint: typeof hint === 'string' && /^[a-f\d]{8,16}$/i.test(hint) ? hint : ''};
}

async function openVirusTotal(sender) {
  const {id, windowId, incognito} = sender.tab;
  if (!Number.isSafeInteger(windowId) || windowId < 0) return fail('unauthorized');
  // Gmail switches threads with a fragment. Chromium's sender.url can still
  // describe the original document; sender.tab.url is the tab at the click.
  const documentUrl = sender.url.split('#', 1)[0];
  let sourceUrl = sender.tab.url;
  async function sourceIsActive() {
    const tab = await chrome.tabs.get(id);
    if (!tab.url || tab.url.split('#', 1)[0] !== documentUrl) return false;
    sourceUrl ??= tab.url;
    return tab.active && tab.windowId === windowId && tab.url === sourceUrl &&
      (!tab.pendingUrl || tab.pendingUrl === tab.url);
  }
  if (!await sourceIsActive()) return fail('unavailable');
  if (chrome.action.openPopup) {
    try {
      await chrome.action.openPopup({windowId});
      return {ok: true};
    } catch {
      // Some Chromium versions expose openPopup only to policy-installed extensions.
      if (!await sourceIsActive()) return fail('unavailable');
    }
  }
  // Only the source tab ID travels in the window URL. The popup reads the
  // selected row directly from that tab, including in a private window.
  await chrome.windows.create({
    type: 'popup', url: chrome.runtime.getURL('popup.html') + '#tab=' + id,
    width: 410, height: 560, incognito: !!incognito
  });
  return {ok: true};
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!['pg:state', 'pg:panel', 'pg:badge', 'pg:settings', 'pg:lookup', 'pg:attachmentReport', 'pg:uploadAttachment',
    'pg:gmail:mailboxHint', 'pg:gmail:openVirusTotal'].includes(msg?.type)) return false;
  const popupUrl = chrome.runtime.getURL('popup.html');
  const fromPopup = sender.url === popupUrl || (sender.url?.startsWith(popupUrl) &&
    /^#tab=(0|[1-9]\d{0,9})$/.test(sender.url.slice(popupUrl.length)));
  const fromGmail = sender.frameId === 0 && Number.isSafeInteger(sender.tab?.id) && sender.tab.id >= 0 &&
    sender.url?.startsWith('https://mail.google.com/mail/');
  if (msg.type === 'pg:badge' || msg.type === 'pg:gmail:mailboxHint' || msg.type === 'pg:gmail:openVirusTotal') {
    if (!fromGmail || sender.id !== chrome.runtime.id || (sender.documentLifecycle && sender.documentLifecycle !== 'active')) {
      reply(fail('unauthorized'));
      return false;
    }
    if (msg.type === 'pg:gmail:mailboxHint') {
      mailboxHint(sender).then(reply, () => reply({ok: true, hint: ''}));
    } else if (msg.type === 'pg:gmail:openVirusTotal') {
      openVirusTotal(sender).then(reply, () => reply(fail('unavailable')));
    } else {
      updateBadge(sender.tab.id, msg).then(reply, () => reply(fail('unavailable')));
    }
    return true;
  }
  if (sender.id !== chrome.runtime.id || !(fromPopup || (msg.type === 'pg:panel' && fromGmail))) {
    reply(fail('unauthorized'));
    return false;
  }
  ready.then(async () => {
    if (msg.type === 'pg:settings') return settings(msg);
    if (msg.type === 'pg:lookup') return lookup(msg);
    if (msg.type === 'pg:attachmentReport' || msg.type === 'pg:uploadAttachment') {
      if ((sender.frameId && sender.frameId !== 0) || (sender.documentLifecycle && sender.documentLifecycle !== 'active')) {
        return fail('unauthorized');
      }
      return attachmentAction(msg, sender);
    }
    await writes;
    if (msg.type === 'pg:panel') return { ok: true, ...await panelPreferences() };
    return state();
  }).then(reply, () => reply(fail('storage')));
  return true;
});

chrome.permissions.onRemoved.addListener(removed => {
  if (!removed.origins?.includes(VT_PERMISSION.origins[0])) return;
  pending?.abort();
  serialize(async () => {
    await ready;
    await withConfig(async config => {
      await chrome.storage.session.remove('vtUploadGrants');
      if (config.enabled) await storage.set({ vtConfig: { ...config, enabled: false } });
    });
  }).catch(() => {});
});

// Manifest scripts handle new documents. Gmail may already be open when an
// unpacked extension is installed or reloaded, including in a pop-out window.
async function attachToOpenMail() {
  const [scripts] = chrome.runtime.getManifest().content_scripts;
  const tabs = await chrome.tabs.query({url: scripts.matches});
  await Promise.allSettled(tabs.filter(tab => !tab.discarded).map(async tab => {
    const target = {tabId: tab.id};
    try {
      const reply = await chrome.tabs.sendMessage(tab.id, {type: "pg:gmail:ping"}, {frameId: 0});
      if (reply?.ready) return;
    } catch { /* A document opened before installation has no receiver yet. */ }
    await chrome.scripting.insertCSS({target, files: scripts.css});
    await chrome.scripting.executeScript({target, files: scripts.js});
  }));
}
chrome.runtime.onInstalled.addListener(attachToOpenMail);
chrome.runtime.onStartup.addListener(attachToOpenMail);
