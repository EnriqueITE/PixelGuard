/* global chrome, importScripts, PixelGuardVTInventory, PixelGuardVTWidget, PixelGuardVault */
importScripts('virustotal/inventory.js', 'virustotal/widget.js', 'vault.js');

const VT_PERMISSION = { origins: ['https://www.virustotal.com/*'] };
const storage = chrome.storage.local;
const vault = PixelGuardVault.create();
// Only the popup and service worker need storage access. Gmail receives the
// visibility preference over messaging, never storage events or the VT key.
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

async function state() {
  return withConfig(async config => {
    const { showPanel } = await storage.get('showPanel');
    const hasKey = !!config.sealedKey;
    const vtEnabled = hasKey && config.enabled === true && await chrome.permissions.contains(VT_PERMISSION);
    return { ok: true, showPanel: showPanel !== false, hasKey, vtEnabled };
  });
}

async function notifyPanels(showPanel) {
  // Tab IDs are available without the broad tabs permission. Only our Gmail
  // content scripts receive this message; other tabs have no listener.
  const tabs = await chrome.tabs.query({});
  await Promise.allSettled(tabs.map(tab => chrome.tabs.sendMessage(tab.id, { type: 'pg:panelChanged', showPanel })));
}

async function settings(msg) {
  return serialize(async () => {
    const update = {};
    if ('showPanel' in msg) {
      if (typeof msg.showPanel !== 'boolean') return fail('unavailable');
      update.showPanel = msg.showPanel;
    }
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
        if (hasKey) {
          const sealedKey = apiKey ? await vault.seal(apiKey) : config.sealedKey;
          await storage.set({ ...update, vtConfig: { enabled, sealedKey } });
        } else {
          await storage.remove('vtConfig');
          await vault.remove();
          if ('showPanel' in update) await storage.set(update);
        }
      });
      if (error) return error;
    } else if ('showPanel' in update) {
      await storage.set(update);
    }
    if ('showPanel' in update) await notifyPanels(update.showPanel);
    return state();
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

async function lookup(msg) {
  const value = observable(msg);
  if (!value) return fail(msg.kind === 'hash' ? 'unavailable' : 'invalid_url');
  if (msg.kind === 'url' && msg.confirmed !== true) return fail('confirmation_required');
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
      return await reserve() || { ok: true, apiKey };
    });
    if (!ticket.ok) return ticket;
    if (controller.signal.aborted) return fail('disabled');
    timeout = setTimeout(() => controller.abort('timeout'), 20000);
    try {
      const reply = await PixelGuardVTWidget.lookup(value, ticket.apiKey, controller.signal);
      if (controller.signal.aborted) return fail(controller.signal.reason === 'timeout' ? 'timeout' : 'disabled');
      if (!reply.ok) return reply;
      return { ok: true, result: { ...reply.result, queriedAt: Date.now(), reportUrl: reply.reportUrl } };
    } catch (_) {
      if (controller.signal.aborted) return fail(controller.signal.reason === 'timeout' ? 'timeout' : 'disabled');
      return fail('network');
    }
  } finally {
    clearTimeout(timeout);
    pending = undefined;
  }
}

async function updateBadge(tabId, { suspicious, externals, links }) {
  const counts = [suspicious, externals, links];
  if (!counts.every(count => Number.isSafeInteger(count) && count >= 0)) return fail('unavailable');
  const hasFindings = counts.some(count => count > 0);
  const text = hasFindings ? counts.map(count => count > 9 ? '+' : String(count)).join('') : '';
  const title = hasFindings ? chrome.i18n.getMessage('badgeFindingsTitle', counts.map(String)) : chrome.runtime.getManifest().name;
  // Issue the tab-scoped updates together, in delivery order, even when the
  // service worker is waking up or an earlier request is still resolving.
  const updates = [chrome.action.setBadgeText({ tabId, text }), chrome.action.setTitle({ tabId, title })];
  if (hasFindings) {
    const color = suspicious > 0 ? '#e53935' : links > 0 ? '#ff9800' : '#00bfa5';
    updates.push(chrome.action.setBadgeBackgroundColor({ tabId, color }));
  }
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

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!['pg:state', 'pg:panel', 'pg:badge', 'pg:settings', 'pg:lookup', 'pg:gmail:mailboxHint'].includes(msg?.type)) return false;
  const fromPopup = sender.url === chrome.runtime.getURL('popup.html');
  const fromGmail = sender.frameId === 0 && Number.isInteger(sender.tab?.id) && sender.tab.id >= 0 &&
    sender.url?.startsWith('https://mail.google.com/mail/');
  if (msg.type === 'pg:badge' || msg.type === 'pg:gmail:mailboxHint') {
    if (!fromGmail || sender.id !== chrome.runtime.id || (sender.documentLifecycle && sender.documentLifecycle !== 'active')) {
      reply(fail('unauthorized'));
      return false;
    }
    if (msg.type === 'pg:gmail:mailboxHint') {
      mailboxHint(sender).then(reply, () => reply({ok: true, hint: ''}));
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
    await writes;
    if (msg.type === 'pg:panel') return { ok: true, showPanel: (await storage.get('showPanel')).showPanel !== false };
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
