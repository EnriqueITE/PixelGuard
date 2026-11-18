/* global browser, PixelGuardI18n */
(async () => {
  const t = PixelGuardI18n.get;
  const keyInput = document.getElementById('vtKey');
  const keySaved = document.getElementById('vtKeySaved');
  const keyHint = document.getElementById('vtKeyHint');
  const consent = document.getElementById('vtConsent');
  const status = document.getElementById('vtConfigStatus');
  const enable = document.getElementById('vtEnable');
  const disable = document.getElementById('vtDisable');
  const remove = document.getElementById('vtDelete');
  let busy = false;
  let config = { enabled: false, configured: false };
  let statusKey = '';
  function setStatus(key) {
    statusKey = key;
    status.textContent = t(key) || t('vt_error_generic');
  }
  function controls() {
    enable.disabled = busy || !consent.checked;
    disable.disabled = busy || !config.enabled;
    remove.disabled = busy || !config.configured;
    keyInput.disabled = busy;
    consent.disabled = busy;
  }
  async function send(action, data = {}) {
    try { return await browser.runtime.sendMessage({ type: `pg:vt:${action}`, ...data }); }
    catch (_) { return { ok: false, error: 'unavailable' }; }
  }
  function translateConfig() {
    keySaved.hidden = !config.configured;
    keySaved.textContent = t('vt_keySaved');
    keyInput.placeholder = t(config.configured ? 'vt_keyReplacePlaceholder' : 'vt_keyPlaceholder');
    keyHint.textContent = t(config.configured ? 'vt_keyHint' : 'vt_keyEmptyHint');
    if (statusKey) setStatus(statusKey);
  }
  function showConfig(result) {
    if (!result?.ok) { setStatus('vt_error_' + result?.error); return; }
    config = result;
    statusKey = result.enabled ? 'vt_enabled' : (result.configured ? 'vt_disabledSaved' : 'vt_disabled');
    translateConfig();
    consent.checked = !!result.enabled;
  }
  consent.addEventListener('change', controls);
  enable.addEventListener('click', async () => {
    if (busy || !consent.checked) return;
    const apiKey = keyInput.value.trim();
    if (!apiKey && !config.configured) { setStatus('vt_error_invalid_key'); keyInput.focus(); return; }
    busy = true; controls();
    try {
      // Request in the click handler, before any await, to retain user activation.
      const granted = await browser.permissions.request({ permissions: ['sensitiveDataUpload'], origins: ['https://www.virustotal.com/*'] });
      if (!granted) { setStatus('vt_error_permission_denied'); return; }
      const payload = { enabled: true, consent: true };
      if (apiKey) payload.apiKey = apiKey;
      showConfig(await send('saveConfig', payload));
    } catch (_) { setStatus('vt_error_permission_denied'); }
    finally { keyInput.value = ''; busy = false; controls(); }
  });
  disable.addEventListener('click', async () => {
    if (busy) return;
    busy = true; controls();
    showConfig(await send('saveConfig', { enabled: false }));
    keyInput.value = ''; busy = false; controls();
  });
  remove.addEventListener('click', async () => {
    if (busy) return;
    busy = true; controls();
    showConfig(await send('deleteConfig'));
    keyInput.value = ''; busy = false; controls();
  });
  browser.permissions.onRemoved.addListener(async () => {
    showConfig(await send('getConfig')); controls();
  });
  controls();
  await PixelGuardI18n.ready;
  PixelGuardI18n.onChange(translateConfig);
  send('getConfig').then(result => { showConfig(result); controls(); });
})();
