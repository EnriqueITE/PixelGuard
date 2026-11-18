/* global browser, PixelGuardI18n */
(() => {
  const t = PixelGuardI18n.get;
  const section = document.getElementById('vtSection');
  const status = document.getElementById('vtStatus');
  const setup = document.getElementById('vtSetup');
  const inventoryEl = document.getElementById('vtInventory');
  let inventory = null;
  let loading = false;
  let generation = 0;
  const errorText = code => t(`vt_error_${code}`) || t('vt_error_generic');
  const setText = PixelGuardI18n.bindText;
  const node = (tag, text, cls, mirrorTitle = false) => {
    const element = document.createElement(tag);
    if (text !== undefined) setText(element, text, mirrorTitle);
    if (cls) element.className = cls;
    return element;
  };
  function button(labelKey, handler) {
    const el = node('button', () => t(labelKey)); el.type = 'button'; el.addEventListener('click', handler); return el;
  }
  async function send(action, payload = {}) {
    try { return await browser.runtime.sendMessage({ type: `pg:vt:${action}`, ...payload }); }
    catch (_) { return { ok: false, error: 'unavailable' }; }
  }
  setup.addEventListener('click', () => browser.runtime.openOptionsPage());
  function createItem(item, attachment, sessionId) {
    const row = node('div', undefined, 'vt-item');
    row.appendChild(node('span', attachment ? item.name || (() => t('vt_attachmentFallback')) : item.host, 'vt-name'));
    const size = Number.isFinite(item.size) ? () => t('vt_attachmentSize', (item.size / 1048576).toLocaleString(PixelGuardI18n.locale(), { maximumFractionDigits: 2 })) : '';
    const detail = node('div', attachment ? size : item.url, 'vt-detail', true); detail.title = detail.textContent;
    row.appendChild(detail);
    const actions = node('div', undefined, 'vt-actions');
    const output = node('div', undefined, 'vt-result'); output.setAttribute('role', 'status'); output.setAttribute('aria-live', 'polite');
    let pending = false;
    let preview = null;
    const buttons = [];
    const rowGeneration = generation;
    async function query(kind, confirmedUrl) {
      if (pending || rowGeneration !== generation) return;
      pending = true; buttons.forEach(el => { el.disabled = true; });
      preview?.remove(); preview = null;
      setText(output, () => t('vt_querying'));
      const response = await send('query', { sessionId, itemId: item.id, kind, ...(confirmedUrl !== undefined ? { confirmedUrl } : {}) });
      if (rowGeneration !== generation) return;
      setText(output, '');
      if (!response?.ok) setText(output, () => errorText(response?.error));
      else {
        const result = response.result;
        if (result?.status === 'no_report') output.appendChild(node('p', () => t('vt_noReport')));
        else if (result?.status === 'reported') {
          const hasRatio = Number.isFinite(result.detections) && Number.isFinite(result.total);
          output.appendChild(node('p', () => hasRatio ? t('vt_ratio', String(result.detections), String(result.total)) : t('vt_noSummary')));
          output.appendChild(node('p', () => t('vt_notSafe'), 'muted'));
          if (result.id) output.appendChild(button('vt_openReport', async () => {
            const opened = await send('openReport', { sessionId, resultId: result.id });
            if (!opened?.ok && rowGeneration === generation) setText(output, () => errorText(opened?.error));
          }));
        } else output.appendChild(node('p', () => t('vt_error_invalid_response')));
        if (Number.isFinite(result?.queriedAt)) output.appendChild(node('p', () => t('vt_queriedAt', new Date(result.queriedAt).toLocaleString(PixelGuardI18n.locale())), 'muted'));
      }
      pending = false; buttons.forEach(el => { el.disabled = false; });
    }
    if (attachment) {
      const lookup = button('vt_queryHash', () => query('file')); buttons.push(lookup); actions.appendChild(lookup);
      if (item.size > 50 * 1048576) { lookup.disabled = true; setText(output, () => t('vt_error_too_large')); }
    } else {
      const domain = button('vt_queryDomain', () => query('domain')); buttons.push(domain); actions.appendChild(domain);
      const url = button('vt_queryUrl', () => {
        if (pending || preview) return;
        preview = node('div', undefined, 'vt-preview');
        preview.appendChild(node('p', () => t('vt_urlWarning')));
        const exact = node('code', item.url); exact.tabIndex = 0; preview.appendChild(exact);
        const controls = node('div', undefined, 'vt-actions');
        const confirm = button('vt_confirmUrl', () => query('url', item.url));
        const cancel = button('vt_cancel', () => { preview.remove(); preview = null; url.focus(); });
        controls.append(confirm, cancel); preview.appendChild(controls); row.appendChild(preview); cancel.focus();
      }); buttons.push(url); actions.appendChild(url);
    }
    row.append(actions, output); return row;
  }
  function group(titleKey, items, attachment, sessionId) {
    const container = node('section', undefined, 'vt-group');
    container.appendChild(node('h4', () => `${t(titleKey)} (${items.length})`));
    let rendered = 0;
    const more = button('vt_more', () => render());
    function render() {
      const end = Math.min(rendered + 5, items.length);
      for (; rendered < end; rendered++) container.insertBefore(createItem(items[rendered], attachment, sessionId), more);
      more.hidden = rendered >= items.length;
    }
    container.appendChild(more); render(); return container;
  }
  async function load() {
    if (loading || inventory) return;
    loading = true;
    const current = ++generation;
    await PixelGuardI18n.ready;
    if (current !== generation) return;
    setText(status, () => t('vt_loading'));
    const config = await send('getConfig');
    if (current !== generation) return;
    setup.hidden = !!(config?.enabled && config.granted);
    if (!config?.ok || !config.enabled || !config.granted) {
      setText(status, () => config?.ok ? t('vt_disabled') : errorText(config?.error));
      loading = false; return;
    }
    const response = await send('getInventory');
    if (current !== generation) return;
    loading = false;
    if (!response?.ok) { setText(status, () => errorText(response?.error)); return; }
    inventory = response;
    inventoryEl.textContent = '';
    const links = response.links || [], attachments = response.attachments || [];
    if (links.length) inventoryEl.appendChild(group('vt_links', links, false, response.sessionId));
    if (attachments.length) inventoryEl.appendChild(group('vt_attachments', attachments, true, response.sessionId));
    setText(status, links.length || attachments.length ? '' : () => t('vt_empty'));
    if (response.attachmentError) setText(status, () => errorText(response.attachmentError));
    if (response.truncated) setText(status, () => t('vt_truncated'));
  }
  section.addEventListener('toggle', () => { if (section.open) load(); });
  function reset() {
    ++generation; inventory = null; loading = false; inventoryEl.textContent = '';
    setText(status, '');
    if (section.open) load();
  }
  browser.permissions.onRemoved.addListener(reset);
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && Object.prototype.hasOwnProperty.call(changes, 'vtConfig')) reset();
  });
})();
