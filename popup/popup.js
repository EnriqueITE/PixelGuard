/* global browser, messenger */
(async function () {
  const API = (typeof browser !== 'undefined') ? browser : (typeof messenger !== 'undefined' ? messenger : null);
  const SECTION_LIMIT = 5;

  function t(key, ...subs) {
    try { return (API?.i18n?.getMessage(key, subs)) || key; } catch (_) { return key; }
  }

  function applyI18n() {
    for (const el of document.querySelectorAll('[data-i18n]')) {
      const key = el.getAttribute('data-i18n');
      el.textContent = t(key);
    }
  }

  const suspCount = document.getElementById('suspCount');
  const extCount = document.getElementById('extCount');
  const linkCount = document.getElementById('linkCount');
  const detailsSections = document.getElementById('detailsSections');
  const senderDomEl = document.getElementById('senderDomain');
  const sumS = document.getElementById('sumS');
  const sumE = document.getElementById('sumE');
  const sumL = document.getElementById('sumL');
  const labS = document.querySelector('[data-i18n="popup_label_pixels"]');
  const labE = document.querySelector('[data-i18n="popup_label_images"]');
  const labL = document.querySelector('[data-i18n="popup_label_links"]');
  const openOptions = document.getElementById('openOptions');

  function labelFor(count, pluralKey, singularKey) {
    return count === 1 ? t(singularKey) : t(pluralKey);
  }

  function confidenceClass(value) {
    const normalized = String(value || 'low').toLowerCase();
    return ['high', 'medium', 'low'].includes(normalized) ? normalized : 'low';
  }

  function compactUrl(raw) {
    try {
      const u = new URL(raw);
      return `${u.pathname}${u.search || ''}` || raw;
    } catch (_) {
      return raw || '';
    }
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    document.body.appendChild(textarea);
    textarea.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    textarea.remove();
    return ok;
  }

  async function copyUrl(text) {
    if (!text) return false;
    if (fallbackCopy(text)) return true;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {}
    return false;
  }

  function createCopyButton(item) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-btn';
    button.textContent = t('popup_copy');
    button.addEventListener('click', async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const copied = await copyUrl(item.url || '');
      button.textContent = copied ? t('popup_copied') : t('popup_copyFailed');
      setTimeout(() => { button.textContent = t('popup_copy'); }, 1300);
    });
    return button;
  }

  function createFindingItem(item) {
    const row = document.createElement('div');
    row.className = 'finding-item';
    row.title = item.url || '';

    const main = document.createElement('div');
    main.className = 'finding-main';

    const host = document.createElement('div');
    host.className = 'finding-host';
    host.textContent = item.host || '?';

    const actions = document.createElement('div');
    actions.className = 'finding-actions';

    const confidence = document.createElement('span');
    const level = confidenceClass(item.confidence);
    confidence.className = `confidence ${level}`;
    confidence.textContent = level;

    actions.appendChild(confidence);
    actions.appendChild(createCopyButton(item));
    main.appendChild(host);
    main.appendChild(actions);

    const reason = document.createElement('div');
    reason.className = 'finding-reason';
    reason.textContent = item.reason || item.classification || t('popup_noDetails');

    const url = document.createElement('div');
    url.className = 'finding-url';
    url.textContent = compactUrl(item.url || '');

    row.appendChild(main);
    row.appendChild(reason);
    row.appendChild(url);
    return row;
  }

  function createSection({ title, items, open, type }) {
    const details = document.createElement('details');
    details.className = `finding-section ${type || ''}`.trim();
    details.open = !!open;

    const summary = document.createElement('summary');
    const label = document.createElement('span');
    label.className = 'section-title';
    label.textContent = title;

    const right = document.createElement('span');
    right.className = 'section-title';

    const count = document.createElement('span');
    count.className = 'section-count';
    count.textContent = String(items.length);

    const chevron = document.createElement('span');
    chevron.className = 'section-chevron';
    chevron.textContent = '>';

    right.appendChild(count);
    right.appendChild(chevron);
    summary.appendChild(label);
    summary.appendChild(right);
    details.appendChild(summary);

    const list = document.createElement('div');
    list.className = 'finding-list';
    details.appendChild(list);

    let expanded = false;
    const renderItems = () => {
      list.textContent = '';
      const visible = expanded ? items : items.slice(0, SECTION_LIMIT);
      for (const item of visible) list.appendChild(createFindingItem(item));
      if (items.length > SECTION_LIMIT) {
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'show-more';
        toggle.textContent = expanded ? t('popup_showLess') : t('popup_showAll', String(items.length));
        toggle.addEventListener('click', (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          expanded = !expanded;
          renderItems();
        });
        list.appendChild(toggle);
      }
    };
    renderItems();
    return details;
  }

  function renderSections(findings) {
    detailsSections.textContent = '';
    const sections = [
      { title: t('popup_suspicious'), items: findings.suspicious || [], open: (findings.suspicious || []).length > 0, type: 'suspicious' },
      { title: t('popup_externalImages'), items: findings.externals || [], open: false, type: 'external' },
      { title: t('popup_trackingLinks'), items: findings.links || [], open: false, type: 'links' }
    ].filter(section => section.items.length > 0);

    if (sections.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-details';
      empty.textContent = t('popup_noDetails');
      detailsSections.appendChild(empty);
      return;
    }

    for (const section of sections) detailsSections.appendChild(createSection(section));
  }

  let lastState = null;
  let lastDomain = '';

  applyI18n();

  async function refreshState() {
    try {
      lastState = await API.runtime.sendMessage({ type: 'pg:getState' }) || {};
    } catch (e) {
      try {
        const stored = await (API?.storage?.local?.get ? API.storage.local.get('settings') : Promise.resolve({}));
        lastState = stored.settings || {};
      } catch (_) {
        lastState = {};
      }
    }
  }

  if (openOptions) {
    openOptions.addEventListener('click', (ev) => {
      ev.preventDefault();
      if (API?.runtime?.openOptionsPage) {
        API.runtime.openOptionsPage();
      } else {
        const fallbackUrl = API?.runtime?.getURL ? API.runtime.getURL('options/options.html') : 'options/options.html';
        window.open(fallbackUrl, '_blank');
      }
    });
  }

  async function refreshFindings() {
    try {
      await refreshState();
      const res = await API.runtime.sendMessage({ type: 'pg:getFindings' });
      const f = res?.findings || { suspicious: [], externals: [], links: [] };
      lastDomain = res?.domain || '';
      senderDomEl.textContent = lastDomain || '-';

      const s = f.suspicious.length, e = f.externals.length, l = f.links.length;
      if (suspCount) suspCount.textContent = String(s);
      if (extCount) extCount.textContent = String(e);
      if (linkCount) linkCount.textContent = String(l);
      if (sumS) sumS.textContent = String(s);
      if (sumE) sumE.textContent = String(e);
      if (sumL) sumL.textContent = String(l);
      if (labS) labS.textContent = labelFor(s, 'popup_label_alerts', 'popup_label_alert');
      if (labE) labE.textContent = labelFor(e, 'popup_label_images', 'popup_label_image');
      if (labL) labL.textContent = labelFor(l, 'popup_label_links', 'popup_label_link');
      renderSections(f);
    } catch (e) {
      console.error('Error refreshing findings:', e);
    }
  }

  refreshFindings();
})();
