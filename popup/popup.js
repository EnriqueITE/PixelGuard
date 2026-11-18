/* global browser, messenger, PixelGuardI18n */
(async function () {
  const API = (typeof browser !== 'undefined') ? browser : (typeof messenger !== 'undefined' ? messenger : null);
  const SECTION_LIMIT = 5;

  const t = PixelGuardI18n.get;
  const bindText = PixelGuardI18n.bindText;

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
    const locale = PixelGuardI18n.locale();
    const form = new Intl.PluralRules(locale).select(count);
    if (form === 'one') return t(singularKey);
    if (form === 'few' && new Intl.Locale(locale).language === 'ru') return t(pluralKey + '_few');
    return t(pluralKey);
  }

  function confidenceClass(value) {
    const normalized = String(value || 'low').toLowerCase();
    return ['high', 'medium', 'low'].includes(normalized) ? normalized : 'low';
  }

  // The scanner supplies locale-independent findings to the badge and message views.
  const findingMessages = {
    'visible remote image': 'reason_visibleRemote',
    'tiny image': 'reason_tiny',
    'explicit 1x1 image': 'reason_onePixel',
    'explicit zero-size image': 'reason_zeroSize',
    'display:none image': 'reason_displayNone',
    'visibility:hidden image': 'reason_visibilityHidden',
    'opacity:0 image': 'reason_opacityZero',
    'recipient id with open path': 'reason_recipientAndOpen',
    'recipient id parameter': 'reason_recipient',
    'open path': 'reason_openPath',
    'visible image with open path': 'reason_visibleOpen',
    'tracking path and host keywords': 'reason_trackingPathAndHost',
    'tracking path keyword': 'reason_trackingPath',
    'tracking host keyword': 'reason_trackingHost',
    'marketing campaign params only': 'reason_campaign',
    'sender-owned host': 'reason_senderHost',
    'image from alternate source attribute': 'reason_alternateSource',
    'open tracking parameter': 'reason_openParameter',
    'tracking link host with redirect path': 'reason_linkRedirectHost',
    'tracking link host': 'reason_linkHost',
    'tracking/redirect path': 'reason_redirectPath',
    'tracking parameter': 'reason_trackingParameter',
    'external link': 'reason_externalLink',
    'external resource': 'reason_externalResource',
    'tracking-pixel': 'reason_trackingPixel',
    'suspicious-image': 'reason_suspiciousImage',
    'external-image': 'reason_externalImage',
    'tracking-link': 'reason_trackingLink'
  };

  function findingReason({ reason, classification }) {
    if (Object.hasOwn(findingMessages, reason)) return t(findingMessages[reason]);
    const combined = /^(.+) with (recipient id|open path)$/.exec(reason || '');
    if (combined && Object.hasOwn(findingMessages, combined[1])) {
      const key = combined[2] === 'recipient id' ? 'reason_withRecipient' : 'reason_withOpenPath';
      return t(key, t(findingMessages[combined[1]]));
    }
    return t(Object.hasOwn(findingMessages, classification) ? findingMessages[classification] : 'popup_noDetails');
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
    let key = 'popup_copy';
    const translate = () => t(key);
    bindText(button, translate);
    button.addEventListener('click', async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const copied = await copyUrl(item.url || '');
      key = copied ? 'popup_copied' : 'popup_copyFailed';
      button.textContent = translate();
      setTimeout(() => { key = 'popup_copy'; button.textContent = translate(); }, 1300);
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
    bindText(confidence, () => t(`popup_confidence_${level}`));

    actions.appendChild(confidence);
    actions.appendChild(createCopyButton(item));
    main.appendChild(host);
    main.appendChild(actions);

    const reason = document.createElement('div');
    reason.className = 'finding-reason';
    bindText(reason, () => findingReason(item));

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
    bindText(label, () => t(title));

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
        bindText(toggle, () => expanded ? t('popup_showLess') : t('popup_showAll', String(items.length)));
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
      { title: 'popup_suspicious', items: findings.suspicious || [], open: (findings.suspicious || []).length > 0, type: 'suspicious' },
      { title: 'popup_externalImages', items: findings.externals || [], open: false, type: 'external' },
      { title: 'popup_trackingLinks', items: findings.links || [], open: false, type: 'links' }
    ].filter(section => section.items.length > 0);

    if (sections.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-details';
      bindText(empty, () => t('popup_noDetails'));
      detailsSections.appendChild(empty);
      return;
    }

    for (const section of sections) detailsSections.appendChild(createSection(section));
  }

  await PixelGuardI18n.ready;
  PixelGuardI18n.translatePage(document);
  PixelGuardI18n.onChange(() => PixelGuardI18n.translatePage(document));

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
      const res = await API.runtime.sendMessage({ type: 'pg:getFindings' });
      const f = res?.findings || { suspicious: [], externals: [], links: [] };
      senderDomEl.textContent = res?.domain || '-';

      const s = f.suspicious.length, e = f.externals.length, l = f.links.length;
      if (suspCount) suspCount.textContent = String(s);
      if (extCount) extCount.textContent = String(e);
      if (linkCount) linkCount.textContent = String(l);
      if (sumS) sumS.textContent = String(s);
      if (sumE) sumE.textContent = String(e);
      if (sumL) sumL.textContent = String(l);
      if (labS) bindText(labS, () => labelFor(s, 'popup_label_alerts', 'popup_label_alert'));
      if (labE) bindText(labE, () => labelFor(e, 'popup_label_images', 'popup_label_image'));
      if (labL) bindText(labL, () => labelFor(l, 'popup_label_links', 'popup_label_link'));
      renderSections(f);
    } catch (e) {
      console.error('Error refreshing findings:', e);
    }
  }

  refreshFindings();
})();
