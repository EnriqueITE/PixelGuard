/* global browser, messenger */
(async function () {
  const API = (typeof browser !== 'undefined') ? browser : (typeof messenger !== 'undefined' ? messenger : null);
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
  const linkCount = document.getElementById('linkCount'); // Fixed typo here
  const detailsWrap = document.getElementById('detailsList');
  const listEl = document.getElementById('list');
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
  function titleize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

  let lastState = null;
  let lastDomain = '';

  applyI18n();

  async function refreshState() {
    try {
      lastState = await API.runtime.sendMessage({ type: "pg:getState" }) || {};
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
      // First, ensure we have the latest state (settings)
      await refreshState();
      // Then, get the findings for the current message
      const res = await API.runtime.sendMessage({ type: 'pg:getFindings' });
      const f = res?.findings || { suspicious:[], externals:[], links:[] };
      lastDomain = res?.domain || '';
      senderDomEl.textContent = lastDomain || '-';

      // Whitelist logic removed

      const s = f.suspicious.length, e = f.externals.length, l = f.links.length;
      if (suspCount) suspCount.textContent = String(s);
      if (extCount) extCount.textContent = String(e);
      if (linkCount) linkCount.textContent = String(l);
      if (sumS) sumS.textContent = String(s);
      if (sumE) sumE.textContent = String(e);
      if (sumL) sumL.textContent = String(l);
      if (labS) labS.textContent = labelFor(s, 'popup_label_pixels', 'popup_label_pixel');
      if (labE) labE.textContent = labelFor(e, 'popup_label_images', 'popup_label_image');
      if (labL) labL.textContent = labelFor(l, 'popup_label_links', 'popup_label_link');
      listEl.innerHTML = '';
      const add = (title, arr) => {
        if (!arr || arr.length === 0) return;
        const header = document.createElement('li');
        header.textContent = title;
        header.style.fontWeight='700';
        listEl.appendChild(header);
        for (const it of arr.slice(0, 20)) {
          const li = document.createElement('li');
          li.textContent = it.url;
          listEl.appendChild(li);
        }
        if (arr.length > 20) {
            const li = document.createElement("li");
            li.textContent = `… +${arr.length - 20} more`;
            listEl.appendChild(li);
        }
      };
      add(titleize(labelFor(s, 'popup_label_pixels', 'popup_label_pixel')), f.suspicious);
      add(titleize(labelFor(e, 'popup_label_images', 'popup_label_image')), f.externals);
      add(titleize(labelFor(l, 'popup_label_links', 'popup_label_link')), f.links);
    } catch (e) {
        console.error("Error refreshing findings:", e);
    }
  }

  // Initial load
  refreshFindings();

  // Whitelist button listener removed
})();
