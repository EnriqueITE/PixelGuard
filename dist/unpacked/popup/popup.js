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

  const toggle = document.getElementById("toggle");
  const det = document.getElementById("detected");
  const blk = document.getElementById("blocked");
  const rowDet = document.getElementById("rowTotalDetected");
  const rowBlk = document.getElementById("rowTotalBlocked");
  const btnOpt = document.getElementById("openOptions");
  const btnRescan = document.getElementById('rescan');
  const btnWL = document.getElementById('toggleWL');
  const suspCount = document.getElementById('suspCount');
  const extCount = document.getElementById('extCount');
  const linkCount = document.getElementById('linkCount');
  const scanTs = document.getElementById('scanTs');
  const scanStatus = document.getElementById('scanStatus');
  const detailsWrap = document.getElementById('detailsList');
  const listEl = document.getElementById('list');
  const senderDomEl = document.getElementById('senderDomain');
  const sumS = document.getElementById('sumS');
  const sumE = document.getElementById('sumE');
  const sumL = document.getElementById('sumL');
  const blockedBadge = document.getElementById('blockedBadge');
  const labS = document.querySelector('[data-i18n="popup_label_pixels"]');
  const labE = document.querySelector('[data-i18n="popup_label_images"]');
  const labL = document.querySelector('[data-i18n="popup_label_links"]');

  function labelFor(count, pluralKey, singularKey) {
    return count === 1 ? t(singularKey) : t(pluralKey);
  }
  function titleize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

  let lastState = null;
  let lastDomain = '';

  applyI18n();

  async function refresh() {
    try {
      const st = await API.runtime.sendMessage({ type: "pg:getState" });
      lastState = st || {};
      const on = !!st.blockMode;
      toggle.textContent = on ? t('state_on') : t('state_off');
      toggle.classList.toggle('on', on);
      toggle.classList.toggle('off', !on);
      const td = Number(st.counters?.totalDetected || 0);
      const tb = Number(st.counters?.totalBlocked || 0);
      det.textContent = String(td);
      blk.textContent = String(tb);
      if (rowDet) rowDet.style.display = '';
      if (rowBlk) rowBlk.style.display = '';
      if (blockedBadge) {
        blockedBadge.textContent = String(tb);
        blockedBadge.style.display = tb > 0 ? 'inline-flex' : 'none';
        blockedBadge.classList.toggle('muted-badge', tb === 0);
        blockedBadge.title = t('ui_blockedTotal');
        blockedBadge.setAttribute('aria-label', t('ui_blockedTotal'));
      }
    } catch (e) {
      try {
        const stored = await (API?.storage?.local?.get ? API.storage.local.get('settings') : Promise.resolve({}));
        const st = stored.settings || {};
        lastState = st;
        const on = !!st.blockMode;
        toggle.textContent = on ? t('state_on') : t('state_off');
        toggle.classList.toggle('on', on);
        toggle.classList.toggle('off', !on);
        const td2 = Number(st.counters?.totalDetected || 0);
        const tb2 = Number(st.counters?.totalBlocked || 0);
        det.textContent = String(td2);
        blk.textContent = String(tb2);
        if (rowDet) rowDet.style.display = '';
        if (rowBlk) rowBlk.style.display = '';
        if (blockedBadge) {
          blockedBadge.textContent = String(tb2);
          blockedBadge.style.display = tb2 > 0 ? 'inline-flex' : 'none';
          blockedBadge.classList.toggle('muted-badge', tb2 === 0);
          blockedBadge.title = t('ui_blockedTotal');
          blockedBadge.setAttribute('aria-label', t('ui_blockedTotal'));
        }
      } catch (_) {}
    }
  }

  toggle.addEventListener("click", async () => {
    try { await API.runtime.sendMessage({ type: "pg:toggleBlock" }); } catch (_) {}
    refresh();
  });

  btnOpt.addEventListener("click", () => API.runtime.openOptionsPage());
  btnRescan.addEventListener('click', async () => {
    try {
      if (scanStatus) scanStatus.textContent = t('popup_rescanning');
      btnRescan.disabled = true;
      await API.runtime.sendMessage({ type: 'pg:rescanNow' });
    } catch (_) {}
    await refreshFindings();
    btnRescan.disabled = false;
    if (scanStatus) scanStatus.textContent = t('popup_done');
  });

  async function refreshFindings() {
    try {
      const res = await API.runtime.sendMessage({ type: 'pg:getFindings' });
      const f = res?.findings || { suspicious:[], externals:[], links:[] };
      lastDomain = res?.domain || '';
      senderDomEl.textContent = lastDomain || '-';
      const inWL = !!(lastDomain && lastState?.whitelist?.includes(lastDomain.toLowerCase()));
      if (btnWL) {
        btnWL.textContent = inWL ? t('popup_whitelistRemove') : t('popup_whitelistAdd');
        // Helpful tooltip/ARIA label for clarity
        const label = (inWL ? t('popup_whitelistRemove') : t('popup_whitelistAdd')) + (lastDomain ? ` ${lastDomain}` : '');
        btnWL.title = label;
        btnWL.setAttribute('aria-label', label);
      }
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
      scanTs.textContent = res?.ts ? new Date(res.ts).toLocaleTimeString() : '-';
      listEl.innerHTML = '';
      const add = (title, arr) => {
        if (!arr || arr.length === 0) return;
        const header = document.createElement('li'); header.textContent = title; header.style.fontWeight='700'; listEl.appendChild(header);
        for (const it of arr.slice(0, 10)) { const li = document.createElement('li'); li.textContent = it.url; listEl.appendChild(li); }
      };
      add(titleize(labelFor(s, 'popup_label_pixels', 'popup_label_pixel')), f.suspicious);
      add(titleize(labelFor(e, 'popup_label_images', 'popup_label_image')), f.externals);
      add(titleize(labelFor(l, 'popup_label_links', 'popup_label_link')), f.links);
    } catch (_) {}
  }

  refresh();
  refreshFindings();

  if (btnWL) {
    btnWL.addEventListener('click', async () => {
      if (!lastDomain) return;
      try {
        const inWL = !!(lastState?.whitelist?.includes(lastDomain.toLowerCase()));
        if (inWL) await API.runtime.sendMessage({ type: 'pg:removeWhitelist', domain: lastDomain });
        else await API.runtime.sendMessage({ type: 'pg:addWhitelist', domain: lastDomain });
        await refresh();
        await refreshFindings();
      } catch (_) {}
      // Remove persistent focus styling after action
      try { btnWL.blur(); } catch (_) {}
    });
  }
})();
