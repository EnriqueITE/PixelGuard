/* global browser */
(async function () {
  function t(key, ...subs) {
    try { return browser.i18n.getMessage(key, subs) || key; } catch (_) { return key; }
  }

  function applyI18n() {
    for (const el of document.querySelectorAll('[data-i18n]')) {
      const key = el.getAttribute('data-i18n');
      el.textContent = t(key);
    }
    for (const el of document.querySelectorAll('[data-i18n-placeholder]')) {
      const key = el.getAttribute('data-i18n-placeholder');
      el.setAttribute('placeholder', t(key));
    }
  }

  const debugToggle = document.getElementById("debugToggle");

  applyI18n();

  async function load() {
    const st = await browser.runtime.sendMessage({ type: "pg:getState" });
    debugToggle.checked = !!st.debug;
  }

  debugToggle.addEventListener('change', async () => {
    await browser.runtime.sendMessage({ type: 'pg:setDebug', value: debugToggle.checked });
  });

  load();
})();
