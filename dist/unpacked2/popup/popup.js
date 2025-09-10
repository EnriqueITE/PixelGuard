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
  }

  const toggle = document.getElementById("toggle");
  const det = document.getElementById("detected");
  const blk = document.getElementById("blocked");
  const btnOpt = document.getElementById("openOptions");

  applyI18n();

  async function refresh() {
    const st = await browser.runtime.sendMessage({ type: "pg:getState" });
    toggle.textContent = st.blockMode ? t('state_on') : t('state_off');
    det.textContent = String(st.counters.totalDetected || 0);
    blk.textContent = String(st.counters.totalBlocked || 0);
  }

  toggle.addEventListener("click", async () => {
    await browser.runtime.sendMessage({ type: "pg:toggleBlock" });
    refresh();
  });

  btnOpt.addEventListener("click", () => browser.runtime.openOptionsPage());

  refresh();
})();

