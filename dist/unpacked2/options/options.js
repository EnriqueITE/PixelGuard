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

  const listEl = document.getElementById("whitelist");
  const inputEl = document.getElementById("whitelistInput");
  const addBtn = document.getElementById("addWhitelist");
  const hostsTa = document.getElementById("hosts");
  const saveHostsBtn = document.getElementById("saveHosts");
  const exportBtn = document.getElementById("export");
  const importFile = document.getElementById("importFile");

  applyI18n();

  function renderWhitelist(list) {
    listEl.innerHTML = "";
    for (const d of list) {
      const li = document.createElement("li");
      li.textContent = d;
      const rm = document.createElement("button");
      rm.textContent = t('options_remove');
      rm.addEventListener("click", async () => {
        await browser.runtime.sendMessage({ type: "pg:removeWhitelist", domain: d });
        load();
      });
      li.appendChild(rm);
      listEl.appendChild(li);
    }
  }

  async function load() {
    const st = await browser.runtime.sendMessage({ type: "pg:getState" });
    renderWhitelist(st.whitelist || []);
    hostsTa.value = (st.suspiciousHosts || []).join("\n");
  }

  addBtn.addEventListener("click", async () => {
    const d = (inputEl.value || "").trim().toLowerCase();
    if (!d) return;
    await browser.runtime.sendMessage({ type: "pg:addWhitelist", domain: d });
    inputEl.value = "";
    load();
  });

  saveHostsBtn.addEventListener("click", async () => {
    const lines = hostsTa.value.split(/\n+/).map(s => s.trim()).filter(Boolean);
    const st = await browser.runtime.sendMessage({ type: "pg:getState" });
    st.suspiciousHosts = lines;
    await browser.runtime.sendMessage({ type: "pg:import", payload: st });
    load();
  });

  exportBtn.addEventListener("click", async () => {
    const st = await browser.runtime.sendMessage({ type: "pg:export" });
    const blob = new Blob([JSON.stringify(st, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "pixelguard-settings.json"; a.click();
    URL.revokeObjectURL(url);
  });

  importFile.addEventListener("change", async () => {
    const file = importFile.files[0];
    if (!file) return;
    const text = await file.text();
    try {
      const json = JSON.parse(text);
      await browser.runtime.sendMessage({ type: "pg:import", payload: json });
      load();
    } catch (e) {
      alert(t('options_invalidJson') + ' ' + e);
    }
  });

  load();
})();

