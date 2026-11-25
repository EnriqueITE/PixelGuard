/* global chrome, PixelGuardVTInventory, initUrlPicker */
(() => {
  const el = id => document.getElementById(id);
  const t = (key, ...args) => chrome.i18n.getMessage(key, args.map(String));
  const validKey = /^[A-Za-z0-9_-]{16,256}$/;
  const send = (type, fields = {}) => chrome.runtime.sendMessage({ type: "pg:" + type, ...fields });
  let state;
  let saving = false;
  let pending = false;
  let revision = 0;
  let preview = "";
  let inventoryRequest;

  document.documentElement.lang = chrome.i18n.getUILanguage();
  for (const item of document.querySelectorAll("[data-msg]")) item.textContent = t(item.dataset.msg);
  const urlPicker = initUrlPicker(forgetLookup);

  function status(text = "", error = false) {
    const line = el("status");
    line.hidden = !text;
    line.textContent = text;
    line.dataset.error = String(error);
  }
  function showError(code) {
    status(t("vt_error_" + code) || t("vt_error_generic"), true);
  }
  function forgetLookup() {
    revision++;
    preview = "";
    el("confirmation").hidden = true;
    el("link-fields").hidden = el("link-mode").getAttribute("aria-pressed") !== "true";
    el("exact-url").textContent = "";
    el("result").hidden = true;
    el("result-title").textContent = "";
    el("result-time").textContent = "";
    el("report").removeAttribute("href");
    status();
    updateButtons();
  }
  function updateButtons() {
    const active = state?.vtEnabled && !pending && !saving;
    const url = PixelGuardVTInventory.validUrl(el("url").value.trim());
    el("query-domain").disabled = !active || !url;
    el("preview-url").disabled = !active || !url;
    el("confirm-url").disabled = !active || !preview;
    el("query-hash").disabled = !active || !el("file").files.length;
  }
  function paint() {
    // Native controls show the user's selection until the save settles.
    if (!saving) {
      el("panel-toggle").checked = state.showPanel;
      el("dark-mode").checked = state.theme === "dark";
      el("vt-toggle").checked = state.vtEnabled;
    }
    document.documentElement.dataset.theme = el("dark-mode").checked ? "dark" : "light";
    el("dark-mode").disabled = saving;
    el("panel-toggle").disabled = saving;
    el("vt-toggle").hidden = !state.hasKey;
    el("vt-toggle").disabled = saving;
    el("setup").hidden = state.hasKey || !el("key-form").hidden;
    el("key-bar").hidden = !state.hasKey || !el("key-form").hidden;
    el("lookup").hidden = !state.vtEnabled;
    el("delete-key").hidden = !state.hasKey;
    el("key").placeholder = t(state.hasKey ? "vt_keyReplacePlaceholder" : "vt_keyPlaceholder");
    for (const id of ["save-key", "key", "delete-key", "manage", "cancel-key", "setup"]) el(id).disabled = saving;
    updateButtons();
  }
  function keyForm(open) {
    el("key-form").hidden = !open;
    el("key").value = "";
    paint();
    if (open) el("key").focus();
  }
  async function save(patch, { permission = false, close = false } = {}) {
    if (saving) return;
    saving = true;
    paint();
    status();
    try {
      // Request directly from the initiating click, before any worker message.
      if (permission && !await chrome.permissions.request({ origins: ["https://www.virustotal.com/*"] })) {
        return showError("permission_denied");
      }
      const next = await send("settings", patch);
      if (patch.onlyIfMissing && next?.error === "key_exists") {
        const current = await send("state");
        if (!current?.ok) return showError(current?.error);
        state = current;
        keyForm(false);
        return status(t("pgKeyConflict"));
      }
      if (!next?.ok) return showError(next?.error);
      state = next;
      if (!next.vtEnabled) {
        forgetLookup();
        el("lookup").open = false;
        inventoryRequest = null;
        el("file").value = "";
        el("url").value = "";
        el("url").removeAttribute("title");
        urlPicker.setLinks([]);
        el("truncated").hidden = true;
      }
      if (close) keyForm(false);
      if (patch.apiKey) status(t("vt_keySaved"));
    } catch { showError("storage"); }
    finally { saving = false; paint(); }
  }
  el("panel-toggle").onchange = event => save({ showPanel: event.target.checked });
  el("dark-mode").onchange = event => save({ theme: event.target.checked ? "dark" : "light" });
  el("vt-toggle").onchange = event => {
    const enabled = event.target.checked;
    return save({ vtEnabled: enabled }, { permission: enabled });
  };
  el("setup").onclick = el("manage").onclick = () => { status(); keyForm(true); };
  el("cancel-key").onclick = () => { keyForm(false); status(); };
  el("key-form").onsubmit = event => {
    event.preventDefault();
    const apiKey = el("key").value.trim();
    if (!validKey.test(apiKey)) return showError("invalid_key");
    const patch = state.hasKey ? { apiKey } : { apiKey, onlyIfMissing: true };
    return save(patch, { close: true });
  };
  el("delete-key").onclick = () => save({ apiKey: "", vtEnabled: false }, { close: true });

  async function loadLinks() {
    if (!state?.vtEnabled || inventoryRequest || !el("lookup").open) return;
    const request = {};
    inventoryRequest = request;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id == null || request !== inventoryRequest) return;
      const data = await chrome.tabs.sendMessage(tab.id, { type: "pg:gmail:links" });
      if (request !== inventoryRequest) return;
      urlPicker.setLinks(data?.links || []);
      el("truncated").hidden = !data?.truncated;
    } catch { /* Pasting a URL also works outside an open Gmail message. */ }
  }
  el("lookup").ontoggle = () => {
    if (el("lookup").open) loadLinks();
    else { urlPicker.close(); forgetLookup(); }
  };
  el("file").onchange = forgetLookup;
  function setMode(file) {
    urlPicker.close();
    el("link-mode").setAttribute("aria-pressed", String(!file));
    el("file-mode").setAttribute("aria-pressed", String(file));
    el("file-fields").hidden = !file;
    forgetLookup();
  }
  el("link-mode").onclick = () => setMode(false);
  el("file-mode").onclick = () => setMode(true);

  function present(result) {
    el("result-title").textContent = result.status === "no_report" ? t("vt_noReport") :
      Number.isInteger(result.total) ? t("vt_ratio", result.detections, result.total) : t("pgReportFound");
    el("zero-note").hidden = result.detections !== 0;
    el("result-time").textContent = t("vt_queriedAt", new Date(result.queriedAt).toLocaleString(document.documentElement.lang));
    const report = el("report");
    const href = PixelGuardVTInventory.reportUrl(result.reportUrl);
    report.hidden = !href;
    if (href) report.href = href; else report.removeAttribute("href");
    el("result").hidden = false;
  }
  async function lookup(kind, value, file) {
    if (!state.vtEnabled || pending || saving) return;
    forgetLookup();
    const current = revision;
    pending = true;
    updateButtons();
    status(t("vt_querying"));
    try {
      if (kind === "hash") {
        if (!file || file.size > PixelGuardVTInventory.MAX_FILE_BYTES) return showError("too_large");
        const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
        value = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
      }
      if (current !== revision) return;
      const response = await send("lookup", { kind, value, confirmed: kind === "url" });
      if (current !== revision) return;
      if (!response?.ok) return showError(response?.error);
      status();
      present(response.result);
    } catch { if (current === revision) showError("unavailable"); }
    finally { pending = false; updateButtons(); }
  }
  el("query-domain").onclick = () => {
    const url = PixelGuardVTInventory.validUrl(el("url").value.trim());
    if (url) lookup("domain", url.hostname);
  };
  el("preview-url").onclick = () => {
    const url = PixelGuardVTInventory.validUrl(el("url").value.trim());
    if (!url) return;
    forgetLookup();
    preview = url.href;
    el("exact-url").textContent = preview;
    el("link-fields").hidden = true;
    el("confirmation").hidden = false;
    updateButtons();
    el("cancel-url").focus();
  };
  el("cancel-url").onclick = () => { forgetLookup(); el("preview-url").focus(); };
  el("confirm-url").onclick = () => { if (preview) lookup("url", preview); };
  el("query-hash").onclick = () => lookup("hash", null, el("file").files[0]);
  send("state").then(reply => {
    if (!reply?.ok) return showError(reply?.error);
    state = reply;
    paint();
  }).catch(() => showError("storage"));
})();
