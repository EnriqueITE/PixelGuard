/* global chrome, PixelGuardVTInventory, initUrlPicker, readGmailAttachment */
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
  let sourceTab;
  let rowUrl = "";
  let rowAttachment, attachmentRead, uploadOffer;
  let attachments = [];
  let attachmentInventoryRequest;

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
    attachmentRead?.abort();
    attachmentRead = null;
    uploadOffer = null;
    el("upload-confirmation").hidden = true;
    el("upload-file-name").textContent = "";
    el("attachment-digest").hidden = true;
    el("attachment-sha").textContent = "";
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
    const active = state?.vtEnabled && !pending && !saving && !attachmentRead;
    const url = PixelGuardVTInventory.validUrl(el("url").value.trim());
    el("query-domain").disabled = !active || !url;
    el("preview-url").disabled = !active || !url;
    el("confirm-url").disabled = !active || !preview;
    el("query-hash").disabled = !active || !(el("attachments").value || el("file").files.length);
    el("confirm-upload").disabled = !active || !uploadOffer;
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
    let resumeRow = false;
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
      if (patch.vtEnabled === false || patch.apiKey === "") {
        rowUrl = "";
        rowAttachment = null;
      }
      if (!next.vtEnabled) {
        forgetLookup();
        el("lookup").open = false;
        inventoryRequest = null;
        attachmentInventoryRequest = null;
        showAttachments([]);
        el("file").value = "";
        el("url").value = "";
        el("url").removeAttribute("title");
        urlPicker.setLinks([]);
        el("truncated").hidden = true;
      }
      if (close) keyForm(false);
      resumeRow = next.vtEnabled && patch.vtEnabled === true && (rowAttachment || rowUrl);
      if (patch.apiKey) status(t("vt_keySaved"));
    } catch { showError("storage"); }
    finally {
      saving = false;
      paint();
      if (resumeRow) showRowLookup();
    }
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

  async function sourceTabId() {
    if (location.hash) {
      const match = /^#tab=(0|[1-9]\d*)$/.exec(location.hash);
      const id = match && Number(match[1]);
      return Number.isSafeInteger(id) ? id : null;
    }
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    return tab?.id;
  }
  async function fromMail(type) {
    sourceTab ??= sourceTabId();
    const id = await sourceTab;
    if (id == null) return null;
    return chrome.tabs.sendMessage(id, {type}, {frameId: 0});
  }
  function showRowLookup() {
    inventoryRequest = null;
    el("lookup").hidden = false;
    el("lookup").open = true;
    if (rowAttachment) {
      showAttachments([rowAttachment], rowAttachment.id);
      rowAttachment = null;
      setMode(true);
      queryAttachment();
      return;
    }
    urlPicker.setLinks([{url: rowUrl}]);
    urlPicker.selectUrl(rowUrl);
    loadLinks();
  }
  async function takeRowSelection() {
    const before = revision;
    try {
      const reply = await fromMail("pg:gmail:takeVtSelection");
      const url = PixelGuardVTInventory.validUrl(reply?.url);
      const attachment = reply?.attachment;
      if ((!url && !validAttachment(attachment)) || before !== revision || saving) return;
      rowUrl = url?.href || "";
      rowAttachment = url ? null : attachment;
      if (state.vtEnabled) {
        showRowLookup();
      } else {
        if (state.hasKey) el("vt-toggle").focus();
        else if (el("key-form").hidden) keyForm(true);
        status(t(rowAttachment ? "pgEnableAttachmentVT" : "pgRowEnableVT"));
      }
    } catch { /* The toolbar also works on tabs without a Gmail content script. */ }
  }

  async function loadLinks() {
    if (!state?.vtEnabled || inventoryRequest || !el("lookup").open) return;
    const request = {};
    inventoryRequest = request;
    try {
      const data = await fromMail("pg:gmail:links");
      if (request !== inventoryRequest) return;
      const links = data?.links || [];
      if (rowUrl && !links.some(link => link.url === rowUrl)) links.unshift({url: rowUrl});
      urlPicker.setLinks(links);
      el("truncated").hidden = !data?.truncated;
    } catch { /* Pasting a URL also works outside an open Gmail message. */ }
  }
  function validAttachment(item) {
    return typeof item?.id === "string" && !!item.id && typeof item.name === "string" && !!item.name;
  }
  function showAttachments(items, selected = "") {
    attachments = items.filter(validAttachment);
    const select = el("attachments");
    const names = new Map();
    for (const item of attachments) names.set(item.name, (names.get(item.name) || 0) + 1);
    const numbered = new Map();
    select.replaceChildren(new Option(t("pgPickLocalFile"), ""));
    for (const item of attachments) {
      let label = item.name;
      if (names.get(item.name) > 1) {
        const n = (numbered.get(item.name) || 0) + 1;
        numbered.set(item.name, n);
        label += " (" + n + ")";
      }
      select.add(new Option(label, item.id));
    }
    select.value = selected;
    if (select.selectedIndex < 0) select.selectedIndex = 0;
    el("attachment-picker").hidden = !attachments.length;
    el("local-file").hidden = !!select.value;
    updateButtons();
  }
  async function loadAttachments() {
    if (!state?.vtEnabled || attachmentInventoryRequest || !el("lookup").open) return;
    const request = {};
    attachmentInventoryRequest = request;
    try {
      const reply = await fromMail("pg:gmail:attachments");
      if (request !== attachmentInventoryRequest || !Array.isArray(reply?.attachments)) return;
      const selected = el("attachments").value;
      showAttachments(reply.attachments, selected);
      if (selected && !el("attachments").value) {
        forgetLookup();
        showError("stale_message");
      }
    } catch { /* The local file picker is available outside Gmail. */ }
  }
  el("lookup").ontoggle = () => {
    if (!el("lookup").open) {
      attachmentInventoryRequest = null;
      urlPicker.close();
      forgetLookup();
    } else if (el("file-fields").hidden) loadLinks();
    else loadAttachments();
  };
  el("attachments").onchange = () => {
    el("file").value = "";
    el("local-file").hidden = !!el("attachments").value;
    forgetLookup();
  };
  el("file").onchange = forgetLookup;
  function setMode(file) {
    urlPicker.close();
    el("link-mode").setAttribute("aria-pressed", String(!file));
    el("file-mode").setAttribute("aria-pressed", String(file));
    el("file-fields").hidden = !file;
    forgetLookup();
    if (file) loadAttachments();
    else { attachmentInventoryRequest = null; loadLinks(); }
  }
  el("link-mode").onclick = () => setMode(false);
  el("file-mode").onclick = () => setMode(true);

  function present(result, fileHash) {
    el("result-title").textContent = result.status === "submitted" ? t("pgFileSubmitted") :
      result.status === "no_report" ? t("vt_noReport") :
      Number.isInteger(result.total) ? t("vt_ratio", result.detections, result.total) : t("pgReportFound");
    el("zero-note").hidden = result.detections !== 0;
    el("result-time").hidden = result.status === "submitted";
    el("result-time").textContent = result.status === "submitted" ? "" :
      t("vt_queriedAt", new Date(result.queriedAt).toLocaleString(document.documentElement.lang));
    const report = el("report");
    const href = fileHash && result.status !== "no_report" ? "https://www.virustotal.com/gui/file/" + fileHash :
      PixelGuardVTInventory.reportUrl(result.reportUrl);
    report.hidden = !href;
    if (href) report.href = href; else report.removeAttribute("href");
    el("result").hidden = false;
  }
  async function sha256(file) {
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  }
  async function queryAttachment() {
    const selected = attachments.find(item => item.id === el("attachments").value);
    if (!selected || !state.vtEnabled || pending || saving || attachmentRead) return;
    forgetLookup();
    const current = revision;
    const controller = new AbortController();
    attachmentRead = controller;
    updateButtons();
    status(t("pgHashingAttachment"));
    try {
      sourceTab ??= sourceTabId();
      const file = await readGmailAttachment(await sourceTab, selected, controller.signal);
      if (current !== revision) return;
      const hash = await sha256(file);
      if (current !== revision) return;
      el("attachment-sha").textContent = hash;
      el("attachment-digest").hidden = false;
      status(t("vt_querying"));
      const reply = await send("attachmentReport", {hash});
      if (current !== revision) return;
      if (!reply?.ok) return showError(reply?.error);
      status();
      present(reply.result, hash);
      if (reply.result.status === "no_report" && reply.uploadToken) {
        uploadOffer = {file, hash, token: reply.uploadToken};
        el("upload-file-name").textContent = file.name + " · " + file.size.toLocaleString(document.documentElement.lang) + " B";
        el("upload-confirmation").hidden = false;
      }
    } catch (error) {
      if (current === revision) showError(error.message === "too_large" ? "too_large" : "unavailable");
    } finally {
      if (attachmentRead === controller) attachmentRead = null;
      updateButtons();
    }
  }
  el("cancel-upload").onclick = () => {
    uploadOffer = null;
    el("upload-confirmation").hidden = true;
    el("upload-file-name").textContent = "";
    updateButtons();
    el("query-hash").focus();
  };
  el("confirm-upload").onclick = async event => {
    if (!event.isTrusted || !uploadOffer || !state.vtEnabled || pending || saving) return;
    const {file, hash, token} = uploadOffer;
    const current = revision;
    uploadOffer = null;
    el("upload-confirmation").hidden = true;
    el("upload-file-name").textContent = "";
    el("result").hidden = true;
    pending = true;
    updateButtons();
    status(t("pgUploadingFile"));
    let blobUrl;
    try {
      blobUrl = URL.createObjectURL(file);
      const reply = await send("uploadAttachment", {hash, name: file.name, blobUrl, uploadToken: token, confirmed: true});
      if (current !== revision) return;
      if (!reply?.ok) return showError(reply?.error);
      status();
      present({status: "submitted", queriedAt: Date.now()}, hash);
    } catch { if (current === revision) showError("network"); }
    finally {
      if (blobUrl) URL.revokeObjectURL(blobUrl);
      pending = false;
      updateButtons();
    }
  };
  window.addEventListener("pagehide", forgetLookup);

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
        value = await sha256(file);
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
  el("query-hash").onclick = () => el("attachments").value ? queryAttachment() : lookup("hash", null, el("file").files[0]);
  send("state").then(reply => {
    if (!reply?.ok) return showError(reply?.error);
    state = reply;
    paint();
    takeRowSelection();
  }).catch(() => showError("storage"));
})();
