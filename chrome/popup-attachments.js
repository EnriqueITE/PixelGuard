/* global chrome, PixelGuardVTInventory */
function attachmentUploadName(original) {
  const name = original.replace(/[\\/\u0000-\u001f\u007f]/g, "_");
  if (!name.trim()) return "_";
  if (name.length <= 512) return name;
  const extension = name.match(/\.[a-z\d]{1,16}$/i)?.[0] || "";
  const stem = name.slice(0, 512 - extension.length).replace(/[\ud800-\udbff]$/, "");
  const shortened = stem + extension;
  return shortened.trim() ? shortened : "_";
}

// Read only the chosen attachment. Disconnecting the port cancels Gmail's read.
function readGmailAttachment(tabId, attachment, signal) {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    if (!Number.isInteger(tabId) || tabId < 0) throw new Error("unavailable");
    const port = chrome.tabs.connect(tabId, {frameId: 0, name: "pg:gmail:attachment"});
    let bytes, offset = 0;
    function stop() {
      port.onDisconnect.removeListener(disconnected);
      port.onMessage.removeListener(receive);
      signal.removeEventListener("abort", cancel);
      port.disconnect();
    }
    function fail(code) {
      stop();
      reject(new Error(code));
    }
    function cancel() { fail("stale_message"); }
    function disconnected() {
      // Read lastError while the disconnect callback is active.
      void chrome.runtime.lastError;
      fail("unavailable");
    }
    function receive(message) {
      if (message?.error) return fail(message.error === "too_large" ? "too_large" : "unavailable");
      try {
        if (!bytes) {
          if (message.name !== attachment.name || !Number.isSafeInteger(message.size) || message.size < 0) return fail("unavailable");
          if (message.size > PixelGuardVTInventory.MAX_FILE_BYTES) return fail("too_large");
          bytes = new Uint8Array(message.size);
        } else if (message.done === true) {
          if (offset !== bytes.length) return fail("unavailable");
          const file = new File([bytes], attachmentUploadName(attachment.name), {type: "application/octet-stream"});
          stop();
          resolve(file);
        } else {
          if (typeof message.chunk !== "string" || !message.chunk.length || message.chunk.length > 4 * Math.ceil(256 * 1024 / 3)) return fail("unavailable");
          const chunk = atob(message.chunk);
          if (!chunk.length || offset + chunk.length > bytes.length) return fail("unavailable");
          for (let i = 0; i < chunk.length; i++) bytes[offset++] = chunk.charCodeAt(i);
        }
      } catch { fail("unavailable"); }
    }
    signal.addEventListener("abort", cancel, {once: true});
    port.onMessage.addListener(receive);
    port.onDisconnect.addListener(disconnected);
    try { port.postMessage({id: attachment.id}); } catch { fail("unavailable"); }
  });
}
