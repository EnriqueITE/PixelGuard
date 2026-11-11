/* global browser, PixelGuardVT */
(() => {
  const service = PixelGuardVT.createService(browser);
  browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!String(msg?.type || '').startsWith('pg:vt:')) return false;
    service.handle(msg, sender).then(sendResponse, () => sendResponse({ ok: false, error: 'unavailable' }));
    return true;
  });
  browser.tabs.onRemoved.addListener(service.invalidate);
  browser.messageDisplay.onMessageDisplayed.addListener(service.messageDisplayed);
  browser.messageDisplay.onMessagesDisplayed?.addListener((tab, messages) => {
    if (messages.length !== 1) service.invalidate(tab.id);
    else service.messageDisplayed(tab, messages[0]);
  });
  browser.permissions.onRemoved.addListener(service.permissionsRemoved);
})();
