/* global browser, PixelGuardI18n */
(async function () {
  const picker = document.getElementById('uiLanguage');
  const languageError = document.getElementById('languageSaveError');
  const debugToggle = document.getElementById("debugToggle");
  const bannerToggle = document.getElementById("inlineBannerToggle");
  const bannerError = document.getElementById("bannerSaveError");

  function showLanguage() {
    PixelGuardI18n.translatePage(document);
    picker.value = PixelGuardI18n.selected;
  }
  await PixelGuardI18n.ready;
  showLanguage();
  PixelGuardI18n.onChange(showLanguage);
  picker.disabled = false;
  picker.addEventListener('change', async () => {
    picker.disabled = true;
    languageError.hidden = true;
    try {
      await PixelGuardI18n.setLanguage(picker.value);
    } catch (_) {
      picker.value = PixelGuardI18n.selected;
      languageError.hidden = false;
    } finally {
      picker.disabled = false;
    }
  });

  async function load() {
    const st = await browser.runtime.sendMessage({ type: "pg:getState" });
    debugToggle.checked = !!st.debug;
    bannerToggle.checked = st.showInlineBanner === true;
    bannerToggle.disabled = false;
  }

  bannerToggle.addEventListener('change', async () => {
    const value = bannerToggle.checked;
    bannerToggle.disabled = true;
    bannerError.hidden = true;
    try {
      const result = await browser.runtime.sendMessage({ type: 'pg:setInlineBanner', value });
      if (!result?.ok) throw new Error('Could not save banner preference');
      bannerToggle.checked = result.showInlineBanner;
    } catch (_) {
      bannerToggle.checked = !value;
      bannerError.hidden = false;
    } finally {
      bannerToggle.disabled = false;
    }
  });

  debugToggle.addEventListener('change', async () => {
    await browser.runtime.sendMessage({ type: 'pg:setDebug', value: debugToggle.checked });
  });

  load();
})();
