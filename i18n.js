/* global browser */
(() => {
  const languages = ['en', 'de', 'el', 'es', 'fr', 'it', 'ru', 'zh_CN'];
  const catalogs = new Map();
  const listeners = new Set();
  const textBindings = new WeakMap();
  let selected = 'auto';
  let catalog = null;
  let revision = 0;
  let loading = Promise.resolve();

  function catalogFor(language) {
    if (language === 'auto') return Promise.resolve(null);
    if (!catalogs.has(language)) {
      const url = browser.runtime.getURL('_locales/' + language + '/messages.json');
      catalogs.set(language, fetch(url).then(response => {
        if (!response.ok) throw new Error('Unable to load the bundled language file');
        return response.json();
      }).catch(error => {
        catalogs.delete(language);
        throw error;
      }));
    }
    return catalogs.get(language);
  }

  function apply(value) {
    const language = languages.includes(value) ? value : 'auto';
    const version = ++revision;
    loading = catalogFor(language).then(messages => {
      if (revision !== version || language === selected) return;
      catalog = messages;
      selected = language;
      for (const listener of listeners) listener();
    });
    return loading;
  }

  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && Object.hasOwn(changes, 'uiLanguage')) {
      apply(changes.uiLanguage.newValue).catch(() => {});
    }
  });
  const ready = browser.storage.local.get('uiLanguage')
    .then(stored => revision ? loading : apply(stored.uiLanguage))
    .catch(() => {});

  function get(key, ...subs) {
    const entry = catalog && Object.hasOwn(catalog, key) && catalog[key];
    if (!entry) return browser.i18n.getMessage(key, subs);
    // Bundled WebExtension catalogs use named placeholders with positional content.
    return entry.message.replace(/\$([\w]+)\$|\$([1-9])|\$\$/g, (token, name, slot) => {
      if (token === '$$') return '$';
      const position = slot || entry.placeholders?.[name.toLowerCase()]?.content.slice(1);
      return subs[Number(position) - 1] ?? '';
    });
  }

  async function setLanguage(language) {
    if (language !== 'auto' && !languages.includes(language)) throw new Error('Unsupported language');
    await catalogFor(language);
    await browser.storage.local.set({ uiLanguage: language });
    // Read back the committed choice in case another settings tab also saved.
    const stored = await browser.storage.local.get('uiLanguage');
    await apply(stored.uiLanguage);
  }

  // Keep focus and expanded rows when the language changes in another window.
  function bindText(element, format, mirrorTitle = false) {
    if (typeof format !== 'function') {
      textBindings.delete(element);
      element.removeAttribute('data-localized');
      element.textContent = format;
      return;
    }
    const update = () => {
      element.textContent = format();
      if (mirrorTitle) element.title = element.textContent;
    };
    textBindings.set(element, update);
    element.setAttribute('data-localized', '');
    update();
  }

  function translatePage(doc) {
    doc.documentElement.lang = locale();
    for (const element of doc.querySelectorAll('[data-i18n]')) {
      element.textContent = get(element.dataset.i18n);
    }
    for (const element of doc.querySelectorAll('[data-i18n-placeholder]')) {
      element.placeholder = get(element.dataset.i18nPlaceholder);
    }
    for (const element of doc.querySelectorAll('[data-localized]')) {
      textBindings.get(element)();
    }
  }

  function locale() {
    return selected === 'auto' ? browser.i18n.getUILanguage() : selected.replace('_', '-');
  }

  globalThis.PixelGuardI18n = { ready, get, locale, bindText, translatePage, setLanguage,
    get selected() { return selected; },
    onChange(listener) { listeners.add(listener); }
  };
})();
