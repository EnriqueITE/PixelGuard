/* global chrome, PixelGuardCatalogs */
(() => {
  const languages = Object.freeze({
    "en-US": "English (US)", de: "Deutsch", el: "Ελληνικά", es: "Español",
    fr: "Français", it: "Italiano", ru: "Русский", "zh-CN": "中文（简体）"
  });
  let locale, plurals;

  function validPreference(preference) {
    return preference === "auto" || (typeof preference === "string" && Object.hasOwn(languages, preference));
  }

  function browserLocale() {
    try {
      const ui = new Intl.Locale(chrome.i18n.getUILanguage().replaceAll("_", "-"));
      if (ui.language === "zh" && ui.maximize().script === "Hans") return "zh-CN";
      if (Object.hasOwn(languages, ui.language)) return ui.language;
    } catch { /* An unknown locale falls back to the extension's default. */ }
    return "en-US";
  }

  function use(preference) {
    const next = preference !== "auto" && validPreference(preference) ? preference : browserLocale();
    if (next !== locale) {
      locale = next;
      plurals = new Intl.PluralRules(locale);
    }
  }

  function t(key, ...values) {
    const message = PixelGuardCatalogs[locale][key] ?? PixelGuardCatalogs["en-US"][key] ?? "";
    return message.replace(/\$(\$|[1-9])/g, (_, index) => index === "$" ? "$" : String(values[Number(index) - 1] ?? ""));
  }

  function pluralKey(one, other, count) {
    const form = plurals.select(count);
    if (form === "one" && one) return one;
    const key = other + form[0].toUpperCase() + form.slice(1);
    return Object.hasOwn(PixelGuardCatalogs[locale], key) ? key : other;
  }

  use("auto");
  globalThis.PixelGuardI18n = {languages, validPreference, use, t, pluralKey, get locale() { return locale; }};
})();
