const filters = document.querySelector(".filters");
const buttons = filters.querySelectorAll("button");
const results = document.querySelectorAll("[data-result]");

function showResult(type) {
  for (const button of buttons) {
    button.setAttribute("aria-pressed", String(button.dataset.filter === type));
  }
  for (const result of results) {
    result.hidden = result.dataset.result !== type;
  }
}

filters.addEventListener("click", event => {
  const button = event.target.closest("button[data-filter]");
  if (button) showResult(button.dataset.filter);
});
showResult("pixel");
filters.hidden = false;

const languageSelect = document.querySelector(".language select");
const preferenceKey = "pixelguard.site.language";
const description = document.querySelector('meta[name="description"]');
const bindings = [
  ...Array.from(document.querySelectorAll("[data-text]"), node => [node, node.dataset.text, "textContent"]),
  ...Array.from(document.querySelectorAll("[data-label]"), node => [node, node.dataset.label, "ariaLabel"]),
  ...Array.from(document.querySelectorAll("[data-alt]"), node => [node, node.dataset.alt, "alt"]),
  [document, "title", "title"],
  [description, "description", "content"]
];
const spanish = Object.fromEntries(bindings.map(([node, key, property]) => [key, node[property]]));
const translations = { ...siteTranslations, es: spanish };

function browserLanguage() {
  for (const tag of navigator.languages?.length ? navigator.languages : [navigator.language]) {
    const base = tag.toLowerCase().split("-")[0];
    if (base === "zh") return "zh-CN";
    if (Object.hasOwn(translations, base)) return base;
  }
  return "en";
}

let preferredLanguage = null;

function applyLanguage() {
  const language = preferredLanguage ?? browserLanguage();
  languageSelect.value = language;
  document.documentElement.lang = language;
  for (const [node, key, property] of bindings) node[property] = translations[language][key];
}

try {
  const stored = localStorage.getItem(preferenceKey);
  if (Object.hasOwn(translations, stored)) preferredLanguage = stored;
} catch { /* Keep automatic selection when storage is unavailable. */ }
languageSelect.addEventListener("change", () => {
  preferredLanguage = languageSelect.value === "auto" ? null : languageSelect.value;
  applyLanguage();
  try {
    if (preferredLanguage === null) localStorage.removeItem(preferenceKey);
    else localStorage.setItem(preferenceKey, preferredLanguage);
  } catch { /* The choice still applies to this page. */ }
});
window.addEventListener("languagechange", applyLanguage);
applyLanguage();
languageSelect.closest(".language").hidden = false;
