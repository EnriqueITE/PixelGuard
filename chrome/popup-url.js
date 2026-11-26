/* global chrome, PixelGuardVTInventory */
// The editable field owns the lookup value. Suggestions and their previews stay local.
function initUrlPicker(onChange) {
  const picker = document.getElementById("url-picker");
  const input = document.getElementById("url");
  const picked = document.getElementById("picked-url");
  const list = document.getElementById("url-options");
  const toggle = document.getElementById("show-links");
  let active;

  input.placeholder = chrome.i18n.getMessage("pgChooseLink");
  toggle.setAttribute("aria-label", chrome.i18n.getMessage("pgThreadLinks"));

  function setActive(option) {
    active?.setAttribute("aria-selected", "false");
    active = option;
    if (active) {
      active.setAttribute("aria-selected", "true");
      input.setAttribute("aria-activedescendant", active.id);
      active.scrollIntoView({block: "nearest"});
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }
  function expand(open) {
    list.hidden = !open;
    input.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-expanded", String(open));
  }
  function close() {
    expand(false);
    setActive(null);
  }
  function open(query = "") {
    const needle = query.trim().toLowerCase();
    let matches = 0;
    for (const option of list.children) {
      option.hidden = !!needle && !option.textContent.toLowerCase().includes(needle);
      if (!option.hidden) matches++;
    }
    setActive(null);
    expand(matches > 0);
  }
  function selectUrl(value) {
    input.value = value;
    input.title = input.value;
    close();
    input.focus({preventScroll: true});
    input.setSelectionRange(0, 0);
    input.scrollLeft = 0;
    picked.textContent = input.value;
    picked.hidden = false;
    onChange();
  }

  toggle.onclick = () => {
    input.focus({preventScroll: true});
    if (list.hidden) open(); else close();
  };
  input.onclick = () => { if (list.hidden && !toggle.hidden) open(); };
  input.onpointerdown = () => { picked.hidden = true; };
  input.oninput = () => {
    input.title = input.value;
    picked.hidden = true;
    open(input.value);
    onChange();
  };
  input.onkeydown = event => {
    if (event.isComposing) return;
    if (event.key !== "Escape") picked.hidden = true;
    if (event.key === "Tab") {
      close();
    } else if (event.key === "Escape" && !list.hidden) {
      event.preventDefault();
      event.stopPropagation();
      close();
    } else if (event.key === "Enter" && active) {
      event.preventDefault();
      selectUrl(active.textContent);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (list.hidden) open();
      if (list.hidden) return;
      event.preventDefault();
      const options = Array.from(list.children).filter(option => !option.hidden);
      const down = event.key === "ArrowDown";
      const next = active ? options.indexOf(active) + (down ? 1 : -1) : (down ? 0 : options.length - 1);
      setActive(options[Math.max(0, Math.min(next, options.length - 1))]);
    }
  };
  list.onmousedown = event => event.preventDefault(); // Keep keyboard focus in the field.
  list.onclick = event => {
    const option = event.target.closest('[role="option"]');
    if (option) selectUrl(option.textContent);
  };
  // Collapse after the click lands, so the action buttons below the list stay put during the click.
  document.addEventListener("click", event => {
    if (!picker.contains(event.target)) close();
  });
  window.addEventListener("blur", close);

  function setLinks(links) {
    close();
    if (!input.value) {
      picked.hidden = true;
      picked.textContent = "";
    }
    const options = document.createDocumentFragment();
    for (const {url: raw} of links) {
      const url = PixelGuardVTInventory.validUrl(raw);
      if (!url) continue;
      const option = document.createElement("div");
      option.className = "url-option";
      option.id = "url-option-" + options.childElementCount;
      option.setAttribute("role", "option");
      option.setAttribute("aria-selected", "false");
      option.textContent = url.href;
      option.title = url.href;
      options.append(option);
    }
    list.replaceChildren(options);
    toggle.hidden = !list.childElementCount;
  }
  return {setLinks, selectUrl, close};
}
