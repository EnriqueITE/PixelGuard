/* global chrome, PixelGuardVTInventory */
// The editable field owns the lookup value. Suggestions and their previews stay local.
function initUrlPicker(onChange) {
  const picker = document.getElementById("url-picker");
  const input = document.getElementById("url");
  const picked = document.getElementById("picked-url");
  const list = document.getElementById("url-options");
  const toggle = document.getElementById("show-links");
  const tip = document.getElementById("url-tip");
  let active, tipOwner;

  input.placeholder = chrome.i18n.getMessage("pgChooseLink");
  toggle.setAttribute("aria-label", chrome.i18n.getMessage("pgThreadLinks"));

  function hideTip() {
    tipOwner?.removeAttribute("aria-describedby");
    tipOwner = null;
    tip.hidden = true;
    tip.textContent = "";
  }
  function showTip(owner) {
    const url = owner === input ? input.value : owner?.textContent;
    if (!url) return hideTip();
    if (owner === tipOwner && tip.textContent === url) return;
    tipOwner?.removeAttribute("aria-describedby");
    tipOwner = owner;
    owner.setAttribute("aria-describedby", tip.id);
    tip.textContent = url;
    tip.hidden = false;
    tip.scrollTop = 0;
  }
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
    hideTip();
  }
  function open(query = "") {
    const needle = query.trim().toLowerCase();
    let matches = 0;
    for (const option of list.children) {
      option.hidden = !!needle && !option.textContent.toLowerCase().includes(needle);
      if (!option.hidden) matches++;
    }
    setActive(null);
    hideTip();
    expand(matches > 0);
  }
  function choose(option) {
    input.value = option.textContent;
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
  input.oninput = () => { picked.hidden = true; open(input.value); onChange(); };
  input.onkeydown = event => {
    if (event.isComposing) return;
    if (event.key !== "Escape") picked.hidden = true;
    if (event.key === "Tab") {
      close();
    } else if (event.key === "Escape" && (!list.hidden || !tip.hidden)) {
      event.preventDefault();
      event.stopPropagation();
      close();
    } else if (event.key === "Enter" && active) {
      event.preventDefault();
      choose(active);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (list.hidden) open();
      if (list.hidden) return;
      event.preventDefault();
      const options = Array.from(list.children).filter(option => !option.hidden);
      const down = event.key === "ArrowDown";
      const next = active ? options.indexOf(active) + (down ? 1 : -1) : (down ? 0 : options.length - 1);
      setActive(options[Math.max(0, Math.min(next, options.length - 1))]);
      showTip(active);
    }
  };
  list.onmousedown = event => event.preventDefault(); // Keep keyboard focus in the field.
  list.onclick = event => {
    const option = event.target.closest('[role="option"]');
    if (option) choose(option);
  };
  picker.onpointerover = event => {
    if (event.pointerType === "touch" || tip.contains(event.target)) return;
    const option = event.target.closest('[role="option"]');
    if (option) showTip(option);
    else if (event.target === input) showTip(input);
    else hideTip();
  };
  picker.onpointerleave = hideTip;
  // Collapse after the click lands, so the action buttons below the list stay put during the click.
  document.addEventListener("click", event => {
    if (!picker.contains(event.target)) close();
  });
  window.addEventListener("blur", close);

  function setLinks(links) {
    close();
    picked.hidden = true;
    picked.textContent = "";
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
      options.append(option);
    }
    list.replaceChildren(options);
    toggle.hidden = !list.childElementCount;
  }
  return {setLinks, close};
}
