"""Build the unpacked Chrome extension from its adapter and shared PixelGuard files."""
import json
import re
from pathlib import Path
from shutil import copyfile

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parent
OUTPUT = ROOT / "dist" / "chrome-gmail"
LOCALES = {"en-US": "en", "de": "de", "el": "el", "es": "es", "fr": "fr",
           "it": "it", "ru": "ru", "zh-CN": "zh_CN"}


def build():
    files = {name: SOURCE / name for name in (
        "manifest.json", "PRIVACY.md", "gmail.js", "gmail.css", "scanner.js", "worker.js", "vault.js", "i18n.js",
        "popup.html", "popup.css", "popup-url.js", "popup-attachments.js", "popup.js", "assets/icon-128.png",
        "virustotal/inventory.js", "virustotal/widget.js", "virustotal/attachments.js",
        "original-mime.js", "original-scan.js", "gmail-original.js", "gmail-attachments.js"
    )}
    for size in (16, 24, 32):
        name = f"assets/toolbar-{size}.png"
        files[name] = SOURCE / name
    for name in ("assets/icon-48.png", "assets/icon-96.png", "LICENSE", "NOTICE"):
        files[name] = ROOT / name
    for name, source in files.items():
        target = OUTPUT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        copyfile(source, target)
    catalogs = {}
    for language, locale in LOCALES.items():
        catalog = Path("_locales") / locale / "messages.json"
        shared = json.loads((ROOT / catalog).read_text(encoding="utf-8"))
        messages = {key: value for key, value in shared.items()
                    if key.startswith(("reason_", "vt_")) or key == "ui_buyCoffee"}
        messages.update(json.loads((SOURCE / f"messages.{locale}.json").read_text(encoding="utf-8")))
        target = OUTPUT / catalog
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(messages, indent=2, ensure_ascii=False), encoding="utf-8")
        # Use the same messages for the browser's manifest and the user's in-app override.
        catalogs[language] = {
            key: re.sub(r"\$(\w+)\$", lambda m: entry["placeholders"][m[1].lower()]["content"],
                        entry["message"]) for key, entry in messages.items()
        }
    compiled = json.dumps(catalogs, ensure_ascii=False, separators=(",", ":"))
    (OUTPUT / "i18n-catalogs.js").write_text("globalThis.PixelGuardCatalogs = " + compiled + ";\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    build()
