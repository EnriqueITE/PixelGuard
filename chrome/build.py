"""Build the unpacked Chrome extension from its adapter and shared PixelGuard files."""
import json
from pathlib import Path
from shutil import copyfile

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parent
OUTPUT = ROOT / "dist" / "chrome-gmail"


def build():
    files = {name: SOURCE / name for name in (
        "manifest.json", "PRIVACY.md", "gmail.js", "gmail.css", "scanner.js", "worker.js", "vault.js",
        "popup.html", "popup.css", "popup-url.js", "popup-attachments.js", "popup.js",
        "virustotal/widget.js", "virustotal/attachments.js",
        "original-mime.js", "original-scan.js", "gmail-original.js", "gmail-attachments.js"
    )}
    for size in (16, 24, 32):
        name = f"assets/toolbar-{size}.png"
        files[name] = SOURCE / name
    for name in ("assets/icon-48.png", "assets/icon-96.png", "virustotal/inventory.js", "LICENSE", "NOTICE"):
        files[name] = ROOT / name
    for name, source in files.items():
        target = OUTPUT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        copyfile(source, target)
    for locale in ("en", "es"):
        catalog = Path("_locales") / locale / "messages.json"
        shared = json.loads((ROOT / catalog).read_text(encoding="utf-8"))
        messages = {key: value for key, value in shared.items() if key.startswith(("reason_", "vt_"))}
        messages.update(json.loads((SOURCE / f"messages.{locale}.json").read_text(encoding="utf-8")))
        target = OUTPUT / catalog
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(messages, indent=2, ensure_ascii=False), encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    build()
