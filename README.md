# PixelGuard (Thunderbird)

Detect and block tracking pixels in emails opened in Thunderbird.

## What It Does
- Scans the displayed message HTML to detect 1×1/hidden images or URLs with common tracking parameters.
- Shows a compact banner with actions: Allow domain, Toggle blocking, Options.
- Optionally blocks suspicious remote requests via `webRequest` (when block mode is ON).
- Per-sender whitelist.

Note: Thunderbird blocks remote content by default. PixelGuard adds explicit detection and selective blocking when remote content is allowed.

## Permissions
- `messagesRead`, `messageDisplay`: read message context.
- `storage`: persist settings.
- `webRequest`, `webRequestBlocking`, `<all_urls>`: optionally block suspicious remote loads.

## Development Installation
1. Open this folder.
2. In Thunderbird: Tools → Add-ons and Themes → ⚙️ → Debug Add-ons.
3. Load Temporary Add-on and select `manifest.json`.
4. Open an HTML email to see the banner.

## Localization
- UI is localized and follows the Thunderbird language automatically.
- Included locales: English (US), English, Spanish, French, German, Greek, Russian, Chinese (Simplified).

## Privacy
- PixelGuard processes content locally only. No data leaves your device.

## Packaging
- Include icons in `icons/` (16, 32, 48, 96, 128).
- Use the helper script to ensure `_locales` and all files are included:
  - `powershell -ExecutionPolicy Bypass -File scripts/package.ps1`
  - Output: `dist/PixelGuard-<version>.xpi`
  - The script reads the version from `manifest.json` and zips the staged files.

If you prefer manual packaging, zip the contents of the extension folder (not the folder itself), ensuring `_locales/en/messages.json` is present inside the archive:

Windows PowerShell (from repo root):

```
$dest = "dist/PixelGuard-0.1.0.xpi"
New-Item -ItemType Directory -Force dist | Out-Null
Compress-Archive -Path manifest.json, background.js, content, options, popup, _locales, icons -DestinationPath $dest -Force
```

Do not zip the `dist/` folder itself, and make sure `_locales/` is included.

## Roadmap
- Finer-grained blocking rules per sender.
- Per-thread counters and history.
- Automated tests (Jest/Vitest with jsdom).

## License
Licensed under the project’s repository license. Update the license file in your repository with the correct project details and remove any placeholders.
