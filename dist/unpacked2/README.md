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
- Package as `.xpi` by zipping the folder contents.

## Roadmap
- Finer-grained blocking rules per sender.
- Per-thread counters and history.
- Automated tests (Jest/Vitest with jsdom).

## License
Licensed under the project’s repository license. Update the license file in your repository with the correct project details and remove any placeholders.

