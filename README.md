# PixelGuard (Thunderbird)

PixelGuard is a Thunderbird extension that detects tracking pixels, links, and external images whenever you open an email, helping you see which messages try to track you before you load remote content.

## Installation
- Download the stable, signed build directly from the official Thunderbird Add-on store (search for “PixelGuard”) to ensure you always get the vetted release.
- For contributors who want to test unreleased changes, compile the add-on from this repository and load it temporarily in Thunderbird.

## What It Does
- Scans the displayed message HTML to spot 1x1/hidden images, suspicious tracking parameters, and externally hosted assets that typically leak engagement.
- Surfaces detections in a compact banner with quick actions such as allowing a sender/domain or opening the options panel.
- Keeps a per-sender whitelist so you can silence warnings from trusted contacts while still flagging others.

Note: Thunderbird blocks remote content by default until you allow it. PixelGuard focuses on detection and transparency so you can make informed decisions before loading anything external.

## Permissions
- `messagesRead`, `messageDisplay`: read message context.
- `storage`: persist detection preferences.

## Development Installation
1. Clone this repository and open the project folder.
2. In Thunderbird, go to Tools → Add-ons and Themes → ⚙ → Debug Add-ons.
3. Load Temporary Add-on and select `manifest.json`.
4. Open an HTML email to see the PixelGuard banner with live detections.

## Localization
- UI follows Thunderbird's selected language automatically.
- Included locales: English (US), English, Spanish, French, German, Greek, Russian, Chinese (Simplified).

## Privacy
- PixelGuard processes content locally only. No data leaves your device.

## Packaging
- Include icons in `icons/` (16, 32, 48, 96, 128).
- Compile the add-on locally with the helper script:
  - `powershell -ExecutionPolicy Bypass -File scripts/package.ps1`
  - Output: `dist/PixelGuard-<version>.xpi`
  - The script reads the version from `manifest.json` and zips the staged files.

## Roadmap
- Refined heuristics to catch more tracking techniques without false positives.
- Per-thread counters and history.
- Automated tests (Jest/Vitest with jsdom).

## License
Licensed under the project's repository license. Update the license file in your repository with the correct project details and remove any placeholders.
