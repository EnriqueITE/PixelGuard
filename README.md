# PixelGuard (Thunderbird)

PixelGuard is a Thunderbird extension that **reports** probable tracking pixels, suspicious links, and external images when you open an email. It explains the evidence behind each finding so you can decide whether to load remote content, and PixelGuard never interferes with Thunderbird's network behavior.

## Installation
- Install the signed build from the official Thunderbird Add-on store (search for "PixelGuard") to ensure you receive the reviewed release.
- Contributors can clone this repository, build from source, and load the extension temporarily in Thunderbird for testing.

## What It Does
- Scans the displayed message HTML to spot 1x1/hidden images, suspicious tracking parameters, and externally hosted assets that may leak engagement.
- Uses confidence-based classification so normal visible images with marketing parameters are not automatically called tracking pixels.
- Surfaces detections in a compact banner and popup with brief reasons for each item.
- Provides transparency only; remote content, images, fonts, and requests remain fully governed by Thunderbird's built-in remote-content controls.

If you need enforcement, rely on Thunderbird's controls (Message > Enable/Disable Remote Content) or another dedicated tool. PixelGuard focuses purely on detection so you can make informed decisions before loading anything external.

## Permissions
- `messagesRead`: read the currently displayed message body and metadata for local analysis.
- `messagesModify`: inject PixelGuard's banner scripts and styles into the displayed message view. PixelGuard does not modify stored email messages.
- `storage`: persist detection preferences locally.

## Development Installation
1. Clone this repository and open the project folder.
2. In Thunderbird, go to Tools > Add-ons and Themes > Debug Add-ons.
3. Click "Load Temporary Add-on" and pick `manifest.json` from this project.
4. Open an HTML email to see the PixelGuard banner with live detections.

## Localization
- UI follows Thunderbird's selected language automatically.
- Included locales: English (US), English, Spanish, French, German, Greek, Russian, Chinese (Simplified).

## Privacy
- PixelGuard processes content locally only. No data leaves your device.

## Packaging
- Include icons in `icons/` (16, 32, 48, 96, 128).
- Run the helper script to create an `.xpi`:
  - `powershell -ExecutionPolicy Bypass -File scripts/package.ps1`
  - Output: `dist/PixelGuard-<version>.xpi`
  - The script reads the version from `manifest.json` and zips the staged files.

## Roadmap
- More user-tunable confidence thresholds.
- Per-thread counters and history.
- Broader fixture coverage for email rendering edge cases.

## License
PixelGuard is free software licensed under the GNU General Public License v3.0 or later. See [LICENSE](LICENSE) for the standard GPL terms and [NOTICE](NOTICE) for the project copyright notice.
