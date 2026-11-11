# PixelGuard (Thunderbird)

PixelGuard is a Thunderbird extension that **reports** probable tracking pixels, suspicious links, and external images when you open an email. It explains the evidence behind each finding so you can decide whether to load remote content. Optional, manual VirusTotal lookups add context about links and attachments; they do not change PixelGuard's tracking detections or Thunderbird's remote-content controls.

## Installation
- Install the published build from the official Thunderbird Add-on store (search for "PixelGuard"). The store version may differ from the source version in this repository.
- Contributors can clone this repository, build from source, and load the extension temporarily in Thunderbird for testing.

## What It Does
- Scans the displayed message HTML to spot 1x1/hidden images, suspicious tracking parameters, and externally hosted assets that may leak engagement.
- Uses confidence-based classification so normal visible images with marketing parameters are not automatically called tracking pixels.
- Surfaces detections in a compact banner and popup with brief reasons for each item.
- Provides transparency only; remote content, images, fonts, and requests remain fully governed by Thunderbird's built-in remote-content controls.
- Closing the inline banner keeps it dismissed for the current message. Rescans do not repeatedly count the same suspicious URL within that message view; opening another message starts a new view.
- Inline CSS background URLs use the element's explicit size and visibility as detection evidence, like image elements.

## Optional VirusTotal Lookups

VirusTotal is disabled by default. Enable it in Settings using your own API key and grant the optional permissions only if you want to use it. Opening a message, opening the popup, or saving a key does not make a VirusTotal request.

- **Message links:** list HTTP(S) links from HTML and plain-text messages, including links that do not look like trackers. Consult the domain, or preview and explicitly confirm the full URL before sharing it with VirusTotal. PixelGuard does not visit the destination or follow redirects.
- **Attachments:** select an attachment to calculate its SHA-256 locally and request existing information using that hash. The initial size limit is 50 MiB per attachment. PixelGuard does not upload, execute, unpack, or request a new scan of the attachment.
- **Results:** show VirusTotal's reported detection ratio and the lookup time, with access to the official report in a separate web tab. If there is no normal Thunderbird window, open the report in the default browser. No report and zero detections are not guarantees of safety. The lookup time is not the report's analysis date.
- **Controls:** disable the integration, replace the key, or delete it in Settings. Keys are stored locally, without synchronization; this is not an encrypted credential vault.

This uses [VT Augment's documented individual-key integration](https://docs.virustotal.com/reference/render-widget) for context, not automatic detection. VirusTotal results do not change PixelGuard's alerts, badges, counters, or classifications. The public API is limited to 4 requests per minute and 500 per day, and has restrictions on commercial products and business workflows. Your own key does not waive those restrictions. Read the [public API conditions](https://docs.virustotal.com/reference/public-vs-premium-api) and the terms applicable to your VirusTotal account. Use of the integration does not imply endorsement by VirusTotal or prior approval by the Thunderbird store.

If you need enforcement, rely on Thunderbird's controls (Message > Enable/Disable Remote Content) or another dedicated tool. PixelGuard focuses purely on detection so you can make informed decisions before loading anything external.

## Permissions
- `messagesRead`: read the currently displayed message body and metadata, list its attachments, and read a selected attachment to calculate its hash locally.
- `messagesModify`: inject PixelGuard's banner scripts and styles into the displayed message view. PixelGuard does not modify stored email messages.
- `storage`: persist preferences, counters, and an optional user-provided VirusTotal key locally.
- Optional `sensitiveDataUpload` and `https://www.virustotal.com/*`: requested when enabling VirusTotal, for the selected domain, full URL, or file-hash lookup authenticated with your key. No attachment bytes or message body are submitted.

The integration uses built-in Thunderbird APIs available in version 115. It requires no Experiments, native helpers, remote scripts, or embedded third-party HTML.

## Development Installation
1. Clone this repository and open the project folder.
2. In Thunderbird, go to Tools > Add-ons and Themes > Debug Add-ons.
3. Click "Load Temporary Add-on" and pick `manifest.json` from this project.
4. Open an HTML email to see the PixelGuard banner with live detections.

For development, use a separate Thunderbird profile and synthetic messages. See [local testing](docs/LOCAL-TESTING.md). Source publication and locally built packages do not establish that version 0.2.0 has been submitted to or approved by the Thunderbird store.

## Localization
- UI follows Thunderbird's selected language automatically.
- Included locales: English (US), English, Spanish, French, German, Greek, Russian, Chinese (Simplified).
- The VirusTotal interface is translated in all included locales. Some existing tracking and general-settings labels are still in English.

## Privacy
- Tracking analysis is local. If you enable VirusTotal, an explicit lookup sends the selected indicator and API key directly to VirusTotal over HTTPS. A file hash can identify a known file, and full URLs may contain private identifiers. See the complete [privacy notice](PRIVACY.md).

## Packaging
- Include icons in `icons/` (16, 32, 48, 96, 128).
- Run the helper script to create an `.xpi`:
  - `powershell -ExecutionPolicy Bypass -File scripts/package.ps1`
  - Output: `dist/PixelGuard-<version>.xpi`
  - The script reads the version from `manifest.json` and zips the staged files.

## Tests
- Run `node --test --test-isolation=none scripts/*.test.js` from the repository root.
- Tests cover classification and simulated DOM/extension lifecycle behavior, including dismissal, duplicate counts and tab-close races. Automated tests do not establish real Thunderbird behavior or VirusTotal connectivity; record those checks separately as described in [local testing](docs/LOCAL-TESTING.md).
- [Reviewer notes](docs/REVIEWER-NOTES.md) explain permissions, APIs, data flow and the release review checklist. [Release notes](docs/RELEASE-NOTES-0.2.0.md) and [store listing text](docs/STORE-LISTING-0.2.0.md) provide English and Spanish copy. [Version 0.2.0 screenshots](store-screenshots/0.2.0/) use synthetic demonstration data.

## Roadmap
- More user-tunable confidence thresholds.
- Per-thread counters and history.
- Broader fixture coverage for email rendering edge cases.

## License
PixelGuard is free software licensed under the GNU General Public License v3.0 or later. See [LICENSE](LICENSE) for the standard GPL terms and [NOTICE](NOTICE) for the project copyright notice.
