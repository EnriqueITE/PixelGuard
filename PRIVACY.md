# PixelGuard Privacy Notice

## Summary
- PixelGuard only scans the HTML of messages you open locally in Thunderbird to flag tracking pixels, links, and external images. No telemetry or account data is collected.
- Settings such as whitelist entries, UI theme, and detection counters are saved using `browser.storage.local`; they never leave your device unless you enable Thunderbird Sync.

## Data PixelGuard Processes
- **Input:** The rendered HTML of the message currently displayed and basic sender metadata (e.g., From header domain) so detections can reference the origin.
- **Storage:** UI theme, debug toggle, whitelist domains, and detection counters are stored locally. PixelGuard does not store message content or detection artifacts once you close the tab.

## Third Parties
- PixelGuard does not contact any third-party services. It only inspects URLs already present in the email; remote resources are fetched by Thunderbird only if you explicitly allow remote content.

## Permissions Justification
- `messagesRead`, `messageDisplay`: Required to access the displayed message body and metadata for scanning.
- `tabs`: Used to map detections to the active tab and show the badge counter.
- `storage`: Saves local settings and counters.

## Contact
Email: hello@enriqueite.com
You can disable or remove PixelGuard anytime from Thunderbird Add-ons Manager.
