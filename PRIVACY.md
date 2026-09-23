# PixelGuard Privacy Notice

## Summary
- PixelGuard only scans the HTML of messages you open locally in Thunderbird to flag tracking pixels, links, and external images. It never interferes with remote requests or transmits message data elsewhere, and no telemetry or account data is collected.
- Settings such as the debug toggle and detection counters are saved using `browser.storage.local`; they never leave your device unless you enable Thunderbird Sync.

## Data PixelGuard Processes
- **Input:** The rendered HTML of the message currently displayed and basic sender metadata (e.g., From header domain) so detections can reference the origin.
- **Storage:** Debug toggle and detection counters are stored locally. PixelGuard does not store message content or detection artifacts once you close the tab.

## Third Parties
- PixelGuard does not contact any third-party services. It only inspects URLs already present in the email; remote resources are fetched by Thunderbird only if you explicitly allow remote content.

## Permissions Justification
- `messagesRead`: Required to access the displayed message body and metadata for scanning.
- `messagesModify`: Required by Thunderbird to register PixelGuard's message-display scripts and show the inline banner. PixelGuard does not edit or save changes to email messages.
- `storage`: Saves local settings and counters.

## Contact
Email: hello@enriqueite.com
You can disable or remove PixelGuard anytime from Thunderbird Add-ons Manager.
