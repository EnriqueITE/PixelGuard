# PixelGuard Privacy Notice

This notice describes PixelGuard 0.2.0, including its optional VirusTotal integration.

## Local Tracking Analysis

PixelGuard reads the currently displayed message's HTML and basic sender metadata, such as the From header domain, to identify possible tracking pixels, tracking links and external images. Its tracking analysis is performed locally. PixelGuard does not change stored messages or override Thunderbird's remote-content controls.

For the optional lookup panel, PixelGuard also reads the displayed message's HTML or plain text to list HTTP(S) links and obtains attachment names and sizes. It does not visit those links or follow their redirects. Selecting an attachment for a lookup reads its bytes through Thunderbird and calculates a SHA-256 hash locally. Thunderbird may need to retrieve message or attachment data from the user's mail service as part of its normal operation. PixelGuard does not execute or unpack the attachment. The initial attachment size limit is 50 MiB.

## Optional Requests to VirusTotal

The integration is disabled by default. Activating it requires entering your own VirusTotal API key, acknowledging the data-sharing explanation and granting optional permissions. Opening a message, opening the popup or saving the key does not cause a VirusTotal lookup.

Only after you request a lookup does PixelGuard send the following directly to VirusTotal over HTTPS:

- The selected domain, or the exact full URL shown in a preview that you explicitly confirm.
- For an attachment lookup, its SHA-256 hash instead of its contents or filename.
- Your VirusTotal API key in an authentication header.

VirusTotal also receives ordinary connection information, such as your IP address. A hash does not reveal the file's bytes, but it can identify a file already known to VirusTotal. A URL can contain personal information, access tokens or other private identifiers. Prefer a domain lookup when you do not want to disclose the complete address.

PixelGuard requests existing context using the VT Augment widget API. It does not upload message bodies or attachment bytes, submit URLs for new scans, or request reanalysis. It has no developer-operated proxy or telemetry service. VirusTotal's results provide optional context and do not change PixelGuard's tracking classifications, alerts or counters.

Opening the official report loads a VirusTotal web page in a separate Thunderbird tab or your default browser. That page is served by VirusTotal, with its own cookies, requests, retention and account policies; actions you take there are outside PixelGuard's lookup flow. Review the [VirusTotal privacy information](https://docs.virustotal.com/docs/privacy-policy), [applicable terms](https://docs.virustotal.com/docs/terms-of-service), and [API conditions](https://docs.virustotal.com/reference/public-vs-premium-api).

## Storage and Retention

- Preferences and detection counters are saved in Thunderbird's extension-local storage. PixelGuard does not synchronize them or transmit them to its developer.
- Request timestamps are stored locally to enforce at most four API requests per minute and 500 in a rolling 24-hour period across restarts. They contain no domains, URLs, hashes or file names. Entries older than 24 hours are discarded when reserving the next request.
- If supplied, the VirusTotal API key is stored separately from the general settings in `browser.storage.local`. This storage is not an encrypted credential vault. Access to your Thunderbird profile, its backups or your device may expose locally stored data. PixelGuard does not include the key in settings exports, API responses to message scripts, logs or its extension package.
- VirusTotal inventory, lookup results and temporary report URLs are kept in memory for the message session, not saved as a lookup history. They are cleared when that message changes or its tab closes, or when the integration is disabled or the key changes. Pending work cannot restore results to an invalidated session.
- Previously opened VirusTotal tabs remain open independently. Clearing PixelGuard's memory does not revoke a temporary report URL or erase browser history, console output or data already received by VirusTotal.
- Debug mode is disabled by default. When enabled, the existing tracking scanner can log findings, including full message URLs, to Thunderbird's local console. VirusTotal keys and temporary report tokens are not logged. Console retention and exports are controlled by Thunderbird and the user.

## Your Controls

In PixelGuard Settings you can disable VirusTotal, replace the key or delete it. Disabling stops new lookups and cancels pending requests; deleting also removes the saved key. Revoking the optional permissions prevents further lookups. Data already transmitted cannot be withdrawn by disabling the integration. You can disable or remove PixelGuard from Thunderbird's Add-ons Manager.

## Permission Purposes

- `messagesRead`: access the displayed message and metadata, list its attachments and read a selected attachment for local hashing.
- `messagesModify`: register PixelGuard's message-display scripts and show its inline banner. PixelGuard does not edit or save changes to email messages.
- `storage`: save local preferences, counters and the optional API key.
- Optional `sensitiveDataUpload`: disclose and authorize the selected indicator sent to the third-party lookup service.
- Optional `https://www.virustotal.com/*`: make the authenticated HTTPS request to the fixed VirusTotal endpoint.

## Contact

Email: hello@enriqueite.com
