# PixelGuard 0.2.0 — notes for Thunderbird reviewers

This is a preparation document for a future submission. The current work and XPI are local; this document does not record an ATN submission or approval.

## Change being reviewed

PixelGuard continues to report possible email tracking locally. Version 0.2.0 adds an optional, user-initiated VirusTotal context lookup for links and attachments of the displayed message. Users bring their own VirusTotal API key. The feature is off by default and is independent of tracking detection, badges and counters.

The popup lists message links, including ordinary links without tracking signals, and attachment metadata. A domain lookup is the default link action. A full-URL lookup requires a preview and affirmative confirmation. An attachment lookup hashes at most 50 MiB locally and submits only its SHA-256. The addon does not scan arbitrary local files, visit link destinations, unpack attachments or submit new analyses.

The popup's document-and-magnifier icon is an original, locally bundled SVG, not the VirusTotal logo. The text identifies the third-party service without claiming endorsement, sponsorship or affiliation. No permission to redistribute an official VirusTotal brand asset has been assumed. This follows the plain-text API references described in [Google's brand guidance](https://about.google/brand-resource-center/guidance/) and [product co-branding guidance](https://partnermarketinghub.withgoogle.com/brands/google/use-cases/product-co-branding/), checked on 2026-11-11.

## APIs and executable code

- Manifest V2, minimum Thunderbird 115; only built-in WebExtension APIs are used.
- Message content/attachments use `messages.getFull`, `messages.listAttachments` and `messages.getAttachmentFile`. Hashing uses Web Crypto.
- The background requests JSON from `GET https://www.virustotal.com/api/v3/widget/url`, using `x-apikey`. There are no file or URL submission POSTs.
- The returned report URL is checked for its HTTPS origin and official widget path before navigation. A normal Thunderbird window receives a content tab. If no normal window is available, `windows.openDefaultBrowser` opens the report externally.
- The report is a normal remote web page. No iframe, `srcdoc`, remote script, fetched HTML injection, content-script injection on VirusTotal, or extension/API bridge is added. The extension's CSP is not weakened.
- No `experiment_apis`, Experiments, native messaging, privileged Thunderbird internals, or additional third-party JavaScript libraries are required.
- Minimum-version compatibility must be tested. In particular, the implementation must not depend on newer `getFull` decode/decrypt options, `listInlineTextParts`, or `tabs.create`'s `linkHandler` option.

## Permission justification

Existing required permissions remain:

| Permission | Purpose |
| --- | --- |
| `messagesRead` | Read the displayed message, list its attachments, and read a selected attachment to hash locally. |
| `messagesModify` | Register message-display scripts and present the existing banner; no stored message modification. |
| `storage` | Store preferences, counters and the user's optional API key locally. |

The new permissions are optional and requested from the user's explicit activation action in Settings:

| Permission | Purpose |
| --- | --- |
| `sensitiveDataUpload` | Disclose/authorize sharing the user-selected indicator with the fixed third-party service. |
| `https://www.virustotal.com/*` | Authenticate the manual lookup against the fixed HTTPS API endpoint. |

No `<all_urls>`, `tabs`, cookies or native permission is added. Revocation disables the integration and invalidates pending work. Do not infer permission necessity solely from the similarly named API: creating a content tab does not require the broad `tabs` permission.

## Data flow and boundaries

The activation text describes domains, full URLs, file hashes, API authentication and local key storage. Saving a key, opening the popup or opening a message does not cause a VirusTotal request. Full URLs require a separate exact-address confirmation. No message body or attachment bytes are sent to VirusTotal.

New privileged runtime requests are accepted only from the addon options/popup pages, not from its message-display scripts. Queries resolve inventory item IDs against the current tab/message session, rather than accepting arbitrary caller-supplied network destinations or attachment paths. Message changes, tab closure, permission removal and key changes invalidate old work.

The key is held separately from general settings, is not synchronized, and is not returned through message-script state, exports or logs. Local extension storage is not an encrypted vault. Results and temporary bearer-like report URLs remain in memory and are cleared when the session is invalidated. Already-open reports and browser history are independent of that cleanup.

Local quota timestamps survive restarts, without retaining the queried indicators. PixelGuard applies a conservative four-per-minute and 500-per-rolling-24-hours cap; other applications using the same key can consume the account quota too, so server-side quota errors are also handled.

## VirusTotal conditions

This follows the documented [VT Augment individual-key model](https://docs.virustotal.com/reference/render-widget) and displays context from its [widget endpoint](https://docs.virustotal.com/reference/widgeturl). A public key can power the basic widget, subject to its account limits and terms. The [public API conditions](https://docs.virustotal.com/reference/public-vs-premium-api) specify 4 requests/minute, 500/day and restrictions on commercial products and business workflows. Neither BYOK nor this integration waives those restrictions. There is no developer-wide API key or resale of VirusTotal results. The project does not claim endorsement or legal/store pre-approval.

## Reproduction and submission preparation

Follow [LOCAL-TESTING.md](LOCAL-TESTING.md) using an isolated profile and synthetic mail. The core addon works without a VirusTotal account. For authenticated checks, enter a suitable test key through Settings; never include credentials in source, packages, reports or public review comments. If reviewers require a different authenticated testing arrangement, settle it privately before submission in a way consistent with the service's terms.

Before any future submission:

1. Record the exact build, hash, automated results and real Thunderbird/API checks. An unperformed check must remain marked pending.
2. Validate the manifest/package. Resolve genuine problems; document tooling warnings individually, including Thunderbird-specific permissions that a generic Firefox linter may not recognize.
3. Put the complete text of `PRIVACY.md` in ATN's privacy field, not only a link. Update the listing to describe optional third-party lookups, accounts, quotas and limitations.
4. Supply readable source and reproducible packaging instructions; the XPI must match that source.
5. Expect manual review because the addon accesses messages. Passing local tests or a validator is not a guarantee of acceptance.

References: [ATN policy](https://thunderbird.github.io/atn-review-policy/), [reviewer guide](https://addons-reviewer-guide.thunderbird.net/add-on-review-guide), [messages API](https://webextension-api.thunderbird.net/en/mv2/messages.html), [permissions API](https://webextension-api.thunderbird.net/en/mv2/permissions.html), [windows API](https://webextension-api.thunderbird.net/en/mv2/windows.html).
