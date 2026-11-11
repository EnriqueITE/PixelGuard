# PixelGuard 0.2.0 — local validation

Use only a separate test profile and synthetic messages. Do not test against a personal inbox, copy a real Thunderbird profile into the repository, or add credentials to fixtures. No command in this guide publishes anything.

## Validation status

- Baseline: 25 scanner/lifecycle tests passed before the VirusTotal implementation.
- The full implementation suite now passes 73 tests. Validator evidence and warning classifications are recorded in [VALIDATION-0.2.0.md](VALIDATION-0.2.0.md).
- Authenticated VirusTotal requests require a key entered through the test profile's Settings UI. Simulated responses are not a live-service test.
- This local build has not been submitted to or approved by ATN.

| Check | Result |
| --- | --- |
| Full automated suite after implementation | Passed: 73 tests |
| Manifest/package checks and warning review | Thunderbird webext-linter 2.5.1: 0 findings. Mozilla addons-linter 10.15.0: 0 errors, 15 reviewed Firefox-specific warnings. |
| Thunderbird 115 isolated-profile run | Native smoke passed on 115.0 with the final XPI; interactive permission flow remains pending. |
| Installed Thunderbird isolated-profile run | Native smoke passed on 160.0 with the final XPI; interactive permission flow remains pending. |
| Real VirusTotal request and official report | Pending; requires UI-entered key |
| Package contents and SHA-256 | Passed: 28 files match source; SHA-256 `52f1c9d8499d8604c3352b5f0543e49588e60606956e61fb7afa309b6ebc1c87` |

## Automated checks

From the repository root in PowerShell:

```powershell
node --test --test-isolation=none scripts/*.test.js
git diff --check
powershell -ExecutionPolicy Bypass -File scripts/package.ps1
Get-FileHash -Algorithm SHA256 -LiteralPath .\dist\PixelGuard-0.2.0.xpi
python scripts/validate-package.py
```

The packaging script replaces its staging directory under `dist/unpacked`; check its resolved location before running it if the script or directory layout has changed. Preserve `dist/PixelGuard-0.1.30.xpi`. Check that the new XPI contains only runtime files and contains neither keys nor profiles/test artifacts. Generic Firefox validators may report Thunderbird-specific APIs or permissions incorrectly; classify each warning against the actual manifest and Thunderbird documentation, and do not silently ignore it.

## Native runtime evidence — 11 November 2026

The final XPI listed above was installed temporarily in fresh, headless Thunderbird 160.0 and 115.0 profiles. Thunderbird 115.0 was extracted from Mozilla's official Windows installer under ignored `dist/qa-tools`; the installed Thunderbird was not replaced. External HTTP(S) requests were routed to a closed loopback proxy. Only the local QA result/resource sink was reachable.

The production addon was installed unchanged. A separate temporary helper, using public APIs and the inventory module copied byte-for-byte from that XPI, exercised synthetic messages. These checks passed on both versions:

- The XPI installs and optional permissions are absent initially.
- The production content script and scanner initialize in the synthetic message, and exactly one tracking banner is visible. The probe only reads this state; it does not inject the detector to make the assertion pass.
- Native extension-page DOMParser collects the exact expected URLs, including separation of adjacent block text.
- The local sink receives no resource GETs from image, iframe, CSS background or `@import` fixtures while parsing and displaying mail with remote content blocked.
- A synthetic message opens in a normal tab and a standalone message window.
- `getFull`, `listAttachments` and `getAttachmentFile` return the expected MIME structure and 3-byte attachment.
- Native Web Crypto produces the known SHA-256 of `abc`.
- The production options page opens through the addon's own tab API; screenshots from 115.0 and 160.0 were inspected.

Evidence is local and not included in the XPI:

- `dist/runtime-qa/compat-fixed-tb160-injection-20261111-144305/result.json` and `options.png`
- `dist/runtime-qa/compat-fixed-tb115-injection-20261111-144245/result.json` and `options.png`

Both final-XPI runs completed, and their QA processes were closed. The preceding XPI (`e48f8c4625060b6f2fa7b1c5a4ffdbe185a4affdc232919bf0505914e21593f3`) failed the banner-injection assertion on 115.0, as recorded in `dist/runtime-qa/compat-old-tb115-injection-20261111-144304/result.json`. Earlier development attempts with driver startup, context or argument-normalization problems are not used as production verdicts. The successful runs above supersede earlier installation/inventory-only checks. Permission gestures and the complete UI flow remain unverified by this automation.

Replay requires Mozilla's `marionette_driver` package, locally installed under `dist/qa-tools/python`:

```powershell
python -m pip install --index-url https://pypi.org/simple --target dist/qa-tools/python marionette_driver==3.7.1
python scripts/thunderbird-smoke.py --binary 'C:\Program Files\Mozilla Thunderbird\thunderbird.exe' --label installed --helper --addon dist/PixelGuard-0.2.0.xpi
python scripts/thunderbird-smoke.py --binary '.\dist\qa-tools\tb115\extracted\core\thunderbird.exe' --label tb115 --helper --addon dist/PixelGuard-0.2.0.xpi
```

The driver uses privileged automation only to install/test addons inside its new profile. Neither that bridge nor the helper is shipped in PixelGuard, and the helper itself uses no Experiments. This smoke test does not establish permission-dialog acceptance/denial, the complete production popup flow, or a real VirusTotal request/report. Those remain separate checks below.

## Isolated Thunderbird setup

1. Use a separate test profile outside tracked source. The automated probe creates profiles under ignored `dist/runtime-qa`; never package or publish that directory. If creating a profile manually, open Thunderbird's Profile Manager with the supported `-P` switch and create a new profile. Do not repurpose your normal profile.
2. Run each target Thunderbird version with its own test profile. Never open the same profile with two versions at once or downgrade a profile used by a newer version.
3. Keep remote message content blocked. Use local synthetic `.eml` files or a local test folder rather than a personal account.
4. Load the extension temporarily through Tools → Add-ons and Themes → Debug Add-ons → Load Temporary Add-on, choosing the workspace manifest or the packaged XPI. Record which artifact was loaded.
5. Record the actual Thunderbird version and the package hash for every run. Test version 115 as well as the installed release; an installed release does not prove minimum-version compatibility.

## Synthetic messages

Prepare at least these fixtures locally, without private content:

- HTML with a normal HTTP(S) anchor, a tracking-style anchor, a full URL in text, and a 1×1 remote image using an `.invalid` hostname.
- Plain-text mail with two HTTP(S) links and trailing punctuation; repeated links should not create duplicate inventory rows.
- Multipart mail with a plain/HTML alternative, a small text attachment and a nested `.eml` attachment. Nested attachment bodies should not be treated as the outer message's link inventory.
- Empty attachment, small attachment with a known SHA-256, attachment exactly at the limit, and attachment above 50 MiB. Avoid sending boundary-size fixtures to a mail service; use a local test fixture.
- Where supported, an unavailable/deleted attachment and an encrypted message that cannot currently be decrypted.

Do not send `.invalid` fixture URLs to VirusTotal just to exercise the service. Mock those responses. For one real lookup, deliberately choose a public, non-sensitive domain or URL and use a key whose terms cover the test.

## Functional and privacy checks

1. **Default/off:** opening mail, popup and Settings produces no VirusTotal request. Existing tracking banners, counters and classifications continue to work.
2. **Activation:** explain the data flow before consent; permissions are optional. Denial leaves lookups disabled. Saving the key produces no lookup and clears the visible password field. Restart the test profile and verify the saved state without displaying the key.
3. **Links:** both ordinary and tracking links appear. A domain lookup sends only the selected host. A full URL is fully visible in a scrollable preview; cancelling sends nothing, confirming sends only that selected address.
4. **Attachments:** inspect the outgoing request with sensitive headers redacted. It contains the SHA-256, not the file content or filename. The known-hash fixture matches an independent local hash. Oversized files are rejected before their bytes are loaded.
5. **Reports:** the summary identifies the lookup time, not an analysis date. The official report opens as an ordinary remote page. Test the popup from both a normal window and a standalone message window, including a case with no normal window available.
6. **Lifecycle:** change/close the message while hashing or awaiting a response; old results must not appear for another message. Repeated clicks must not create duplicate requests. Disabling, deleting/replacing the key or revoking permissions cancels pending work and clears in-memory lookup state.
7. **Failure cases:** simulate unauthorized/forbidden responses, no report, 429, offline, timeout, invalid JSON and a hostile returned report URL. They must produce clear local errors without retries, arbitrary navigation or sensitive logging.
8. **Boundaries:** message content scripts cannot invoke privileged lookup/configuration commands. General state, exports and logs must not reveal the API key or report token. Lookup results must not alter tracking badges or counters.
9. **Minimum version:** confirm only public APIs are used and runtime paths work on 115. No Experiments, privileged APIs or later-version options should be introduced as a fallback.

Keep network evidence local and redact `x-apikey`, full private URLs and temporary report URLs before sharing a screenshot or log. A successful API request does not establish compatibility of the separate official report page; verify both. Once done, remove the key from the test profile and close report tabs. Do not archive or distribute the profile as part of the test package.

## Record the result

Update the status table with passed/failed/pending, actual versions, test counts and SHA-256. Record unresolved limitations explicitly. A successful local validator run is not store approval. Future submission requires the complete privacy text, readable source and reviewer instructions described in [REVIEWER-NOTES.md](REVIEWER-NOTES.md).
