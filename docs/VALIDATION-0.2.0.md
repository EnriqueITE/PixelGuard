# Local validation — PixelGuard 0.2.0

Date: 2026-11-11. This record covers the 0.2.0 source publication candidate. Store submission and authenticated VirusTotal queries were not performed by these checks.

## Automated checks

- 72 Node tests passed: the original 25 scanner/lifecycle checks, plus inventory, service, permission, consent, UI and package-policy checks. Saved-key feedback is checked after saving, reopening, disabling and deleting, including failed saves and denied permissions.
- `git diff --check` passed. Git's CRLF conversion notices are working-tree line-ending advisories, not failing checks.
- XPI validation compares every archived file byte-for-byte with the runtime source allowlist, rejects duplicate paths, validates JSON and tests archive integrity. Tests, profiles, dependencies and QA tools are excluded.
- The prior `PixelGuard-0.1.30.xpi` is preserved.

## Thunderbird validator

Official `thunderbird/webext-linter` 2.5.1, source commit `7802ee765fc3c86fb5baec5833a47092f6ef8d00`, using Thunderbird 159.0.1 release-MV2 schemas:

**0 errors, 0 holds, 0 warnings, 0 informational findings.**

The review includes minimum-version API, manifest, permission, Experiment and remote-code checks. CDN lookup was explicitly disabled; no extension source or package was uploaded. Dependencies and schema downloads are confined to local QA tooling under ignored `dist`.

The tool's dependency install emitted a Node engine advisory for `ini@7` (Node >=24.15 versus the host's 24.11); the validator completed successfully with exit code 0. This is not store approval.

Local report: `dist/qa-tools/thunderbird-linter-report.json`.

## Generic Mozilla validator warnings

`addons-linter` 10.15.0: **0 errors, 15 warnings**, all reviewed below. This tool targets Firefox, not Thunderbird.

| Count | Warning | Assessment |
| --- | --- | --- |
| 2 | `messagesRead`, `messagesModify` permissions | Public Thunderbird permissions; existing functionality requires them. |
| 1 | Optional `sensitiveDataUpload` | Public Thunderbird permission available since 115; deliberately optional. |
| 10 | `messageDisplayScripts.register`, `messageDisplay.onMessageDisplayed`, `messageDisplay.getDisplayedMessage`, `messages.getFull`, `messageDisplay.onMessagesDisplayed` | Public Thunderbird APIs unsupported by Firefox. Repeated references are separate warnings. |
| 1 | Missing Firefox `data_collection_permissions` | The warning describes Firefox submission requirements. Thunderbird requires explicit consent and `sensitiveDataUpload`; both are implemented. No false `none` declaration was added. |
| 1 | `permissions.request` on Firefox for Android 115 | PixelGuard targets desktop Thunderbird, whose supported permission API is used. |

Local report: `dist/addons-linter-0.2.0.json`. The Thunderbird-specific validator reports no findings for these items.

## Package

- File: `dist/PixelGuard-0.2.0.xpi`
- 28 runtime files, 759089 bytes.
- SHA-256: `e48f8c4625060b6f2fa7b1c5a4ffdbe185a4affdc232919bf0505914e21593f3`
- Exact source comparison: `dist/package-validation-0.2.0.json`.

## Runtime and remaining verification

The final XPI listed above was temporarily installed in fresh, network-isolated profiles on **Thunderbird 115.0 and 160.0**. Both runs passed initial permission checks (no optional permissions granted), native message opening in tabs and standalone windows, `getFull`, `listAttachments`, `getAttachmentFile`, and the SHA-256 of a synthetic `abc` attachment. The production inventory parser was exercised inside a separate test helper using public APIs; adjacent HTML text nodes remain separated. A local resource sink observed no image, iframe, CSS background or stylesheet-import requests during parsing and message display.

The final XPI includes saved-key feedback in Settings, a more prominent popup section with an original document-and-magnifier icon, and translated descriptions. The full automated suite, package validators and native Thunderbird smoke tests were rerun. The collapsed and expanded popup layouts were also visually checked in a local Edge preview with synthetic data and simulated extension APIs. The collapsed preview made no VT-related calls; expanding only requested configuration and inventory, with no query. Store screenshots use synthetic data, not live VirusTotal results; they and all QA tooling are excluded from the XPI.

Evidence under ignored `dist/runtime-qa`:

- `release-final-tb115-20261111-141948/result.json` and `options.png`
- `release-final-installed-20261111-141949/result.json` and `options.png`

These are targeted runtime smoke tests, not a complete end-to-end UI or remote-service test. The QA helper and automation use a separate profile and are excluded from the release XPI. The options page was visually inspected on both versions, and no QA processes remained after the checks. Real permission-prompt gestures, activation and the complete popup-to-VirusTotal flow were not verified by this automation. Reproduction instructions are in `LOCAL-TESTING.md`.

Authenticated VirusTotal queries and the resulting live official report remain pending: no real API key was supplied or used. Enter a suitable key in the test profile's Settings UI to perform that check; never put it in source, a test fixture or this document. Unit tests use simulated responses and cannot establish live-service behavior or account licensing.
