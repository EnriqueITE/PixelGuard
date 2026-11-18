# Message banner regression in PixelGuard 0.2.0

On November 18, 2026, we compared archived PixelGuard packages on the Windows release of Thunderbird 153.7.0esr. Each run used a fresh profile and the same synthetic messages. The ordinary newsletter contained a 400 × 200 external image and had zero tracking alerts.

| Package | What happened when opening the ordinary newsletter |
| --- | --- |
| 0.1.29 | The background reported the external image. The message content script did not initialize and no banner appeared. |
| 0.1.30 | The result matched 0.1.29 on this ESR build. Issue 8 reports a banner with 0.1.30 on another installation. |
| 0.2.0 | The content script inserted a dark, 119 CSS-pixel banner into a 447-pixel reading pane. Its bottom edge stayed at 119 pixels after scrolling 500 pixels. |
| 0.2.1 | Opening the newsletter leaves the message untouched, including when inline notices are enabled. The toolbar indicator and the panel still report the external image. |

The old banner was triggered by ordinary external images as well as possible trackers. It used a hard-coded near-black background (`#0b0d0f`) and `position: sticky`. The change to message-script registration in 0.2.0 made the banner run on configurations where earlier registration options had prevented injection. The French screenshot shows the PixelGuard banner with its findings. Whether the black box reported on every message on Windows 10 has this same cause is still unconfirmed. [Issue 8](https://github.com/EnriqueITE/PixelGuard/issues/8) · [Issue 9](https://github.com/EnriqueITE/PixelGuard/issues/9) · [Issue 10](https://github.com/EnriqueITE/PixelGuard/issues/10)

## Verify the fix

1. Install the candidate in a fresh profile, or upgrade a profile that has settings from 0.2.0. Open a newsletter with tracking pixels and open the PixelGuard panel. The panel and toolbar indicator should report the findings while the message remains clear.
2. Enable the compact message notice in PixelGuard Settings. A message with a tracking alert should show a single row. Scroll past it, then return to the top and dismiss it. It should stay dismissed when the same message is rescanned.
3. Open a newsletter with only a normal external image. The image should appear in the panel and the message should have no notice. Turn the preference off with the tracking message still open and verify that its notice disappears. Repeat in a standalone message window.

The [native smoke test](../scripts/thunderbird-smoke.py) checks native tabs, standalone windows, banner geometry, badge values and the findings used by the panel. Run it with `--helper --binary <thunderbird.exe> --addon dist/PixelGuard-0.2.1.xpi`. Add `--banner-mode compare` when recording a historical package. Results are written to `dist/runtime-qa/`.

## Results for the local candidate

All 19 native checks passed on each of Thunderbird 115.0, 153.7.0esr and 160.0. In all three, the optional notice measured 28 CSS pixels in both a tab and a standalone window and scrolled completely out of view. Turning the preference off removed it in open messages. The ordinary image still appeared in the panel data and the toolbar badge in every tested setting. The local resource sink recorded zero requests for message resources.

For the candidate with the language selector, add `--widget-languages` to the native smoke command. This also exercises French, German and Italian in the packaged settings and popup, reopens the pages and restores the Thunderbird language.

All 87 Node tests passed. Thunderbird's `webext-linter` reported zero errors, holds, warnings or informational findings. Package validation matched all 29 archived files against source. The localized `PixelGuard-0.2.1.xpi` has SHA-256 `0fe68db83222074bbe4c1420a3f736ae9595cb0eea78ffdc0b49b7e0253d4a8c`.
