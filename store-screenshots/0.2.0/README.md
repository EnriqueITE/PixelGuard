# PixelGuard 0.2.0 store images

Ten PNG images, each **1280 × 960**, are provided in English (`en/`) and Spanish (`es/`). Use the files in the matching language directory for the new store listing. Images in the parent `store-screenshots/` directory belong to an earlier version.

These are screenshots of the **actual extension HTML, CSS and JavaScript rendered in a local browser**, surrounded by an explanatory frame. Extension API responses are simulated with synthetic messages, example.com domains and an example PDF attachment. Each image is labelled as illustrative. They are not screenshots of a connected mailbox or evidence of a live VirusTotal lookup, and no VirusTotal verdict or detection ratio is fabricated. No real API key is present; the saved-key example supplies only the public configuration flags expected by the UI.

The Spanish images preserve the current product's language behavior: VirusTotal controls are translated, while some older tracking and general-settings labels remain in English.

| Image | English caption | Leyenda en español |
| --- | --- | --- |
| `01-tracking-overview.png` | Review possible tracking pixels, external images and tracking links. | Revisa posibles píxeles de rastreo, imágenes externas y enlaces de seguimiento. |
| `02-virustotal-links-and-attachments.png` | Optional, manual lookups for link domains and attachment hashes. | Consultas opcionales y manuales de dominios y huellas de adjuntos. |
| `03-full-url-confirmation.png` | Review the exact URL before sharing it with VirusTotal. | Revisa la URL exacta antes de compartirla con VirusTotal. |
| `04-optional-setup.png` | Review the data-sharing explanation before enabling VirusTotal. | Revisa qué datos se envían antes de activar VirusTotal. |
| `05-saved-key.png` | Keep, replace or delete a saved key without displaying it. | Conserva, reemplaza o elimina la clave guardada sin mostrarla. |

## Reproduce

From the repository root on Windows with Microsoft Edge installed:

```powershell
python scripts/generate-store-screenshots.py
```

Pass `--browser PATH` for a compatible Chromium browser installed elsewhere. The script copies runtime files to ignored `dist/store-preview`, generates mock API responses there, and launches a hidden browser with a separate disposable profile for each image. A closed loopback proxy prevents external HTTP(S) requests. All mock actions except local state/configuration/inventory reads fail deliberately, so this fixture cannot perform an authenticated lookup or upload a file.

The generation script, screenshots, browser profiles and fixtures are not included in the XPI. Review the resulting images after any UI or translation change before reusing them for publication.
