# PixelGuard 0.2.0 — release notes

Release text for the 0.2.0 source and package. Publishing the source to GitHub does not submit this version to the Thunderbird store or imply store approval. Ready-to-paste listing fields are in [STORE-LISTING-0.2.0.md](STORE-LISTING-0.2.0.md).

## Español

- Nueva consulta opcional a VirusTotal con tu propia API key, desactivada inicialmente.
- Los ajustes muestran «Clave guardada» sin revelar la clave y aclaran cómo reemplazarla o conservarla.
- Acceso a VirusTotal más visible en el panel, con un icono propio y una descripción de las consultas manuales de enlaces y adjuntos.
- Consulta dominios de enlaces del correo y, tras confirmar la dirección que se compartirá, URLs completas. También aparecen los enlaces sin señales de rastreo.
- Consulta informes existentes de adjuntos mediante su huella SHA-256 calculada localmente, sin subir el archivo. Límite inicial: 50 MiB por adjunto.
- Accede al informe oficial de VirusTotal desde una pestaña independiente. Las consultas son manuales y no alteran las alertas de rastreo de PixelGuard.
- Mejoras de estabilidad: se evitan análisis repetidos del aviso, recuentos duplicados y resultados antiguos al cambiar de mensaje. Mejora la detección de píxeles en fondos CSS y la limpieza de datos temporales.
- Corregido el registro del aviso en los correos para usar únicamente opciones compatibles con Thunderbird 115.

La integración requiere una cuenta y una clave de VirusTotal, permisos opcionales y aceptación del envío de los datos seleccionados. Se aplican los límites y condiciones de tu cuenta. «Sin informe» o cero detecciones no garantizan que un enlace o archivo sea seguro. PixelGuard no solicita nuevos análisis ni envía el correo o el contenido de los adjuntos.

## English

- New optional VirusTotal lookups using your own API key, disabled by default.
- Settings show when a key is saved without revealing it, and explain how to replace or keep it.
- More prominent VirusTotal access in the popup, with an original icon and a description of manual link and attachment checks.
- Look up message-link domains and, after confirming the exact address to share, complete URLs. Ordinary links without tracking signals are included.
- Look up existing attachment reports using a locally calculated SHA-256 hash, without uploading the file. Initial limit: 50 MiB per attachment.
- Open the official VirusTotal report in a separate tab. Lookups are manual and do not change PixelGuard's tracking alerts.
- Stability improvements prevent repeated banner analysis, duplicate counts and stale results when switching messages. Improved CSS-background pixel detection and temporary-data cleanup.
- Fixed message-banner registration to use only options supported by Thunderbird 115.

The integration requires a VirusTotal account/key, optional permissions and consent to share the selected data. Your account's limits and terms apply. No report or zero detections does not guarantee that a link or file is safe. PixelGuard does not request new analyses or submit message bodies or attachment contents.
