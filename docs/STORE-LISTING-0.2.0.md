# PixelGuard 0.2.0 — store submission text

Copy the text under the relevant language and field. Publishing this repository or building the XPI does not submit the extension to Thunderbird Add-ons (ATN).

## English (US): short description

225 characters; ATN field limit: 250.

Detect tracking pixels, tracking links and external images in Thunderbird. Optional manual VirusTotal checks send selected domains, URLs or attachment hashes using your own API key. No files are uploaded. Account terms apply.

## English (US): detailed description

PixelGuard helps you understand possible tracking in the email you are reading. It reports probable tracking pixels, suspicious tracking links and external images, with a brief explanation of the evidence behind each finding.

Tracking analysis runs locally. Thunderbird continues to control whether remote content is loaded; PixelGuard does not block requests, change stored messages or replace an antivirus.

Optional VirusTotal lookups

The message panel also offers manual VirusTotal lookups for links and attachments. This feature is disabled by default and requires your own VirusTotal account and API key, your consent and optional permissions.

- Look up the domain of a message link, including ordinary links without tracking signals.
- To look up a complete URL, first review and confirm the exact address that will be shared.
- Look up an attachment by its SHA-256 hash, calculated on your device. The maximum attachment size is 50 MiB. PixelGuard does not upload, execute or unpack the file.
- View available results and open the official VirusTotal report in a separate Thunderbird tab, or in your default browser when no normal Thunderbird window is available.

Opening an email, opening the panel or saving your key does not start a VirusTotal lookup. Only a lookup you request sends the chosen domain, URL or file hash and your API key to VirusTotal. URLs can contain private information, and a hash can identify a file already known to the service. VirusTotal also receives ordinary connection information, such as your IP address.

Your key is stored locally, without synchronization. Local storage is not an encrypted credential vault. Settings let you disable the integration, replace the key or delete it. The complete privacy policy explains the data flow, storage and controls.

VirusTotal's account limits and terms apply, including restrictions on the public API. Your own key does not waive those restrictions. PixelGuard requests existing information; it does not submit files or URLs for new scans or request reanalysis. Neither a missing report nor zero detections guarantees safety. VirusTotal results do not change PixelGuard's tracking alerts or counters.

The VirusTotal interface is translated into English, Spanish, German, French, Greek, Russian and Simplified Chinese. Some older tracking and general-settings labels remain in English. Requires Thunderbird 115 or later. PixelGuard is an independent project and does not claim endorsement by VirusTotal.

## Español: descripción breve

248 caracteres; límite del campo de ATN: 250.

Detecta píxeles de rastreo, enlaces e imágenes externas en Thunderbird. Las consultas manuales opcionales a VirusTotal envían dominios, URLs o huellas de adjuntos con tu propia API key. No se suben archivos. Se aplican las condiciones de tu cuenta.

## Español: descripción detallada

PixelGuard te ayuda a reconocer posibles rastreadores en el correo que estás leyendo. Señala probables píxeles de rastreo, enlaces con indicios de seguimiento e imágenes externas, y explica brevemente las señales que ha encontrado.

El análisis de rastreo se realiza en tu equipo. Thunderbird sigue controlando si se carga el contenido remoto: PixelGuard no bloquea peticiones, modifica los mensajes guardados ni sustituye a un antivirus.

Consultas opcionales a VirusTotal

El panel del mensaje también permite consultar manualmente enlaces y adjuntos en VirusTotal. Esta función viene desactivada y requiere tu propia cuenta y API key de VirusTotal, tu consentimiento y permisos opcionales.

- Consulta el dominio de un enlace del correo, incluidos enlaces normales sin señales de rastreo.
- Para consultar una URL completa, revisa y confirma primero la dirección exacta que vas a compartir.
- Consulta un adjunto mediante su huella SHA-256, calculada en tu equipo. El límite por adjunto es de 50 MiB. PixelGuard no sube, ejecuta ni descomprime el archivo.
- Consulta los resultados disponibles y abre el informe oficial de VirusTotal en una pestaña independiente de Thunderbird, o en tu navegador predeterminado si no hay una ventana normal de Thunderbird disponible.

Abrir un correo, abrir el panel o guardar la clave no inicia ninguna consulta a VirusTotal. Solo una consulta que solicites envía el dominio, la URL o la huella seleccionados y tu API key a VirusTotal. Una URL puede contener información privada y una huella puede identificar un archivo conocido por el servicio. VirusTotal también recibe información habitual de conexión, como tu dirección IP.

La clave se guarda localmente, sin sincronización. Ese almacenamiento no es una caja fuerte cifrada. Desde los ajustes puedes desactivar la integración, reemplazar la clave o eliminarla. La política de privacidad completa explica los datos compartidos, su almacenamiento y tus controles.

Se aplican los límites y las condiciones de tu cuenta de VirusTotal, incluidas las restricciones de la API pública. Utilizar tu propia clave no elimina esas restricciones. PixelGuard consulta información existente: no envía archivos o URLs para nuevos análisis ni solicita reanálisis. La ausencia de un informe o cero detecciones no garantizan que algo sea seguro. Los resultados de VirusTotal no cambian las alertas ni los contadores de rastreo de PixelGuard.

La interfaz de VirusTotal está traducida al español, inglés, alemán, francés, griego, ruso y chino simplificado. Algunos textos antiguos de detección y ajustes generales siguen en inglés. Requiere Thunderbird 115 o posterior. PixelGuard es un proyecto independiente y no afirma contar con el respaldo de VirusTotal.

## English (US): version 0.2.0 release notes

- Added optional, manual VirusTotal lookups using your own API key. The integration is disabled by default.
- Look up link domains, confirmed full URLs and locally calculated attachment hashes, without uploading files. Attachment limit: 50 MiB.
- Open the official VirusTotal report from a more visible section in the message panel.
- Settings clearly show when a key is saved, without displaying the key, and allow replacing or deleting it.
- Improved stability when switching messages, closing the tracking banner and rescanning. Prevented duplicate counts and improved detection of tiny CSS-background images.
- Fixed tracking-banner registration using options compatible with Thunderbird 115.

VirusTotal account terms and limits apply. Neither a missing report nor zero detections guarantees safety. All lookups are optional and leave PixelGuard's tracking detection independent.

## Español: notas de la versión 0.2.0

- Nuevas consultas manuales y opcionales a VirusTotal con tu propia API key. La integración viene desactivada.
- Consulta dominios, URLs completas tras confirmarlas y huellas de adjuntos calculadas localmente, sin subir los archivos. Límite por adjunto: 50 MiB.
- Abre el informe oficial de VirusTotal desde una sección más visible del panel del mensaje.
- Los ajustes indican cuándo hay una clave guardada, sin mostrarla, y permiten reemplazarla o eliminarla.
- Mejoras de estabilidad al cambiar de mensaje, cerrar el aviso de rastreo y repetir el análisis. Se evitan recuentos duplicados y mejora la detección de imágenes diminutas en fondos CSS.
- Corregido el registro del aviso de rastreo con opciones compatibles con Thunderbird 115.

Se aplican los límites y las condiciones de la cuenta de VirusTotal. La ausencia de un informe o cero detecciones no garantizan seguridad. Las consultas son opcionales e independientes de la detección de rastreo de PixelGuard.

## English: notes to reviewers

PixelGuard 0.2.0 adds optional VirusTotal context lookups while retaining local tracking detection. It uses only public Thunderbird WebExtension APIs, with a minimum version of 115. There are no Experiments, native helpers, remote scripts, embedded remote HTML or changes to the default extension CSP.

VirusTotal is disabled by default. Activation requires a user-provided key, an explicit data-sharing acknowledgement and the optional permissions sensitiveDataUpload and https://www.virustotal.com/*. Opening mail or the popup and saving a key make no VirusTotal request. Each lookup is manual. Domain lookup is the default link action; sharing a full URL requires an exact-address preview and confirmation. An attachment lookup calculates SHA-256 locally with a 50 MiB limit; only the hash is sent, never the attachment bytes.

The background uses GET /api/v3/widget/url with the user's key. It validates the returned report URL before opening the official report as a separate web page. It does not submit new scans or reanalyses, and does not use VirusTotal results to drive PixelGuard detections.

The key is stored in extension-local storage and is not returned to message scripts or logged. Users can disable the integration and replace or delete the key. Permission revocation and message changes invalidate pending work and cached results.

The XPI contains readable source. Packaging instructions, verification results and the exact artifact hash are in the supplied repository's scripts/package.ps1, docs/LOCAL-TESTING.md and docs/VALIDATION-0.2.0.md. Detailed API, permission and testing notes are in docs/REVIEWER-NOTES.md. Reported automated and isolated-profile checks do not imply an authenticated live VirusTotal test; consult the validation record for outstanding checks.

The core feature can be reviewed without a VirusTotal account. Authenticated tests require a suitable key entered through Settings, subject to VirusTotal's account terms. No credential is included in the package or public repository. If an additional testing arrangement is required, please request it privately. Store screenshots use synthetic demonstration data and do not document live VirusTotal verdicts.

## Español: notas para revisores

PixelGuard 0.2.0 incorpora consultas opcionales de contexto a VirusTotal y mantiene el análisis local de rastreo. Solo usa APIs públicas de Thunderbird, con versión mínima 115. No incluye Experiments, componentes nativos, scripts remotos, HTML remoto incrustado ni cambios en la CSP predeterminada.

VirusTotal viene desactivado. Activarlo requiere una clave del usuario, aceptación explícita de los datos compartidos y los permisos opcionales sensitiveDataUpload y https://www.virustotal.com/*. Abrir correos o el panel y guardar la clave no contacta con VirusTotal. Cada consulta es manual. La consulta de dominio es la acción predeterminada para enlaces; compartir una URL completa requiere verla y confirmarla. Para adjuntos se calcula SHA-256 localmente con un límite de 50 MiB y solo se envía la huella, nunca el contenido.

El proceso de fondo utiliza GET /api/v3/widget/url con la clave del usuario. Valida la dirección devuelta antes de abrir el informe oficial como una página web independiente. No solicita nuevos análisis ni reanálisis, y los resultados no cambian las detecciones de PixelGuard.

La clave se guarda localmente y no se devuelve a los scripts de mensajes ni se registra en logs. Los ajustes permiten desactivar la integración y reemplazar o eliminar la clave. La revocación de permisos y los cambios de mensaje invalidan las peticiones pendientes y los resultados temporales.

El XPI contiene código legible. Las instrucciones de empaquetado, resultados de verificación y huella exacta están en scripts/package.ps1, docs/LOCAL-TESTING.md y docs/VALIDATION-0.2.0.md. docs/REVIEWER-NOTES.md detalla las APIs, permisos y pruebas. Las pruebas automáticas y con perfiles aislados no equivalen a consultas reales autenticadas: el informe de validación identifica las comprobaciones pendientes.

La función principal se puede revisar sin cuenta de VirusTotal. Las pruebas autenticadas requieren una clave adecuada introducida en Ajustes, conforme a las condiciones de su cuenta. No se incluye ninguna credencial en el paquete ni en el repositorio público. Si es necesario otro mecanismo de prueba, solicítenlo por un canal privado. Las capturas de la tienda usan datos de demostración y no documentan resultados reales de VirusTotal.

## Campo de política de privacidad de ATN

Abre [PRIVACY.md](../PRIVACY.md) y copia **todo su texto**, desde «PixelGuard Privacy Notice» hasta el correo de contacto incluido. Pégalo directamente en el campo «Política de privacidad» de la ficha del complemento. Si el editor permite varios idiomas, la política preparada actualmente está en inglés.

No pegues únicamente el enlace a GitHub, una frase de resumen o las notas para revisores. La política explica los datos enviados, el almacenamiento de la clave, la retención y los controles del usuario. La [guía oficial del revisor](https://addons-reviewer-guide.thunderbird.net/add-on-review-guide) exige que el texto de la política figure en el campo de ATN cuando el complemento usa un servicio externo con dirección predefinida.

Actualiza tanto la descripción breve de «Información básica» como la descripción larga de «Detalles del complemento»: son campos distintos. Guarda las notas de versión en la versión 0.2.0 y las instrucciones de prueba en el campo privado de notas para revisores. No pegues allí una clave salvo que exista un acuerdo privado de prueba compatible con las condiciones del servicio.

Las capturas de 0.2.0 y sus pies se encuentran en [store-screenshots/0.2.0](../store-screenshots/0.2.0/). No mezcles capturas antiguas de la raíz de store-screenshots con las nuevas si presentan una interfaz anterior.
