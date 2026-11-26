# Privacidad de PixelGuard para Gmail

## Al abrir un correo

PixelGuard lee el mensaje que expandes en Gmail y pide su original a `mail.google.com` con la sesión de esa cuenta. En tu navegador examina las direcciones de las imágenes y los enlaces como texto. Puedes mantener las imágenes bloqueadas. Este análisis no abre los enlaces, no carga los píxeles del remitente y no envía el correo a VirusTotal ni a un servidor de PixelGuard.

Si PixelGuard no puede examinar todo el mensaje, muestra **Análisis parcial**. Ocultar la barra cambia dónde ves los resultados. El análisis sigue activo y puedes consultar el contador en el escudo.

## Qué recibe VirusTotal si lo activas

VirusTotal está desactivado de forma predeterminada. Para usarlo, guardas tu clave de API y concedes a la extensión permiso para acceder a `www.virustotal.com`. Cada petición al servicio usa tu clave. Seleccionar un elemento del correo prepara la consulta en el widget. Tú decides cuándo enviarla.

| Acción | Datos que compartes con VirusTotal |
| --- | --- |
| Consultar dominio | El nombre del dominio, incluido el subdominio. La ruta y los parámetros quedan fuera de la consulta. |
| Confirmar la consulta de la URL completa | La dirección que acabas de revisar. Su ruta o sus parámetros pueden contener tu dirección de correo, un identificador de destinatario o un enlace de acceso personal. |
| Consultar la huella de un archivo | La huella SHA-256 que PixelGuard calcula en tu equipo. Para un adjunto, PixelGuard obtiene el archivo de tu cuenta de Gmail. También puedes elegir un archivo de tu equipo para consultar su huella. |
| Confirmar la subida de un adjunto | El nombre y el contenido del archivo. Esta opción aparece cuando VirusTotal responde que desconoce la huella del adjunto y requiere una confirmación aparte. |

VirusTotal comparte los informes del análisis con su comunidad y puede compartir los archivos enviados con sus socios de seguridad y clientes autorizados. Tenlo en cuenta antes de confirmar la subida de un adjunto privado. [Cómo utiliza VirusTotal las muestras recibidas](https://docs.virustotal.com/docs/how-it-works).

## Qué queda en tu navegador

PixelGuard procesa el correo y los adjuntos en memoria. No crea un archivo de mensajes, adjuntos ni informes. Guarda en el perfil local el tema, la visibilidad de la barra, el estado de VirusTotal y las horas de las consultas para controlar la cuota. Cuando VirusTotal desconoce un adjunto, la extensión también conserva en la sesión su huella y una autorización válida durante diez minutos para que puedas confirmar la subida.

La clave de API se guarda cifrada con AES-GCM. La clave que permite descifrarla es no exportable y se guarda en IndexedDB dentro del perfil de la extensión. PixelGuard no sincroniza estas claves entre dispositivos.

Desactivar VirusTotal impide nuevas consultas, cancela las operaciones pendientes y conserva tu clave. **Gestionar clave → Eliminar clave y desactivar** borra también las dos claves del navegador. Estas acciones tienen efecto en tu navegador. Los datos que ya hayas enviado siguen sujetos al tratamiento de VirusTotal.
