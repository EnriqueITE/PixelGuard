# Política de privacidad de PixelGuard

Esta política describe PixelGuard 0.2.0, incluida su integración opcional con VirusTotal.

## Análisis local de rastreo

PixelGuard lee el HTML del mensaje que se muestra y metadatos básicos del remitente, como el dominio de la cabecera From, para identificar posibles píxeles de rastreo, enlaces de seguimiento e imágenes externas. El análisis de rastreo se realiza localmente. PixelGuard no modifica los mensajes guardados ni anula los controles de contenido remoto de Thunderbird.

Para el panel de consultas opcionales, PixelGuard también lee el HTML o el texto plano del mensaje mostrado para enumerar los enlaces HTTP(S) y obtiene los nombres y tamaños de los adjuntos. No visita esos enlaces ni sigue sus redirecciones. Al seleccionar un adjunto para consultarlo, lee sus bytes mediante Thunderbird y calcula localmente una huella SHA-256. Como parte de su funcionamiento normal, Thunderbird puede necesitar recuperar datos del mensaje o del adjunto desde el servicio de correo del usuario. PixelGuard no ejecuta ni descomprime el adjunto. El límite inicial de tamaño por adjunto es de 50 MiB.

## Solicitudes opcionales a VirusTotal

La integración viene desactivada. Para activarla debes introducir tu propia API key de VirusTotal, aceptar la explicación sobre los datos compartidos y conceder los permisos opcionales. Abrir un mensaje, abrir el panel emergente o guardar la clave no provoca ninguna consulta a VirusTotal.

Solo cuando solicitas una consulta, PixelGuard envía directamente a VirusTotal por HTTPS los siguientes datos:

- El dominio seleccionado, o la URL completa exacta que se muestra en una vista previa y que confirmas expresamente.
- Para consultar un adjunto, su huella SHA-256 en lugar de su contenido o nombre de archivo.
- Tu API key de VirusTotal en una cabecera de autenticación.

VirusTotal también recibe información habitual de conexión, como tu dirección IP. Una huella no revela los bytes del archivo, pero puede identificar un archivo ya conocido por VirusTotal. Una URL puede contener información personal, tokens de acceso u otros identificadores privados. Elige la consulta del dominio si no quieres compartir la dirección completa.

PixelGuard solicita información de contexto existente mediante la API del widget VT Augment. No sube cuerpos de mensajes ni bytes de adjuntos, no envía URLs para nuevos análisis ni solicita reanálisis. No utiliza un proxy ni un servicio de telemetría gestionados por el desarrollador. Los resultados de VirusTotal aportan contexto opcional y no modifican las clasificaciones, alertas ni contadores de rastreo de PixelGuard.

Al abrir el informe oficial, se carga una página web de VirusTotal en una pestaña independiente de Thunderbird o en tu navegador predeterminado. VirusTotal sirve esa página, que tiene sus propias cookies, solicitudes y políticas de conservación de datos y de cuenta; las acciones que realices allí quedan fuera del flujo de consultas de PixelGuard. Consulta la [información de privacidad de VirusTotal](https://docs.virustotal.com/docs/privacy-policy), las [condiciones aplicables](https://docs.virustotal.com/docs/terms-of-service) y las [condiciones de la API](https://docs.virustotal.com/reference/public-vs-premium-api).

## Almacenamiento y conservación

- Las preferencias y los contadores de detección se guardan en el almacenamiento local de la extensión en Thunderbird. PixelGuard no los sincroniza ni los transmite a su desarrollador.
- Las marcas de tiempo de las solicitudes se guardan localmente para aplicar un máximo de cuatro solicitudes a la API por minuto y 500 en un período móvil de 24 horas, incluso después de reiniciar. No contienen dominios, URLs, huellas ni nombres de archivo. Las entradas de más de 24 horas se descartan al reservar la siguiente solicitud.
- Si la proporcionas, la API key de VirusTotal se guarda por separado de los ajustes generales en `browser.storage.local`. Este almacenamiento no es una caja fuerte cifrada para credenciales. El acceso a tu perfil de Thunderbird, a sus copias de seguridad o a tu dispositivo puede exponer los datos guardados localmente. PixelGuard no incluye la clave en las exportaciones de ajustes, en las respuestas de la API a los scripts de mensajes, en los registros ni en el paquete de la extensión.
- El inventario de VirusTotal, los resultados de las consultas y las URLs temporales de los informes se mantienen en memoria durante la sesión del mensaje; no se guardan como historial de consultas. Se borran cuando cambia el mensaje o se cierra su pestaña, cuando se desactiva la integración o cuando cambia la clave. Las operaciones pendientes no pueden restaurar resultados en una sesión invalidada.
- Las pestañas de VirusTotal abiertas anteriormente siguen abiertas de forma independiente. Vaciar la memoria de PixelGuard no revoca una URL temporal de informe ni borra el historial del navegador, la salida de la consola o los datos ya recibidos por VirusTotal.
- El modo de depuración viene desactivado. Al activarlo, el analizador de rastreo existente puede registrar sus hallazgos, incluidas las URLs completas de los mensajes, en la consola local de Thunderbird. No se registran las claves de VirusTotal ni los tokens temporales de los informes. Thunderbird y el usuario controlan la conservación y la exportación de la consola.

## Tus controles

En los ajustes de PixelGuard puedes desactivar VirusTotal, reemplazar la clave o eliminarla. Desactivar la integración detiene las nuevas consultas y cancela las solicitudes pendientes; eliminar la clave también borra la clave guardada. Revocar los permisos opcionales impide nuevas consultas. Desactivar la integración no permite retirar los datos ya transmitidos. Puedes desactivar o eliminar PixelGuard desde el administrador de complementos de Thunderbird.

## Finalidad de los permisos

- `messagesRead`: acceder al mensaje mostrado y a sus metadatos, enumerar sus adjuntos y leer un adjunto seleccionado para calcular su huella localmente.
- `messagesModify`: registrar los scripts de visualización de mensajes de PixelGuard y mostrar su aviso dentro del mensaje. PixelGuard no edita ni guarda cambios en los correos electrónicos.
- `storage`: guardar las preferencias locales, los contadores y la API key opcional.
- `sensitiveDataUpload`, opcional: informar sobre el indicador seleccionado que se envía al servicio de consulta de terceros y autorizar su envío.
- `https://www.virustotal.com/*`, opcional: realizar la solicitud HTTPS autenticada al endpoint fijo de VirusTotal.

## Contacto

Correo electrónico: hello@enriqueite.com
