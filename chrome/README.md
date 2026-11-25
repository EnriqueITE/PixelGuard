# PixelGuard para Gmail

Prototipo de PixelGuard para Gmail en Chrome y Brave de escritorio. Su código, manifiesto, versión y pruebas están en `chrome/`. La extensión de Thunderbird sigue en la raíz del mismo repositorio.

Al expandir un mensaje en Gmail, PixelGuard añade un resumen encima del cuerpo. Despliega el resumen para ver el texto del enlace, su dirección completa y el motivo de la detección. Puedes copiar cada URL y recorrer los resultados de tres en tres. La interfaz sigue el idioma del navegador y está disponible en español e inglés.

## Cargar en Chrome

1. Clona el repositorio completo y, desde la raíz, ejecuta `python chrome/build.py`.
2. Abre `chrome://extensions` o `brave://extensions`, activa **Modo de desarrollador**, pulsa **Cargar descomprimida** y selecciona `dist/chrome-gmail`.
3. Abre un mensaje en Gmail. Si ya tienes el buzón abierto, PixelGuard se conecta a esa pestaña. Tras modificar el código, repite la compilación y recarga la extensión.

## Qué puede observar

El escudo muestra tres posiciones, igual que en Thunderbird. La primera suma los posibles píxeles de seguimiento y las imágenes sospechosas. La segunda cuenta las imágenes externas ordinarias y la tercera, los enlaces con indicios de seguimiento. Cada posición muestra `+` a partir de diez. Un correo con un posible píxel, 24 imágenes externas y 25 enlaces con indicios muestra `1++` en rojo. Al pasar el puntero por el escudo aparecen las tres cifras completas. El contador suma los mensajes expandidos de esa pestaña, incluso con la barra oculta. Al volver a la bandeja desaparece.

El escudo y la barra toman el color del indicio de mayor prioridad. Un posible píxel o una imagen sospechosa tiene prioridad roja. Le siguen los enlaces con indicios de seguimiento en naranja y las imágenes externas en turquesa. Puedes desplegar el panel y filtrar por tipo. Cada fila lleva su propia etiqueta y color.

Al abrir un correo, PixelGuard analiza los elementos que muestra Gmail. Usa las dimensiones explícitas, la visibilidad y los indicios de la URL. Si Gmail bloquea las imágenes y quita su dirección, el panel indica que el análisis es parcial.

**Analizar original**, dentro del panel desplegado, pide a Gmail el original de ese mensaje usando la sesión abierta. PixelGuard decodifica el cuerpo HTML en memoria. Busca las direcciones y los indicios de seguimiento sin ejecutar el HTML ni solicitar imágenes al remitente. El panel y el escudo pasan a mostrar el resultado del original. Si la lectura falla, el panel conserva los hallazgos de la vista normal. También puedes abrir **Mostrar original** en el menú del mensaje. PixelGuard analiza el texto que Gmail presenta en esa pestaña.

El análisis admite originales de hasta 8 MiB con un cuerpo HTML de hasta 2 MiB y excluye adjuntos y mensajes reenviados como archivo. Una alerta indica que el mensaje contiene elementos compatibles con seguimiento. El remitente podría registrar la apertura si algún cliente carga la imagen.

El detector se activa en `https://mail.google.com/mail/*`. El análisis del mensaje es local y respeta la elección de imágenes de Gmail. El [detector de Gmail](scanner.js) parte del de Thunderbird y reconoce las direcciones del proxy de imágenes de Gmail. La compilación reutiliza los iconos de PixelGuard, las traducciones de los indicios y las funciones de inventario de enlaces que ya están en la raíz.

## Ajustes y VirusTotal

Pulsa el escudo de la barra de herramientas para mostrar u ocultar el panel en los correos. La preferencia se guarda en el navegador. En **VirusTotal → Configurar**, introduce tu clave de API y pulsa **Guardar clave**. Las consultas están desactivadas inicialmente. Para habilitarlas, usa el interruptor de VirusTotal y concede el permiso de acceso.

PixelGuard cifra la clave de API localmente con AES-GCM. La clave de cifrado de Web Crypto es no exportable y se conserva en IndexedDB, en el origen privado de la extensión. El navegador no sincroniza estas claves. Alguien que controle tu sesión de Windows o el perfil del navegador aún podría usar la integración. En **Gestionar clave**, **Eliminar clave y desactivar** borra la clave de API guardada y desactiva las consultas.

Con VirusTotal activado, elige un enlace del hilo abierto o introduce una URL. Puedes consultar el dominio o revisar y confirmar la dirección completa que se enviará. También puedes seleccionar un archivo de hasta 50 MiB para consultar su SHA-256. El cálculo se realiza en tu equipo y solo se envía la huella. El popup permite estas consultas incluso si ocultas el panel de los correos. Cada consulta consume la cuota de tu clave.

## Repetir las pruebas

Los [tres mensajes sintéticos](tests/mail) contienen un píxel de 1 × 1 con identificador, un enlace de campaña y un logotipo visible. Sus dominios de prueba no reciben tráfico. La prueba instala la compilación en Chrome for Testing con un perfil temporal e intercepta la navegación antes de que llegue a Gmail. Simula el cuerpo del mensaje, el proxy, un hilo que se contrae y vuelve a expandirse y un borrador. Comprueba los textos que ve el usuario.

Con Node, `playwright-core` y su navegador Chromium instalados, ejecuta desde la raíz:

```sh
python chrome/build.py
node --test chrome/tests/scanner.test.cjs chrome/tests/worker.test.cjs
node chrome/tests/smoke.cjs
node chrome/tests/original-smoke.cjs
```

Puedes indicar el ejecutable de Chrome for Testing mediante `CHROME_FOR_TESTING`. Para contrastar el resultado con Gmail real, abre los mensajes elegidos en el buzón de prueba con la extensión cargada. Anota por separado el resumen y los indicios que aparecen al desplegarlo.
