# Datenschutzhinweise zu PixelGuard

Diese Hinweise beschreiben PixelGuard 0.2.0 einschließlich der optionalen VirusTotal-Integration.

## Lokale Analyse von Tracking

PixelGuard liest den HTML-Inhalt der aktuell angezeigten Nachricht und grundlegende Absendermetadaten, etwa die Domain aus dem From-Header, um mögliche Tracking-Pixel, Tracking-Links und externe Bilder zu erkennen. Diese Analyse erfolgt lokal. PixelGuard verändert keine gespeicherten Nachrichten und setzt Thunderbirds Einstellungen für externe Inhalte nicht außer Kraft.

Für den optionalen Abfragebereich liest PixelGuard außerdem den HTML- oder Klartextinhalt der angezeigten Nachricht, um HTTP(S)-Links aufzulisten, und ermittelt die Namen und Größen der Anhänge. Es ruft diese Links nicht auf und folgt ihren Weiterleitungen nicht. Wenn Sie einen Anhang für eine Abfrage auswählen, liest PixelGuard dessen Bytes über Thunderbird und berechnet lokal einen SHA-256-Hashwert. Dabei muss Thunderbird im Rahmen seines normalen Betriebs möglicherweise Nachrichten- oder Anhangsdaten vom E-Mail-Dienst des Nutzers abrufen. PixelGuard führt den Anhang nicht aus und entpackt ihn nicht. Die anfängliche Größenbegrenzung für Anhänge beträgt 50 MiB.

## Optionale Anfragen an VirusTotal

Die Integration ist standardmäßig deaktiviert. Zum Aktivieren müssen Sie Ihren eigenen VirusTotal-API-Schlüssel eingeben, die Erläuterung zur Datenweitergabe bestätigen und optionale Berechtigungen erteilen. Das Öffnen einer Nachricht oder des Popups und das Speichern des Schlüssels lösen keine VirusTotal-Abfrage aus.

Erst wenn Sie eine Abfrage anfordern, übermittelt PixelGuard Folgendes direkt über HTTPS an VirusTotal:

- Die ausgewählte Domain oder die genaue vollständige URL, die Ihnen in einer Vorschau angezeigt wird und die Sie ausdrücklich bestätigen.
- Bei einer Anhangsabfrage dessen SHA-256-Hashwert statt seines Inhalts oder Dateinamens.
- Ihren VirusTotal-API-Schlüssel in einem Authentifizierungsheader.

VirusTotal erhält außerdem übliche Verbindungsdaten, etwa Ihre IP-Adresse. Ein Hashwert legt die Bytes der Datei nicht offen, kann aber eine VirusTotal bereits bekannte Datei identifizieren. Eine URL kann personenbezogene Informationen, Zugriffstoken oder andere private Kennungen enthalten. Bevorzugen Sie eine Domain-Abfrage, wenn Sie die vollständige Adresse nicht weitergeben möchten.

PixelGuard fragt über die Widget-API von VT Augment vorhandene Kontextinformationen ab. Es lädt weder Nachrichteninhalte noch die Bytes von Anhängen hoch, übermittelt keine URLs für neue Scans und fordert keine erneute Analyse an. Es verwendet keinen vom Entwickler betriebenen Proxy- oder Telemetriedienst. Die Ergebnisse von VirusTotal liefern optionalen Kontext und verändern die Tracking-Einstufungen, Warnungen oder Zähler von PixelGuard nicht.

Beim Öffnen des offiziellen Berichts wird eine VirusTotal-Webseite in einem separaten Thunderbird-Tab oder in Ihrem Standardbrowser geladen. Diese Seite wird von VirusTotal bereitgestellt und unterliegt dessen eigenen Regeln zu Cookies, Anfragen, Aufbewahrung und Konten. Ihre dortigen Aktionen liegen außerhalb des Abfrageablaufs von PixelGuard. Lesen Sie die [Datenschutzhinweise von VirusTotal](https://docs.virustotal.com/docs/privacy-policy), die [geltenden Bedingungen](https://docs.virustotal.com/docs/terms-of-service) und die [API-Bedingungen](https://docs.virustotal.com/reference/public-vs-premium-api).

## Speicherung und Aufbewahrung

- Einstellungen und Erkennungszähler werden in Thunderbirds lokalem Erweiterungsspeicher gespeichert. PixelGuard synchronisiert sie nicht und übermittelt sie nicht an seinen Entwickler.
- Zeitstempel von Anfragen werden lokal gespeichert, damit auch nach Neustarts höchstens vier API-Anfragen pro Minute und 500 innerhalb eines gleitenden Zeitraums von 24 Stunden zugelassen werden. Sie enthalten keine Domains, URLs, Hashwerte oder Dateinamen. Einträge, die älter als 24 Stunden sind, werden bei der Reservierung der nächsten Anfrage verworfen.
- Falls Sie einen VirusTotal-API-Schlüssel angeben, wird dieser getrennt von den allgemeinen Einstellungen in `browser.storage.local` gespeichert. Dieser Speicher ist kein verschlüsselter Tresor für Zugangsdaten. Wer Zugriff auf Ihr Thunderbird-Profil, dessen Sicherungskopien oder Ihr Gerät hat, kann möglicherweise auf lokal gespeicherte Daten zugreifen. PixelGuard nimmt den Schlüssel weder in Einstellungsexporte noch in API-Antworten an Nachrichtenskripte, Protokolle oder das Erweiterungspaket auf.
- Die für VirusTotal zusammengestellte Liste der Links und Anhänge, Abfrageergebnisse und temporäre Berichts-URLs bleiben für die Sitzung der Nachricht im Arbeitsspeicher und werden nicht als Abfrageverlauf gespeichert. Sie werden gelöscht, wenn sich die angezeigte Nachricht ändert, ihr Tab geschlossen, die Integration deaktiviert oder der Schlüssel geändert wird. Noch ausstehende Vorgänge können Ergebnisse nicht in einer bereits ungültigen Sitzung wiederherstellen.
- Zuvor geöffnete VirusTotal-Tabs bleiben unabhängig davon geöffnet. Das Leeren des PixelGuard-Arbeitsspeichers widerruft keine temporäre Berichts-URL und löscht weder den Browserverlauf noch Konsolenausgaben oder bereits bei VirusTotal eingegangene Daten.
- Der Debug-Modus ist standardmäßig deaktiviert. Wenn er aktiviert ist, kann der vorhandene Tracking-Scanner Funde einschließlich vollständiger URLs aus Nachrichten in Thunderbirds lokaler Konsole protokollieren. VirusTotal-Schlüssel und temporäre Berichtstoken werden nicht protokolliert. Die Aufbewahrung und der Export von Konsolendaten werden durch Thunderbird und den Nutzer gesteuert.

## Ihre Einstellungsmöglichkeiten

In den PixelGuard-Einstellungen können Sie VirusTotal deaktivieren und den Schlüssel ersetzen oder löschen. Das Deaktivieren verhindert neue Abfragen und bricht ausstehende Anfragen ab; beim Löschen wird zusätzlich der gespeicherte Schlüssel entfernt. Das Entziehen der optionalen Berechtigungen verhindert weitere Abfragen. Bereits übermittelte Daten lassen sich durch Deaktivieren der Integration nicht zurückholen. Sie können PixelGuard in Thunderbirds Add-ons-Verwaltung deaktivieren oder entfernen.

## Zweck der Berechtigungen

- `messagesRead`: auf die angezeigte Nachricht und ihre Metadaten zugreifen, ihre Anhänge auflisten und einen ausgewählten Anhang zur lokalen Hashberechnung lesen.
- `messagesModify`: PixelGuards Skripte für die Nachrichtenanzeige registrieren und das Banner innerhalb der Nachricht anzeigen. PixelGuard bearbeitet keine E-Mail-Nachrichten und speichert keine Änderungen daran.
- `storage`: lokale Einstellungen, Zähler und den optionalen API-Schlüssel speichern.
- Optional `sensitiveDataUpload`: die Übermittlung des ausgewählten Indikators an den externen Abfragedienst offenlegen und autorisieren.
- Optional `https://www.virustotal.com/*`: die authentifizierte HTTPS-Anfrage an den festgelegten VirusTotal-Endpunkt stellen.

## Kontakt

E-Mail: hello@enriqueite.com
