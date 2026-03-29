## Kurze Beschreibung

**Sicherer 2FA-Authenticator mit verschlüsselter Datenspeicherung**

Desktop-Anwendung für TOTP-basierte Zwei-Faktor-Authentifizierung mit AES-GCM-Verschlüsselung und Argon2-Key-Derivation. Speichert alle Accounts lokal und verschlüsselt mit Master-Passwort. Unterstützt Import/Export, QR-Code-Scan, automatisches Lock-out bei Inaktivität und anpassbare Oberfläche.

---

## Ausführliche Beschreibung

# 2FA Authenticator

Ein sicherer Desktop-Authenticator für Zwei-Faktor-Authentifizierung (2FA) mit verschlüsselter lokaler Datenspeicherung.

## Bebildert

### Masterpasswort und erstellen der Datenbank
Bitte die Konfiguration ggf. anpassen. Nicht alle haben genug Arbeitsspeicher oder CPU-Kerne.
Wird nur eins von den 3 Einstellungen *Nachträglich* geändert, so ändert sich die Berechnung und das Masterpasswort funktioniert nicht mehr.
Also bitte vor dem erstellen einer Datenbank (`authenticator_data.json`) diese Einstellungen anpassen!

Starten mit vorliegenden Einstellungen
```python
ARGON_TIME_COST    = 20          # CPU-Aufwand für Argon2
ARGON_MEMORY_COST  = 1024 * 1024 # 1 GiB Speicher
ARGON_PARALLELISM  = 4           # Anzahl paralleler Threads
```
![Set Masterpassword](./images_/2fa_master_pw.jpg) → ![Repeat Masterpassword](./images_/2fa_master_pw_b.jpg)

Datenbank erstellt im gleichen Ordner: `authenticator_data.json`

### Neuen Account erstellen
Untere Knöpfe: Account Hinzufügen.

![GUI - Add new Account](./images_/2fa_GUI_add_account.jpg)

### Hinzufügen neuer Daten
Einfügen der Informationen und im Anschluss auf `OK`.

> **Hinweis:** Die Felder „Information" und „Firma (Issuer)" sind optional — nur der Kontoname und der TOTP-Schlüssel sind Pflichtfelder.

![Create new Account](./images_/2fa_new_account.jpg)

#### QR-Code scannen (neu)
Im Hinzufügen- und Bearbeiten-Dialog stehen zwei Schaltflächen bereit:

- **📷 Von QR-Code scannen (Screenshot)** – Markiert per Maus einen Bereich auf dem Bildschirm. Der QR-Code wird sofort ausgelesen und alle Felder automatisch ausgefüllt.
- **🖼 Von Bilddatei** – Öffnet eine Bilddatei (PNG, JPG, BMP …) und liest den QR-Code daraus.

> **Voraussetzung:** `pip install pillow pyzbar`
> Sind diese Pakete nicht installiert, werden die Schaltflächen nicht angezeigt – das Programm läuft weiterhin normal.

#### Weitere Accounts

![Add new Accounts and overview](./images_/2fa_gui_with_new_account.jpg)

#### 30 Sekunden Token
Klick auf die \* und das Token wird in die Zwischenablage kopiert!

![Token](./images_/2fa_gui_with_new_account_token.jpg)

#### Bearbeiten des Accounts
In der GUI: Rechtsklick → Bearbeiten.

- Alle Felder können geändert werden, einschließlich des TOTP-Schlüssels.
- Das Schlüssel-Feld ist standardmäßig maskiert. Mit „Schlüssel anzeigen?" wird der Klartext eingeblendet – erst dann kann er bearbeitet werden.
- Auch im Bearbeitungs-Dialog steht der QR-Code-Scanner zur Verfügung.

![Edit Account](./images_/2fa_gui_with_new_account_edit.jpg)



## 🔐 Hauptmerkmale

### Sicherheit
- **AES-GCM-Verschlüsselung**: Alle Daten werden mit modernster AEAD-Verschlüsselung gesichert
- **Argon2-Key-Derivation**: Robuste Passwort-Hashing-Funktion mit konfigurierbaren Parametern
- **Automatisches Lock-out**: Sperrt sich nach 5 Minuten Inaktivität; Clipboard wird dabei geleert
- **Lokale Datenspeicherung**: Keine Cloud, alle Daten bleiben auf Ihrem Gerät

### Funktionen
- **TOTP-Unterstützung**: Kompatibel mit gängigen 2FA-Diensten (Google, Microsoft, GitHub, etc.)
- **QR-Code-Scan**: Direkt per Screenshot-Auswahl oder Bilddatei – Felder werden automatisch ausgefüllt
- **Mehrere Hash-Algorithmen**: SHA1, SHA256, SHA512
- **Flexible Code-Längen**: 4–8 Ziffern
- **Import/Export**: Daten-Backup mit optionaler Verschlüsselung
- **Live-Suche**: Schnelles Filtern nach Name, Firma oder Information
- **Countdown-Timer**: Zeigt verbleibende Zeit bis zum Code-Wechsel an
- **Anpassbare Oberfläche**: Schriftgröße individuell einstellbar

### Benutzerfreundlichkeit
- **Einfaches Kopieren**: Klick auf Code kopiert ihn in die Zwischenablage
- **Übersichtliche Struktur**: Sortierung nach Account, Firma und Information
- **Kontextmenü**: Schnelles Bearbeiten per Rechtsklick
- **Master-Passwort ändern**: Jederzeit neue Verschlüsselung möglich
- **Optionale Felder**: Information und Firma sind nicht zwingend erforderlich

## 📋 Voraussetzungen

### Volle Funktionalität:
```bash
pip install pyotp cryptography argon2-cffi pillow pyzbar
```

### Minimum:
```bash
pip install pyotp cryptography argon2-cffi
```

### (Optional) Für QR-Code-Scan:
```bash
pip install pillow pyzbar
```

### Bibliothekenbeschreibungen

**Erforderliche Python-Pakete:**
- `pyotp` – TOTP-Code-Generierung
- `cryptography` – AES-GCM-Verschlüsselung
- `argon2-cffi` – Sichere Key-Derivation
- `tkinter` – GUI (meist vorinstalliert)

**Optionale Pakete (für QR-Code-Scan):**
- `pillow` – Bildverarbeitung und Screenshots
- `pyzbar` – QR-Code- und Barcode-Dekodierung

## 🚀 Installation & Start


1. Für volle Funktionalität
   ```bash
   pip install pyotp cryptography argon2-cffi pillow pyzbar
   ```
   
   Oder Separat: 
   nur notwendige Abhängigkeiten installieren:
   ```bash
   pip install pyotp cryptography argon2-cffi
   ```
   Optional für QR-Scan:
   ```bash
   pip install pillow pyzbar
   ```

2. Programm starten:
   ```bash
   python 2FA.py
   ```
   oder umbenennen in `2FA.pyw` → kein Terminal mehr (empfohlen).
   ```bash
   python 2FA.pyw
   ```
   oder einfach via Doppelklick auf diese Datei/Anwendung.

3. Beim ersten Start Master-Passwort festlegen

## 💾 Datenspeicherung

Die verschlüsselte Datenbank wird als `authenticator_data.json` im Programmverzeichnis gespeichert. Die Datei enthält:
- Salt für Key-Derivation (Base64-kodiert)
- Verschlüsselte Account-Daten (AES-GCM)

**Wichtig**: Bewahren Sie Ihr Master-Passwort sicher auf. Ohne dieses können die Daten nicht wiederhergestellt werden!

## 🔧 Konfiguration

In der Datei sollten folgende Parameter angepasst werden:

```python
ARGON_TIME_COST    = 20          # CPU-Aufwand für Argon2
ARGON_MEMORY_COST  = 1024 * 1024 # 1 GiB Speicher
ARGON_PARALLELISM  = 4           # Anzahl paralleler Threads
```

**⚠️ Achtung**: Änderungen an den Verschlüsselungsparametern machen bestehende Datenbanken unbrauchbar!

## 📤 Import/Export

### Export
- **Unverschlüsselt**: JSON-Format für Kompatibilität
- **Verschlüsselt**: Mit Master-Passwort geschützte Backup-Datei

### Import
- Unterstützt eigenes verschlüsseltes Format
- Kompatibel mit Google Authenticator Export-Format
- Accounts können hinzugefügt oder ersetzt werden
- Bei verschlüsselten Importen mit fremdem Passwort: das eigene Master-Passwort wird dabei **nicht** verändert

## 🛡️ Sicherheitshinweise

- Die Verschlüsselung ist sehr stark (Argon2 + AES-GCM)
- Regelmäßige Backups erstellen (Export-Funktion nutzen)
- Master-Passwort sicher verwahren
- Keine Passwort-Wiederherstellung möglich
- Inaktivitäts-Timeout nicht deaktivierbar (Sicherheitsfeature). Zeit (cooldown) lässt sich aber in der editieren: `self.inactivity_timeout`
- Zwischenablage wird beim Sperren, beim Beenden und nach 5 Sekunden automatisch geleert

## 📝 Lizenz

MIT License (Non-Commercial)

Copyright © 2025 Waldemar Koch

Kostenlose Nutzung für nicht-kommerzielle Zwecke. Kommerzielle Nutzung erfordert schriftliche Genehmigung.

## 🤝 Beitragen

Verbesserungsvorschläge und Bug-Reports sind willkommen! Bitte erstellen Sie ein Issue oder Pull Request.

## ⚠️ Haftungsausschluss

Diese Software wird "wie besehen" bereitgestellt, ohne jegliche Garantie. Nutzen Sie sie auf eigene Verantwortung.

---

**Version**: 1.2.0
**Letzte Aktualisierung**: 2026-03-29
