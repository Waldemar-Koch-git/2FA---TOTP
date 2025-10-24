#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
2FA Authenticator – Desktop‑Anwendung

Dieses Skript implementiert einen einfachen TOTP‑Authenticator mit
verschlüsselter Persistenz, Import/Export‑Fähigkeit und einer Tkinter‑GUI.
Alle Daten werden in einem JSON‑Datei verschlüsselt gespeichert.
Der Master‑Password wird mithilfe von Argon2 (KDF) in einen Schlüssel
umgewandelt, der dann die Fernet‑Verschlüsselung steuert.

Die Hauptkomponenten:
    * :class:`Account` – Datensatz für ein TOTP‑Konto.
    * :class:`CryptoHelper` – Krypto‑Hilfsfunktionen (Key‑Derivation,
      Verschlüsseln/Entschlüsseln).
    * :class:`DataStore` – Lese-/Schreibvorgänge zur verschlüsselten JSON‑Datei.
    * :class:`AuthenticatorApp` – Tkinter‑Basierte GUI und Anwendungslogik.

install: pip install pyotp cryptography argon2-cffi

-----------------------------------------------------------------------------------

Author      : Waldemar Koch
Created     : 2025-08-09
Last Update : 2025-10-15
Version     : 1.0.5
License     : MIT License (Modified: Non-Commercial Use Only)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to use,
copy, modify, merge, publish, and distribute the Software for non-commercial
purposes only, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import multiprocessing
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Tuple

import pyotp
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import tkinter.font as tkfont
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import uuid


# --------------------------------------------------------------------------- #
# Konfiguration – alles in Großbuchstaben
# --------------------------------------------------------------------------- #
# Speicherort der Datei
DATA_FILE = Path("authenticator_data.json")

SALT_SIZE          = 32                 # Bytes für den KDF‑Salz # 32 Standard und muss nicht geändert werden..
# ACHTUNG! Diese 3 Variablen verändern die Verschlüsselung! Aktuell ist die verschlüsselung seeehr stark!
ARGON_TIME_COST    = 20                 # CPU‑Kosten für Argon2
ARGON_MEMORY_COST  = 1024 * 1024         # 1 GiB
#ARGON_PARALLELISM  = multiprocessing.cpu_count()
# feste Zahl einstellen! So wird das Masterpasswort an verschiedenen Geräten gleich berechnet
ARGON_PARALLELISM  = 4  # 4 sollte mitlerweile jedes gerät hinkriegen!

COUNTDOWN_START   = 30                 # Sekunden bis zum nächsten Codewechsel

HASH_OPTIONS      = ("sha1", "sha256", "sha512")
DEFAULT_DIGITS    = 6
DEFAULT_HASH      = "sha1"

# --------------------------------------------------------------------------- #
# Logging‑Setup
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
)

# --------------------------------------------------------------------------- #
# Datenmodell
# --------------------------------------------------------------------------- #

@dataclass
class Account:
    """
    Repräsentiert ein einzelnes TOTP‑Konto.

    Attributes
    ----------
    name : str
        Benutzerfreundlicher Kontoname.
    info : str
        Zusätzliche Beschreibung (z. B. E‑Mail-Adresse).
    firma : str
        Aussteller/Unternehmen, der dem Konto zugeordnet ist.
    secret : str
        Base32‑kodierter TOTP‑Geheimschlüssel.
    hash_algo : str, optional
        Hash‑Algorithmus für die TOTP‑Berechnung (default: ``sha1``).
    digits : int, optional
        Anzahl der Ziffern des OTPs (default: ``6``).
    """
    name: str
    info: str            # z.B. Kontoinformation / Beschreibung
    firma: str           # neuer Feld für den Aussteller/Unternehmen
    secret: str
    hash_algo: str = DEFAULT_HASH
    digits: int = DEFAULT_DIGITS

    def to_dict(self) -> dict[str, object]:
        """Serialisiert das Objekt in ein Dictionary."""
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Account":
        """
        Deserialisiert ein Dictionary zurück zu einem :class:`Account`.

        Parameters
        ----------
        data : dict
            Enthält die Schlüssel ``name``, ``info`` etc.
        """
        return Account(
            name=data["name"],
            info=data.get("info", ""),
            firma=data.get("firma", ""),   # neuer Key im Dictionary
            secret=data["secret"],
            hash_algo=data.get("hash_algo", DEFAULT_HASH),
            digits=int(data.get("digits", DEFAULT_DIGITS)),
        )


# ──────────────────────────────────────────────────────────────
# CryptoHelper – jetzt AES‑GCM statt Fernet
# ──────────────────────────────────────────────────────────────
class CryptoHelper:
    """Hilfsklasse für Kryptografie‑Operationen (Key‑Derivation, AEAD)."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Ableitet einen 256‑Bit‑Schlüssel aus Passwort und Salt.
        Der zurückgegebene Schlüssel ist **raw** (32 Byte), nicht base64‑kodiert.

        Args:
            password: Master‑Password
            salt:      32‑Byte‑Salt

        Returns:
            bytes: 32‑byte raw Key für AESGCM
        """
        key = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=ARGON_TIME_COST,
            memory_cost=ARGON_MEMORY_COST,
            parallelism=ARGON_PARALLELISM,
            hash_len=32,
            type=Type.ID,
        )
        return key   # raw 256‑bit key

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> str:
        """
        Verschlüsselt `plaintext` mit AES‑GCM.
        Das Ergebnis ist ein base64‑kodierter String, der *Nonce + Ciphertext* enthält.

        Args:
            plaintext: Klartext in Bytes
            key:       32‑byte raw Key (aus derive_key)

        Returns:
            str: Base64‑String (Nonce | Ciphertext)
        """
        # GCM benötigt einen 12‑Byte‑Nonce. Es gibt kein AESGCM.NONCE_SIZE.
        nonce = os.urandom(12)   # ← feste Länge von 12 Bytes
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)  # kein AD (Associated Data)
        return base64.urlsafe_b64encode(nonce + ct).decode()

    @staticmethod
    def decrypt(ciphertext_b64: str, key: bytes) -> bytes:
        """
        Entschlüsselt einen Base64‑kodierten Ciphertext (Nonce | Ciphertext).

        Args:
            ciphertext_b64: Encrypted data from `encrypt`
            key:            32‑byte raw Key

        Returns:
            bytes: Klartext

        Raises:
            ValueError: Wenn die Authentifizierung fehlschlägt
        """
        try:
            raw = base64.urlsafe_b64decode(ciphertext_b64)
            # Der erste Block (12 Bytes) ist der Nonce, alles danach Ciphertext
            nonce, ct = raw[:12], raw[12:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ct, None)
        except Exception as exc:
            raise ValueError("Falsches Passwort oder beschädigte Datei.") from exc



class DataStore:
    """Verwaltet Lese- und Schreibvorgänge der verschlüsselten Datenbank."""

    def __init__(self, file_path: Path) -> None:
        self.file = file_path

    # ────────────────────────────────────────────────────────
    # 1. Laden der Accounts (inkl. Salt & Schlüsselableitung)
    # ────────────────────────────────────────────────────────
    def load(self, password: str) -> Tuple[List[Account], bytes]:
        """
        Lädt die Accounts aus der verschlüsselten Datei.

        Der Ablauf ist:
          1. Prüfen, ob die Datei existiert.
          2. JSON‑Datei einlesen → enthält `salt` und `data`.
          3. Salt base64‑decode und Schlüssel mit Argon2 ableiten.
          4. AES‑GCM entschlüsseln (Nonce | Ciphertext).
          5. Klartext (JSON) in Account‑Objekte umwandeln.

        Parameters
        ----------
        password : str
            Master‑Password des Benutzers.

        Returns
        -------
        tuple(list[Account], bytes)
            Die geladenen Konten und das Salt, das bei der Schlüsselableitung verwendet wurde.
        """
        # 1. Existenz prüfen
        if not self.file.exists():
            raise FileNotFoundError("Datenbank existiert nicht.")

        # 2. Datei einlesen (JSON‑Objekt mit `salt` + `data`)
        with self.file.open(encoding="utf-8") as f:
            data = json.load(f)

        # Base64‑decode des Salzes
        salt = base64.urlsafe_b64decode(data["salt"])
        ciphertext_b64 = data["data"]

        # 3. Schlüssel ableiten (Argon2 → raw 32‑Byte‑Key)
        key = CryptoHelper.derive_key(password, salt)

        # 4. AES‑GCM entschlüsseln
        plaintext_bytes = CryptoHelper.decrypt(ciphertext_b64, key)

        # 5. Klartext (JSON) in Account‑Objekte umwandeln
        raw_accounts: List[dict] = json.loads(plaintext_bytes.decode())
        accounts = [Account.from_dict(a) for a in raw_accounts]

        return accounts, salt

    # ────────────────────────────────────────────────────────
    # 2. Speichern der Accounts (inkl. Salt & Verschlüsselung)
    # ────────────────────────────────────────────────────────
    def save(self, password: str, accounts: List[Account], salt: bytes) -> None:
        """
        Speichert die Konten verschlüsselt in die JSON‑Datei.

        Der Ablauf ist:
          1. Schlüssel mit Argon2 ableiten.
          2. Accounts als JSON‑String serialisieren → Bytes.
          3. AES‑GCM verschlüsseln (Nonce + Ciphertext).
          4. Salt + ciphertext base64‑kodiert in die Datei schreiben.

        Parameters
        ----------
        password : str
            Master‑Password, mit dem die Datenbank verschlüsselt wird.
        accounts : list[Account]
            Alle Konten, die gespeichert werden sollen.
        salt : bytes
            Salt für die Schlüsselableitung (kann neu generiert oder wiederverwendet werden).
        """
        # 1. Schlüssel ableiten
        key = CryptoHelper.derive_key(password, salt)

        # 2. Accounts serialisieren → JSON‑Bytes
        plaintext_bytes = json.dumps([a.to_dict() for a in accounts]).encode()

        # 3. AES‑GCM verschlüsseln (Nonce | Ciphertext)
        ciphertext_b64 = CryptoHelper.encrypt(plaintext_bytes, key)

        # 4. Salt + ciphertext als base64‑kodierte JSON‑Datei schreiben
        data_obj = {"salt": base64.urlsafe_b64encode(salt).decode(),
                    "data": ciphertext_b64}
        tmp_path = self.file.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data_obj, f)
        os.replace(tmp_path, self.file)  # atomare Umbenennung


class AuthenticatorApp:
    """Hauptanwendung – Tkinter‑GUI und Logik für 2FA‑Authentifizierung."""

    def __init__(self) -> None:
        """
        Konstruktor: setzt die komplette Anwendung auf.
        Ablauf:

          1. Tkinter‑Fenster initialisieren (versteckt bis Login/Setup abgeschlossen).
          2. Schriftgröße, Countdown‑Timer und Datenbank‑Handler einrichten.
          3. Master‑Password holen – entweder login oder neues Passwort anlegen.
          4. UI aufbauen & OTP‑Updater starten.
          5. Inaktivitäts‑Tracking aktivieren (Key / Button / Motion).
          6. Periodischen Timeout‑Check starten.
        """
        # ────────────────────────────────────────────────────────
        # 1. Tkinter‑Fenster – versteckt bis Authentifizierung fertig
        # ────────────────────────────────────────────────────────
        self.root = tk.Tk()
        self.root.withdraw()                      # zunächst unsichtbar

        # ────────────────────────────────────────────────────────
        # 2. UI‑Grundlagen: Schrift, Countdown & Datenbank‑Handler
        # ────────────────────────────────────────────────────────
        self._font_size: int = 10               # Basis­schriftgröße (kann später angepasst werden)
        self.remaining: int = COUNTDOWN_START   # Sekunden bis zum nächsten OTP‑Wechsel

        self.data_store = DataStore(DATA_FILE)

        # Master‑Password & Salt – erst nach Login/Setup gesetzt
        self.master_password: str | None = None
        self.salt: bytes | None = None

        # Alle Accounts im Speicher (Liste von Account‑Objekten)
        self.accounts: List[Account] = []

        # ────────────────────────────────────────────────────────
        # 3. Login oder neues Master‑Password anlegen
        # ────────────────────────────────────────────────────────
        if DATA_FILE.exists():
            # Bestehende Datenbank – Login‑Dialog zeigen
            self._login_dialog()
        else:
            # Keine DB vorhanden – neuen Master‑Passwort festlegen
            self._setup_new_master()

        # ────────────────────────────────────────────────────────
        # 4. UI aufbauen & OTP‑Updater starten
        # ────────────────────────────────────────────────────────
        self._apply_global_font(self._font_size)   # Schriftgrößen setzen

        self.remaining = COUNTDOWN_START           # Countdown zurücksetzen
        self._build_main_window()                  # Treeview + Buttons etc.
        self._update_otps()                        # Erste OTP‑Berechnung & Timer starten

        # ────────────────────────────────────────────────────────
        # 5. Inaktivitäts‑Tracking: jedes UI‑Ereignis aktualisiert den Zeitstempel
        # ────────────────────────────────────────────────────────
        self.last_activity = time.time()           # Startzeit
        self.inactivity_timeout = 5 * 60           # 5 Minuten

        # Bindings für Tastatur, Mausklick & Mausbewegung
        self.root.bind_all("<Key>",      self._update_last_activity)
        self.root.bind_all("<Button-1>", self._update_last_activity)
        self.root.bind_all("<Motion>",   self._update_last_activity)

        # ────────────────────────────────────────────────────────
        # 6. Periodischen Timeout‑Check starten (alle 5 Sekunden)
        # ────────────────────────────────────────────────────────
        self._check_inactivity()

        # ────────────────────────────────────────────────────────
        # 7. Tkinter‑Hauptloop – läuft bis die Anwendung geschlossen wird
        # ────────────────────────────────────────────────────────
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logging.info("Programm wird beendet.")

    # ────────────────────────────────────────────────────────
    # 1. Inaktivität überwachen
    # ────────────────────────────────────────────────────────
    def _update_last_activity(self, event=None) -> None:
        """Jedes UI‑Ereignis ruft diese Methode auf – setzt den Zeitstempel."""
        self.last_activity = time.time()

    def _check_inactivity(self) -> None:
        """
        Wird alle 5 Sekunden aufgerufen.
        Prüft die Inaktivität und sperrt die App, wenn das Timeout überschritten wurde.

        Ablauf bei Timeout:
          1. Hauptfenster vollständig verstecken (root.withdraw()).
          2. Ein **modaler** Login‑Dialog wird angezeigt – der Rest der Anwendung ist
             dadurch blockiert.
          3. Bei erfolgreicher Authentifizierung werden die Konten neu geladen,
             der abgeleitete Schlüssel in einer privaten Variable gespeichert und
             danach sofort gelöscht, die UI aktualisiert und das Fenster wieder eingeblendet.
          4. Falls der Nutzer abbricht, wird die App beendet.
        """
        if (time.time() - self.last_activity) > self.inactivity_timeout:
            # ---------- 1. Fenster verstecken ----------
            self.root.withdraw()

            # ---------- 2. Passwort‑Dialog (modal) ----------
            messagebox.showinfo(
                "Sicherheit",
                f"Nach {self.inactivity_timeout // 60} Minuten Inaktivität erneut anmelden!"
            )

            success = False
            while not success:
                pwd = simpledialog.askstring(
                    "Passwort eingeben",
                    "Bitte Master‑Password:",
                    parent=self.root,
                    show="*"
                )
                if pwd is None:  # Benutzer hat Abbruch gewählt
                    self.root.destroy()
                    exit()

                try:
                    accounts, salt = self.data_store.load(pwd)
                    self.accounts = accounts
                    self.salt = salt

                    # --- Schlüssel abgeleiten und temporär speichern -------------
                    derived_key = CryptoHelper.derive_key(pwd, salt)
                    self.__derived_key = derived_key  # private Variable
                    del derived_key  # sofort löschen

                    success = True
                except Exception as exc:
                    messagebox.showerror("Fehler", f"Login fehlgeschlagen: {exc}")

            # ---------- 3. UI neu aufbauen ----------
            self._refresh_tree()
            self.root.deiconify()  # Fenster wieder sichtbar

        # ---------- 4. Nächsten Check planen (alle 5 Sekunden) ----------
        self.root.after(5000, self._check_inactivity)

    # ----------------------------------------------------------------------
    # Methode zum Anpassen der Schriftgröße (intern & UI‑Update)
    # ----------------------------------------------------------------------
    def _apply_global_font(self, size: int) -> None:
        """
        Setzt die globale Standardschriftgröße für alle Tkinter‑ und ttk‑Widgets.
        Die Größe wird in Punkten angegeben; Werte zwischen 8 und 24 sind sinnvoll.
        """
        self._font_size = max(8, min(24, size))

        # Tkinter‑Standardfonts (Labels, Buttons, Menüs, Text etc.)
        tkfont.nametofont("TkDefaultFont").configure(size=self._font_size)
        tkfont.nametofont("TkMenuFont").configure(size=self._font_size)
        tkfont.nametofont("TkTextFont").configure(size=self._font_size)

        # ttk‑Widgets – Theme‑Fonts anpassen
        style = ttk.Style()
        style.configure(".", font=("Arial", self._font_size))
        # Zeilenhöhe der Treeview etwas skalieren, damit die Zeile nicht zu klein wird
        rowheight = int(self._font_size * 1.6)
        style.configure("Treeview", rowheight=rowheight)

    def _increase_font(self) -> None:
        """Vergrößert die Schriftgröße um einen Punkt."""
        self._apply_global_font(self._font_size + 1)

    def _decrease_font(self) -> None:
        """Verschlechtert die Schriftgröße um einen Punkt."""
        self._apply_global_font(self._font_size - 1)

    # --------------------------------------------------------------------- #
    # Login / Setup
    # --------------------------------------------------------------------- #

    def _login_dialog(self) -> None:
        """
        Zeigt einen Dialog zur Eingabe des Master‑Passwords an.
        Lädt die Accounts, wenn das Passwort korrekt ist.
        Der abgeleitete Schlüssel wird in einer privaten Variable gespeichert
        und danach sofort gelöscht (nach erfolgreichem Login).
        """
        while True:
            pwd = simpledialog.askstring(
                "2FA",
                "Bitte gib dein Master‑Passwort ein:",
                parent=self.root,
                show="*",
            )
            if pwd is None:          # Benutzer hat Abbrechen gedrückt
                self.root.destroy()
                exit()

            try:
                accounts, salt = self.data_store.load(pwd)
                self.master_password = pwd
                self.salt = salt
                self.accounts = accounts

                # --- Schlüssel abgeleiten und temporär speichern -------------
                derived_key = CryptoHelper.derive_key(pwd, salt)
                self.__derived_key = derived_key     # private Variable
                del derived_key                     # sofort löschen

                break
            except ValueError as exc:
                messagebox.showerror("Fehler", str(exc))
            except Exception as exc:
                messagebox.showerror("Unbekannter Fehler", f"{exc}")

    def _setup_new_master(self) -> None:
        """
        Erstellt ein neues Master‑Password und initialisiert die Datenbank.
        Der Benutzer muss das Passwort zweimal eingeben, um Tippfehler zu vermeiden.
        """
        while True:
            pwd1 = simpledialog.askstring(
                "Master‑Passwort festlegen",
                "Bitte gib ein neues Master‑Passwort ein:",
                parent=self.root,
                show="*",
            )
            if pwd1 is None:
                self.root.destroy()
                exit()

            pwd2 = simpledialog.askstring(
                "Bestätigung",
                "Noch einmal: Passwort eingeben:",
                parent=self.root,
                show="*"
            )
            if pwd2 is None:
                self.root.destroy()
                exit()

            if pwd1 != pwd2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                continue

            # Alles ok – Datenbank anlegen
            self.master_password = pwd1
            self.salt = os.urandom(SALT_SIZE)
            self.accounts = []
            self.data_store.save(pwd1, [], self.salt)
            break

    # --------------------------------------------------------------------- #
    # GUI‑Erstellung
    # --------------------------------------------------------------------- #

    def _build_main_window(self) -> None:
        """Stellt das Hauptfenster und sämtliche Widgets zusammen."""
        self.root.deiconify()
        self.root.title("2FA Authenticator")

        menubar = tk.Menu(self.root)

        # Einstellungsmenü (Master‑Passwort ändern)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(
            label="Master‑Passwort ändern",
            command=self._change_master_password,
        )
        menubar.add_cascade(label="Einstellungen", menu=settings_menu)

        # ----------  Schriftgröße ----------
        display_menu = tk.Menu(menubar, tearoff=0)
        display_menu.add_command(
            label="Schriftgröße vergrößern",
            command=self._increase_font,
        )
        display_menu.add_command(
            label="Schriftgröße verkleinern",
            command=self._decrease_font,
        )
        menubar.add_cascade(label="Anzeige", menu=display_menu)
        # ------------------------------------

        # Datenmenü (Import/Export)
        data_menu = tk.Menu(menubar, tearoff=0)
        data_menu.add_command(
            label="Exportieren…",
            command=self._export_data,
        )
        data_menu.add_command(
            label="Importieren…",
            command=self._import_data,
        )
        menubar.add_cascade(label="Daten", menu=data_menu)

        self.root.config(menu=menubar)

        # Countdown‑Label
        self.countdown_label = ttk.Label(
            self.root,
            text=f"Wechsel in {self.remaining}s",
            font=("Arial", 16),
        )
        self.countdown_label.pack(pady=5)

        # Suchfeld für Live‑Filterung der Accounts
        search_frame = ttk.Frame(self.root, padding=(10, 0))
        search_frame.pack(fill=tk.X)

        ttk.Label(search_frame, text="Suche:").pack(side=tk.LEFT, padx=5)

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Beim Schreiben in das Suchfeld wird der Filter angewendet
        self.search_var.trace_add("write", lambda *args: self._apply_search_filter())

        # Hauptbereich mit Treeview (Liste der Accounts)
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            frame,
            columns=("account", "firma", "info", "code"),  # neue Spalte „Firma“
            show="headings",
            height=15,
        )

        # Beschriftungen und Breiten der Spalten
        for col, (text, width) in (
                ("account", ("Account", 150)),
                ("firma", ("Firma", 120)),  # neue Spalte
                ("info", ("Information", 200)),
                ("code", ("TOTP", 80)),
        ):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.tree.configure(yscrollcommand=vsb.set)

        # Button‑Bereich (Hinzufügen/Löschen)
        btn_frame = ttk.Frame(self.root, padding=(10, 0))
        btn_frame.pack(fill=tk.X)

        add_btn = ttk.Button(
            btn_frame,
            text="Account hinzufügen",
            command=self._add_account_dialog,
        )
        add_btn.pack(side=tk.LEFT, padx=5)

        del_btn = ttk.Button(
            btn_frame,
            text="Account löschen",
            command=self._delete_selected_account,
        )
        del_btn.pack(side=tk.LEFT, padx=5)

        # Kontext‑Menü und Klick‑Handler für die Treeview
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self._refresh_tree()

    def _apply_search_filter(self) -> None:
        """
        Filtert die angezeigten Accounts anhand des Suchtextes.
        Der Filter berücksichtigt Name, Firma und Info.
        """
        pattern = self.search_var.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)

        for idx, acct in enumerate(self.accounts):
            if pattern and not (
                    pattern in acct.name.lower()
                    or pattern in acct.firma.lower()  # neue Filterbedingung
                    or pattern in acct.info.lower()
            ):
                continue

            self.tree.insert("", "end", iid=str(idx),
                             values=(acct.name, acct.firma, acct.info, "***"))

    def _entry_from_account(self, acct: Account) -> dict[str, object]:
        """
        Konvertiert ein Account‑Objekt in das Export‑Format (Google Authenticator).

        Parameters
        ----------
        acct : Account

        Returns
        -------
        dict
            Dictionary im erwarteten JSON‑Schema.
        """
        return {
            "type": "totp",
            "uuid": str(uuid.uuid4()),
            "name": acct.name,
            "issuer": acct.firma,                 # hier wird die Firma exportiert
            "note": acct.info,
            "favorite": False,
            "icon": None,
            "info": {
                "secret": acct.secret,
                "algo": acct.hash_algo.upper(),
                "digits": acct.digits,
                "period": COUNTDOWN_START,
            },
            "groups": [],
        }

    # --------------------------------------------------------------------- #
    # Import / Export
    # --------------------------------------------------------------------- #

    def _export_data(self) -> None:
        """Exportiert die Accounts als JSON, optional verschlüsselt."""
        if not self.master_password or not self.salt:
            messagebox.showerror("Fehler", "Keine Master‑Passwort‑Informationen vorhanden.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Exportieren – Ziel wählen",
            defaultextension=".json",
            filetypes=[("JSON‑Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not save_path:
            return

        encrypt = messagebox.askyesno(
            "Exportieren",
            "Soll die Datei verschlüsselt werden?",
            icon="question"
        )

        entries = [self._entry_from_account(a) for a in self.accounts]

        export_obj: dict[str, object] = {
            "version": 1,
            "header": {"slots": None, "params": None},
            "db": {"entries": entries},
        }

        try:
            if encrypt:
                key = CryptoHelper.derive_key(self.master_password, self.salt)
                plaintext_bytes = json.dumps(export_obj).encode()
                ciphertext_b64 = CryptoHelper.encrypt(plaintext_bytes, key)

                final_obj = {
                    "salt": base64.urlsafe_b64encode(self.salt).decode(),
                    "data": ciphertext_b64,
                }

                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(final_obj, f, indent=2)
            else:
                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(export_obj, f, indent=2)

            messagebox.showinfo(
                "Exportieren",
                f"Datei erfolgreich gespeichert: {save_path}"
            )
        except Exception as exc:
            messagebox.showerror("Fehler beim Export", str(exc))

    def _account_from_external(self, entry: dict) -> Account:
        """
        Konvertiert einen Eintrag aus einer externen Datei in ein :class:`Account`.

        Parameters
        ----------
        entry : dict
            Dictionary mit den Schlüsseln ``name``, ``note`` usw.

        Returns
        -------
        Account
        """
        info = entry.get("info", {})
        return Account(
            name=entry.get("name") or "",
            info=entry.get("note") or "",          # Feld „note“ wird als info übernommen
            firma=entry.get("issuer") or "",       # hier die Firma aus dem Export
            secret=info.get("secret", ""),
            hash_algo=info.get("algo", DEFAULT_HASH).lower(),
            digits=int(info.get("digits", DEFAULT_DIGITS)),
        )

    def _import_data(self) -> None:
        """Importiert Accounts aus einer JSON‑Datei – unterstützt optional verschlüsselte Exporte.

        Wenn die Datei verschlüsselt ist, wird zunächst mit dem aktuell eingestellten Master‑Passwort
        entschlüsselt. Scheitert das (z. B. weil ein anderes Passwort verwendet wurde),
        fragt die Methode den Benutzer nach einem neuen Passwort und wiederholt den Vorgang,
        bis der Entschlüsselungsversuch erfolgreich ist oder der Benutzer abbricht.
        """
        # ------------------------------------------------------------------
        # 1. Sicherstellen, dass ein Master‑Passwort bereits vorhanden ist
        # ------------------------------------------------------------------
        if not self.master_password or not self.salt:
            messagebox.showerror("Fehler", "Keine Master‑Passwort‑Informationen vorhanden.")
            return

        # ------------------------------------------------------------------
        # 2. Datei auswählen
        # ------------------------------------------------------------------
        import_path = filedialog.askopenfilename(
            title="Importieren – Quelle wählen",
            defaultextension=".json",
            filetypes=[("JSON‑Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not import_path:
            return

        # ------------------------------------------------------------------
        # 3. Datei einlesen
        # ------------------------------------------------------------------
        try:
            with open(import_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as exc:
            messagebox.showerror("Fehler beim Laden", str(exc))
            return

        # ------------------------------------------------------------------
        # 4. Prüfen ob es sich um ein verschlüsseltes Export‑Format handelt
        #    und ggf. mit (eventuell neu eingegebenem) Passwort entschlüsseln.
        # ------------------------------------------------------------------
        if isinstance(raw, dict) and {"salt", "data"} <= raw.keys():
            export_salt = base64.urlsafe_b64decode(raw["salt"])
            while True:
                try:
                    key = CryptoHelper.derive_key(self.master_password, export_salt)
                    plaintext_bytes = CryptoHelper.decrypt(raw["data"], key)
                    # Entschlüsselung erfolgreich – weiterarbeiten
                    raw = json.loads(plaintext_bytes.decode())
                    break
                except ValueError as exc:  # InvalidToken -> falsches Passwort
                    pwd_new = simpledialog.askstring(
                        "Passwort für verschlüsselte Datei",
                        "Das aktuelle Master‑Passwort kann die Datei nicht entschlüsseln.\n"
                        "Bitte geben Sie ein anderes Passwort ein:",
                        parent=self.root,
                        show="*",
                    )
                    if pwd_new is None:  # Benutzer hat Abbruch gewählt
                        return
                    self.master_password = pwd_new  # Neues Passwort ausprobieren

        # ------------------------------------------------------------------
        # 5. Jetzt ist 'raw' entweder ein Export‑Objekt (dict mit db/entries) oder
        #    eine alte Liste von Account‑Dictionaries.
        # ------------------------------------------------------------------
        if isinstance(raw, dict) and "db" in raw and "entries" in raw.get("db", {}):
            entries = raw["db"]["entries"]
            try:
                imported_accounts = [
                    self._account_from_external(entry)
                    for entry in entries
                    if entry.get("type") == "totp"
                ]
            except Exception as exc:
                messagebox.showerror("Fehler bei der Konvertierung", str(exc))
                return
        else:  # alt‑Format (Liste von dicts)
            if not isinstance(raw, list):
                messagebox.showerror(
                    "Ungültiges Format",
                    "Die Datei enthält keine Account‑Liste.",
                )
                return
            imported_accounts = [Account.from_dict(a) for a in raw]

        # ------------------------------------------------------------------
        # 6. Benutzer entscheiden lassen – ersetzen oder anhängen
        # ------------------------------------------------------------------
        replace = messagebox.askyesno(
            "Import",
            "Möchten Sie die vorhandenen Accounts vollständig ersetzen?\n"
            "(Nein = neue Accounts hinzufügen\nGleicher Name+Info → werden ersetzt!)",
            icon="question",
        )

        if replace:
            self.accounts = imported_accounts
        else:
            existing_keys = {(a.name, a.info) for a in self.accounts}
            new_unique = [
                a for a in imported_accounts if (a.name, a.info) not in existing_keys
            ]
            self.accounts.extend(new_unique)

        # ------------------------------------------------------------------
        # 7. Datenbank speichern (immer mit aktuellem Master‑Passwort & Salt)
        # ------------------------------------------------------------------
        try:
            self.data_store.save(self.master_password, self.accounts, self.salt)
        except Exception as exc:
            messagebox.showerror("Fehler beim Speichern", str(exc))
            return

        # ------------------------------------------------------------------
        # 8. UI aktualisieren
        # ------------------------------------------------------------------
        self._refresh_tree()
        messagebox.showinfo(
            "Importieren",
            f"Erfolgreich importiert.\n{len(imported_accounts)} Accounts.",
        )

    # --------------------------------------------------------------------- #
    # Master‑Password ändern
    # --------------------------------------------------------------------- #

    def _change_master_password(self) -> None:
        """
        Ermöglicht dem Benutzer, das Master‑Passwort zu ändern.
        Das Salt wird neu generiert und die Datenbank verschlüsselt neu geschrieben.
        """
        pwd_current = simpledialog.askstring(
            "Master‑Passwort ändern",
            "Geben Sie Ihr aktuelles Master‑Passwort ein:",
            parent=self.root,
            show="*",
        )
        if pwd_current is None:
            return

        if pwd_current != self.master_password:
            messagebox.showerror("Fehler", "Falsches Passwort.")
            return

        while True:
            new_pwd1 = simpledialog.askstring(
                "Master‑Passwort ändern",
                "Geben Sie ein neues Master‑Passwort ein:",
                parent=self.root,
                show="*",
            )
            if new_pwd1 is None:
                return

            new_pwd2 = simpledialog.askstring(
                "Bestätigung",
                "Noch einmal: Passwort eingeben:",
                parent=self.root,
                show="*",
            )
            if new_pwd2 is None:
                return

            if new_pwd1 != new_pwd2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
                continue

            # Alles ok – neues Salt und Datenbank neu speichern
            self.master_password = new_pwd1
            self.salt = os.urandom(SALT_SIZE)
            self.data_store.save(self.master_password, self.accounts, self.salt)
            messagebox.showinfo("Erfolg", "Master‑Passwort erfolgreich geändert.")
            break

    # --------------------------------------------------------------------- #
    # Treeview‑Management & OTP‑Anzeige
    # --------------------------------------------------------------------- #

    def _refresh_tree(self) -> None:
        """Lädt die Accounts in die Treeview (ohne aktuelle OTPs)."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, acct in enumerate(self.accounts):
            self.tree.insert("", "end", iid=str(idx),
                             values=(acct.name, acct.firma, acct.info, "***"))

    def _update_otps(self) -> None:
        """
        Aktualisiert den Countdown‑Timer und ruft sich selbst alle 1 Sekunde erneut auf.
        """
        self.remaining = COUNTDOWN_START - (int(time.time()) % COUNTDOWN_START)
        self.countdown_label.config(text=f"Wechsel in {self.remaining}s")
        self.root.after(1000, self._update_otps)

    def _add_account_dialog(self) -> None:
        """Öffnet ein Dialogfenster zum Hinzufügen eines neuen Accounts."""
        dialog = AddAccountDialog(self.root)
        self.root.wait_window(dialog)
        if dialog.result is None:
            return

        name, info, firma, secret, hash_algo, digits = dialog.result
        if not (name and info and firma and secret):
            messagebox.showerror("Fehler", "Alle Felder müssen ausgefüllt sein.")
            return

        # Prüfen ob Secret gültig ist (TOTP‑Berechnung)
        try:
            pyotp.TOTP(secret, digits=digits, digest=getattr(hashlib, hash_algo)).now()
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc))
            return

        self.accounts.append(
            Account(name=name, info=info, firma=firma, secret=secret,
                    hash_algo=hash_algo, digits=digits)
        )
        self.data_store.save(self.master_password, self.accounts, self.salt)
        self._refresh_tree()

    def _delete_selected_account(self) -> None:
        """Löscht den aktuell ausgewählten Account."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Kein Account ausgewählt.")
            return

        idx = int(selected[0])
        acct = self.accounts[idx]
        confirm = messagebox.askyesno(
            "Bestätigung",
            f"Account '{acct.name}' ({acct.info}) wirklich löschen?",
        )
        if not confirm:
            return

        del self.accounts[idx]
        self.data_store.save(self.master_password, self.accounts, self.salt)
        self._refresh_tree()

    def _edit_selected_account(self, idx: int) -> None:
        """Öffnet ein Dialogfenster zum Bearbeiten eines Accounts."""
        acct = self.accounts[idx]

        dialog = EditAccountDialog(self.root, acct)
        self.root.wait_window(dialog)
        if dialog.result is None:
            return

        name, info, firma, secret, hash_algo, digits = dialog.result
        try:
            pyotp.TOTP(secret, digits=digits,
                       digest=getattr(hashlib, hash_algo)).now()
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc))
            return

        self.accounts[idx] = Account(name=name, info=info, firma=firma,
                                    secret=secret, hash_algo=hash_algo, digits=digits)
        self.data_store.save(self.master_password, self.accounts, self.salt)
        self._refresh_tree()

    def _on_tree_click(self, event) -> None:
        """
        Zeigt das OTP an, wenn die Code‑Spalte geklickt wird.
        Der Code wird 5 Sekunden lang im Feld angezeigt und anschließend
        wieder ausgeblendet. Außerdem wird er in die Zwischenablage kopiert.
        """
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return

        column = self.tree.identify_column(event.x)
        if column != "#4":  # nur die Code‑Spalte
            return

        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        idx = int(row_id)
        acct = self.accounts[idx]
        totp_code = pyotp.TOTP(
            acct.secret,
            digits=acct.digits,
            digest=getattr(hashlib, acct.hash_algo),
        ).now()

        # Code in die Treeview eintragen
        self.tree.set(row_id, "code", totp_code)

        # In Zwischenablage kopieren
        self.root.clipboard_clear()
        self.root.clipboard_append(totp_code)

        # Nach 5 Sekunden wieder ausblenden
        self.root.after(5000, lambda: self._reveal_back(idx))

    def _reveal_back(self, idx: int) -> None:
        """Setzt die Code‑Spalte zurück auf „***“."""
        row_id = str(idx)
        if not self.tree.exists(row_id):
            return
        self.tree.set(row_id, "code", "***")
        self.root.clipboard_clear()  # zusätzlich Clipboard leeren

    def _show_context_menu(self, event) -> None:
        """Kontext‑Menü beim Rechtsklick in der Treeview anzeigen."""
        selected_item = self.tree.identify_row(event.y)
        if not selected_item:
            return

        idx = int(selected_item)

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Bearbeiten", command=lambda: self._edit_selected_account(idx))
        menu.post(event.x_root, event.y_root)

# --------------------------------------------------------------------------- #
# Dialoge – Account‑Eintrag
# --------------------------------------------------------------------------- #

class AccountDialog(tk.Toplevel):
    """
    Basisdialog zum Eingeben eines Accounts.

    Unterklassen können das Verhalten für “Hinzufügen” bzw. “Bearbeiten”
    leicht anpassen (z. B. Voreinstellungen, Sichtbarkeit des Secrets).
    """

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self.title("Account")
        self.grab_set()
        self.resizable(False, False)

        # --- Felder -------------------------------------------------------- #
        ttk.Label(self, text="Kontoname:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.name_entry = ttk.Entry(self, width=30)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self, text="Information:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.info_entry = ttk.Entry(self, width=30)
        self.info_entry.grid(row=1, column=1, padx=5, pady=5)

        # Neues Feld für Firma/Issuer
        ttk.Label(self, text="Firma (Issuer):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.firma_entry = ttk.Entry(self, width=30)
        self.firma_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(self, text="TOTP‑Schlüssel:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.secret_entry = ttk.Entry(self, width=30)
        self.secret_entry.grid(row=3, column=1, padx=5, pady=5)


        ttk.Label(self, text="Hash‑Algorithmus:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.hash_var = tk.StringVar(value=DEFAULT_HASH)
        hash_cb = ttk.Combobox(
            self,
            textvariable=self.hash_var,
            values=list(HASH_OPTIONS),
            state="readonly",
            width=28,
        )
        hash_cb.grid(row=5, column=1, padx=5, pady=5)

        ttk.Label(self, text=f"Ziffern ({DEFAULT_DIGITS}):").grid(row=6, column=0, padx=5, pady=5, sticky="e")
        self.digits_spin = ttk.Spinbox(self, from_=4, to=8, width=28)
        self.digits_spin.set(str(DEFAULT_DIGITS))
        self.digits_spin.grid(row=6, column=1, padx=5, pady=5)

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=10)

        ok_btn = ttk.Button(btn_frame, text="OK", command=self._ok)
        ok_btn.pack(side=tk.LEFT, padx=5)
        cancel_btn = ttk.Button(btn_frame, text="Abbrechen", command=self.destroy)
        cancel_btn.pack(side=tk.LEFT, padx=5)

        # Ergebnis (kann später abgerufen werden)
        self.result: Tuple[str, str, str, str, str, int] | None = None


    def _ok(self) -> None:
        """Validiert die Eingaben und speichert sie im Ergebnisattribut."""
        name = self.name_entry.get().strip()
        info = self.info_entry.get().strip()
        firma = self.firma_entry.get().strip()
        secret = self.secret_entry.get().strip()
        hash_algo = self.hash_var.get()
        digits = int(self.digits_spin.get())

        if not (name and info and firma and secret):
            messagebox.showerror("Fehler", "Alle Felder müssen ausgefüllt sein.")
            return

        # Prüfen ob Secret gültig ist
        try:
            pyotp.TOTP(secret, digits=digits,
                       digest=getattr(hashlib, hash_algo)).now()
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc))
            return

        self.result = (name, info, firma, secret, hash_algo, digits)
        self.destroy()


class AddAccountDialog(AccountDialog):
    """Dialog zum Hinzufügen eines neuen Accounts – nutzt die Basisklasse."""
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self.title("Neuer Account")


class EditAccountDialog(AddAccountDialog):
    """
    Dialog zum Bearbeiten eines bestehenden Accounts.
    Zeigt das Secret als Maskierung an und kann es im Detail anzeigen.
    """

    def __init__(self, parent: tk.Widget, account: Account) -> None:
        super().__init__(parent)

        # Vorbefüllung der Felder
        self.name_entry.delete(0, tk.END)
        self.name_entry.insert(0, account.name)

        self.info_entry.delete(0, tk.END)
        self.info_entry.insert(0, account.info)

        # Firma setzen
        self.firma_entry.delete(0, tk.END)
        self.firma_entry.insert(0, account.firma)

        # Secret verwalten – erst als Maskierung anzeigen
        self.original_secret = account.secret

        self.hash_var.set(account.hash_algo)
        self.digits_spin.set(str(account.digits))

        # Checkbox zum Anzeigen des Secrets
        self.show_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(
            self,
            text="Schlüssel anzeigen?",
            variable=self.show_var,
            command=self._toggle_show_secret,
        )
        show_cb.grid(row=3, column=2, columnspan=2, pady=(5, 10))

        # Secret‑Feld – maskiert
        self.secret_entry.delete(0, tk.END)
        self.secret_entry.insert(0, "*" * len(self.original_secret))

    def _toggle_show_secret(self) -> None:
        """Schaltet zwischen Maskierung und Klartext des Secrets."""
        if self.show_var.get():
            self.secret_entry.delete(0, tk.END)
            self.secret_entry.insert(0, self.original_secret)
        else:
            self.secret_entry.delete(0, tk.END)
            self.secret_entry.insert(0, "*" * len(self.original_secret))

    def _ok(self) -> None:
        """Validiert die Eingaben und speichert sie im Ergebnisattribut."""
        name = self.name_entry.get().strip()
        info = self.info_entry.get().strip()
        firma = self.firma_entry.get().strip()
        hash_algo = self.hash_var.get()
        digits = int(self.digits_spin.get())

        if not (name and info and firma):
            messagebox.showerror("Fehler", "Alle Felder müssen ausgefüllt sein.")
            return

        # Secret bleibt unverändert, es wird aber auf Gültigkeit geprüft
        try:
            pyotp.TOTP(
                self.original_secret,
                digits=digits,
                digest=getattr(hashlib, hash_algo),
            ).now()
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc))
            return

        self.result = (name, info, firma, self.original_secret, hash_algo, digits)
        self.destroy()


if __name__ == "__main__":
    AuthenticatorApp()
