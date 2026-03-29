#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
2FA Authenticator :: TOTP – Desktop‑Anwendung

Dieses Skript implementiert einen einfachen TOTP‑Authenticator mit
verschlüsselter Persistenz, Import/Export‑Fähigkeit und einer Tkinter‑GUI.
Alle Daten werden in einer JSON‑Datei verschlüsselt gespeichert.
Das Master‑Passwort wird mithilfe von Argon2 (KDF) in einen Schlüssel
umgewandelt, der dann die AES‑GCM‑Verschlüsselung steuert.

Die Hauptkomponenten:
    * :class:`Account`          – Datensatz für ein TOTP‑Konto.
    * :class:`CryptoHelper`     – Krypto‑Hilfsfunktionen (Key‑Derivation,
      Verschlüsseln/Entschlüsseln).
    * :class:`DataStore`        – Lese-/Schreibvorgänge zur verschlüsselten JSON‑Datei.
    * :class:`AuthenticatorApp` – Tkinter‑basierte GUI und Anwendungslogik.
    * :class:`AccountDialog`    – Basisdialog für Account‑Eingabe (Add/Edit).
    * :class:`EditAccountDialog`– Spezialisierung für das Bearbeiten bestehender Accounts.
    * :class:`SnippingTool`     – Transparentes Overlay für QR‑Code‑Screenshot‑Scan.

install: pip install pyotp cryptography argon2-cffi

-----------------------------------------------------------------------------------

Author      : Waldemar Koch
Created     : 2025-08-09
Last Update : 2026-03-29
Version     : 1.2.0
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
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import pyotp
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, simpledialog, filedialog

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- DPI-Anpassung für Windows ---
# Ohne diesen Block stimmen auf HiDPI-Monitoren die Screenshot-Koordinaten
# nicht mit den Canvas-Koordinaten überein → ImageGrab schneidet falsche Stelle aus.
import platform
if platform.system() == "Windows":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


# QR-Code Scan Support (optional – benötigt Pillow und pyzbar)
try:
    from PIL import ImageGrab, Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as _pyzbar_decode
    _PYZBAR_AVAILABLE = True
except ImportError:
    _PYZBAR_AVAILABLE = False

QR_SCAN_AVAILABLE = _PIL_AVAILABLE and _PYZBAR_AVAILABLE


# --------------------------------------------------------------------------- #
# Konfiguration – alles in Großbuchstaben
# --------------------------------------------------------------------------- #

DATA_FILE = Path("authenticator_data.json")

SALT_SIZE         = 32        # Bytes für den KDF‑Salt (Standard, nicht ändern)
# ACHTUNG: Diese 3 Variablen steuern die Verschlüsselungsstärke! ARGON_TIME_COST, ARGON_MEMORY_COST, ARGON_PARALLELISM
ARGON_TIME_COST   = 20        # CPU‑Kosten für Argon2
ARGON_MEMORY_COST = 1024 * 1024  # 1 GiB
# Feste Zahl – so wird das Masterpasswort auf verschiedenen Geräten gleich berechnet
ARGON_PARALLELISM = 4         # 4 Threads – auf jedem modernen Gerät verfügbar

COUNTDOWN_START   = 30        # Sekunden bis zum nächsten Codewechsel

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
# Hilfsfunktionen (Modul-Ebene)
# --------------------------------------------------------------------------- #

def _validate_totp(secret: str, digits: int, hash_algo: str) -> None:
    """
    Prüft ob ein TOTP‑Secret gültig ist, indem einmalig ein Code berechnet wird.

    Args:
        secret:    Base32‑kodiertes TOTP‑Secret.
        digits:    Anzahl der OTP‑Ziffern.
        hash_algo: Name des Hash‑Algorithmus (z. B. ``"sha1"``).

    Raises:
        Exception: Wenn das Secret ungültig ist oder die TOTP‑Berechnung fehlschlägt.
    """
    pyotp.TOTP(secret, digits=digits, digest=getattr(hashlib, hash_algo)).now()


def _set_entry(entry: ttk.Entry, value: str) -> None:
    """
    Setzt den Inhalt eines ttk.Entry‑Feldes (löscht zuerst, dann einfügen).

    Args:
        entry: Das Entry‑Widget.
        value: Der neue Wert.
    """
    entry.delete(0, tk.END)
    entry.insert(0, value)


def _decode_qr(pil_img) -> list[str]:
    """
    Dekodiert QR‑Codes aus einem PIL‑Image mittels pyzbar.

    Args:
        pil_img: Ein PIL‑Image‑Objekt (RGB oder L).

    Returns:
        Liste der dekodierten UTF-8‑Strings. Leer, wenn kein Code gefunden.
    """
    if not _PYZBAR_AVAILABLE:
        return []
    try:
        return [obj.data.decode("utf-8") for obj in _pyzbar_decode(pil_img)]
    except Exception:
        return []


def _ask_confirmed_password(
    parent: tk.Widget,
    title: str = "Passwort festlegen",
    prompt_first: str = "Neues Passwort eingeben:",
    prompt_confirm: str = "Noch einmal: Passwort eingeben:",
    allow_cancel: bool = True,
) -> Optional[str]:
    """
    Fragt zweimal nach einem Passwort und gibt es zurück, wenn beide übereinstimmen.
    Bei Abbruch wird ``None`` zurückgegeben (sofern ``allow_cancel=True``).
    Bei ``allow_cancel=False`` wird ``sys.exit()`` aufgerufen (für Initialisierung).

    Args:
        parent:         Tkinter‑Parent‑Widget.
        title:          Fenstertitel für beide Dialoge.
        prompt_first:   Aufforderungstext für die erste Eingabe.
        prompt_confirm: Aufforderungstext für die Bestätigung.
        allow_cancel:   Ob Abbruch erlaubt ist (True) oder die App beendet (False).

    Returns:
        Das bestätigte Passwort, oder ``None`` bei Abbruch.
    """
    while True:
        pwd1 = simpledialog.askstring(title, prompt_first, parent=parent, show="*")
        if pwd1 is None:
            if allow_cancel:
                return None
            sys.exit()

        pwd2 = simpledialog.askstring("Bestätigung", prompt_confirm, parent=parent, show="*")
        if pwd2 is None:
            if allow_cancel:
                return None
            sys.exit()

        if pwd1 != pwd2:
            messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.")
            continue

        return pwd1


def _parse_otpauth_uri(uri: str) -> dict:
    """
    Parst einen ``otpauth://totp/...``‑URI und gibt ein Dict zurück.

    Returns:
        Dict mit den Schlüsseln ``secret``, ``issuer``, ``account``,
        ``digits`` und ``algorithm``. Leer, wenn der URI ungültig ist.
    """
    import urllib.parse
    result = {}
    if not uri.startswith("otpauth://totp/"):
        return result

    without_scheme = uri[len("otpauth://totp/"):]
    label_enc, query_str = (without_scheme.split("?", 1)
                            if "?" in without_scheme
                            else (without_scheme, ""))

    label = urllib.parse.unquote(label_enc)
    issuer_label, account = (label.split(":", 1) if ":" in label else ("", label))

    params = dict(urllib.parse.parse_qsl(query_str))
    result["account"]   = account.strip()
    result["issuer"]    = params.get("issuer", issuer_label).strip()
    result["secret"]    = params.get("secret", "").strip()
    result["digits"]    = int(params.get("digits", DEFAULT_DIGITS))
    result["algorithm"] = params.get("algorithm", DEFAULT_HASH).lower()
    return result


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
    name:      str
    info:      str
    firma:     str
    secret:    str
    hash_algo: str = DEFAULT_HASH
    digits:    int = DEFAULT_DIGITS

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
            Enthält die Schlüssel ``name``, ``info``, ``firma``, ``secret`` usw.
        """
        return Account(
            name=data["name"],
            info=data.get("info", ""),
            firma=data.get("firma", ""),
            secret=data["secret"],
            hash_algo=data.get("hash_algo", DEFAULT_HASH),
            digits=int(data.get("digits", DEFAULT_DIGITS)),
        )


# --------------------------------------------------------------------------- #
# CryptoHelper – AES‑GCM
# --------------------------------------------------------------------------- #

class CryptoHelper:
    """Hilfsklasse für Kryptografie‑Operationen (Key‑Derivation, AEAD)."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Leitet einen 256‑Bit‑Schlüssel aus Passwort und Salt ab (Argon2id).

        Args:
            password: Master‑Passwort.
            salt:     32‑Byte‑Salt.

        Returns:
            bytes: 32‑Byte raw Key für AESGCM.
        """
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=ARGON_TIME_COST,
            memory_cost=ARGON_MEMORY_COST,
            parallelism=ARGON_PARALLELISM,
            hash_len=32,
            type=Type.ID,
        )

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> str:
        """
        Verschlüsselt ``plaintext`` mit AES‑GCM.
        Das Ergebnis ist ein Base64‑kodierter String (Nonce | Ciphertext).

        Args:
            plaintext: Klartext in Bytes.
            key:       32‑Byte raw Key (aus :meth:`derive_key`).

        Returns:
            str: Base64‑String (Nonce | Ciphertext).
        """
        nonce = os.urandom(12)          # GCM‑Standard: 12 Byte Nonce
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return base64.urlsafe_b64encode(nonce + ct).decode()

    @staticmethod
    def decrypt(ciphertext_b64: str, key: bytes) -> bytes:
        """
        Entschlüsselt einen Base64‑kodierten AES‑GCM‑Ciphertext (Nonce | Ciphertext).

        Args:
            ciphertext_b64: Verschlüsselte Daten aus :meth:`encrypt`.
            key:            32‑Byte raw Key.

        Returns:
            bytes: Klartext.

        Raises:
            ValueError: Wenn die Authentifizierung fehlschlägt (falsches Passwort
                        oder beschädigte Datei).
        """
        try:
            raw = base64.urlsafe_b64decode(ciphertext_b64)
            nonce, ct = raw[:12], raw[12:]
            return AESGCM(key).decrypt(nonce, ct, None)
        except Exception as exc:
            raise ValueError("Falsches Passwort oder beschädigte Datei.") from exc


# --------------------------------------------------------------------------- #
# DataStore
# --------------------------------------------------------------------------- #

class DataStore:
    """Verwaltet Lese- und Schreibvorgänge der verschlüsselten Datenbank."""

    def __init__(self, file_path: Path) -> None:
        self.file = file_path

    def load(self, password: str) -> Tuple[List[Account], bytes]:
        """
        Lädt die Accounts aus der verschlüsselten Datei.

        Ablauf:
          1. Existenz prüfen.
          2. JSON einlesen → enthält ``salt`` und ``data``.
          3. Salt dekodieren und Schlüssel mit Argon2 ableiten.
          4. AES‑GCM entschlüsseln.
          5. JSON in :class:`Account`‑Objekte umwandeln.

        Parameters
        ----------
        password : str
            Master‑Passwort des Benutzers.

        Returns
        -------
        tuple(list[Account], bytes)
            Geladene Konten und das verwendete Salt.
        """
        if not self.file.exists():
            raise FileNotFoundError("Datenbank existiert nicht.")

        with self.file.open(encoding="utf-8") as f:
            data = json.load(f)

        salt           = base64.urlsafe_b64decode(data["salt"])
        key            = CryptoHelper.derive_key(password, salt)
        plaintext      = CryptoHelper.decrypt(data["data"], key)
        raw_accounts   = json.loads(plaintext.decode())

        return [Account.from_dict(a) for a in raw_accounts], salt

    def save(self, password: str, accounts: List[Account], salt: bytes) -> None:
        """
        Speichert die Konten verschlüsselt in die JSON‑Datei (atomares Schreiben).

        Ablauf:
          1. Schlüssel mit Argon2 ableiten.
          2. Accounts als JSON‑Bytes serialisieren.
          3. AES‑GCM verschlüsseln.
          4. Salt + Ciphertext Base64‑kodiert in .tmp schreiben, dann atomar umbenennen.

        Parameters
        ----------
        password : str
            Master‑Passwort.
        accounts : list[Account]
            Alle zu speichernden Konten.
        salt : bytes
            Salt für die Schlüsselableitung.
        """
        key           = CryptoHelper.derive_key(password, salt)
        plaintext     = json.dumps([a.to_dict() for a in accounts]).encode()
        ciphertext_b64 = CryptoHelper.encrypt(plaintext, key)

        data_obj = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "data": ciphertext_b64,
        }
        tmp_path = self.file.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data_obj, f)
        os.replace(tmp_path, self.file)  # atomare Umbenennung → kein Datenverlust


# --------------------------------------------------------------------------- #
# AuthenticatorApp
# --------------------------------------------------------------------------- #

class AuthenticatorApp:
    """Hauptanwendung – Tkinter‑GUI und Logik für 2FA‑Authentifizierung."""

    def __init__(self) -> None:
        """
        Konstruktor: setzt die komplette Anwendung auf.

        Ablauf:
          1. Tkinter‑Fenster initialisieren (versteckt bis Login/Setup abgeschlossen).
          2. Schriftgröße, Countdown‑Timer und Datenbank‑Handler einrichten.
          3. Master‑Passwort holen – entweder Login oder Erstkonfiguration.
          4. UI aufbauen & OTP‑Updater starten.
          5. Inaktivitäts‑Tracking aktivieren (Key / Button / Motion).
          6. Periodischen Timeout‑Check starten.
        """
        # 1. Tkinter‑Fenster – zunächst versteckt
        self.root = tk.Tk()
        self.root.withdraw()

        # 2. UI‑Grundlagen
        self._font_size: int    = 10
        self.remaining:  int    = COUNTDOWN_START
        self.data_store          = DataStore(DATA_FILE)
        self.master_password: Optional[str]   = None
        self.salt:            Optional[bytes] = None
        self.accounts:        List[Account]   = []

        # 3. Login oder Ersteinrichtung
        if DATA_FILE.exists():
            self._login_dialog()
        else:
            self._setup_new_master()

        # 4. UI aufbauen
        self._apply_global_font(self._font_size)
        self.remaining = COUNTDOWN_START
        self._build_main_window()
        self._update_otps()

        # 5. Inaktivitäts‑Tracking
        self.last_activity     = time.time()
        self.inactivity_timeout = 5 * 60        # 5 Minuten

        for event in ("<Key>", "<Button-1>", "<Motion>"):
            self.root.bind_all(event, self._update_last_activity)

        # 6. Timeout‑Check starten
        self._check_inactivity()

        # 7. Tkinter‑Hauptloop
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logging.info("Programm wird beendet.")

    # ------------------------------------------------------------------ #
    # Inaktivitäts‑Management
    # ------------------------------------------------------------------ #

    def _on_close(self) -> None:
        """Fenster wird geschlossen – Anwendung sauber beenden."""
        self.root.destroy()

    def _update_last_activity(self, event=None) -> None:
        """Setzt den Inaktivitäts‑Zeitstempel auf jetzt."""
        self.last_activity = time.time()

    def _check_inactivity(self) -> None:
        """
        Wird alle 5 Sekunden aufgerufen.
        Sperrt die App nach Ablauf des Inaktivitäts‑Timeouts.

        Bei Timeout:
          1. Fenster verstecken.
          2. Modalen Login‑Dialog anzeigen.
          3. Bei Erfolg: Konten neu laden, UI aktualisieren, Fenster einblenden.
          4. Bei Abbruch: App beenden.
        """
        if (time.time() - self.last_activity) > self.inactivity_timeout:
            self.root.withdraw()
            messagebox.showinfo(
                "Sicherheit",
                f"Nach {self.inactivity_timeout // 60} Minuten Inaktivität erneut anmelden!",
            )

            while True:
                pwd = simpledialog.askstring(
                    "Passwort eingeben",
                    "Bitte Master‑Passwort:",
                    parent=self.root,
                    show="*",
                )
                if pwd is None:
                    self.root.destroy()
                    sys.exit()

                try:
                    accounts, salt = self.data_store.load(pwd)
                    self.accounts        = accounts
                    self.salt            = salt
                    self.master_password = pwd
                    break
                except Exception as exc:
                    messagebox.showerror("Fehler", f"Login fehlgeschlagen: {exc}")

            self._refresh_tree()
            self.root.deiconify()

        self.root.after(5000, self._check_inactivity)

    # ------------------------------------------------------------------ #
    # Schriftgröße
    # ------------------------------------------------------------------ #

    def _apply_global_font(self, size: int) -> None:
        """
        Setzt die globale Schriftgröße für alle Tkinter‑ und ttk‑Widgets.
        Gültige Werte: 8–24 Punkte.
        """
        self._font_size = max(8, min(24, size))

        for font_name in ("TkDefaultFont", "TkMenuFont", "TkTextFont"):
            tkfont.nametofont(font_name).configure(size=self._font_size)

        style = ttk.Style()
        style.configure(".", font=("Arial", self._font_size))
        rowheight = max(22, int(self._font_size * 2.2))
        style.configure("Treeview", rowheight=rowheight)

    def _increase_font(self) -> None:
        """Vergrößert die Schriftgröße um einen Punkt."""
        self._apply_global_font(self._font_size + 1)

    def _decrease_font(self) -> None:
        """Verkleinert die Schriftgröße um einen Punkt."""
        self._apply_global_font(self._font_size - 1)

    # ------------------------------------------------------------------ #
    # Login / Setup
    # ------------------------------------------------------------------ #

    def _login_dialog(self) -> None:
        """
        Zeigt den Login‑Dialog und lädt die Accounts bei korrektem Passwort.
        Beendet die App, wenn der Benutzer abbricht.
        """
        while True:
            pwd = simpledialog.askstring(
                "2FA:TOTP",
                "Bitte gib dein Master‑Passwort ein:",
                parent=self.root,
                show="*",
            )
            if pwd is None:
                self.root.destroy()
                sys.exit()

            try:
                accounts, salt       = self.data_store.load(pwd)
                self.master_password = pwd
                self.salt            = salt
                self.accounts        = accounts
                break
            except ValueError as exc:
                messagebox.showerror("Fehler", str(exc))
            except Exception as exc:
                messagebox.showerror("Unbekannter Fehler", str(exc))

    def _setup_new_master(self) -> None:
        """
        Erstellt ein neues Master‑Passwort und initialisiert die Datenbank.
        Nutzt :func:`_ask_confirmed_password` – beendet die App bei Abbruch.
        """
        pwd = _ask_confirmed_password(
            parent=self.root,
            title="Master‑Passwort festlegen",
            prompt_first="Bitte gib ein neues Master‑Passwort ein:",
            allow_cancel=False,
        )
        self.master_password = pwd
        self.salt            = os.urandom(SALT_SIZE)
        self.accounts        = []
        self.data_store.save(pwd, [], self.salt)

    # ------------------------------------------------------------------ #
    # GUI‑Erstellung
    # ------------------------------------------------------------------ #

    def _build_main_window(self) -> None:
        """Stellt das Hauptfenster mit Menü, Suchfeld, Treeview und Buttons zusammen."""
        self.root.deiconify()
        self.root.title("2FA Authenticator :: TOTP")

        menubar = tk.Menu(self.root)

        # Einstellungsmenü
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(
            label="Master‑Passwort ändern",
            command=self._change_master_password,
        )
        menubar.add_cascade(label="Einstellungen", menu=settings_menu)

        # Anzeige‑Menü (Schriftgröße)
        display_menu = tk.Menu(menubar, tearoff=0)
        display_menu.add_command(label="Schriftgröße vergrößern", command=self._increase_font)
        display_menu.add_command(label="Schriftgröße verkleinern", command=self._decrease_font)
        menubar.add_cascade(label="Anzeige", menu=display_menu)

        # Daten‑Menü (Import/Export)
        data_menu = tk.Menu(menubar, tearoff=0)
        data_menu.add_command(label="Exportieren…", command=self._export_data)
        data_menu.add_command(label="Importieren…", command=self._import_data)
        menubar.add_cascade(label="Daten", menu=data_menu)

        self.root.config(menu=menubar)

        # Countdown‑Label
        self.countdown_label = ttk.Label(
            self.root,
            text=f"Wechsel in {self.remaining}s",
            font=("Arial", 16),
        )
        self.countdown_label.pack(pady=5)

        # Suchfeld
        search_frame = ttk.Frame(self.root, padding=(10, 0))
        search_frame.pack(fill=tk.X)
        ttk.Label(search_frame, text="Suche:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_var.trace_add("write", lambda *_: self._refresh_tree())

        # Treeview
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            frame,
            columns=("account", "firma", "info", "code"),
            show="headings",
            height=15,
        )
        for col, text, width in (
            ("account", "Account",     150),
            ("firma",   "Firma",       120),
            ("info",    "Information", 200),
            ("code",    "TOTP",         80),
        ):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.tree.configure(yscrollcommand=vsb.set)

        # Buttons
        btn_frame = ttk.Frame(self.root, padding=(10, 0))
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Account hinzufügen",
                   command=self._add_account_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Account löschen",
                   command=self._delete_selected_account).pack(side=tk.LEFT, padx=5)

        # Bindings
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self._refresh_tree()

    # ------------------------------------------------------------------ #
    # Treeview‑Management
    # ------------------------------------------------------------------ #

    def _refresh_tree(self) -> None:
        """
        Füllt den Treeview mit gefilterten Accounts.
        Berücksichtigt den aktuellen Suchtext (Name, Firma, Info).
        Ersetzt sowohl das frühere ``_refresh_tree`` als auch ``_apply_search_filter``.
        """
        pattern = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""

        for item in self.tree.get_children():
            self.tree.delete(item)

        for idx, acct in enumerate(self.accounts):
            if pattern and not (
                pattern in acct.name.lower()
                or pattern in acct.firma.lower()
                or pattern in acct.info.lower()
            ):
                continue
            self.tree.insert("", "end", iid=str(idx),
                             values=(acct.name, acct.firma, acct.info, "***"))

    # ------------------------------------------------------------------ #
    # OTP‑Countdown
    # ------------------------------------------------------------------ #

    def _update_otps(self) -> None:
        """
        Aktualisiert den Countdown‑Timer jede Sekunde.
        Synchronisiert sich mit dem TOTP‑30‑Sekunden‑Fenster.
        """
        self.remaining = COUNTDOWN_START - (int(time.time()) % COUNTDOWN_START)
        self.countdown_label.config(text=f"Wechsel in {self.remaining}s")
        self.root.after(1000, self._update_otps)

    # ------------------------------------------------------------------ #
    # Account‑Aktionen
    # ------------------------------------------------------------------ #

    def _save_accounts(self) -> None:
        """Speichert den aktuellen Account‑Stand und aktualisiert den Treeview."""
        self.data_store.save(self.master_password, self.accounts, self.salt)
        self._refresh_tree()

    def _add_account_dialog(self) -> None:
        """Öffnet den Dialog zum Hinzufügen eines neuen Accounts."""
        dialog = AccountDialog(self.root, title="Neuer Account")
        self.root.wait_window(dialog)
        if dialog.result is None:
            return

        name, info, firma, secret, hash_algo, digits = dialog.result
        self.accounts.append(
            Account(name=name, info=info, firma=firma,
                    secret=secret, hash_algo=hash_algo, digits=digits)
        )
        self._save_accounts()

    def _delete_selected_account(self) -> None:
        """Löscht den ausgewählten Account nach Bestätigung."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Kein Account ausgewählt.")
            return

        idx  = int(selected[0])
        acct = self.accounts[idx]
        if not messagebox.askyesno(
            "Bestätigung",
            f"Account '{acct.name}' ({acct.info}) wirklich löschen?",
        ):
            return

        del self.accounts[idx]
        self._save_accounts()

    def _edit_selected_account(self, idx: int) -> None:
        """Öffnet den Bearbeiten‑Dialog für den Account mit dem Index ``idx``."""
        acct   = self.accounts[idx]
        dialog = EditAccountDialog(self.root, acct)
        self.root.wait_window(dialog)
        if dialog.result is None:
            return

        name, info, firma, secret, hash_algo, digits = dialog.result
        self.accounts[idx] = Account(
            name=name, info=info, firma=firma,
            secret=secret, hash_algo=hash_algo, digits=digits,
        )
        self._save_accounts()

    # ------------------------------------------------------------------ #
    # Treeview‑Interaktion
    # ------------------------------------------------------------------ #

    def _on_tree_click(self, event) -> None:
        """
        Zeigt das OTP 5 Sekunden lang an und kopiert es in die Zwischenablage,
        wenn der Benutzer die Code‑Spalte (``#4``) anklickt.
        """
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#4":
            return

        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        idx  = int(row_id)
        acct = self.accounts[idx]
        code = pyotp.TOTP(
            acct.secret,
            digits=acct.digits,
            digest=getattr(hashlib, acct.hash_algo),
        ).now()

        self.tree.set(row_id, "code", code)
        self.root.clipboard_clear()
        self.root.clipboard_append(code)
        self.root.after(5000, lambda: self._hide_code(idx))

    def _hide_code(self, idx: int) -> None:
        """Setzt die Code‑Spalte nach der Anzeige‑Dauer wieder auf ``'***'``."""
        row_id = str(idx)
        if self.tree.exists(row_id):
            self.tree.set(row_id, "code", "***")

    def _show_context_menu(self, event) -> None:
        """Zeigt ein Kontext‑Menü mit 'Bearbeiten' beim Rechtsklick in der Treeview."""
        selected_item = self.tree.identify_row(event.y)
        if not selected_item:
            return
        idx  = int(selected_item)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Bearbeiten",
                         command=lambda: self._edit_selected_account(idx))
        menu.post(event.x_root, event.y_root)

    # ------------------------------------------------------------------ #
    # Master‑Passwort ändern
    # ------------------------------------------------------------------ #

    def _change_master_password(self) -> None:
        """
        Ermöglicht das Ändern des Master‑Passworts.
        Prüft erst das aktuelle Passwort, dann wird ein neues (bestätigtes) gesetzt.
        Das Salt wird neu generiert und die Datenbank neu verschlüsselt.
        """
        pwd_current = simpledialog.askstring(
            "Master‑Passwort ändern",
            "Aktuelles Master‑Passwort eingeben:",
            parent=self.root,
            show="*",
        )
        if pwd_current is None:
            return
        if pwd_current != self.master_password:
            messagebox.showerror("Fehler", "Falsches Passwort.")
            return

        new_pwd = _ask_confirmed_password(
            parent=self.root,
            title="Master‑Passwort ändern",
            prompt_first="Neues Master‑Passwort eingeben:",
            allow_cancel=True,
        )
        if new_pwd is None:
            return

        self.master_password = new_pwd
        self.salt            = os.urandom(SALT_SIZE)
        self.data_store.save(self.master_password, self.accounts, self.salt)
        messagebox.showinfo("Erfolg", "Master‑Passwort erfolgreich geändert.")

    # ------------------------------------------------------------------ #
    # Export / Import
    # ------------------------------------------------------------------ #

    def _entry_from_account(self, acct: Account) -> dict[str, object]:
        """Konvertiert einen :class:`Account` in das Aegis‑Export‑Format."""
        return {
            "type":     "totp",
            "uuid":     str(uuid.uuid4()),
            "name":     acct.name,
            "issuer":   acct.firma,
            "note":     acct.info,
            "favorite": False,
            "icon":     None,
            "info": {
                "secret": acct.secret,
                "algo":   acct.hash_algo.upper(),
                "digits": acct.digits,
                "period": COUNTDOWN_START,
            },
            "groups": [],
        }

    def _account_from_external(self, entry: dict) -> Account:
        """Konvertiert einen Aegis‑Import‑Eintrag in einen :class:`Account`."""
        info = entry.get("info", {})
        return Account(
            name=      entry.get("name")   or "",
            info=      entry.get("note")   or "",
            firma=     entry.get("issuer") or "",
            secret=    info.get("secret", ""),
            hash_algo= info.get("algo", DEFAULT_HASH).lower(),
            digits=    int(info.get("digits", DEFAULT_DIGITS)),
        )

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
            "Exportieren", "Soll die Datei verschlüsselt werden?", icon="question"
        )

        export_obj: dict[str, object] = {
            "version": 1,
            "header":  {"slots": None, "params": None},
            "db":      {"entries": [self._entry_from_account(a) for a in self.accounts]},
        }

        try:
            if encrypt:
                key            = CryptoHelper.derive_key(self.master_password, self.salt)
                ciphertext_b64 = CryptoHelper.encrypt(json.dumps(export_obj).encode(), key)
                final_obj      = {
                    "salt": base64.urlsafe_b64encode(self.salt).decode(),
                    "data": ciphertext_b64,
                }
                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(final_obj, f, indent=2)
            else:
                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(export_obj, f, indent=2)

            messagebox.showinfo("Exportieren",
                                f"Datei erfolgreich gespeichert:\n{save_path}")
        except Exception as exc:
            messagebox.showerror("Fehler beim Export", str(exc))

    def _import_data(self) -> None:
        """
        Importiert Accounts aus einer JSON‑Datei (unverschlüsselt oder verschlüsselt).

        Bei verschlüsselten Dateien wird zuerst das aktuelle Master‑Passwort versucht.
        Schlägt das fehl, kann der Benutzer ein alternatives Passwort eingeben.
        Das interne Master‑Passwort wird dabei nie überschrieben.
        """
        if not self.master_password or not self.salt:
            messagebox.showerror("Fehler", "Keine Master‑Passwort‑Informationen vorhanden.")
            return

        import_path = filedialog.askopenfilename(
            title="Importieren – Quelle wählen",
            defaultextension=".json",
            filetypes=[("JSON‑Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )
        if not import_path:
            return

        try:
            with open(import_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as exc:
            messagebox.showerror("Fehler beim Laden", str(exc))
            return

        # Verschlüsselte Datei erkennen und entschlüsseln
        if isinstance(raw, dict) and {"salt", "data"} <= raw.keys():
            export_salt = base64.urlsafe_b64decode(raw["salt"])
            # Sicherheit: lokale Variable – self.master_password wird nie überschrieben
            _try_pwd = self.master_password
            while True:
                try:
                    key      = CryptoHelper.derive_key(_try_pwd, export_salt)
                    plaintext = CryptoHelper.decrypt(raw["data"], key)
                    raw      = json.loads(plaintext.decode())
                    break
                except ValueError:
                    _try_pwd = simpledialog.askstring(
                        "Passwort für verschlüsselte Datei",
                        "Das aktuelle Master‑Passwort kann die Datei nicht entschlüsseln.\n"
                        "Bitte anderes Passwort eingeben:",
                        parent=self.root,
                        show="*",
                    )
                    if _try_pwd is None:
                        return

        # Aegis‑Format (db/entries) oder Altformat (Liste)
        if isinstance(raw, dict) and "db" in raw and "entries" in raw.get("db", {}):
            try:
                imported = [
                    self._account_from_external(e)
                    for e in raw["db"]["entries"]
                    if e.get("type") == "totp"
                ]
            except Exception as exc:
                messagebox.showerror("Fehler bei der Konvertierung", str(exc))
                return
        elif isinstance(raw, list):
            imported = [Account.from_dict(a) for a in raw]
        else:
            messagebox.showerror("Ungültiges Format",
                                 "Die Datei enthält keine Account‑Liste.")
            return

        replace = messagebox.askyesno(
            "Import",
            "Möchten Sie die vorhandenen Accounts vollständig ersetzen?\n"
            "(Nein = neue Accounts hinzufügen; gleicher Name+Info → werden ersetzt)",
            icon="question",
        )
        if replace:
            self.accounts = imported
        else:
            existing_keys = {(a.name, a.info) for a in self.accounts}
            self.accounts.extend(
                a for a in imported if (a.name, a.info) not in existing_keys
            )

        try:
            self.data_store.save(self.master_password, self.accounts, self.salt)
        except Exception as exc:
            messagebox.showerror("Fehler beim Speichern", str(exc))
            return

        self._refresh_tree()
        messagebox.showinfo("Importieren",
                            f"Erfolgreich importiert.\n{len(imported)} Accounts.")


# --------------------------------------------------------------------------- #
# Snipping‑Tool für QR‑Code‑Scan
# --------------------------------------------------------------------------- #

class SnippingTool(tk.Toplevel):
    """
    Transparentes Vollbild‑Overlay zum Markieren eines Bildschirmbereichs.
    Wird für den QR‑Code‑Screenshot‑Scan im Account‑Dialog verwendet.
    """

    def __init__(self, parent, callback) -> None:
        super().__init__(parent)
        self.callback = callback
        self.attributes("-fullscreen", True)
        self.attributes("-alpha", 0.3)
        self.configure(bg="black")

        self.canvas = tk.Canvas(self, cursor="cross", bg="black")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<ButtonPress-1>",   self._on_press)
        self.canvas.bind("<B1-Motion>",       self._on_move)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Escape>", self._on_escape)

        self.start_x = self.start_y = None
        self.rect = None

    def _on_escape(self, event=None) -> None:
        """Escape – Abbruch: Overlay schließen und Callback mit None aufrufen."""
        self.destroy()
        self.callback(None)

    def _on_press(self, event) -> None:
        self.start_x = self.canvas.canvasx(event.x)
        self.start_y = self.canvas.canvasy(event.y)
        self.rect = self.canvas.create_rectangle(
            self.start_x, self.start_y, self.start_x, self.start_y,
            outline="red", width=3, fill="white",
        )

    def _on_move(self, event) -> None:
        self.canvas.coords(
            self.rect,
            self.start_x, self.start_y,
            self.canvas.canvasx(event.x), self.canvas.canvasy(event.y),
        )

    def _on_release(self, event) -> None:
        x1 = min(self.start_x, self.canvas.canvasx(event.x))
        y1 = min(self.start_y, self.canvas.canvasy(event.y))
        x2 = max(self.start_x, self.canvas.canvasx(event.x))
        y2 = max(self.start_y, self.canvas.canvasy(event.y))
        self.destroy()
        self.after(200, lambda: self._grab(x1, y1, x2, y2))

    def _grab(self, x1, y1, x2, y2) -> None:
        if x2 - x1 < 5 or y2 - y1 < 5:
            self.callback(None)
            return
        try:
            img = ImageGrab.grab(bbox=(int(x1), int(y1), int(x2), int(y2)))
            self.callback(img)
        except Exception as exc:
            messagebox.showerror("Fehler", f"Screenshot fehlgeschlagen: {exc}")
            self.callback(None)


# --------------------------------------------------------------------------- #
# AccountDialog – Basis für Hinzufügen und Bearbeiten
# --------------------------------------------------------------------------- #

class AccountDialog(tk.Toplevel):
    """
    Dialog zum Eingeben / Bearbeiten eines TOTP‑Accounts.

    Durch Übergabe von ``title`` kann dieselbe Klasse für "Neu" und "Bearbeiten"
    genutzt werden – ``AddAccountDialog`` als separate Unterklasse entfällt.

    Parameters
    ----------
    parent : tk.Widget
        Eltern‑Widget.
    title : str
        Fenstertitel (default: ``"Account"``).
    """

    def __init__(self, parent: tk.Widget, title: str = "Account") -> None:
        super().__init__(parent)
        self.title(title)
        self.grab_set()
        self.resizable(False, False)

        # Eingabefelder
        ttk.Label(self, text="Kontoname:").grid(     row=0, column=0, padx=5, pady=5, sticky="e")
        self.name_entry = ttk.Entry(self, width=30)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self, text="Information:").grid(   row=1, column=0, padx=5, pady=5, sticky="e")
        self.info_entry = ttk.Entry(self, width=30)
        self.info_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self, text="Firma (Issuer):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.firma_entry = ttk.Entry(self, width=30)
        self.firma_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(self, text="TOTP‑Schlüssel:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.secret_entry = ttk.Entry(self, width=30)
        self.secret_entry.grid(row=3, column=1, padx=5, pady=5)

        # QR‑Code‑Buttons (nur wenn Pillow + pyzbar installiert)
        if QR_SCAN_AVAILABLE:
            qr_frame = ttk.Frame(self)
            qr_frame.grid(row=4, column=0, columnspan=2, pady=(0, 2))
            ttk.Button(qr_frame, text="📷  Von QR‑Code scannen (Screenshot)",
                       command=self._scan_qr_screenshot).pack(side=tk.LEFT, padx=5)
            ttk.Button(qr_frame, text="🖼  Von Bilddatei",
                       command=self._scan_qr_file).pack(side=tk.LEFT, padx=5)

        ttk.Label(self, text="Hash‑Algorithmus:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.hash_var = tk.StringVar(value=DEFAULT_HASH)
        ttk.Combobox(
            self, textvariable=self.hash_var,
            values=list(HASH_OPTIONS), state="readonly", width=28,
        ).grid(row=5, column=1, padx=5, pady=5)

        ttk.Label(self, text=f"Ziffern ({DEFAULT_DIGITS}):").grid(
            row=6, column=0, padx=5, pady=5, sticky="e")
        self.digits_spin = ttk.Spinbox(self, from_=4, to=8, width=28)
        self.digits_spin.set(str(DEFAULT_DIGITS))
        self.digits_spin.grid(row=6, column=1, padx=5, pady=5)

        # OK / Abbrechen
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="OK",         command=self._ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Abbrechen",  command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.result: Optional[Tuple[str, str, str, str, str, int]] = None

    # --- QR‑Code‑Scan -------------------------------------------------- #

    def _fill_from_qr_image(self, img) -> None:
        """Dekodiert ein PIL‑Image als QR‑Code und befüllt die Felder."""
        self.deiconify()
        self.lift()
        self.focus_force()
        self.grab_set()

        if img is None:
            return

        try:
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
        except Exception:
            pass

        decoded = _decode_qr(img)
        if not decoded:
            # Zweiter Versuch mit verdoppelter Bildgröße
            try:
                w, h  = img.size
                img_big = img.resize((w * 2, h * 2), Image.LANCZOS)
                decoded = _decode_qr(img_big)
            except Exception:
                pass

        if not decoded:
            messagebox.showwarning(
                "QR‑Code",
                "Kein QR‑Code erkannt.\nTipp: Bereich etwas größer markieren.",
                parent=self,
            )
            return

        parsed = _parse_otpauth_uri(decoded[0])
        if not parsed.get("secret"):
            messagebox.showwarning(
                "QR‑Code",
                f"Kein gültiger otpauth‑URI gefunden:\n{decoded[0]}",
                parent=self,
            )
            return

        _set_entry(self.name_entry,   parsed.get("account", ""))
        _set_entry(self.info_entry,   "")
        _set_entry(self.firma_entry,  parsed.get("issuer", ""))
        _set_entry(self.secret_entry, parsed.get("secret", ""))

        algo = parsed.get("algorithm", DEFAULT_HASH)
        if algo in HASH_OPTIONS:
            self.hash_var.set(algo)
        self.digits_spin.set(str(parsed.get("digits", DEFAULT_DIGITS)))

    def _scan_qr_screenshot(self) -> None:
        """Minimiert den Dialog und öffnet das Snipping‑Tool."""
        if not QR_SCAN_AVAILABLE:
            return
        self.grab_release()
        self.withdraw()
        root = self
        while getattr(root, "master", None) is not None:
            root = root.master
        self.after(150, lambda: SnippingTool(root, self._fill_from_qr_image))

    def _scan_qr_file(self) -> None:
        """Öffnet eine Bilddatei und liest den QR‑Code daraus."""
        if not QR_SCAN_AVAILABLE:
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="QR‑Code‑Bild öffnen",
            filetypes=[("Bilder", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")],
        )
        if not path:
            return
        try:
            self._fill_from_qr_image(Image.open(path))
        except Exception as exc:
            messagebox.showerror("Fehler", str(exc), parent=self)

    # --- Validierung & Bestätigung -------------------------------------- #

    def _ok(self) -> None:
        """Validiert die Eingaben und schreibt das Ergebnis in ``self.result``."""
        name      = self.name_entry.get().strip()
        info      = self.info_entry.get().strip()
        firma     = self.firma_entry.get().strip()
        secret    = self.secret_entry.get().strip()
        hash_algo = self.hash_var.get()
        digits    = int(self.digits_spin.get())

        if not name:
            messagebox.showerror("Fehler", "Der Kontoname darf nicht leer sein.")
            return
        if not secret:
            messagebox.showerror("Fehler", "Der TOTP‑Schlüssel darf nicht leer sein.")
            return

        try:
            _validate_totp(secret, digits, hash_algo)
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc))
            return

        self.result = (name, info, firma, secret, hash_algo, digits)
        self.destroy()


# --------------------------------------------------------------------------- #
# EditAccountDialog – spezialisiert für bestehende Accounts
# --------------------------------------------------------------------------- #

class EditAccountDialog(AccountDialog):
    """
    Dialog zum Bearbeiten eines bestehenden Accounts.

    Erweitert :class:`AccountDialog` um:
    - Vorausfüllung aller Felder mit den aktuellen Account‑Werten.
    - Secret‑Maskierung mit Checkbox zum Einblenden.
    - Sicheres Erkennen ob das Secret geändert wurde (Flag statt Heuristik).
    """

    def __init__(self, parent: tk.Widget, account: Account) -> None:
        super().__init__(parent, title="Account bearbeiten")

        # Felder vorausfüllen
        _set_entry(self.name_entry,  account.name)
        _set_entry(self.info_entry,  account.info)
        _set_entry(self.firma_entry, account.firma)

        self.hash_var.set(account.hash_algo)
        self.digits_spin.set(str(account.digits))

        # Secret‑Verwaltung: Original merken, Feld maskieren
        self.original_secret  = account.secret
        self._secret_modified = False       # robustes Flag statt Zeichenheuristik

        _set_entry(self.secret_entry, "*" * len(self.original_secret))

        # Checkbox zum Anzeigen / Verbergen des Secrets
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self,
            text="Schlüssel anzeigen?",
            variable=self.show_var,
            command=self._toggle_show_secret,
        ).grid(row=3, column=2, columnspan=2, pady=(5, 10))

    def _fill_from_qr_image(self, img) -> None:
        """Überschreibt die Basismethode: synchronisiert original_secret nach QR‑Scan."""
        super()._fill_from_qr_image(img)
        new_secret = self.secret_entry.get().strip()
        if new_secret:
            self.original_secret  = new_secret
            self._secret_modified = True
            self.show_var.set(True)

    def _toggle_show_secret(self) -> None:
        """Schaltet zwischen Klartext und Maskierung des Secrets um."""
        if self.show_var.get():
            _set_entry(self.secret_entry, self.original_secret)
        else:
            _set_entry(self.secret_entry, "*" * len(self.original_secret))

    def _ok(self) -> None:
        """
        Validiert die Eingaben.

        Das Secret wird nur dann aus dem Feld übernommen, wenn es tatsächlich
        geändert wurde (``_secret_modified``‑Flag) – andernfalls wird
        ``original_secret`` unverändert verwendet.
        """
        name      = self.name_entry.get().strip()
        info      = self.info_entry.get().strip()
        firma     = self.firma_entry.get().strip()
        hash_algo = self.hash_var.get()
        digits    = int(self.digits_spin.get())

        if not name:
            messagebox.showerror("Fehler", "Der Kontoname darf nicht leer sein.")
            return

        # Secret bestimmen: Flag verhindert versehentliches Überschreiben mit Maskierung
        if self._secret_modified or self.show_var.get():
            entered = self.secret_entry.get().strip()
            secret_to_use = entered if entered else self.original_secret
        else:
            secret_to_use = self.original_secret

        try:
            _validate_totp(secret_to_use, digits, hash_algo)
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc))
            return

        self.result = (name, info, firma, secret_to_use, hash_algo, digits)
        self.destroy()


# --------------------------------------------------------------------------- #
# Einstiegspunkt
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    AuthenticatorApp()
