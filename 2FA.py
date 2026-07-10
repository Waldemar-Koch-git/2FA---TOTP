#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

__version__ = "v1.6"
"""
2FA Authenticator :: TOTP – Desktop‑Anwendung

Dieses Skript implementiert einen einfachen TOTP‑Authenticator mit
verschlüsselter Persistenz, Import/Export‑Fähigkeit und einer Tkinter‑GUI.
Alle Daten werden in einer JSON‑Datei verschlüsselt gespeichert.
Das Master‑Passwort wird mithilfe von Argon2 (KDF) in einen Schlüssel
umgewandelt, der dann die AES‑GCM‑Verschlüsselung steuert.

install:
    pip install pyotp cryptography argon2-cffi

optional für QR-Code-Scan:
    pip install pillow zxing-cpp numpy

-----------------------------------------------------------------------------------

Author      : Waldemar Koch
Created     : 2025-08-09
Last Update : 2026-07-10
Version     : 1.6
License     : Custom Non-Commercial License
              MIT-style terms, but non-commercial use only.
              This is not the MIT License and not OSI-approved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to use,
copy, modify, merge, publish, and distribute the Software for non-commercial
purposes only, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

Commercial use, selling, sublicensing for commercial purposes, or use as part
of a commercial product or commercial service is not permitted without prior
written permission from the author.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
"""

import atexit
import base64
import hashlib
import json
import logging
import os
import platform
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# --- DPI-Anpassung für Windows ---
# Muss vor tk.Tk() passieren, da Tkinter sonst die DPI-Skalierung
# nicht korrekt erkennt und auf HiDPI-Monitoren Screenshot-Koordinaten
# nicht mit Canvas-Koordinaten übereinstimmen.
if platform.system() == "Windows":
    try:
        import ctypes

        # Windows 10/11: Per-Monitor DPI Awareness v2
        # -4 entspricht DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        try:
            # Fallback: Per-Monitor DPI Awareness (v1)
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                # Letzter Fallback: System-DPI-aware
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass

import pyotp
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, simpledialog, filedialog

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# QR-Code Scan Support (optional – benötigt Pillow und zxing-cpp)
try:
    from PIL import ImageGrab, Image

    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import zxingcpp as _zxingcpp

    def _pyzbar_decode(pil_img):
        """Wrapper um zxingcpp, der das pyzbar-Interface nachahmt."""
        import numpy as np

        results = _zxingcpp.read_barcodes(np.array(pil_img))

        class _Obj:
            def __init__(self, text):
                self.data = text.encode("utf-8")

        return [_Obj(r.text) for r in results]

    _PYZBAR_AVAILABLE = True
except ImportError:
    _PYZBAR_AVAILABLE = False

QR_SCAN_AVAILABLE = _PIL_AVAILABLE and _PYZBAR_AVAILABLE


# --------------------------------------------------------------------------- #
# Konfiguration – alles in Großbuchstaben
# --------------------------------------------------------------------------- #


def _get_app_base_dir() -> Path:
    """
    Liefert das Verzeichnis, in dem sich das Programm selbst befindet.

    BUGFIX (1.5 -> 1.5.1): Ein rein relativer Pfad wird gegen das
    Working Directory aufgelöst, das je nach Startart (Autostart,
    Verknüpfung, Doppelklick ...) ein geschützter Ordner sein kann.
    Deshalb wird immer der tatsächliche Speicherort der Programmdatei
    verwendet, nie das CWD.
    """
    if getattr(sys, "frozen", False):
        # Als PyInstaller-o.ä.-EXE gepackt: sys.executable ist die .exe.
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


DATA_FILE = _get_app_base_dir() / "authenticator_data.json"
LOCK_FILE = DATA_FILE.with_suffix(".lock")

SALT_SIZE = 32  # Bytes für den KDF‑Salt

# ACHTUNG: Diese 3 Variablen steuern die Verschlüsselungsstärke!
# ARGON_TIME_COST, ARGON_MEMORY_COST, ARGON_PARALLELISM
# Wenn Du sie änderst, sind bestehende Dateien mit alten Parametern
# nicht mehr ohne Migration lesbar, weil die Parameter nicht in der Datei stehen.
ARGON_TIME_COST = 20
ARGON_MEMORY_COST = 1024 * 1024  # 1 GiB
ARGON_PARALLELISM = 4

COUNTDOWN_START = 30
DEFAULT_PERIOD = COUNTDOWN_START

HASH_OPTIONS = ("sha1", "sha256", "sha512")
DEFAULT_DIGITS = 6
DEFAULT_HASH = "sha1"


# --------------------------------------------------------------------------- #
# Logging‑Setup
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
)


# --------------------------------------------------------------------------- #
# Hilfsfunktionen Modul-Ebene
# --------------------------------------------------------------------------- #

def _normalize_secret(secret: str) -> str:
    """
    Normalisiert ein TOTP-Secret für Import/Validierung.

    Entfernt Leerzeichen und Bindestriche und wandelt in Großbuchstaben um.
    """
    return secret.replace(" ", "").replace("-", "").strip().upper()


def _validate_totp(
    secret: str,
    digits: int,
    hash_algo: str,
    period: int = DEFAULT_PERIOD,
) -> None:
    """
    Prüft, ob ein TOTP‑Secret gültig ist, indem einmalig ein Code berechnet wird.

    Args:
        secret:    Base32‑kodiertes TOTP‑Secret.
        digits:    Anzahl der OTP‑Ziffern.
        hash_algo: Name des Hash‑Algorithmus, z. B. ``"sha1"``.
        period:    TOTP-Periode in Sekunden.

    Raises:
        Exception: Wenn Secret, Digits, Algorithmus oder Period ungültig sind.
    """
    secret = _normalize_secret(secret)

    if hash_algo not in HASH_OPTIONS:
        raise ValueError(f"Ungültiger Hash-Algorithmus: {hash_algo}")

    if not (4 <= int(digits) <= 10):
        raise ValueError(f"Ungültige Ziffernanzahl: {digits}")

    if not (1 <= int(period) <= 3600):
        raise ValueError(f"Ungültige Periode: {period}")

    pyotp.TOTP(
        secret,
        digits=int(digits),
        digest=getattr(hashlib, hash_algo),
        interval=int(period),
    ).now()


def _validate_and_normalize_account(acct: "Account") -> "Account":
    """
    Validiert einen importierten Account und gibt eine normalisierte Kopie zurück.

    Wird beim Import verwendet. Fehlerhafte Accounts können dadurch sauber
    übersprungen und dem Benutzer aufgelistet werden.
    """
    name = (acct.name or "").strip()
    info = (acct.info or "").strip()
    firma = (acct.firma or "").strip()
    secret = _normalize_secret(acct.secret or "")
    hash_algo = (acct.hash_algo or DEFAULT_HASH).lower().strip()

    try:
        digits = int(acct.digits)
    except Exception:
        raise ValueError(f"Ungültige Ziffernanzahl: {acct.digits}")

    try:
        period = int(acct.period)
    except Exception:
        raise ValueError(f"Ungültige Periode: {acct.period}")

    if not name:
        raise ValueError("Kontoname ist leer.")

    if not secret:
        raise ValueError("TOTP-Schlüssel ist leer.")

    _validate_totp(secret, digits, hash_algo, period)

    return Account(
        name=name,
        info=info,
        firma=firma,
        secret=secret,
        hash_algo=hash_algo,
        digits=digits,
        period=period,
    )


def _format_error_list(errors: list[str], max_items: int = 15) -> str:
    """Formatiert Importfehler kompakt für Messageboxen."""
    if not errors:
        return ""

    shown = errors[:max_items]
    text = "\n".join(shown)

    if len(errors) > max_items:
        text += f"\n... und {len(errors) - max_items} weitere."

    return text


def _set_entry(entry: ttk.Entry, value: str) -> None:
    """
    Setzt den Inhalt eines ttk.Entry‑Feldes.
    """
    entry.delete(0, tk.END)
    entry.insert(0, value)


def _decode_qr(pil_img) -> list[str]:
    """
    Dekodiert QR‑Codes aus einem PIL‑Image mittels zxing-cpp.
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
    Fragt zweimal nach einem Passwort und gibt es zurück,
    wenn beide Eingaben übereinstimmen.
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
            messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.", parent=parent)
            continue

        return pwd1


def _parse_otpauth_uri(uri: str) -> dict:
    """
    Parst einen ``otpauth://totp/...``‑URI und gibt ein Dict zurück.
    """
    import urllib.parse

    result = {}

    if not uri.startswith("otpauth://totp/"):
        return result

    without_scheme = uri[len("otpauth://totp/"):]

    label_enc, query_str = (
        without_scheme.split("?", 1)
        if "?" in without_scheme
        else (without_scheme, "")
    )

    label = urllib.parse.unquote(label_enc)
    issuer_label, account = label.split(":", 1) if ":" in label else ("", label)

    params = dict(urllib.parse.parse_qsl(query_str))

    result["account"] = account.strip()
    result["issuer"] = params.get("issuer", issuer_label).strip()
    result["secret"] = params.get("secret", "").strip()

    try:
        result["digits"] = int(params.get("digits", DEFAULT_DIGITS))
    except Exception:
        result["digits"] = DEFAULT_DIGITS

    try:
        result["period"] = int(params.get("period", DEFAULT_PERIOD))
    except Exception:
        result["period"] = DEFAULT_PERIOD

    result["algorithm"] = params.get("algorithm", DEFAULT_HASH).lower().strip()

    return result


# --------------------------------------------------------------------------- #
# Single-Instance-Lock
# --------------------------------------------------------------------------- #

class SingleInstanceLock:
    """
    Verhindert, dass mehrere Instanzen gleichzeitig dieselbe Datenbank bearbeiten.

    Nutzt OS-Dateisperren (Windows: msvcrt.locking, Unix: fcntl.flock).
    Eine nach einem Crash liegen gebliebene Lock-Datei ist unkritisch,
    da die echte OS-Sperre und nicht die Existenz der Datei entscheidet.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = None
        self._locked = False
        # error_kind unterscheidet "locked" (andere Instanz hält den Lock),
        # "permission" (keine Schreibrechte) und "other" für die Fehlermeldung.
        self.error_kind: Optional[str] = None
        self.error_message: Optional[str] = None

    def acquire(self) -> bool:
        """Versucht, den Lock nicht-blockierend zu erwerben."""
        self.error_kind = None
        self.error_message = None

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError as exc:
            logging.error("Lock-Verzeichnis nicht erstellbar (Rechte): %s", exc)
            self.error_kind = "permission"
            self.error_message = str(exc)
            return False
        except Exception as exc:
            logging.error("Lock-Verzeichnis nicht erstellbar: %s", exc)
            self.error_kind = "other"
            self.error_message = str(exc)
            return False

        try:
            self.handle = open(self.path, "a+b")
        except PermissionError as exc:
            # Kein Konkurrenzzugriff, sondern fehlende Schreibrechte auf
            # die Lock-Datei bzw. deren Verzeichnis.
            logging.error("Lock-Datei nicht öffenbar (Rechte): %s", exc)
            self.error_kind = "permission"
            self.error_message = str(exc)
            return False
        except OSError as exc:
            logging.error("Lock-Datei nicht öffenbar: %s", exc)
            self.error_kind = "other"
            self.error_message = str(exc)
            return False

        try:
            if os.name == "nt":
                import msvcrt

                # Sicherstellen, dass mindestens 1 Byte existiert.
                self.handle.seek(0)
                self.handle.write(b"0")
                self.handle.flush()
                self.handle.seek(0)

                try:
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    self.handle.close()
                    self.handle = None
                    # Dieser Fehler bedeutet: eine andere Instanz hält den
                    # Lock bereits – das ist der einzig echte "belegt"-Fall.
                    self.error_kind = "locked"
                    self.error_message = str(exc)
                    return False
            else:
                import fcntl

                try:
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    self.handle.close()
                    self.handle = None
                    self.error_kind = "locked"
                    self.error_message = str(exc)
                    return False

            self._locked = True

            try:
                self.handle.seek(0)
                self.handle.truncate()
                self.handle.write(str(os.getpid()).encode("ascii", errors="ignore"))
                self.handle.flush()
            except Exception:
                pass

            return True

        except Exception as exc:
            logging.error("Lock konnte nicht erworben werden: %s", exc)

            try:
                if self.handle:
                    self.handle.close()
            except Exception:
                pass

            self.handle = None
            self._locked = False
            self.error_kind = "other"
            self.error_message = str(exc)
            return False

    def release(self) -> None:
        """Gibt den Lock frei."""
        if not self.handle:
            return

        try:
            if self._locked:
                if os.name == "nt":
                    import msvcrt

                    try:
                        self.handle.seek(0)
                        msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    import fcntl

                    try:
                        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
        finally:
            try:
                self.handle.close()
            except Exception:
                pass

            self.handle = None
            self._locked = False

            try:
                self.path.unlink(missing_ok=True)
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Datenmodell
# --------------------------------------------------------------------------- #

@dataclass
class Account:
    """
    Repräsentiert ein einzelnes TOTP‑Konto.
    """
    name: str
    info: str
    firma: str
    secret: str
    hash_algo: str = DEFAULT_HASH
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD

    def to_dict(self) -> dict[str, object]:
        """Serialisiert das Objekt in ein Dictionary."""
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Account":
        """Deserialisiert ein Dictionary zurück zu einem Account."""
        return Account(
            name=data["name"],
            info=data.get("info", ""),
            firma=data.get("firma", ""),
            secret=data["secret"],
            hash_algo=data.get("hash_algo", DEFAULT_HASH),
            digits=int(data.get("digits", DEFAULT_DIGITS)),
            period=int(data.get("period", DEFAULT_PERIOD)),
        )


# --------------------------------------------------------------------------- #
# CryptoHelper – AES‑GCM
# --------------------------------------------------------------------------- #

class CryptoHelper:
    """Hilfsklasse für Kryptografie‑Operationen."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Leitet einen 256‑Bit‑Schlüssel aus Passwort und Salt ab.
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
        Verschlüsselt Klartext mit AES‑GCM.
        """
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return base64.urlsafe_b64encode(nonce + ct).decode()

    @staticmethod
    def decrypt(ciphertext_b64: str, key: bytes) -> bytes:
        """
        Entschlüsselt AES‑GCM-Ciphertext.
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
        """
        if not self.file.exists():
            raise FileNotFoundError("Datenbank existiert nicht.")

        with self.file.open(encoding="utf-8") as f:
            data = json.load(f)

        salt = base64.urlsafe_b64decode(data["salt"])
        key = CryptoHelper.derive_key(password, salt)
        plaintext = CryptoHelper.decrypt(data["data"], key)
        raw_accounts = json.loads(plaintext.decode())

        return [Account.from_dict(a) for a in raw_accounts], salt

    def save(self, password: str, accounts: List[Account], salt: bytes) -> None:
        """
        Speichert die Konten verschlüsselt in die JSON‑Datei.
        """
        key = CryptoHelper.derive_key(password, salt)
        plaintext = json.dumps([a.to_dict() for a in accounts]).encode()
        ciphertext_b64 = CryptoHelper.encrypt(plaintext, key)

        data_obj = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "data": ciphertext_b64,
        }

        tmp_path = self.file.with_suffix(".tmp")

        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data_obj, f)

        os.replace(tmp_path, self.file)


# --------------------------------------------------------------------------- #
# AuthenticatorApp
# --------------------------------------------------------------------------- #

class AuthenticatorApp:
    """Hauptanwendung – Tkinter‑GUI und Logik."""

    def __init__(self) -> None:
        """
        Konstruktor: setzt die komplette Anwendung auf.
        """
        self.root = tk.Tk()
        self.root.withdraw()

        # Single-Instance-Lock gegen parallele Schreibzugriffe.
        self.instance_lock = SingleInstanceLock(LOCK_FILE)

        if not self.instance_lock.acquire():
            if self.instance_lock.error_kind == "locked":
                # Echter Fall: eine andere Instanz hält den OS-Lock.
                messagebox.showerror(
                    "Bereits geöffnet",
                    "Die Anwendung scheint bereits geöffnet zu sein.\n\n"
                    "Damit keine Daten überschrieben werden, wird diese Instanz beendet.",
                    parent=self.root,
                )
            elif self.instance_lock.error_kind == "permission":
                # Programmordner ist schreibgeschützt (z.B. "Program Files").
                retry_as_admin = messagebox.askretrycancel(
                    "Zugriff verweigert",
                    "Die Anwendung konnte nicht auf ihren eigenen Programmordner "
                    "schreiben (keine Schreibrechte):\n\n"
                    f"{LOCK_FILE.parent}\n\n"
                    f"Technischer Grund: {self.instance_lock.error_message}\n\n"
                    "Das passiert typischerweise, wenn das Programm in einem "
                    "geschützten Ordner liegt (z.B. 'Programme'/'Program Files').\n"
                    "Empfehlung: Programmordner an einen Ort verschieben, an dem "
                    "du normal schreiben darfst (z.B. Desktop, Dokumente, eigener "
                    "Ordner) – dann ist auch künftig kein Admin-Start nötig.\n\n"
                    "Klicke auf 'Wiederholen', um die App stattdessen jetzt "
                    "einmalig mit erhöhten Rechten neu zu starten, oder auf "
                    "'Abbrechen' zum Beenden.",
                    parent=self.root,
                )
                if retry_as_admin:
                    self._relaunch_as_admin()
            else:
                messagebox.showerror(
                    "Startfehler",
                    "Die Anwendung konnte nicht gestartet werden:\n\n"
                    f"{self.instance_lock.error_message}",
                    parent=self.root,
                )
            self.root.destroy()
            sys.exit()

        atexit.register(self.instance_lock.release)

        self.dpi_scale = self._get_dpi_scale()

        try:
            self.root.tk.call("tk", "scaling", self.dpi_scale)
        except Exception:
            pass

        self._font_size: int = 10
        self.remaining: int = COUNTDOWN_START
        self.data_store = DataStore(DATA_FILE)

        self.master_password: Optional[str] = None
        self.salt: Optional[bytes] = None
        self.accounts: List[Account] = []

        if DATA_FILE.exists():
            self._login_dialog()
        else:
            self._setup_new_master()

        self._apply_global_font(self._font_size)
        self.remaining = COUNTDOWN_START
        self._build_main_window()
        self._update_otps()

        self.last_activity = time.time()
        self.inactivity_timeout = 5 * 60

        for event in ("<Key>", "<Button-1>", "<Motion>"):
            self.root.bind_all(event, self._update_last_activity)

        self._check_inactivity()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logging.info("Programm wird beendet.")
        finally:
            self.instance_lock.release()

    # ------------------------------------------------------------------ #
    # Neustart mit erhöhten Rechten (Fallback bei Rechteproblemen)
    # ------------------------------------------------------------------ #

    def _relaunch_as_admin(self) -> None:
        """
        Startet die Anwendung mit erhöhten Rechten neu.

        Nur als Fallback für Sonderfälle gedacht (z.B. Virenscanner oder
        Gruppenrichtlinie blockiert den Zugriff), kein empfohlener Normalfall.
        """
        try:
            if platform.system() == "Windows":
                import ctypes

                params = " ".join(f'"{a}"' for a in sys.argv)
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, params, None, 1
                )
            else:
                # Unix/macOS: kein "runas"-Äquivalent für GUI-Apps.
                # pkexec/sudo starten, falls vorhanden.
                import shutil
                import subprocess

                elevator = shutil.which("pkexec") or shutil.which("sudo")
                if elevator:
                    subprocess.Popen([elevator, sys.executable, *sys.argv])
                else:
                    messagebox.showerror(
                        "Nicht möglich",
                        "Kein Werkzeug zum Erhöhen der Rechte gefunden "
                        "(pkexec/sudo). Bitte Verzeichnisrechte manuell prüfen.",
                        parent=self.root,
                    )
                    return
        except Exception as exc:
            logging.error("Neustart mit erhöhten Rechten fehlgeschlagen: %s", exc)
            messagebox.showerror(
                "Fehlgeschlagen",
                f"Neustart mit erhöhten Rechten fehlgeschlagen:\n{exc}",
                parent=self.root,
            )

    # ------------------------------------------------------------------ #
    # DPI / Skalierung
    # ------------------------------------------------------------------ #

    def _get_dpi_scale(self) -> float:
        """Ermittelt den DPI-Skalierungsfaktor."""
        try:
            return self.root.winfo_fpixels("1i") / 96.0
        except Exception:
            return 1.0

    def _px(self, value: int | float) -> int:
        """Skaliert Pixelwerte mit dem DPI-Faktor."""
        return int(round(value * self.dpi_scale))

    # ------------------------------------------------------------------ #
    # Inaktivitäts‑Management
    # ------------------------------------------------------------------ #

    def _on_close(self) -> None:
        """Fenster wird geschlossen – Anwendung sauber beenden."""
        self.instance_lock.release()
        self.root.destroy()

    def _update_last_activity(self, event=None) -> None:
        """Setzt den Inaktivitäts‑Zeitstempel auf jetzt."""
        self.last_activity = time.time()

    def _check_inactivity(self) -> None:
        """
        Sperrt die App nach Ablauf des Inaktivitäts‑Timeouts.
        """
        if (time.time() - self.last_activity) > self.inactivity_timeout:
            self.root.withdraw()

            messagebox.showinfo(
                "Sicherheit",
                f"Nach {self.inactivity_timeout // 60} Minuten Inaktivität erneut anmelden!",
                parent=self.root,
            )

            while True:
                pwd = simpledialog.askstring(
                    "Passwort eingeben",
                    "Bitte Master-Passwort:",
                    parent=self.root,
                    show="*",
                )

                if pwd is None:
                    self.root.destroy()
                    sys.exit()

                try:
                    accounts, salt = self.data_store.load(pwd)
                    self.accounts = accounts
                    self.salt = salt
                    self.master_password = pwd
                    break
                except Exception as exc:
                    messagebox.showerror("Fehler", f"Login fehlgeschlagen: {exc}", parent=self.root)

            self.last_activity = time.time()
            self._refresh_tree()
            self.root.deiconify()

        self.root.after(5000, self._check_inactivity)

    # ------------------------------------------------------------------ #
    # Schrift / Style
    # ------------------------------------------------------------------ #

    def _apply_global_font(self, size: int) -> None:
        """
        Setzt die globale Schriftgröße für alle Tkinter‑ und ttk‑Widgets.
        """
        self._font_size = max(8, min(24, size))

        for font_name in ("TkDefaultFont", "TkMenuFont", "TkTextFont"):
            try:
                tkfont.nametofont(font_name).configure(size=self._font_size)
            except Exception:
                pass

        style = ttk.Style()
        style.configure(".", font=("Arial", self._font_size))

        rowheight = max(
            24,
            int(round(self._font_size * 2.7 * max(1.0, self.dpi_scale))),
        )

        style.configure(
            "Treeview",
            font=("Arial", self._font_size),
            rowheight=rowheight,
        )

        style.configure(
            "Treeview.Heading",
            font=("Arial", self._font_size, "bold"),
        )

        if hasattr(self, "info_label"):
            self.info_label.configure(font=("Arial", self._font_size + 2))

        if hasattr(self, "tree"):
            self._resize_tree_columns()

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
        """Zeigt den Login‑Dialog und lädt die Accounts."""
        while True:
            pwd = simpledialog.askstring(
                f"2FA:TOTP - {__version__}",
                "Bitte gib dein Master-Passwort ein:",
                parent=self.root,
                show="*",
            )

            if pwd is None:
                self.root.destroy()
                sys.exit()

            try:
                accounts, salt = self.data_store.load(pwd)
                self.master_password = pwd
                self.salt = salt
                self.accounts = accounts
                break
            except ValueError as exc:
                messagebox.showerror("Fehler", str(exc), parent=self.root)
            except Exception as exc:
                messagebox.showerror("Unbekannter Fehler", str(exc), parent=self.root)

    def _setup_new_master(self) -> None:
        """Erstellt ein neues Master‑Passwort und initialisiert die Datenbank."""
        pwd = _ask_confirmed_password(
            parent=self.root,
            title="Master-Passwort festlegen",
            prompt_first="Bitte gib ein neues Master-Passwort ein:",
            allow_cancel=False,
        )

        if pwd is None:
            self.root.destroy()
            sys.exit()

        salt = os.urandom(SALT_SIZE)

        try:
            self.data_store.save(pwd, [], salt)
        except Exception as exc:
            messagebox.showerror(
                "Fehler",
                f"Datenbank konnte nicht erstellt werden:\n{exc}",
                parent=self.root,
            )
            self.root.destroy()
            sys.exit()

        self.master_password = pwd
        self.salt = salt
        self.accounts = []

    # ------------------------------------------------------------------ #
    # GUI‑Erstellung
    # ------------------------------------------------------------------ #

    def _build_main_window(self) -> None:
        """Stellt das Hauptfenster zusammen."""
        self.root.deiconify()
        self.root.title(f"2FA Authenticator :: TOTP :: {__version__}")

        self.root.geometry("900x620")
        self.root.minsize(760, 500)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=0)
        self.root.rowconfigure(1, weight=0)
        self.root.rowconfigure(2, weight=1)
        self.root.rowconfigure(3, weight=0)

        menubar = tk.Menu(self.root)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(
            label="Master-Passwort ändern",
            command=self._change_master_password,
        )
        menubar.add_cascade(label="Einstellungen", menu=settings_menu)

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

        data_menu = tk.Menu(menubar, tearoff=0)
        data_menu.add_command(label="Exportieren…", command=self._export_data)
        data_menu.add_command(label="Importieren…", command=self._import_data)
        menubar.add_cascade(label="Daten", menu=data_menu)

        self.root.config(menu=menubar)

        # Hinweis-Label
        self.info_label = ttk.Label(
            self.root,
            text="Zum Kopieren des Codes auf jeweiligen TOTP klicken",
            font=("Arial", self._font_size + 2),
            anchor="center",
        )
        self.info_label.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=10,
            pady=(8, 5),
        )

        search_frame = ttk.Frame(self.root, padding=(10, 0))
        search_frame.grid(row=1, column=0, sticky="ew", padx=0, pady=(0, 5))
        search_frame.columnconfigure(1, weight=1)

        ttk.Label(search_frame, text="Suche:").grid(
            row=0,
            column=0,
            sticky="w",
            padx=(0, 5),
        )

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.grid(
            row=0,
            column=1,
            sticky="ew",
        )
        self.search_var.trace_add("write", lambda *_: self._refresh_tree())

        frame = ttk.Frame(self.root, padding=(10, 5, 10, 5))
        frame.grid(row=2, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            frame,
            columns=("account", "firma", "info", "countdown", "code"),
            show="headings",
            height=10,
        )

        for col, text, width in (
            ("account", "Account", 150),
            ("firma", "Firma", 120),
            ("info", "Information", 220),
            ("countdown", "Ablauf", 80),
            ("code", "TOTP", 90),
        ):
            self.tree.heading(col, text=text)
            self.tree.column(
                col,
                width=width,
                minwidth=60,
                stretch=True,
                anchor=tk.CENTER if col in ("countdown", "code") else tk.W,
            )

        # Farbliche Markierung nach Restlaufzeit.
        # Hinweis: Je nach Betriebssystem/Theme ignorieren manche ttk-Themes
        # einzelne Farben teilweise. Falls das passiert, kann man später ein
        # anderes Theme setzen, z. B. "clam".
        self.tree.tag_configure("normal", background="")
        self.tree.tag_configure("warning", background="#fff3cd")   # helles Gelb/Orange
        self.tree.tag_configure("critical", background="#f8d7da")  # helles Rot

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Configure>", self._resize_tree_columns)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        btn_frame = ttk.Frame(self.root, padding=(10, 5, 10, 10))
        btn_frame.grid(row=3, column=0, sticky="ew")
        btn_frame.columnconfigure(99, weight=1)

        ttk.Button(
            btn_frame,
            text="Account hinzufügen",
            command=self._add_account_dialog,
        ).grid(row=0, column=0, padx=(0, 5), sticky="w")

        ttk.Button(
            btn_frame,
            text="Account löschen",
            command=self._delete_selected_account,
        ).grid(row=0, column=1, padx=5, sticky="w")

        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self._refresh_tree()
        self.root.after(100, self._resize_tree_columns)

    def _resize_tree_columns(self, event=None) -> None:
        """
        Verteilt die Treeview-Spalten dynamisch auf die verfügbare Breite.

        Spalten:
          - account
          - firma
          - info
          - countdown
          - code
        """
        if not hasattr(self, "tree"):
            return

        total_width = self.tree.winfo_width()

        if total_width <= 50:
            return

        total_width -= 24

        layout = {
            "account": 0.24,
            "firma": 0.18,
            "info": 0.38,
            "countdown": 0.10,
            "code": 0.10,
        }

        minimum = {
            "account": 120,
            "firma": 100,
            "info": 180,
            "countdown": 70,
            "code": 80,
        }

        for col, ratio in layout.items():
            self.tree.column(
                col,
                width=max(minimum[col], int(total_width * ratio)),
                stretch=True,
            )

    # ------------------------------------------------------------------ #
    # Treeview‑Management
    # ------------------------------------------------------------------ #

    def _refresh_tree(self) -> None:
        """
        Füllt den Treeview mit gefilterten Accounts.
        Berücksichtigt den aktuellen Suchtext (Name, Firma, Info).

        Zusätzlich wird pro Zeile die individuelle Ablaufzeit angezeigt.
        """
        if not hasattr(self, "tree"):
            return

        pattern = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        now = int(time.time())

        for item in self.tree.get_children():
            self.tree.delete(item)

        for idx, acct in enumerate(self.accounts):
            if pattern and not (
                pattern in acct.name.lower()
                or pattern in acct.firma.lower()
                or pattern in acct.info.lower()
            ):
                continue

            remaining = self._account_remaining_seconds(acct, now)
            tag = self._countdown_tag(remaining)

            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    acct.name,
                    acct.firma,
                    acct.info,
                    self._format_remaining(remaining),
                    "***",
                ),
                tags=(tag,),
            )

    # ------------------------------------------------------------------ #
    # OTP‑Countdown
    # ------------------------------------------------------------------ #
    
    def _account_remaining_seconds(self, acct: Account, now: Optional[int] = None) -> int:
        """
        Berechnet die verbleibenden Sekunden bis zum nächsten TOTP-Wechsel
        für einen einzelnen Account.

        Args:
            acct: Account mit individueller period.
            now: Optionaler Unix-Zeitstempel als int.

        Returns:
            int: Verbleibende Sekunden. Mindestens 1.
        """
        if now is None:
            now = int(time.time())

        try:
            period = int(acct.period)
        except Exception:
            period = DEFAULT_PERIOD

        if period <= 0:
            period = DEFAULT_PERIOD

        remaining = period - (now % period)

        if remaining <= 0:
            remaining = period

        return remaining


    def _countdown_tag(self, remaining: int) -> str:
        """
        Gibt den Treeview-Tag für die farbliche Markierung zurück.

        Schwellen:
          - 1 bis 5 Sekunden: kritisch/rot
          - 6 bis 10 Sekunden: Warnung/orange
          - sonst: normal
        """
        if remaining <= 5:
            return "critical"

        if remaining <= 10:
            return "warning"

        return "normal"


    def _format_remaining(self, remaining: int) -> str:
        """
        Formatiert die Restlaufzeit für die Ablauf-Spalte.
        """
        return f"{remaining:02d}s"


    def _update_countdown_column(self) -> None:
        """
        Aktualisiert nur die Ablauf-Spalte und die Zeilenfarbe.

        Wichtig:
        Die Tabelle wird dabei nicht neu aufgebaut. Dadurch bleiben Auswahl,
        Scrollposition und sichtbare Codes erhalten.
        """
        if not hasattr(self, "tree"):
            return

        now = int(time.time())

        for row_id in self.tree.get_children():
            try:
                idx = int(row_id)
            except Exception:
                continue

            if idx < 0 or idx >= len(self.accounts):
                continue

            acct = self.accounts[idx]
            remaining = self._account_remaining_seconds(acct, now)
            tag = self._countdown_tag(remaining)

            try:
                self.tree.set(row_id, "countdown", self._format_remaining(remaining))
                self.tree.item(row_id, tags=(tag,))
            except Exception:
                pass

    def _update_otps(self) -> None:
        """
        Aktualisiert die Ablauf-Spalte jede Sekunde.

        Der globale Wechsel-Countdown wurde durch einen statischen Hinweis ersetzt,
        weil jede Zeile ihren individuellen Countdown besitzt.
        """
        self._update_countdown_column()
        self.root.after(1000, self._update_otps)

    # ------------------------------------------------------------------ #
    # Account‑Aktionen
    # ------------------------------------------------------------------ #

    def _save_accounts(self) -> bool:
        """
        Speichert den aktuellen Account‑Stand.

        Returns:
            bool: True bei Erfolg, False bei Fehler.
        """
        if self.master_password is None or self.salt is None:
            messagebox.showerror(
                "Fehler",
                "Keine Master-Passwort-Informationen vorhanden.",
                parent=self.root,
            )
            return False

        try:
            self.data_store.save(self.master_password, self.accounts, self.salt)
        except Exception as exc:
            messagebox.showerror(
                "Fehler beim Speichern",
                str(exc),
                parent=self.root,
            )
            return False

        self._refresh_tree()
        return True

    def _add_account_dialog(self) -> None:
        """Öffnet den Dialog zum Hinzufügen eines neuen Accounts."""
        dialog = AccountDialog(self.root, title="Neuer Account")
        self.root.wait_window(dialog)

        if dialog.result is None:
            return

        name, info, firma, secret, hash_algo, digits, period = dialog.result

        new_account = Account(
            name=name,
            info=info,
            firma=firma,
            secret=secret,
            hash_algo=hash_algo,
            digits=digits,
            period=period,
        )

        self.accounts.append(new_account)

        if not self._save_accounts():
            self.accounts.pop()
            self._refresh_tree()

    def _delete_selected_account(self) -> None:
        """Löscht den ausgewählten Account nach Bestätigung."""
        selected = self.tree.selection()

        if not selected:
            messagebox.showinfo("Info", "Kein Account ausgewählt.", parent=self.root)
            return

        idx = int(selected[0])

        if idx < 0 or idx >= len(self.accounts):
            return

        acct = self.accounts[idx]

        if not messagebox.askyesno(
            "Bestätigung",
            f"Account '{acct.name}' ({acct.info}) wirklich löschen?",
            parent=self.root,
        ):
            return

        removed = self.accounts.pop(idx)

        if not self._save_accounts():
            self.accounts.insert(idx, removed)
            self._refresh_tree()

    def _edit_selected_account(self, idx: int) -> None:
        """Öffnet den Bearbeiten‑Dialog."""
        if idx < 0 or idx >= len(self.accounts):
            return

        old_account = self.accounts[idx]
        dialog = EditAccountDialog(self.root, old_account)
        self.root.wait_window(dialog)

        if dialog.result is None:
            return

        name, info, firma, secret, hash_algo, digits, period = dialog.result

        new_account = Account(
            name=name,
            info=info,
            firma=firma,
            secret=secret,
            hash_algo=hash_algo,
            digits=digits,
            period=period,
        )

        self.accounts[idx] = new_account

        if not self._save_accounts():
            self.accounts[idx] = old_account
            self._refresh_tree()

    # ------------------------------------------------------------------ #
    # Treeview‑Interaktion
    # ------------------------------------------------------------------ #

    def _on_tree_click(self, event) -> None:
        """
        Zeigt das OTP 5 Sekunden lang an und kopiert es in die Zwischenablage.
        """
        if self.tree.identify("region", event.x, event.y) != "cell":
            return

        if self.tree.identify_column(event.x) != "#5":
            return

        row_id = self.tree.identify_row(event.y)

        if not row_id:
            return

        idx = int(row_id)

        if idx < 0 or idx >= len(self.accounts):
            return

        acct = self.accounts[idx]

        try:
            code = pyotp.TOTP(
                acct.secret,
                digits=acct.digits,
                digest=getattr(hashlib, acct.hash_algo),
                interval=acct.period,
            ).now()
        except Exception as exc:
            messagebox.showerror(
                "TOTP-Fehler",
                f"Code konnte nicht berechnet werden:\n{exc}",
                parent=self.root,
            )
            return

        self.tree.set(row_id, "code", code)
        self.root.clipboard_clear()
        self.root.clipboard_append(code)
        self.root.after(5000, lambda row=row_id: self._hide_code(row))

    def _hide_code(self, row_id: str) -> None:
        """Setzt die Code‑Spalte wieder auf ``'***'``."""
        if hasattr(self, "tree") and self.tree.exists(row_id):
            self.tree.set(row_id, "code", "***")

    def _show_context_menu(self, event) -> None:
        """Zeigt ein Kontext‑Menü beim Rechtsklick."""
        selected_item = self.tree.identify_row(event.y)

        if not selected_item:
            return

        idx = int(selected_item)

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(
            label="Bearbeiten",
            command=lambda: self._edit_selected_account(idx),
        )
        menu.post(event.x_root, event.y_root)

    # ------------------------------------------------------------------ #
    # Master‑Passwort ändern
    # ------------------------------------------------------------------ #

    def _change_master_password(self) -> None:
        """
        Ermöglicht das Ändern des Master‑Passworts.

        Wichtig:
        Der interne Zustand wird erst geändert, nachdem das Speichern erfolgreich war.
        """
        pwd_current = simpledialog.askstring(
            "Master-Passwort ändern",
            "Aktuelles Master-Passwort eingeben:",
            parent=self.root,
            show="*",
        )

        if pwd_current is None:
            return

        if pwd_current != self.master_password:
            messagebox.showerror("Fehler", "Falsches Passwort.", parent=self.root)
            return

        new_pwd = _ask_confirmed_password(
            parent=self.root,
            title="Master-Passwort ändern",
            prompt_first="Neues Master-Passwort eingeben:",
            allow_cancel=True,
        )

        if new_pwd is None:
            return

        new_salt = os.urandom(SALT_SIZE)

        try:
            self.data_store.save(new_pwd, self.accounts, new_salt)
        except Exception as exc:
            messagebox.showerror(
                "Fehler beim Speichern",
                f"Master-Passwort wurde nicht geändert.\n\n{exc}",
                parent=self.root,
            )
            return

        self.master_password = new_pwd
        self.salt = new_salt

        messagebox.showinfo(
            "Erfolg",
            "Master-Passwort erfolgreich geändert.",
            parent=self.root,
        )

    # ------------------------------------------------------------------ #
    # Export / Import
    # ------------------------------------------------------------------ #

    def _entry_from_account(self, acct: Account) -> dict[str, object]:
        """Konvertiert einen Account in das Aegis‑Export‑Format."""
        return {
            "type": "totp",
            "uuid": str(uuid.uuid4()),
            "name": acct.name,
            "issuer": acct.firma,
            "note": acct.info,
            "favorite": False,
            "icon": None,
            "info": {
                "secret": acct.secret,
                "algo": acct.hash_algo.upper(),
                "digits": acct.digits,
                "period": acct.period,
            },
            "groups": [],
        }

    def _account_from_external(self, entry: dict) -> Account:
        """Konvertiert einen Aegis‑Import‑Eintrag in einen Account."""
        info = entry.get("info", {}) or {}

        return Account(
            name=entry.get("name") or "",
            info=entry.get("note") or "",
            firma=entry.get("issuer") or "",
            secret=info.get("secret", ""),
            hash_algo=(info.get("algo", DEFAULT_HASH) or DEFAULT_HASH).lower(),
            digits=int(info.get("digits", DEFAULT_DIGITS)),
            period=int(info.get("period", DEFAULT_PERIOD)),
        )

    def _export_data(self) -> None:
        """Exportiert die Accounts als JSON, optional verschlüsselt."""
        if not self.master_password or not self.salt:
            messagebox.showerror(
                "Fehler",
                "Keine Master-Passwort-Informationen vorhanden.",
                parent=self.root,
            )
            return

        save_path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Exportieren – Ziel wählen",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )

        if not save_path:
            return

        encrypt = messagebox.askyesno(
            "Exportieren",
            "Soll die Datei verschlüsselt werden?",
            icon="question",
            parent=self.root,
        )

        export_obj: dict[str, object] = {
            "version": 1,
            "header": {"slots": None, "params": None},
            "db": {"entries": [self._entry_from_account(a) for a in self.accounts]},
        }

        try:
            if encrypt:
                key = CryptoHelper.derive_key(self.master_password, self.salt)
                ciphertext_b64 = CryptoHelper.encrypt(json.dumps(export_obj).encode(), key)

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
                f"Datei erfolgreich gespeichert:\n{save_path}",
                parent=self.root,
            )

        except Exception as exc:
            messagebox.showerror("Fehler beim Export", str(exc), parent=self.root)

    def _import_data(self) -> None:
        """
        Importiert Accounts aus einer JSON‑Datei.

        Fehlerhafte Accounts werden erkannt. Der Benutzer kann entscheiden,
        ob gültige Accounts trotzdem importiert und fehlerhafte übersprungen werden.
        """
        if not self.master_password or not self.salt:
            messagebox.showerror(
                "Fehler",
                "Keine Master-Passwort-Informationen vorhanden.",
                parent=self.root,
            )
            return

        import_path = filedialog.askopenfilename(
            parent=self.root,
            title="Importieren – Quelle wählen",
            defaultextension=".json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")],
        )

        if not import_path:
            return

        try:
            with open(import_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as exc:
            messagebox.showerror("Fehler beim Laden", str(exc), parent=self.root)
            return

        if isinstance(raw, dict) and {"salt", "data"} <= raw.keys():
            export_salt = base64.urlsafe_b64decode(raw["salt"])
            try_pwd = self.master_password

            while True:
                try:
                    key = CryptoHelper.derive_key(try_pwd, export_salt)
                    plaintext = CryptoHelper.decrypt(raw["data"], key)
                    raw = json.loads(plaintext.decode())
                    break
                except ValueError:
                    try_pwd = simpledialog.askstring(
                        "Passwort für verschlüsselte Datei",
                        "Das aktuelle Master-Passwort kann die Datei nicht entschlüsseln.\n"
                        "Bitte anderes Passwort eingeben:",
                        parent=self.root,
                        show="*",
                    )

                    if try_pwd is None:
                        return

        if isinstance(raw, dict) and "db" in raw and "entries" in raw.get("db", {}):
            try:
                imported_raw = [
                    self._account_from_external(e)
                    for e in raw["db"]["entries"]
                    if e.get("type") == "totp"
                ]
            except Exception as exc:
                messagebox.showerror("Fehler bei der Konvertierung", str(exc), parent=self.root)
                return

        elif isinstance(raw, list):
            try:
                imported_raw = [Account.from_dict(a) for a in raw]
            except Exception as exc:
                messagebox.showerror("Fehler bei der Konvertierung", str(exc), parent=self.root)
                return

        else:
            messagebox.showerror(
                "Ungültiges Format",
                "Die Datei enthält keine Account-Liste.",
                parent=self.root,
            )
            return

        imported: list[Account] = []
        import_errors: list[str] = []

        for index, acct in enumerate(imported_raw, start=1):
            label = acct.name or acct.info or acct.firma or f"Eintrag {index}"

            try:
                imported.append(_validate_and_normalize_account(acct))
            except Exception as exc:
                import_errors.append(f"{index}. {label}: {exc}")

        if import_errors:
            if not imported:
                messagebox.showerror(
                    "Import-Validierung",
                    "Alle importierten Accounts sind fehlerhaft.\n\n"
                    f"{_format_error_list(import_errors)}",
                    parent=self.root,
                )
                return

            proceed = messagebox.askyesno(
                "Import-Validierung",
                f"{len(imported)} Account(s) sind gültig.\n"
                f"{len(import_errors)} Account(s) sind fehlerhaft.\n\n"
                "Fehlerhafte Accounts überspringen und gültige trotzdem importieren?\n\n"
                f"{_format_error_list(import_errors)}",
                icon="warning",
                parent=self.root,
            )

            if not proceed:
                return

        replace = messagebox.askyesno(
            "Import",
            "Möchten Sie die vorhandenen Accounts vollständig ersetzen?\n"
            "(Nein = neue Accounts hinzufügen; gleicher Name+Info wird ersetzt)",
            icon="question",
            parent=self.root,
        )

        old_accounts = list(self.accounts)

        if replace:
            self.accounts = imported
        else:
            by_key = {(a.name, a.info): a for a in self.accounts}

            for a in imported:
                by_key[(a.name, a.info)] = a

            self.accounts = list(by_key.values())

        try:
            self.data_store.save(self.master_password, self.accounts, self.salt)
        except Exception as exc:
            self.accounts = old_accounts
            self._refresh_tree()

            messagebox.showerror("Fehler beim Speichern", str(exc), parent=self.root)
            return

        self._refresh_tree()

        if import_errors:
            messagebox.showwarning(
                "Importieren abgeschlossen",
                f"Erfolgreich importiert: {len(imported)} Account(s).\n"
                f"Übersprungen wegen Fehlern: {len(import_errors)} Account(s).\n\n"
                f"{_format_error_list(import_errors)}",
                parent=self.root,
            )
        else:
            messagebox.showinfo(
                "Importieren",
                f"Erfolgreich importiert.\n{len(imported)} Accounts.",
                parent=self.root,
            )


# --------------------------------------------------------------------------- #
# Snipping‑Tool für QR‑Code‑Scan
# --------------------------------------------------------------------------- #

class SnippingTool(tk.Toplevel):
    """
    Transparentes Vollbild‑Overlay zum Markieren eines Bildschirmbereichs.
    """

    def __init__(self, parent, callback) -> None:
        super().__init__(parent)

        self.callback = callback

        self.attributes("-fullscreen", True)
        self.attributes("-alpha", 0.3)
        self.configure(bg="black")
        self.lift()
        self.focus_force()

        self.canvas = tk.Canvas(self, cursor="cross", bg="black", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_move)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Escape>", self._on_escape)

        self.start_x = None
        self.start_y = None
        self.rect = None

    def _on_escape(self, event=None) -> None:
        """Escape – Abbruch."""
        self.destroy()
        self.callback(None)

    def _on_press(self, event) -> None:
        self.start_x = self.canvas.canvasx(event.x)
        self.start_y = self.canvas.canvasy(event.y)

        self.rect = self.canvas.create_rectangle(
            self.start_x,
            self.start_y,
            self.start_x,
            self.start_y,
            outline="red",
            width=3,
            fill="white",
        )

    def _on_move(self, event) -> None:
        if self.rect is None:
            return

        self.canvas.coords(
            self.rect,
            self.start_x,
            self.start_y,
            self.canvas.canvasx(event.x),
            self.canvas.canvasy(event.y),
        )

    def _on_release(self, event) -> None:
        if self.start_x is None or self.start_y is None:
            self.callback(None)
            self.destroy()
            return

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
    """

    def __init__(self, parent: tk.Widget, title: str = "Account") -> None:
        super().__init__(parent)

        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        self.result: Optional[Tuple[str, str, str, str, str, int, int]] = None

        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="Kontoname:").grid(row=0, column=0, padx=8, pady=6, sticky="e")
        self.name_entry = ttk.Entry(self, width=34)
        self.name_entry.grid(row=0, column=1, padx=8, pady=6, sticky="ew")

        ttk.Label(self, text="Information:").grid(row=1, column=0, padx=8, pady=6, sticky="e")
        self.info_entry = ttk.Entry(self, width=34)
        self.info_entry.grid(row=1, column=1, padx=8, pady=6, sticky="ew")

        ttk.Label(self, text="Firma (Issuer):").grid(row=2, column=0, padx=8, pady=6, sticky="e")
        self.firma_entry = ttk.Entry(self, width=34)
        self.firma_entry.grid(row=2, column=1, padx=8, pady=6, sticky="ew")

        ttk.Label(self, text="TOTP-Schlüssel:").grid(row=3, column=0, padx=8, pady=6, sticky="e")
        self.secret_entry = ttk.Entry(self, width=34)
        self.secret_entry.grid(row=3, column=1, padx=8, pady=6, sticky="ew")

        next_row = 4

        if QR_SCAN_AVAILABLE:
            qr_frame = ttk.Frame(self)
            qr_frame.grid(row=next_row, column=0, columnspan=2, pady=(0, 4))

            ttk.Button(
                qr_frame,
                text="📷  Von QR-Code scannen (Screenshot)",
                command=self._scan_qr_screenshot,
            ).pack(side=tk.LEFT, padx=5)

            ttk.Button(
                qr_frame,
                text="🖼  Von Bilddatei",
                command=self._scan_qr_file,
            ).pack(side=tk.LEFT, padx=5)

            next_row += 1

        ttk.Label(self, text="Hash-Algorithmus:").grid(row=next_row, column=0, padx=8, pady=6, sticky="e")
        self.hash_var = tk.StringVar(value=DEFAULT_HASH)

        self.hash_combo = ttk.Combobox(
            self,
            textvariable=self.hash_var,
            values=list(HASH_OPTIONS),
            state="readonly",
            width=31,
        )
        self.hash_combo.grid(row=next_row, column=1, padx=8, pady=6, sticky="ew")

        next_row += 1

        ttk.Label(self, text=f"Ziffern ({DEFAULT_DIGITS}):").grid(row=next_row, column=0, padx=8, pady=6, sticky="e")
        self.digits_spin = ttk.Spinbox(self, from_=4, to=10, width=31)
        self.digits_spin.set(str(DEFAULT_DIGITS))
        self.digits_spin.grid(row=next_row, column=1, padx=8, pady=6, sticky="ew")

        next_row += 1

        ttk.Label(self, text=f"Periode Sekunden ({DEFAULT_PERIOD}):").grid(
            row=next_row,
            column=0,
            padx=8,
            pady=6,
            sticky="e",
        )
        self.period_spin = ttk.Spinbox(self, from_=1, to=3600, width=31)
        self.period_spin.set(str(DEFAULT_PERIOD))
        self.period_spin.grid(row=next_row, column=1, padx=8, pady=6, sticky="ew")

        next_row += 1

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=next_row, column=0, columnspan=2, pady=12)

        ttk.Button(btn_frame, text="OK", command=self._ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Abbrechen", command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.bind("<Return>", lambda event: self._ok())
        self.bind("<Escape>", lambda event: self.destroy())

        self.name_entry.focus_set()

        self.update_idletasks()
        self._center_on_parent(parent)

    def _center_on_parent(self, parent: tk.Widget) -> None:
        """Zentriert den Dialog relativ zum Parent-Fenster."""
        try:
            self.update_idletasks()

            parent_x = parent.winfo_rootx()
            parent_y = parent.winfo_rooty()
            parent_w = parent.winfo_width()
            parent_h = parent.winfo_height()

            w = self.winfo_width()
            h = self.winfo_height()

            x = parent_x + max(0, (parent_w - w) // 2)
            y = parent_y + max(0, (parent_h - h) // 2)

            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # QR‑Code‑Scan
    # ------------------------------------------------------------------ #

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
            try:
                w, h = img.size
                img_big = img.resize((w * 2, h * 2), Image.LANCZOS)
                decoded = _decode_qr(img_big)
            except Exception:
                pass

        if not decoded:
            messagebox.showwarning(
                "QR-Code",
                "Kein QR-Code erkannt.\nTipp: Bereich etwas größer markieren.",
                parent=self,
            )
            return

        parsed = _parse_otpauth_uri(decoded[0])

        if not parsed.get("secret"):
            messagebox.showwarning(
                "QR-Code",
                f"Kein gültiger otpauth-URI gefunden:\n{decoded[0]}",
                parent=self,
            )
            return

        _set_entry(self.name_entry, parsed.get("account", ""))
        _set_entry(self.info_entry, "")
        _set_entry(self.firma_entry, parsed.get("issuer", ""))
        _set_entry(self.secret_entry, parsed.get("secret", ""))

        algo = parsed.get("algorithm", DEFAULT_HASH)

        if algo in HASH_OPTIONS:
            self.hash_var.set(algo)

        self.digits_spin.set(str(parsed.get("digits", DEFAULT_DIGITS)))
        self.period_spin.set(str(parsed.get("period", DEFAULT_PERIOD)))

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
            title="QR-Code-Bild öffnen",
            filetypes=[("Bilder", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")],
        )

        if not path:
            return

        try:
            self._fill_from_qr_image(Image.open(path))
        except Exception as exc:
            messagebox.showerror("Fehler", str(exc), parent=self)

    # ------------------------------------------------------------------ #
    # Validierung & Bestätigung
    # ------------------------------------------------------------------ #

    def _ok(self) -> None:
        """Validiert die Eingaben und schreibt das Ergebnis."""
        name = self.name_entry.get().strip()
        info = self.info_entry.get().strip()
        firma = self.firma_entry.get().strip()
        secret = _normalize_secret(self.secret_entry.get())
        hash_algo = self.hash_var.get()

        try:
            digits = int(self.digits_spin.get())
        except Exception:
            messagebox.showerror("Fehler", "Ungültige Ziffernanzahl.", parent=self)
            return

        try:
            period = int(self.period_spin.get())
        except Exception:
            messagebox.showerror("Fehler", "Ungültige Periode.", parent=self)
            return

        if not name:
            messagebox.showerror("Fehler", "Der Kontoname darf nicht leer sein.", parent=self)
            return

        if not secret:
            messagebox.showerror("Fehler", "Der TOTP-Schlüssel darf nicht leer sein.", parent=self)
            return

        if hash_algo not in HASH_OPTIONS:
            messagebox.showerror("Fehler", "Ungültiger Hash-Algorithmus.", parent=self)
            return

        try:
            _validate_totp(secret, digits, hash_algo, period)
        except Exception as exc:
            messagebox.showerror("Ungültiges Secret", str(exc), parent=self)
            return

        self.result = (name, info, firma, secret, hash_algo, digits, period)
        self.destroy()


# --------------------------------------------------------------------------- #
# EditAccountDialog – spezialisiert für bestehende Accounts
# --------------------------------------------------------------------------- #

class EditAccountDialog(AccountDialog):
    """
    Dialog zum Bearbeiten eines bestehenden Accounts.

    Secret-Maskierung erfolgt jetzt über Entry(show="*") statt über echte
    Sternchen als Feldinhalt.
    """

    def __init__(self, parent: tk.Widget, account: Account) -> None:
        super().__init__(parent, title="Account bearbeiten")

        _set_entry(self.name_entry, account.name)
        _set_entry(self.info_entry, account.info)
        _set_entry(self.firma_entry, account.firma)
        _set_entry(self.secret_entry, account.secret)

        self.hash_var.set(account.hash_algo)
        self.digits_spin.set(str(account.digits))
        self.period_spin.set(str(account.period))

        self.secret_entry.configure(show="*")

        self.show_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            self,
            text="Schlüssel anzeigen?",
            variable=self.show_var,
            command=self._toggle_show_secret,
        ).grid(row=3, column=2, padx=(0, 8), pady=6, sticky="w")

    def _toggle_show_secret(self) -> None:
        """Schaltet zwischen Klartext und maskierter Anzeige um."""
        self.secret_entry.configure(show="" if self.show_var.get() else "*")

    def _fill_from_qr_image(self, img) -> None:
        """
        Überschreibt die Basismethode.

        Nach QR-Scan wird der neue Secret sichtbar angezeigt, damit der Nutzer
        sieht, dass etwas übernommen wurde.
        """
        super()._fill_from_qr_image(img)

        if self.secret_entry.get().strip():
            self.show_var.set(True)
            self.secret_entry.configure(show="")

    # _ok() wird unverändert von AccountDialog geerbt – identische Validierung.


# --------------------------------------------------------------------------- #
# Einstiegspunkt
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    AuthenticatorApp()