#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backups_palo_alto.py

Respaldo de firewalls Palo Alto Networks (PAN-OS) con verificación SHA-256 y reporte por e-mail.
Incluye:
  - Inventario en CSV o cifrado DPAPI (.dpapi) en Windows (hide/reveal)
  - Carga de variables desde .env
  - Descarga vía PAN-OS XML API con fallback SSH CLI
  - Logs rotados
"""

from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import io
import html
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shlex
import smtplib
import socket
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from email.message import EmailMessage
from ipaddress import ip_address
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import quote

import paramiko
import requests
import urllib3

from resources.logger import logger
from resources.email_client import EmailClient
from modules.panos_client import export_panos_backup, PanosApiError
from modules.dpapi import hide_csv_to_dpapi, reveal_dpapi_to_csv, read_inventory_bytes
from modules.csv_parser import parse_equipo_fields

# ─── Carga opcional de .env ──────────────────────────────────────
try:
    from dotenv import load_dotenv
    _ENV_PATH = Path(__file__).resolve().parent / ".env"
    if _ENV_PATH.exists():
        load_dotenv(_ENV_PATH)
except Exception:
    pass

# ─── CONFIG GENERAL ──────────────────────────────────────────────
BASE_FOLDER = Path(os.getenv("BASE_FOLDER", r"E:\Respaldos_new")).resolve()
LOGS_FOLDER = BASE_FOLDER / "logs_paloalto"
EQUIPOS_FILE = os.getenv("EQUIPOS_FILE", "equipos_paloalto.dpapi")

BACKUP_HISTORY_LIMIT = int(os.getenv("BACKUP_HISTORY_LIMIT", "1"))
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "60"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "5"))

PANOS_API_PORT = int(os.getenv("PANOS_API_PORT", "443"))
PANOS_EXPORT_CATEGORY = os.getenv("PANOS_EXPORT_CATEGORY", "configuration")

ENABLE_MAIL = os.getenv("ENABLE_MAIL", "true").lower() in ("1", "true", "yes")

_INVISIBLE_TRANSLATION = {
    ord("\ufeff"): None,
    ord("\u200b"): None,
    ord("\u200c"): None,
    ord("\u200d"): None,
    ord("\u2060"): None,
    ord("\u00ad"): None,
    ord("\u00a0"): ord(" "),
}


def _strip_invisibles(text: str) -> str:
    if text is None:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE_TRANSLATION)
    text = "".join(ch for ch in text if ch == " " or ch.isprintable())
    return text.strip()


def _clean_secret(pwd: str) -> str:
    if pwd is None:
        return ""
    if pwd.startswith("\ufeff"):
        pwd = pwd[1:]
    return pwd.rstrip("\r\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _cleanup_local(folder: Path, limit: int, pattern: str = "backup-*.*") -> None:
    files = sorted(
        (p for p in folder.glob(pattern) if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for p in files[limit:]:
        try:
            p.unlink()
        except Exception:
            pass


def _connect_panos_transport(host: str, user: str, pwd: str, timeout: int = 60) -> paramiko.Transport:
    """Conecta por SSH a Palo Alto Networks soportando keyboard-interactive (requerido por PAN-OS)."""
    sock = socket.create_connection((host, 22), timeout=timeout)
    tr = paramiko.Transport(sock)
    tr.start_client(timeout=timeout)
    auth_ok = False
    try:
        def handler(title, instructions, prompt_list):
            return [pwd for _ in prompt_list]
        tr.auth_interactive(user, handler)
        if tr.is_authenticated():
            auth_ok = True
    except Exception:
        pass
    if not auth_ok:
        try:
            tr.auth_password(user, pwd)
            if tr.is_authenticated():
                auth_ok = True
        except Exception:
            pass
    if not auth_ok:
        tr.close()
        sock.close()
        raise paramiko.AuthenticationException(f"Autenticación SSH fallida en {host} para usuario '{user}' (keyboard-interactive y password rechazados)")
    return tr


def _backup_via_ssh_cli(host: str, user: str, pwd: str, out_path: Path, timeout: int = 60) -> int:
    tr = _connect_panos_transport(host, user, pwd, timeout=timeout)
    try:
        chan = tr.open_session(timeout=timeout)
        chan.settimeout(timeout)
        chan.invoke_shell(term="dumb", width=512, height=1000)
        time.sleep(1)
        if chan.recv_ready():
            chan.recv(4096)
        chan.send("set cli pager off\n")
        time.sleep(1)
        if chan.recv_ready():
            chan.recv(2048)
        chan.send("show config running\n")
        
        chunks = []
        start_w = time.time()
        while time.time() - start_w < timeout:
            if chan.recv_ready():
                c = chan.recv(8192).decode("utf-8", errors="ignore")
                chunks.append(c)
                if "</config>" in c or "<result></result>" in c:
                    if "</config>" in "".join(chunks):
                        break
            time.sleep(0.5)
            
        full = "".join(chunks)
        s_idx = full.find("<config")
        e_idx = full.rfind("</config>")
        if s_idx != -1 and e_idx != -1:
            xml_data = full[s_idx : e_idx + len("</config>")]
        else:
            xml_data = full.replace("show config running", "").strip()
            
        if not xml_data or len(xml_data) < 100:
            raise IOError(f"Contenido XML insuficiente vía SSH de {host}")
        with out_path.open("w", encoding="utf-8") as f:
            f.write(xml_data)
        return out_path.stat().st_size
    finally:
        tr.close()


def parse_equipos(path: str) -> List[Dict]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Inventario no encontrado: {path}")
    raw_bytes = read_inventory_bytes(str(p))
    try:
        txt = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        txt = raw_bytes.decode("latin-1")

    f = io.StringIO(txt)
    sample = f.read(2048)
    f.seek(0)
    try:
        delim = csv.Sniffer().sniff(sample, delimiters=",;|\t").delimiter
    except Exception:
        delim = ","

    reader = csv.reader(f, delimiter=delim)
    equipos = []
    seen = set()
    for idx, row in enumerate(reader, 1):
        if not row or not any(row):
            continue
        eq_dict = parse_equipo_fields(row, timeout=DEFAULT_TIMEOUT)
        if not eq_dict:
            continue
        ip = eq_dict["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        eq_dict["linea"] = idx
        equipos.append(eq_dict)
    return equipos


def process_single(eq: Dict) -> Dict:
    host, ip, g = eq["hostname"], eq["ip"], eq["grupo"]
    u, pw, tmo = eq["username"], eq["password"], eq["timeout"]
    start = time.time()
    ext = ".tgz" if PANOS_EXPORT_CATEGORY == "device-state" else ".xml"
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bname = f"backup-{host}-{ts}{ext}"
    local_dir = BASE_FOLDER / g / host
    local_dir.mkdir(parents=True, exist_ok=True)
    local_path = local_dir / bname
    method = "XML-API"

    try:
        try:
            export_panos_backup(
                host=ip,
                user=u,
                pwd=pw,
                out_path=local_path,
                category=PANOS_EXPORT_CATEGORY,
                port=PANOS_API_PORT,
                timeout=tmo,
            )
            method = f"XML-API({PANOS_EXPORT_CATEGORY})"
        except Exception as e_api:
            logger.warning(f"XML-API falló para {host} ({e_api}). Probando SSH...")
            if local_path.exists():
                try:
                    local_path.unlink()
                except Exception:
                    pass
            if PANOS_EXPORT_CATEGORY == "configuration":
                _backup_via_ssh_cli(ip, u, pw, local_path, timeout=tmo)
                method = "SSH-CLI"
            else:
                raise e_api

        if not local_path.exists() or local_path.stat().st_size == 0:
            raise IOError(f"Archivo 0 bytes vía {method}")

        h_local = sha256_file(local_path)
        _cleanup_local(local_dir, BACKUP_HISTORY_LIMIT, f"backup-*{ext}")
        elapsed = round(time.time() - start, 1)
        logger.info(f"✅ {host} backup OK vía {method}")
        return dict(
            eq,
            status="OK",
            backup_file=str(local_path),
            method=method,
            elapsed=elapsed,
            sha256_local=h_local,
            file_size=local_path.stat().st_size,
        )
    except Exception as e:
        logger.error(f"❌ {host} backup ERROR: {e}")
        return dict(eq, status="ERROR", error_detail=str(e), method=method, elapsed=round(time.time() - start, 1))


def run_batch() -> int:
    try:
        equipos = parse_equipos(EQUIPOS_FILE)
    except Exception as e:
        logger.error(f"Error cargando inventario {EQUIPOS_FILE}: {e}")
        return 1

    if not equipos:
        logger.warning("No hay equipos para procesar.")
        return 0

    logger.info(f"Iniciando respaldo de {len(equipos)} firewalls Palo Alto...")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = [pool.submit(process_single, eq) for eq in equipos]
        for fut in as_completed(futs):
            results.append(fut.result())

    total_ok = sum(1 for r in results if r.get("status") == "OK")
    total_err = sum(1 for r in results if r.get("status") != "OK")
    logger.info(f"RESUMEN FINAL PALO ALTO: OK={total_ok}, ERROR={total_err}, Total={len(results)}")

    if ENABLE_MAIL:
        try:
            from modules.email_reports import send_consolidated_summary
            send_consolidated_summary(results)
        except Exception as e_m:
            logger.error(f"Error enviando correo consolidado: {e_m}")

    return 0 if total_err == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="Backups masivos de firewalls Palo Alto Networks."
    )
    sub = parser.add_subparsers(dest="cmd")
    p_hide = sub.add_parser("hide", help="Cifra un CSV a .dpapi")
    p_hide.add_argument("--in", dest="in_path", default="equipos_paloalto.csv")
    p_hide.add_argument("--out", dest="out_path", default="equipos_paloalto.dpapi")
    p_hide.add_argument("--keep-csv", action="store_true")

    p_reveal = sub.add_parser("reveal", help="Descifra un .dpapi a CSV")
    p_reveal.add_argument("--in", dest="in_path", default="equipos_paloalto.dpapi")
    p_reveal.add_argument("--out", dest="out_path", default="equipos_paloalto.csv")

    sub.add_parser("run", help="Ejecuta respaldos del inventario (default)")

    args = parser.parse_args()
    if args.cmd == "hide":
        hide_csv_to_dpapi(args.in_path, args.out_path, delete_plain=not args.keep_csv)
        print(f"[OK] Cifrado exitoso: {args.out_path}")
        return 0
    elif args.cmd == "reveal":
        reveal_dpapi_to_csv(args.in_path, args.out_path)
        print(f"[OK] Descifrado exitoso: {args.out_path}")
        return 0
    else:
        return run_batch()


if __name__ == "__main__":
    import sys
    sys.exit(main())
