#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backups_f5_fixed.py

Respaldo UCS de F5 BIG‑IP con verificación SHA‑256 y reporte por e‑mail.
Incluye:
- Inventario en CSV o cifrado DPAPI (.dpapi) en Windows (hide/reveal)
- Carga de variables sensibles desde .env (python-dotenv opcional)
- Descarga UCS por REST (iControl file-transfer) con fallback a SFTP/CAT
- Logs rotados

DPAPI (Windows): https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
python-dotenv:   https://pypi.org/project/python-dotenv/
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
from paramiko import SFTPError
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    SSHException,
)

# ───────────────────────────────────────────────────────────────
#                 Carga opcional de .env (python-dotenv)
# ───────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv  # type: ignore
    _ENV_PATH = Path(__file__).resolve().parent / ".env"
    if _ENV_PATH.exists():
        load_dotenv(_ENV_PATH)
except Exception:
    # Sin dependencia o sin .env: se usan variables del sistema.
    pass

# ───────────────────────────────────────────────────────────────
#                     Helpers de variables de entorno
# ───────────────────────────────────────────────────────────────
def _env_str(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v if v is not None else default

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or not str(v).strip():
        return default
    try:
        return int(str(v).strip())
    except ValueError:
        return default

def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")

def _env_list(name: str, default: List[str] | None = None) -> List[str]:
    if default is None:
        default = []
    v = os.getenv(name)
    if v is None or not str(v).strip():
        return default
    # separador: coma
    return [x.strip() for x in str(v).split(",") if x.strip()]

# ───────────────────────────────────────────────────────────────
#                DPAPI (Windows) para inventario cifrado
# ───────────────────────────────────────────────────────────────
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_CryptProtectData = _crypt32.CryptProtectData
_CryptProtectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB), wintypes.LPCWSTR,
    ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
    wintypes.DWORD, ctypes.POINTER(_DATA_BLOB)
]
_CryptProtectData.restype = wintypes.BOOL

_CryptUnprotectData = _crypt32.CryptUnprotectData
_CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
    wintypes.DWORD, ctypes.POINTER(_DATA_BLOB)
]
_CryptUnprotectData.restype = wintypes.BOOL

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [ctypes.c_void_p]
_LocalFree.restype = ctypes.c_void_p

def _raise_last_winerr(prefix: str) -> None:
    err = ctypes.get_last_error()
    raise OSError(f"{prefix} (winerr={err})")

def dpapi_encrypt_bytes(data: bytes) -> bytes:
    in_blob = _DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = _DATA_BLOB()
    if not _CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        _raise_last_winerr("DPAPI CryptProtectData falló")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _LocalFree(out_blob.pbData)

def dpapi_decrypt_bytes(data: bytes) -> bytes:
    in_blob = _DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = _DATA_BLOB()
    if not _CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        _raise_last_winerr("DPAPI CryptUnprotectData falló")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _LocalFree(out_blob.pbData)

def hide_csv_to_dpapi(csv_path: str, dpapi_path: str, delete_plain: bool = True) -> None:
    p_in = Path(csv_path)
    p_out = Path(dpapi_path)
    if not p_in.exists():
        raise FileNotFoundError(f"No existe CSV: {p_in}")
    p_out.write_bytes(dpapi_encrypt_bytes(p_in.read_bytes()))
    if delete_plain:
        p_in.unlink()

def reveal_dpapi_to_csv(dpapi_path: str, csv_path: str) -> None:
    p_in = Path(dpapi_path)
    p_out = Path(csv_path)
    if not p_in.exists():
        raise FileNotFoundError(f"No existe DPAPI: {p_in}")
    p_out.write_bytes(dpapi_decrypt_bytes(p_in.read_bytes()))

def _read_inventory_bytes(path: str) -> bytes:
    p = Path(path)
    raw = p.read_bytes()
    if p.suffix.lower() == ".dpapi":
        return dpapi_decrypt_bytes(raw)
    return raw

# ───────────────────────────────────────────────────────────────
#                          CONFIG GENERAL
# ───────────────────────────────────────────────────────────────
EQUIPOS_FILE = _env_str("EQUIPOS_FILE", "equipos_f5.dpapi")  # .csv o .dpapi
BASE_FOLDER = Path(_env_str("BASE_FOLDER", r"E:\Respaldos_new")).resolve()
LOGS_FOLDER = BASE_FOLDER / "logs_f5"

ENABLE_MAIL = _env_bool("ENABLE_MAIL", True)
DEVICE_FLOW_MAIL = _env_bool("DEVICE_FLOW_MAIL", True)  # correos 1x equipo para flujos
ENABLE_CONSOLIDATED_MAIL = _env_bool("ENABLE_CONSOLIDATED_MAIL", False)  # evita doble correo

BACKUP_HISTORY_LIMIT = _env_int("BACKUP_HISTORY_LIMIT", 1)
REMOTE_DIR = _env_str("REMOTE_DIR", "/var/local/ucs")
DEFAULT_TIMEOUT = _env_int("DEFAULT_TIMEOUT", 60)
WAIT_TIMEOUT = _env_int("WAIT_TIMEOUT", 60)
WAIT_INTERVAL = _env_int("WAIT_INTERVAL", 30)
KEEPALIVE_INT = _env_int("KEEPALIVE_INT", 25)
SFTP_RETRIES = _env_int("SFTP_RETRIES", 2)
AUTOMATION_NAME = _env_str("AUTOMATION_NAME", "Automatización SOC - F5 Backup")

REST_PORT = _env_int("REST_PORT", 443)
REST_VERIFY_TLS = _env_bool("REST_VERIFY_TLS", False)

# SMTP / Email (sensibles en .env)
SMTP_SERVER = _env_str("SMTP_SERVER", "")
SMTP_PORT = _env_int("SMTP_PORT", 25)
USE_SSL = _env_bool("USE_SSL", False)
USE_STARTTLS = _env_bool("SMTP_USE_STARTTLS", True)
SMTP_REQUIRES_AUTH = _env_bool("SMTP_REQUIRES_AUTH", True)
SMTP_USER = _env_str("SMTP_USER", "")
SMTP_PASS = _env_str("SMTP_PASS", "")

EMAIL_FROM = _env_str("EMAIL_FROM", "")
EMAIL_TO = _env_list("EMAIL_TO", [])
EMAIL_CC = _env_list("EMAIL_CC", [])
EMAIL_BCC = _env_list("EMAIL_BCC", [])

_INVISIBLE_TRANSLATION = {
    ord("\ufeff"): None,
    ord("\u200b"): None,
    ord("\u200c"): None,
    ord("\u200d"): None,
    ord("\u2060"): None,
    ord("\u00ad"): None,
    ord("\u00a0"): ord(" "),
}

# ───────────────────────────────────────────────────────────────
#                               LOGGING
# ───────────────────────────────────────────────────────────────
logger = logging.getLogger("f5_backup")
logger.setLevel(logging.INFO)

class _DropParamikoNoise(logging.Filter):
    def filter(self, record):
        msg = record.getMessage().lower()
        return ("unhandled type 3" not in msg) and ("unimplemented" not in msg)

class ContextualFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'

    def format(self, record):
        prefix = []
        if hasattr(record, 'equipo_hostname'):
            prefix.append(str(record.equipo_hostname))
        if hasattr(record, 'equipo_ip'):
            prefix.append(str(record.equipo_ip))
        if prefix:
            record.msg = f"[{'|'.join(prefix)}] {record.msg}"
        log_message = super().format(record)
        if getattr(self, 'use_colors', False):
            color = self.COLORS.get(record.levelname, self.RESET)
            log_message = f"{color}{log_message}{self.RESET}"
        return log_message

def init_logging():
    LOGS_FOLDER.mkdir(parents=True, exist_ok=True)
    log_file = LOGS_FOLDER / f"resp_{datetime.now():%Y%m%d-%H%M%S}.log"

    detailed_fmt = ContextualFormatter(
        "%(asctime)s | %(levelname)-8s | %(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_fmt = ContextualFormatter("%(asctime)s %(levelname)s: %(message)s", datefmt="%H:%M:%S")
    console_fmt.use_colors = True

    fh = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=10, encoding="utf-8")
    fh.setFormatter(detailed_fmt)
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setFormatter(console_fmt)
    ch.setLevel(logging.INFO)

    logger.handlers.clear()
    logger.addHandler(fh)
    logger.addHandler(ch)

    logging.getLogger("paramiko").setLevel(logging.ERROR)
    logging.getLogger("paramiko.transport").addFilter(_DropParamikoNoise())
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)

    if not REST_VERIFY_TLS:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logger.info("=" * 60)
    logger.info("Iniciando proceso de backup F5 UCS")
    logger.info("Inventario: %s", EQUIPOS_FILE)
    logger.info("Carpeta base: %s", BASE_FOLDER)
    logger.info("=" * 60)

# ───────────────────────────────────────────────────────────────
#                               SMTP
# ───────────────────────────────────────────────────────────────
class SMTPClient:
    def __enter__(self):
        if USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=30)
            server.ehlo()
        else:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30)
            server.ehlo()
            if USE_STARTTLS:
                server.starttls()
                server.ehlo()
        if SMTP_REQUIRES_AUTH:
            server.login(SMTP_USER, SMTP_PASS)
        self.server = server
        return self.server

    def __exit__(self, exc_type, exc, tb):
        try:
            self.server.quit()
        except Exception:
            pass

def build_message(subject: str, body: str, html: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    if EMAIL_CC:
        msg["Cc"] = ", ".join(EMAIL_CC)
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    return msg

def send_email(msg: EmailMessage):
    # Validación SMTP diferida (permite usar 'hide' sin .env listo)
    if not SMTP_SERVER or not EMAIL_FROM or not EMAIL_TO:
        raise RuntimeError("Faltan SMTP_SERVER / EMAIL_FROM / EMAIL_TO en .env")
    if SMTP_REQUIRES_AUTH and (not SMTP_USER or not SMTP_PASS):
        raise RuntimeError("SMTP_REQUIRES_AUTH=true pero SMTP_USER/SMTP_PASS vacíos (revisa .env)")

    recipients = EMAIL_TO + EMAIL_CC + EMAIL_BCC
    with SMTPClient() as server:
        server.send_message(msg, to_addrs=recipients)

# ───────────────────────────────────────────────────────────────
#                          UTILIDADES
# ───────────────────────────────────────────────────────────────
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
    pwd = unicodedata.normalize("NFKC", pwd)
    pwd = pwd.translate(_INVISIBLE_TRANSLATION)
    pwd = "".join(ch for ch in pwd if ch == " " or ch.isprintable())
    return pwd

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ───────────────────────────────────────────────────────────────
#                      PARSE CSV (SIN HEADERS)
# ───────────────────────────────────────────────────────────────
def parse_equipos_csv(path: str) -> List[Dict]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Archivo no encontrado: {path}")

    equipos: List[Dict] = []
    seen = set()

    logger.info("Parseando inventario: %s", path)

    inv_bytes = _read_inventory_bytes(str(p))
    f = io.StringIO(inv_bytes.decode("utf-8-sig", errors="replace"))
    sample = f.read(1024)
    f.seek(0)

    sniffer = csv.Sniffer()
    try:
        delimiter = sniffer.sniff(sample, delimiters=',;|\t').delimiter
    except csv.Error:
        delimiter = ","

    reader = csv.reader(f, delimiter=delimiter)

    for idx, row in enumerate(reader, 1):
        if not row or row[0].strip().startswith("#"):
            continue
        if len(row) != 4:
            logger.error("Línea #%d inválida (esperado 4 cols): %s", idx, row)
            continue

        grupo = _strip_invisibles(row[0])
        ip_str = _strip_invisibles(row[1])
        hostname = _strip_invisibles(row[2])
        auth_field = row[3].strip()

        if ":" not in auth_field:
            logger.error("Línea #%d sin user:pass", idx)
            continue

        usuario_raw, clave_raw = auth_field.split(":", 1)
        usuario = _strip_invisibles(usuario_raw)
        clave = _clean_secret(clave_raw)

        try:
            ip = str(ip_address(ip_str))
        except ValueError:
            logger.error("Línea #%d IP inválida: %s", idx, ip_str)
            continue

        if ip in seen:
            continue
        seen.add(ip)

        equipos.append({
            "grupo": grupo,
            "hostname": hostname,
            "ip": ip,
            "timeout": DEFAULT_TIMEOUT,
            "username": usuario,
            "password": clave,
            "linea": idx,
        })

    return equipos

# ───────────────────────────────────────────────────────────────
#                                SSH
# ───────────────────────────────────────────────────────────────
def _kbdint_handler(secret: str):
    def handler(title, instructions, prompts):
        return [secret for _p, _e in prompts]
    return handler

def _connect_via_kbdint(ip: str, user: str, pwd: str, tmo: int):
    sock = socket.create_connection((ip, 22), tmo)
    tr = paramiko.Transport(sock)
    tr.start_client(timeout=tmo)
    tr.set_keepalive(KEEPALIVE_INT)
    tr.auth_interactive(user, _kbdint_handler(pwd))
    if not tr.is_authenticated():
        raise AuthenticationException("kbd-int failed")

    ssh = paramiko.SSHClient()
    ssh._transport = tr
    return ssh

def connect_ssh(ip: str, user: str, pwd: str, tmo: int):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=ip,
            username=user,
            password=pwd,
            timeout=tmo,
            banner_timeout=tmo,
            auth_timeout=tmo,
            look_for_keys=False,
            allow_agent=False,
        )
        tr = ssh.get_transport()
        if tr:
            tr.set_keepalive(KEEPALIVE_INT)
        return ssh

    except AuthenticationException:
        alt = pwd.rstrip()
        if alt != pwd:
            ssh.connect(
                hostname=ip,
                username=user,
                password=alt,
                timeout=tmo,
                banner_timeout=tmo,
                auth_timeout=tmo,
                look_for_keys=False,
                allow_agent=False,
            )
            return ssh

        return _connect_via_kbdint(ip, user, pwd, tmo)

    except BadAuthenticationType as e:
        if "keyboard-interactive" in (e.allowed_types or []):
            return _connect_via_kbdint(ip, user, pwd, tmo)
        raise

def _exec(ssh, cmd: str):
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read()
    err = stderr.read()
    rc = stdout.channel.recv_exit_status()
    return rc, out, err

def run_tmsh(ssh, cmd: str) -> bytes:
    wrapped = f"tmsh -q -c {shlex.quote(cmd)}"
    rc, out, _err = _exec(ssh, wrapped)
    if rc == 0:
        return out

    rc2, out2, _err2 = _exec(ssh, cmd)
    if rc2 == 0:
        return out2

    raise SSHException(f"TMSH falló: {cmd}")

def run_bash(ssh, cmd: str) -> bytes:
    return run_tmsh(ssh, f"run util bash -c {shlex.quote(cmd)}")

# ───────────────────────────────────────────────────────────────
#                                REST
# ───────────────────────────────────────────────────────────────
def rest_download_ucs(host: str, user: str, pwd: str, fname: str, out_path: Path, total_size: int):
    url = f"https://{host}:{REST_PORT}/mgmt/shared/file-transfer/ucs-downloads/{quote(fname)}"
    chunk = 1024 * 1024

    with requests.Session() as s, out_path.open("wb") as f:
        s.auth = (user, pwd)
        s.verify = REST_VERIFY_TLS

        r0 = s.get(url, timeout=180)
        if r0.status_code == 200:
            f.write(r0.content)
        else:
            start = 0
            while start < total_size:
                end = min(start + chunk - 1, total_size - 1)
                headers = {"Content-Range": f"{start}-{end}/{total_size}"}
                r = s.get(url, headers=headers, timeout=180)
                r.raise_for_status()
                f.write(r.content)

                cr = r.headers.get("Content-Range", "")
                m = re.search(r"(\d+)-(\d+)/(\d+)", cr)
                if m:
                    start = int(m.group(2)) + 1
                else:
                    start += len(r.content)

    if out_path.stat().st_size != total_size:
        raise IOError("Size mismatch REST")

# ───────────────────────────────────────────────────────────────
#                     SFTP / CAT / LIMPIEZA
# ───────────────────────────────────────────────────────────────
def open_sftp_with_retry(ssh, retries: int = SFTP_RETRIES):
    for att in range(1, retries + 1):
        try:
            return ssh.open_sftp()
        except SFTPError:
            if att < retries:
                time.sleep(att * 2)
            else:
                raise

def backup_via_sftp(ssh, remote: str, local: Path):
    with open_sftp_with_retry(ssh) as sftp:
        sftp.get(remote, str(local))

def backup_via_cat(ssh, remote_q: str, local: Path):
    inner = f"cat {remote_q}"
    cmd = f"run util bash -c {shlex.quote(inner)}"
    full = f"tmsh -q -c {shlex.quote(cmd)}"

    with local.open("wb") as f:
        chan = ssh.get_transport().open_session()
        chan.exec_command(full)
        while True:
            data = chan.recv(32768)
            if not data and chan.exit_status_ready():
                break
            if data:
                f.write(data)
        chan.close()

def cleanup_local(folder: Path, limit: int):
    return  # Deshabilitado: sin limite en destino
    files = sorted((p for p in folder.glob("*.ucs")), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files[limit:]:
        try:
            p.unlink()
        except Exception:
            pass

def cleanup_remote_old(ssh):
    bash = f"ls -1t {REMOTE_DIR}/*.ucs 2>/dev/null | awk 'NR>1 {{print}}' | xargs -r rm -f"
    run_bash(ssh, bash)

def remote_size(ssh, remote_q: str) -> int:
    out = run_bash(ssh, f"wc -c < {remote_q}")
    s = out.decode(errors="ignore").strip()
    return int(s) if s.isdigit() else -1

def wait_file_ready(ssh, remote_q: str, timeout: int, interval: int) -> Tuple[int, str]:
    waited = 0
    last = -1

    while waited < timeout:
        out = run_bash(ssh, f"test -e {remote_q} && echo OK || echo NO")
        if out.strip() == b"OK":
            size = remote_size(ssh, remote_q)
            if size > 0 and size == last:
                out_h = run_bash(ssh, f"sha256sum {remote_q}")
                remote_hash = out_h.decode(errors="ignore").split()[0]
                return size, remote_hash
            last = size

        time.sleep(interval)
        waited += interval

    raise TimeoutError("Timeout esperando archivo UCS")

# ───────────────────────────────────────────────────────────────
#                              WORKER
# ───────────────────────────────────────────────────────────────
def process_equipo(eq: Dict) -> Dict:
    g, host, ip, tmo = eq["grupo"], eq["hostname"], eq["ip"], eq["timeout"]
    user, pwd = eq["username"], eq["password"]

    ctx_logger = logging.LoggerAdapter(logger, {"equipo_ip": ip, "equipo_hostname": host})
    ctx_logger.info("Iniciando backup…")

    ssh = None
    start = time.time()

    try:
        ssh = connect_ssh(ip, user, pwd, tmo)

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        bname = f"backup-{host}-{ts}"
        run_tmsh(ssh, f"save /sys ucs {shlex.quote(bname)}")

        rem_path = f"{REMOTE_DIR}/{bname}.ucs"
        rem_q = shlex.quote(rem_path)

        size_remote, hash_remote = wait_file_ready(ssh, rem_q, WAIT_TIMEOUT, WAIT_INTERVAL)

        local_dir = (BASE_FOLDER / g / host)
        local_dir.mkdir(parents=True, exist_ok=True)
        local_path = local_dir / f"{bname}.ucs"

        method = "REST"
        try:
            rest_download_ucs(ip, user, pwd, f"{bname}.ucs", local_path, size_remote)
        except Exception:
            try:
                backup_via_sftp(ssh, rem_path, local_path)
                method = "SFTP"
            except Exception:
                backup_via_cat(ssh, rem_q, local_path)
                method = "CAT"

        local_hash = sha256_file(local_path)

        if local_hash != hash_remote:
            return dict(eq, status="ERROR", error_detail="Hash mismatch", method=method)

        # Servidor de destino: NO se borra ningún backup (retención ilimitada)
        # cleanup_local(local_dir, BACKUP_HISTORY_LIMIT)

        # En el equipo F5: retener solo 1 backup (el más reciente) y limpiar temporales
        try:
            cleanup_remote_old(ssh)
        except Exception:
            pass
        try:
            run_bash(ssh, f"rm -f /tmp/{bname}.ucs")
        except Exception:
            pass

        elapsed = time.time() - start
        return dict(eq, status="OK", backup_file=str(local_path), method=method, elapsed=elapsed)

    except Exception as e:
        return dict(eq, status="ERROR", error_detail=str(e))

    finally:
        try:
            if ssh:
                ssh.close()
        except Exception:
            pass

# ───────────────────────────────────────────────────────────────
#                              EMAILS
# ───────────────────────────────────────────────────────────────

# ───────────────────────────────────────────────────────────────
#               EMAILS POR GRUPO (OK / FAIL)
# ───────────────────────────────────────────────────────────────
def send_ok_reports(ok_results: Dict[str, List[Dict]]):
    """Envía correo 'Backup Running Config Report' por grupo (OK)."""
    if not ok_results:
        return

    for grupo, equipos in ok_results.items():
        subj = f"{grupo} (Backup Running Config Report) - F5 Python"
        rows_html = "".join([
            f"""<tr>
<td>{eq['grupo']}</td>
<td>{eq['hostname']}</td>
<td>{eq['ip']}</td>
<td>OK</td>
<td>New</td>
</tr>"""
            for eq in equipos
        ])

        html = f"""
<html>
<head>
<style>
table {{ border-collapse: collapse; width: 100%; }}
th {{ background-color: #4A90E2; color: #FFFF00; }}
td, th {{ border: 1px solid #CCC; padding: 6px; }}
</style>
</head>
<body>
<h2>{subj}</h2>
<table>
<tr><th>Group</th><th>Device</th><th>IP</th><th>Status</th><th>Changes</th></tr>
{rows_html}
</table>
</body>
</html>
"""

        text = "\n".join([subj, "", f"Total OK: {len(equipos)}"])
        msg = build_message(subj, text, html)
        send_email(msg)

def send_fail_reports(error_results: Dict[str, List[Dict]]):
    """Envía correo 'Backup Running Config Report' por grupo (FAIL)."""
    if not error_results:
        return

    for grupo, equipos in error_results.items():
        subj = f"{grupo} (Backup Running Config Report) - FAIL - F5 Python"
        rows_html = "".join([
            f"""<tr>
<td>{eq['hostname']}</td>
<td>{eq['ip']}</td>
<td>{eq.get('error_detail','N/A')}</td>
</tr>"""
            for eq in equipos
        ])

        html = f"""
<html>
<head>
<style>
table {{ border-collapse: collapse; width: 100%; }}
th {{ background-color: #D0021B; color: #FFFFFF; }}
td, th {{ border: 1px solid #CCC; padding: 6px; }}
</style>
</head>
<body>
<h2>{subj}</h2>
<table>
<tr><th>Device</th><th>IP</th><th>Error</th></tr>
{rows_html}
</table>
</body>
</html>
"""

        text = "\n".join([subj, "", f"Total FAIL: {len(equipos)}"])
        msg = build_message(subj, text, html)
        send_email(msg)

def send_consolidated_summary(ok_results: Dict[str, List[Dict]], error_results: Dict[str, List[Dict]]):
    ts = datetime.now().strftime("%d/%m/%Y %H:%M")

    total_ok = sum(len(v) for v in ok_results.values())
    total_err = sum(len(v) for v in error_results.values())
    tot = total_ok + total_err

    if total_ok and not total_err:
        st = "COMPLETADO"
    elif total_ok and total_err:
        st = "PARCIAL"
    else:
        st = "FALLIDO"

    subj = f"[{AUTOMATION_NAME}] Resumen Final - {st}"

    lines = [
        "Resumen Consolidado",
        f"Generado: {ts}",
        f"Estado general: {st}",
        f"Total equipos: {tot}",
        f"OK: {total_ok}",
        f"ERROR: {total_err}",
    ]

    text = "\n".join(lines)
    msg = build_message(subj, text)
    send_email(msg)

# ───────────────────────────────────────────────────────────────
#                                MAIN
# ───────────────────────────────────────────────────────────────


def _render_backup_running_config_html(grupo: str, rows: list[dict]) -> str:
    # Formato compatible con Outlook: estilos inline, sin imágenes externas.
    # Columnas como el ejemplo: Group | Device | IP | Backup | Changes
    header_style = "background:#0057B8;color:#FFFFFF;font-weight:bold;text-align:center"
    th = "padding:10px;border:1px solid #0057B8"
    td = "padding:9px;border:1px solid #E6E6E6;font-family:Calibri,Arial,sans-serif;font-size:13px"
    table = [
        "<div style='font-family:Calibri,Arial,sans-serif'>",
        f"<h2 style='margin:0 0 12px 0;font-size:28px;font-weight:800;color:#000'>"
        f"{grupo} (Backup Running Config Report) - F5 Python</h2>",
        "<table style='border-collapse:collapse;width:100%'>",
        "<thead><tr>",
        f"<th style='{header_style};{th}'>Group</th>",
        f"<th style='{header_style};{th}'>Device</th>",
        f"<th style='{header_style};{th}'>IP</th>",
        f"<th style='{header_style};{th}'>Backup</th>",
        f"<th style='{header_style};{th}'>Changes</th>",
        "</tr></thead><tbody>"
    ]

    for r in rows:
        status = "OK" if r.get("status") == "OK" else "FAIL"
        device = r.get("hostname", "")
        ip_ = r.get("ip", "")
        changes = r.get("changes", "New")  # no tenemos diff de running config; se deja como antes
        table.append("<tr>")
        table.append(f"<td style='{td}'>{html.escape(str(grupo))}</td>")
        table.append(f"<td style='{td}'>{html.escape(str(device))}</td>")
        table.append(f"<td style='{td}'>{html.escape(str(ip_))}</td>")
        table.append(f"<td style='{td};font-weight:700;text-align:center'>{status}</td>")
        table.append(f"<td style='{td}'>{html.escape(str(changes))}</td>")
        table.append("</tr>")

    table.append("</tbody></table></div>")
    return "".join(table)

def send_backup_running_config_report(results: list[dict]) -> None:
    """Mantiene el formato histórico:
    - 1 correo por GRUPO
    - Subject: '{GRUPO} (Backup Running Config Report) - F5 Python'
    - Tabla con Group/Device/IP/Backup/Changes
    """
    by_group: dict[str, list[dict]] = {}
    for r in results:
        g = r.get("grupo") or "SIN_GRUPO"
        by_group.setdefault(g, []).append(r)

    for grupo, rows in by_group.items():
        subject = f"{grupo} (Backup Running Config Report) - F5 Python 🐍"
        body = f"{grupo} (Backup Running Config Report) - F5 Python\nEquipos: {len(rows)}\n"
        html_body = _render_backup_running_config_html(grupo, rows)
        msg = build_message(subject, body, html_body)
        send_email(msg)


def _render_error_schedule_html(grupo: str, rows: list[dict]) -> str:
    header_style = "background:#0057B8;color:#FFFFFF;font-weight:bold;text-align:center"
    th = "padding:10px;border:1px solid #0057B8"
    td = "padding:9px;border:1px solid #E6E6E6;font-family:Calibri,Arial,sans-serif;font-size:13px"

    html_rows = []
    for r in rows:
        html_rows.append(
            "<tr>"
            + f"<td style='{td}'>" + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "</td>"
            + f"<td style='{td}'>" + str(r.get('hostname','')) + "</td>"
            + f"<td style='{td}'>" + str(r.get('error_detail','')) + "</td>"
            + "</tr>"
        )

    return (
        f"<h2 style='font-family:Calibri,Arial'>Error with schedule: {grupo} - F5 Python</h2>"
        + "<table style='border-collapse:collapse;width:100%'>"
        + "<thead><tr>"
        + f"<th style='{header_style};{th}'>Date</th>"
        + f"<th style='{header_style};{th}'>Device</th>"
        + f"<th style='{header_style};{th}'>Error</th>"
        + "</tr></thead>"
        + "<tbody>" + "".join(html_rows) + "</tbody></table>"
    )

def send_error_schedule_report(results: list[dict]) -> None:
    errors_by_group: dict[str, list[dict]] = {}
    for r in results:
        if r.get('status') != 'OK':
            g = r.get('grupo') or 'SIN_GRUPO'
            errors_by_group.setdefault(g, []).append(r)

    for grupo, rows in errors_by_group.items():
        subject = f"Error with schedule: {grupo} - F5 Python 🐍"
        body = f"Error with schedule: {grupo} - F5 Python\\nErrores: {len(rows)}"
        html_body = _render_error_schedule_html(grupo, rows)
        msg = build_message(subject, body, html_body)
        send_email(msg)



def _render_single_row_running_config_html(grupo: str, r: dict) -> str:
    header_style = "background:#0057B8;color:#FFFFFF;font-weight:bold;text-align:center"
    th = "padding:10px;border:1px solid #0057B8"
    td = "padding:9px;border:1px solid #E6E6E6;font-family:Calibri,Arial,sans-serif;font-size:13px"
    status = "OK" if r.get("status") == "OK" else "FAIL"
    changes = r.get("changes", "New")
    device = r.get("hostname", "")
    ip_ = r.get("ip", "")
    title = f"{grupo} (Backup Running Config Report) - F5 Python 🐍"
    return (
        "<div style='font-family:Calibri,Arial,sans-serif'>"
        f"<h2 style='margin:0 0 12px 0;font-size:28px;font-weight:800;color:#000'>{html.escape(title)}</h2>"
        "<table style='border-collapse:collapse;width:100%'>"
        "<thead><tr>"
        f"<th style='{header_style};{th}'>Group</th>"
        f"<th style='{header_style};{th}'>Device</th>"
        f"<th style='{header_style};{th}'>IP</th>"
        f"<th style='{header_style};{th}'>Backup</th>"
        f"<th style='{header_style};{th}'>Changes</th>"
        "</tr></thead><tbody><tr>"
        f"<td style='{td}'>{html.escape(str(grupo))}</td>"
        f"<td style='{td}'>{html.escape(str(device))}</td>"
        f"<td style='{td}'>{html.escape(str(ip_))}</td>"
        f"<td style='{td};font-weight:700;text-align:center'>{html.escape(status)}</td>"
        f"<td style='{td}'>{html.escape(str(changes))}</td>"
        "</tr></tbody></table></div>"
    )

def _render_single_row_error_html(grupo: str, r: dict) -> str:
    header_style = "background:#0057B8;color:#FFFFFF;font-weight:bold;text-align:center"
    th = "padding:10px;border:1px solid #0057B8"
    td = "padding:9px;border:1px solid #E6E6E6;font-family:Calibri,Arial,sans-serif;font-size:13px"
    dt = r.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dev = r.get("hostname", "")
    err = r.get("error_detail", "")
    return (
        "<div style='font-family:Calibri,Arial,sans-serif'>"
        f"<h2 style='font-family:Calibri,Arial'>Error with schedule: {html.escape(str(grupo))} - F5 Python</h2>"
        "<table style='border-collapse:collapse;width:100%'>"
        "<thead><tr>"
        f"<th style='{header_style};{th}'>Date</th>"
        f"<th style='{header_style};{th}'>Device</th>"
        f"<th style='{header_style};{th}'>Error</th>"
        "</tr></thead><tbody><tr>"
        f"<td style='{td}'>{html.escape(str(dt))}</td>"
        f"<td style='{td}'>{html.escape(str(dev))}</td>"
        f"<td style='{td}'>{html.escape(str(err))}</td>"
        "</tr></tbody></table></div>"
    )

def send_device_flow_emails(results: list[dict]) -> None:
    """Correos dinámicos por cliente/hostname/ip/estado (para flujos)."""
    if not DEVICE_FLOW_MAIL:
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for r in results:
        grupo = r.get("grupo") or "SIN_GRUPO"
        hostname = r.get("hostname") or ""
        ip_ = r.get("ip") or ""
        status = "OK" if r.get("status") == "OK" else "FAIL"

        if status == "OK":
            subject = f"{grupo} (Backup Running Config Report) - {hostname} - {ip_} - OK - F5 Python 🐍"
            body = (
                f"{subject}\n"
                f"DATE={now}\nCLIENTE={grupo}\nHOSTNAME={hostname}\nIP={ip_}\nSTATUS=OK\n"
            )
            html_body = _render_single_row_running_config_html(grupo, dict(r, date=now))
            msg = build_message(subject, body, html_body)
            send_email(msg)
        else:
            subject = f"Error with schedule: {grupo} - {hostname} - {ip_} - F5 Python 🐍"
            body = (
                f"{subject}\n"
                f"DATE={now}\nCLIENTE={grupo}\nHOSTNAME={hostname}\nIP={ip_}\nSTATUS=FAIL\n"
                f"ERROR={r.get('error_detail','')}\n"
            )
            html_body = _render_single_row_error_html(grupo, dict(r, date=now))
            msg = build_message(subject, body, html_body)
            send_email(msg)

def run_backups() -> int:
    start = time.time()
    init_logging()

    equipos = parse_equipos_csv(EQUIPOS_FILE)
    results: List[Dict] = []

    with ThreadPoolExecutor(max_workers=_env_int("MAX_WORKERS", 5)) as pool:
        for fut in as_completed([pool.submit(process_equipo, eq) for eq in equipos]):
            results.append(fut.result())

    ok_by_group: Dict[str, List[Dict]] = {}
    err_by_group: Dict[str, List[Dict]] = {}

    for r in results:
        g = r["grupo"]
        if r.get("status") == "OK":
            ok_by_group.setdefault(g, []).append(r)
        else:
            err_by_group.setdefault(g, []).append(r)

    if ENABLE_MAIL:
        # Evita duplicidad: si el flujo por equipo está activo, NO enviamos reportes por grupo.
        if DEVICE_FLOW_MAIL:
            send_device_flow_emails(results)
        else:
            # Solo 1 correo por grupo: si hay errores -> 'Error with schedule', si no -> Running Config Report
            has_errors = any(r.get('status') != 'OK' for r in results)
            if has_errors:
                send_error_schedule_report(results)
            else:
                send_backup_running_config_report(results)

        # Consolidado opcional (desactivado por defecto para evitar 2 correos)
        if ENABLE_CONSOLIDATED_MAIL:
            send_consolidated_summary(ok_by_group, err_by_group)

    logger.info("Tiempo total: %.1f seg", time.time() - start)
    return 0

def main():
    return run_backups()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backups UCS F5 con inventario seguro (CSV o DPAPI).")
    sub = parser.add_subparsers(dest="cmd")

    p_hide = sub.add_parser("hide", help="Cifra un CSV y lo guarda como .dpapi (elimina el CSV por defecto).")
    p_hide.add_argument("--in", dest="in_path", default="equipos_f5.csv", help="Ruta del CSV en claro.")
    p_hide.add_argument("--out", dest="out_path", default="equipos_f5.dpapi", help="Ruta de salida .dpapi.")
    p_hide.add_argument("--keep-csv", action="store_true", help="No elimina el CSV en claro (no recomendado).")

    p_reveal = sub.add_parser("reveal", help="Descifra un .dpapi y lo escribe como CSV en claro (uso puntual).")
    p_reveal.add_argument("--in", dest="in_path", default="equipos_f5.dpapi", help="Ruta del .dpapi.")
    p_reveal.add_argument("--out", dest="out_path", default="equipos_f5.csv", help="Ruta del CSV en claro a generar.")

    sub.add_parser("run", help="Ejecuta respaldos (default).")

    args = parser.parse_args()

    if args.cmd == "hide":
        hide_csv_to_dpapi(args.in_path, args.out_path, delete_plain=not args.keep_csv)
        print(f"[OK] Inventario cifrado: {args.out_path}")
        if not args.keep_csv:
            print("[OK] CSV en claro eliminado.")
    elif args.cmd == "reveal":
        reveal_dpapi_to_csv(args.in_path, args.out_path)
        print(f"[OK] CSV en claro generado: {args.out_path}")
        print("[WARN] Vuelve a cifrarlo luego con: python backups_f5_fixed.py hide")
    else:
        raise SystemExit(main())