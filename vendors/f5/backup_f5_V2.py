#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backup_f5_V2.py

Respaldo UCS de F5 BIG‑IP con verificación SHA‑256.
Recibe los datos del equipo como argumento de línea de comandos en lugar de un archivo.
Elimina backups antiguos en el F5 (mantiene solo el último).
Entrega el resultado como un objeto JSON en la salida estándar.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shlex
import socket
import time
import unicodedata
import json
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Dict, Tuple

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
#                          CONFIG GENERAL
# ───────────────────────────────────────────────────────────────
BASE_FOLDER = Path(os.getenv("BASE_FOLDER", r"E:\Respaldos_new")).resolve()
LOGS_FOLDER = BASE_FOLDER / "logs_f5"

BACKUP_HISTORY_LIMIT = int(os.getenv("BACKUP_HISTORY_LIMIT", "1"))
REMOTE_DIR = os.getenv("REMOTE_DIR", "/var/local/ucs")
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "60"))
WAIT_TIMEOUT = int(os.getenv("WAIT_TIMEOUT", "60"))
WAIT_INTERVAL = int(os.getenv("WAIT_INTERVAL", "15"))
KEEPALIVE_INT = int(os.getenv("KEEPALIVE_INT", "25"))
SFTP_RETRIES = int(os.getenv("SFTP_RETRIES", "2"))

REST_PORT = int(os.getenv("REST_PORT", "443"))
REST_VERIFY_TLS = os.getenv("REST_VERIFY_TLS", "false").lower() in ("1", "true", "yes")

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
#                      PARSE ARGUMENTOS
# ───────────────────────────────────────────────────────────────
import urllib.parse

def parse_input_string(input_str: str) -> Dict:
    """
    Parsea la cadena de entrada de forma robusta.
    Ejemplo: "SOC_PROYECTO, AMUF5VCMP03LTM-ASM-ESC01AB, <ip-ficticia>, f5_netwrk, restorepoint:<token>"
    """
    logger.info("Parseando entrada de línea de comandos...")
    parts = [p.strip() for p in input_str.split(',')]
    
    if len(parts) < 4:
        raise ValueError(f"Formato de entrada inválido. Se esperaban al menos 4 partes separadas por coma, se obtuvieron {len(parts)}: {input_str}")
    
    grupo = _strip_invisibles(parts[0])
    auth_field = parts[-1].strip()
    
    # Identificar robustamente cuál es la IP y cuál es el hostname (ya que puede venir invertido)
    ip = None
    hostname = ""
    part_1 = _strip_invisibles(parts[1])
    part_2 = _strip_invisibles(parts[2])
    
    try:
        ip = str(ip_address(part_1))
        hostname = part_2
    except ValueError:
        try:
            ip = str(ip_address(part_2))
            hostname = part_1
        except ValueError:
            raise ValueError(f"No se pudo encontrar una IP válida ni en la segunda ni en la tercera posición: {part_1} | {part_2}")

    if ":" not in auth_field:
        raise ValueError("El campo de credenciales (último elemento) no tiene el formato usuario:password")
        
    usuario_raw, clave_raw = auth_field.split(":", 1)
    usuario = _strip_invisibles(usuario_raw)
    clave = _clean_secret(clave_raw)

    return {
        "grupo": grupo,
        "hostname": hostname,
        "ip": ip,
        "username": usuario,
        "password": clave,
        "timeout": DEFAULT_TIMEOUT,
    }

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

def connect_ssh(ip: str, user: str, pwd: str, tmo: int, max_retries: int = 3):
    last_error = None
    for attempt in range(1, max_retries + 1):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
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
                
        except (socket.error, OSError, SSHException) as e:
            last_error = e
            if attempt < max_retries:
                logger.warning(f"Intento {attempt}/{max_retries} fallido de conexión a {ip}: {e}. Reintentando en 5s...")
                time.sleep(5)
                continue
            
    raise ConnectionError(f"No se pudo conectar a {ip} tras {max_retries} intentos. Último error: {last_error}")

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
    url = f"https://{host}:{REST_PORT}/mgmt/shared/file-transfer/ucs-downloads/{urllib.parse.quote(fname)}"
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
    """
    Elimina todos los UCS antiguos en el F5, manteniendo solo el más reciente.
    """
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

    raise TimeoutError("Timeout esperando archivo UCS en el F5")

# ───────────────────────────────────────────────────────────────
#                              WORKER
# ───────────────────────────────────────────────────────────────
def process_equipo(eq: Dict) -> Dict:
    g, host, ip, tmo = eq["grupo"], eq["hostname"], eq["ip"], eq["timeout"]
    user, pwd = eq["username"], eq["password"]

    ctx_logger = logging.LoggerAdapter(logger, {"equipo_ip": ip, "equipo_hostname": host})
    ctx_logger.info(f"Iniciando backup para {host} ({ip}) - Grupo: {g}...")

    ssh = None
    start = time.time()
    result_info = {
        "hostname": host,
        "ip": ip,
        "grupo": g,
        "status": "PENDING",
        "method": None,
        "backup_file": None,
        "elapsed_seconds": 0,
        "error_detail": None
    }

def process_equipo(eq: Dict) -> Dict:
    g, host, ip, tmo = eq["grupo"], eq["hostname"], eq["ip"], eq["timeout"]
    user, pwd = eq["username"], eq["password"]

    ctx_logger = logging.LoggerAdapter(logger, {"equipo_ip": ip, "equipo_hostname": host})
    
    max_global_retries = 3
    result_info = {
        "hostname": host,
        "ip": ip,
        "grupo": g,
        "status": "PENDING",
        "method": None,
        "backup_file": None,
        "elapsed_seconds": 0,
        "error_detail": None
    }
    
    start = time.time()

    for attempt in range(1, max_global_retries + 1):
        ssh = None
        ctx_logger.info(f"Iniciando proceso de backup para {host} ({ip}) - Intento {attempt}/{max_global_retries}...")
        
        try:
            ctx_logger.info("Conectando por SSH...")
            ssh = connect_ssh(ip, user, pwd, tmo)

            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            bname = f"backup-{host}-{ts}"
            
            ctx_logger.info(f"Generando backup UCS: {bname}.ucs")
            # En caso de que haya fallado un intento anterior y el backup siga en progreso, 
            # tmsh podría arrojar error, pero el reintento general ayuda a mitigar si se libera a tiempo.
            run_tmsh(ssh, f"save /sys ucs {shlex.quote(bname)}")

            rem_path = f"{REMOTE_DIR}/{bname}.ucs"
            rem_q = shlex.quote(rem_path)

            ctx_logger.info("Esperando que el archivo UCS esté listo en el F5...")
            size_remote, hash_remote = wait_file_ready(ssh, rem_q, WAIT_TIMEOUT, WAIT_INTERVAL)
            ctx_logger.info(f"UCS listo. Tamaño: {size_remote} bytes, SHA256: {hash_remote}")

            local_dir = (BASE_FOLDER / g)
            local_dir.mkdir(parents=True, exist_ok=True)
            local_path = local_dir / f"{bname}.ucs"

            method = "REST"
            ctx_logger.info("Intentando descarga vía REST...")
            try:
                rest_download_ucs(ip, user, pwd, f"{bname}.ucs", local_path, size_remote)
            except Exception as e:
                ctx_logger.warning(f"Fallo descarga REST: {e}. Intentando SFTP...")
                try:
                    backup_via_sftp(ssh, rem_path, local_path)
                    method = "SFTP"
                except Exception as e:
                    ctx_logger.warning(f"Fallo descarga SFTP: {e}. Intentando CAT (fallback final)...")
                    backup_via_cat(ssh, rem_q, local_path)
                    method = "CAT"

            ctx_logger.info(f"Descarga finalizada vía {method}. Verificando integridad...")
            local_hash = sha256_file(local_path)

            if local_hash != hash_remote:
                raise ValueError(f"Hash mismatch: Remoto={hash_remote} vs Local={local_hash}")

            ctx_logger.info("Limpiando backups antiguos locales...")
            # cleanup_local(local_dir, BACKUP_HISTORY_LIMIT)  # Deshabilitado: sin limite en destino
            
            ctx_logger.info("Limpiando backups antiguos en el equipo F5 (manteniendo el último)...")
            try:
                cleanup_remote_old(ssh)
                ctx_logger.info("Limpieza remota exitosa.")
            except Exception as e:
                ctx_logger.warning(f"No se pudo limpiar el equipo remoto: {e}")

            elapsed = time.time() - start
            ctx_logger.info(f"Backup finalizado exitosamente en {elapsed:.1f}s.")
            
            result_info.update({
                "status": "OK",
                "backup_file": str(local_path),
                "method": method,
                "elapsed_seconds": round(elapsed, 2)
            })
            
            # Proceso completado exitosamente, rompemos el ciclo de reintentos
            break

        except Exception as e:
            elapsed = time.time() - start
            ctx_logger.error(f"Error en el proceso de backup (Intento {attempt}/{max_global_retries}): {e}")
            result_info.update({
                "status": "ERROR",
                "error_detail": str(e),
                "elapsed_seconds": round(elapsed, 2)
            })
            
            if attempt < max_global_retries:
                ctx_logger.info("Esperando 10 segundos antes de reintentar el proceso completo...")
                time.sleep(10)

        finally:
            try:
                if ssh:
                    ssh.close()
            except Exception:
                pass
                
    return result_info


# ───────────────────────────────────────────────────────────────
#                                MAIN
# ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Backup UCS F5 individual por línea de comandos.")
    parser.add_argument("datos_equipo", help='Datos separados por coma ej: "SOC_PROYECTO, AMUF5VCMP03LTM-ASM-ESC01AB, <ip-ficticia>, f5_netwrk, restorepoint:<token>"')
    args = parser.parse_args()

    init_logging()
    
    # 1. Parsear datos
    try:
        equipo = parse_input_string(args.datos_equipo)
    except Exception as e:
        logger.error(f"Error parseando argumentos: {e}")
        output = {
            "status": "ERROR",
            "error_detail": f"Error parseando argumentos: {e}",
            "input": args.datos_equipo
        }
        print(json.dumps(output, indent=4))
        return 1

    logger.info("=" * 60)
    logger.info("Iniciando proceso de backup F5 UCS")
    logger.info(f"Equipo: {equipo['hostname']} ({equipo['ip']})")
    logger.info(f"Carpeta destino base: {BASE_FOLDER}")
    logger.info("=" * 60)

    # 2. Ejecutar backup
    result = process_equipo(equipo)

    # 3. Entregar resultado final como JSON en la salida estándar
    logger.info("Resultado final:")
    
    # Imprimimos el JSON para que el llamador pueda parsearlo fácilmente.
    print(json.dumps(result, indent=4))
    
    if result["status"] != "OK":
        return 1
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
