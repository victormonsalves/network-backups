#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Checkpoint GAIA — Backup individual (invocado desde Ansible)

Uso:
    python backup_checkpoint.py "SOC_CAS, CAS_CHECKPOINT_FW-DC-VIT-Info, <ip-ficticia>, checkpoint, userempresa:3nt31_2025!"

Input (string con 5 campos separados por coma):
    grupo, hostname, ip, vendor, username:password

Output (stdout JSON):
    - Resultado de la ejecución (OK/ERROR)
    - Datos del backup: peso, extensión, fecha, duración, sha256, ruta, etc.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import sys
import time
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import paramiko
from paramiko.ssh_exception import SSHException

# Intentar cargar .env si está disponible en el directorio del script
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

# ───────────────────────── Configuración ─────────────────────────
BASE_FOLDER = Path(os.getenv("BASE_FOLDER", r"F:\Respaldos_PYTHON_SOC")).resolve()
LOGS_FOLDER = BASE_FOLDER / "logs_cp"

# Tiempos de espera (timeouts) en segundos
CONNECT_TIMEOUT = 30
SSH_TIMEOUT = 1800  # 30 minutos para el comando del backup (add backup local)
KEEPALIVE_INTERVAL = 30  # Keepalive cada 30 segundos para evitar caídas de canal

# Validaciones de tamaño
MIN_BACKUP_SIZE_MB = 10.0  # Al menos 10 MB para considerarse un backup válido

# ──────────────────────── Logging (archivo + CLI) ───────────────
logger = logging.getLogger("cp_backup_v2")
logger.setLevel(logging.INFO)


def init_logging() -> None:
    global LOGS_FOLDER
    fmt = logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s")

    # 1. Asegurar registro siempre en la carpeta local logs/ del proyecto
    local_logs_dir = Path(__file__).resolve().parent / "logs"
    try:
        local_logs_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.now().strftime("%Y-%m-%d")
        local_log_file = local_logs_dir / f"automation_{today}.log"
        fh_local = logging.FileHandler(local_log_file, encoding="utf-8")
        fh_local.setFormatter(fmt)
        logger.addHandler(fh_local)
    except Exception as e:
        print(f"Advertencia: No se pudo inicializar log local en {local_logs_dir}: {e}", file=sys.stderr)

    # 2. Intentar también en LOGS_FOLDER (BASE_FOLDER/logs_cp)
    try:
        LOGS_FOLDER.mkdir(parents=True, exist_ok=True)
        log_file = LOGS_FOLDER / f"backup_v2_{datetime.now():%Y%m%d-%H%M%S}.log"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass

    # 3. Consola (CLI)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.info(f"Log file local: {local_logs_dir / f'automation_{datetime.now():%Y-%m-%d}.log'}")



# ─────────────────── Utilidades generales ───────────────────────

def sha256_file(path: Path) -> str:
    """Calcula el hash SHA-256 de un archivo local en bloques."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(size_bytes: int) -> str:
    """Convierte bytes a formato legible (KB, MB, GB, etc.)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


def check_local_disk_space(path: Path, min_gb: int = 5) -> bool:
    """Verifica si hay al menos min_gb de espacio libre en el disco local."""
    try:
        total, used, free = shutil.disk_usage(path.anchor)
        free_gb = free // (2**30)
        if free_gb < min_gb:
            logger.error(f"Espacio en disco local insuficiente: {free_gb}GB libres (se requieren mínimo {min_gb}GB)")
            return False
        return True
    except Exception:
        return True  # Proceder por compatibilidad si falla la verificación


# ──────────────────── Parseo del input de Ansible ───────────────

def parse_input(raw: str) -> Dict[str, str]:
    """
    Parsea la línea de entrada de Ansible.
    Formato: "grupo, hostname, ip, vendor, username:password"
    La contraseña puede contener comas u otros caracteres especiales,
    por lo que se usa split con maxsplit=4.
    """
    parts = raw.split(",", 4)
    if len(parts) < 5:
        raise ValueError(
            f"Se esperan 5 campos (grupo, hostname, ip, vendor, username:password). "
            f"Recibido: {len(parts)} campos"
        )
    credential = parts[4].strip()
    if ":" not in credential:
        raise ValueError(
            f"Campo 5 (credencial) debe tener formato 'username:password'. "
            f"Recibido: '{credential}'"
        )
    user, passwd = credential.split(":", 1)
    return {
        "grupo": parts[0].strip(),
        "hostname": parts[1].strip(),
        "ip": parts[2].strip(),
        "vendor": parts[3].strip(),
        "user": user.strip(),
        "passwd": passwd.strip(),
    }


# ─────────────────── Helpers de checkpoint ───────────────────────

def check_connectivity(ip: str) -> Optional[str]:
    """Verifica la conectividad básica al puerto 22 SSH."""
    logger.info(f"[conectividad] Verificando TCP/22 hacia {ip}...")
    try:
        with socket.create_connection((ip, 22), timeout=CONNECT_TIMEOUT):
            pass
    except Exception as e:
        return f"TCP/22 fail: {e}"
    logger.info(f"[conectividad] {ip} OK")
    return None


def get_remote_hash(ssh: paramiko.SSHClient, remote_path: str) -> Optional[str]:
    """Obtiene el hash SHA-256 de un archivo en el equipo remoto usando sha256sum."""
    logger.info(f"[integridad] Solicitando hash remoto de {remote_path}...")
    try:
        stdin, stdout, stderr = ssh.exec_command(f"sha256sum {remote_path}", timeout=60)
        output = stdout.read().decode().strip()
        if output:
            return output.split()[0]
    except Exception as e:
        logger.warning(f"No se pudo obtener hash remoto de {remote_path}: {e}")
    return None


def _latest_previous_tgz(grupo: str, hostname: str, current_dir: Path) -> Optional[Path]:
    """Busca el archivo .tgz del backup anterior en el histórico."""
    base = BASE_FOLDER / grupo / hostname
    if not base.exists():
        return None
    # Listar directorios de fecha/hora excluyendo el actual
    dirs = [d for d in base.iterdir() if d.is_dir() and d != current_dir]
    if not dirs:
        return None
    dirs.sort(reverse=True)  # De más nuevo a más viejo
    for d in dirs:
        tgz_files = list(d.glob("*.tgz"))
        if tgz_files:
            return tgz_files[0]
    return None


# ───────────────────────── Ejecución principal ──────────────────

def backup_device(grupo: str, hostname: str, ip: str, vendor: str, user: str, passwd: str) -> Dict:
    t0 = datetime.now()
    res = {
        "grupo": grupo,
        "hostname": hostname,
        "ip": ip,
        "vendor": vendor,
        "status": "ERROR",
        "message": "",
        "path": "",
        "sha256": "",
        "size_bytes": 0,
        "size_human": "",
        "extension": "",
        "changes": "-",
        "started_at": t0.isoformat(),
        "finished_at": None,
        "duration_seconds": 0,
    }

    # 1. Validar espacio en disco local
    if not check_local_disk_space(BASE_FOLDER, min_gb=5):
        res["message"] = "Espacio insuficiente en servidor local"
        res["finished_at"] = datetime.now().isoformat()
        res["duration_seconds"] = round((datetime.now() - t0).total_seconds(), 2)
        return res

    # 2. Conectividad TCP básica
    err = check_connectivity(ip)
    if err:
        res["message"] = f"Conectividad: {err}"
        res["finished_at"] = datetime.now().isoformat()
        res["duration_seconds"] = round((datetime.now() - t0).total_seconds(), 2)
        logger.error(f"[{hostname}] {res['message']}")
        return res

    # 3. Conexión SSH y Ejecución
    ssh = None
    try:
        logger.info(f"[{hostname}] Conectando vía SSH...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=ip,
            username=user,
            password=passwd,
            timeout=CONNECT_TIMEOUT,
            banner_timeout=CONNECT_TIMEOUT,
            auth_timeout=CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False
        )

        transport = ssh.get_transport()
        if not transport or not transport.is_active():
            raise SSHException("Transporte SSH inactivo posterior al establecimiento de la conexión")
        
        # Configurar keepalive para evitar desconexión del socket durante la creación del backup pesado
        transport.set_keepalive(KEEPALIVE_INTERVAL)
        logger.info(f"[{hostname}] Conexión SSH establecida exitosamente con keepalive={KEEPALIVE_INTERVAL}s")

        # 4. Validar espacio libre en el firewall remoto (/var/log)
        logger.info(f"[{hostname}] Verificando espacio en disco remoto (/var/log)...")
        stdin, stdout, stderr = ssh.exec_command("df -m /var/log | tail -1 | awk '{print $4}'", timeout=30)
        remote_free_mb = stdout.read().decode().strip()
        if remote_free_mb.isdigit():
            free_mb = int(remote_free_mb)
            logger.info(f"[{hostname}] Espacio libre en cortafuegos (/var/log): {free_mb} MB")
            # Recomendado tener al menos 3000 MB dado que el backup pesa ~2GB
            if free_mb < 3000:
                raise RuntimeError(f"Espacio libre insuficiente en cortafuegos (/var/log): {free_mb}MB (requerido >= 3000MB)")
        else:
            logger.warning(f"[{hostname}] No se pudo determinar el espacio libre en /var/log de forma precisa. Salida obtenida: '{remote_free_mb}'")

        # 5. Adquirir lock database override en clish
        logger.info(f"[{hostname}] Solicitando lock database override en clish...")
        ssh.exec_command('clish -c "lock database override"', timeout=30)
        time.sleep(2)  # Pausa breve

        # 6. Ejecutar creación del backup local de manera interactiva/estable
        logger.info(f"[{hostname}] Generando backup local en Checkpoint. Esto puede tardar...")
        stdin, stdout, stderr = ssh.exec_command('clish -c "add backup local"', timeout=SSH_TIMEOUT)
        
        channel = stdout.channel
        stdout_chunks = []
        stderr_chunks = []

        # Esperamos activamente leyendo los buffers de salida para mantener el flujo activo
        while not channel.exit_status_ready():
            if channel.recv_ready():
                data = channel.recv(4096).decode("utf-8", errors="ignore")
                if data:
                    stdout_chunks.append(data)
                    for line in data.splitlines():
                        logger.info(f"[{hostname} SSH] {line.strip()}")
            if channel.recv_stderr_ready():
                data_err = channel.recv_stderr(4096).decode("utf-8", errors="ignore")
                if data_err:
                    stderr_chunks.append(data_err)
                    for line in data_err.splitlines():
                        logger.warning(f"[{hostname} SSH-ERR] {line.strip()}")
            time.sleep(2)

        # Consumir el buffer remanente
        if channel.recv_ready():
            stdout_chunks.append(channel.recv(65535).decode("utf-8", errors="ignore"))
        if channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(65535).decode("utf-8", errors="ignore"))

        exit_status = channel.recv_exit_status()
        out_msg = "".join(stdout_chunks).strip()
        err_msg = "".join(stderr_chunks).strip()

        if exit_status != 0:
            full_err = (out_msg + " " + err_msg).strip()
            raise RuntimeError(f"Error generando backup local (Exit {exit_status}): {full_err or 'Sin mensajes'}")

        logger.info(f"[{hostname}] Proceso 'add backup local' completado exitosamente en el equipo remoto")

        # 7. Localizar el archivo backup (.tgz) generado recientemente
        logger.info(f"[{hostname}] Identificando el archivo .tgz generado...")
        remote_file = ""
        # Reintentos de búsqueda en caso de que tarde un instante en reflejarse en filesystem
        for attempt in range(6):
            stdin, stdout, stderr = ssh.exec_command("ls -1t /var/log/CPbackup/backups/*.tgz | head -1", timeout=30)
            remote_file = stdout.read().decode().strip()
            if remote_file:
                break
            time.sleep(5)

        if not remote_file:
            raise RuntimeError("No se localizó ningún archivo .tgz en /var/log/CPbackup/backups/ después del backup")

        filename = os.path.basename(remote_file)
        logger.info(f"[{hostname}] Archivo detectado en firewall: {remote_file}")

        # 8. Extraer el backup: Preparar destino y descargar vía SFTP
        outdir = BASE_FOLDER / grupo / hostname / f"{datetime.now():%Y%m%d_%H%M%S}"
        outdir.mkdir(parents=True, exist_ok=True)
        local_file = outdir / filename

        # Obtener hash remoto antes de iniciar la transferencia
        remote_hash = get_remote_hash(ssh, remote_file)
        if not remote_hash:
            raise RuntimeError("No fue posible calcular el hash SHA-256 en el firewall remoto")
        logger.info(f"[{hostname}] Hash remoto: {remote_hash}")

        # Iniciar descarga SFTP
        logger.info(f"[{hostname}] Iniciando transferencia SFTP de {filename} a {local_file}...")
        sftp = ssh.open_sftp()

        # Callback para reportar progreso
        def progress_callback(transferred: int, total: int) -> None:
            percent = (transferred / total) * 100
            if not hasattr(progress_callback, "last_reported"):
                progress_callback.last_reported = -10
            if percent - progress_callback.last_reported >= 10:
                logger.info(f"[{hostname} SFTP] Descargado {percent:.1f}% ({human_size(transferred)} de {human_size(total)})")
                progress_callback.last_reported = int(percent)

        sftp.get(remote_file, str(local_file), callback=progress_callback)
        sftp.close()
        logger.info(f"[{hostname}] Transferencia SFTP finalizada correctamente")

        # 9. Revisión de Integridad
        logger.info(f"[{hostname}] Iniciando validaciones de integridad del archivo local...")
        if not local_file.exists():
            raise RuntimeError("El archivo local no fue creado con éxito posterior a la descarga SFTP")

        size_bytes = local_file.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        logger.info(f"[{hostname}] Tamaño de archivo local: {human_size(size_bytes)} ({size_bytes} bytes)")

        # Validar tamaño mínimo de seguridad
        if size_mb < MIN_BACKUP_SIZE_MB:
            raise RuntimeError(f"El archivo descargado es anormalmente pequeño: {size_mb:.2f} MB (requerido >= {MIN_BACKUP_SIZE_MB} MB)")

        # Calcular hash local
        logger.info(f"[{hostname}] Calculando hash SHA-256 del archivo local...")
        local_hash = sha256_file(local_file)
        logger.info(f"[{hostname}] Hash local: {local_hash}")

        if local_hash != remote_hash:
            raise RuntimeError(f"Discrepancia en revisión de integridad (Hash mismatch).\nRemoto: {remote_hash}\nLocal:  {local_hash}")
        
        logger.info(f"[{hostname}] Integridad validada con éxito. Archivo íntegro.")

        # 10. Limpieza en el Firewall (Remoción temporal del backup exitoso)
        logger.info(f"[{hostname}] Eliminando archivo backup temporal del firewall para liberar espacio...")
        stdin, stdout, stderr = ssh.exec_command(f"rm -f {remote_file}", timeout=30)
        del_exit = stdout.channel.recv_exit_status()
        if del_exit == 0:
            logger.info(f"[{hostname}] Archivo temporal eliminado del firewall de manera exitosa")
        else:
            logger.warning(f"[{hostname}] No se pudo eliminar el archivo temporal del firewall (Exit Code {del_exit})")

        # 11. Detección de cambios
        prev_file = _latest_previous_tgz(grupo, hostname, outdir)
        if prev_file and prev_file.exists():
            logger.info(f"[{hostname}] Comparando con backup previo: {prev_file}")
            prev_hash = sha256_file(prev_file)
            changes = "New" if prev_hash != local_hash else "No Change"
        else:
            changes = "New"

        t1 = datetime.now()
        res.update({
            "status": "OK",
            "message": "Backup completado y verificado exitosamente",
            "path": str(local_file),
            "sha256": local_hash,
            "size_bytes": size_bytes,
            "size_human": human_size(size_bytes),
            "extension": local_file.suffix,
            "changes": changes,
            "finished_at": t1.isoformat(),
            "duration_seconds": round((t1 - t0).total_seconds(), 2),
        })

    except Exception as e:
        logger.error(f"[{hostname}] Error durante ejecución: {e}", exc_info=True)
        res["message"] = str(e)
        t1 = datetime.now()
        res["finished_at"] = t1.isoformat()
        res["duration_seconds"] = round((t1 - t0).total_seconds(), 2)

    finally:
        if ssh:
            try:
                ssh.close()
                logger.info(f"[{hostname}] Conexión SSH cerrada")
            except Exception:
                pass

    return res


# ───────────────────────── Main ─────────────────────────────────

def main() -> None:
    init_logging()
    logger.info("=" * 60)
    logger.info("Checkpoint GAIA Backup v2 - Ejecucion desde Ansible")
    logger.info("=" * 60)

    # Validar argumentos
    if len(sys.argv) < 2:
        error_output = {
            "status": "ERROR",
            "message": "No se recibió input. Uso: python backup_checkpoint.py \"grupo, hostname, ip, vendor, username:password\"",
        }
        logger.error(error_output["message"])
        print(json.dumps(error_output, indent=2, ensure_ascii=False))
        sys.exit(1)

    raw_input = sys.argv[1]
    logger.info(f"Input recibido: {raw_input}")

    # Parsear input
    try:
        params = parse_input(raw_input)
    except ValueError as e:
        error_output = {
            "status": "ERROR",
            "message": str(e),
        }
        logger.error(error_output["message"])
        print(json.dumps(error_output, indent=2, ensure_ascii=False))
        sys.exit(1)

    logger.info(f"Dispositivo: grupo={params['grupo']}, hostname={params['hostname']}, ip={params['ip']}, vendor={params['vendor']}, user={params['user']}")

    # Ejecutar backup
    result = backup_device(
        grupo=params["grupo"],
        hostname=params["hostname"],
        ip=params["ip"],
        vendor=params["vendor"],
        user=params["user"],
        passwd=params["passwd"],
    )

    # Log del resultado
    logger.info("=" * 60)
    if result["status"] == "OK":
        logger.info(f"RESULTADO: OK - {result['hostname']} ({result['ip']})")
        logger.info(f"  Archivo    : {result['path']}")
        logger.info(f"  Tamaño     : {result['size_human']} ({result['size_bytes']} bytes)")
        logger.info(f"  Extensión  : {result['extension']}")
        logger.info(f"  SHA256     : {result['sha256']}")
        logger.info(f"  Cambios    : {result['changes']}")
        logger.info(f"  Duración   : {result['duration_seconds']}s")
        logger.info(f"  Inicio     : {result['started_at']}")
        logger.info(f"  Fin        : {result['finished_at']}")
    else:
        logger.error(f"RESULTADO: ERROR - {result['hostname']} ({result['ip']})")
        logger.error(f"  Mensaje    : {result['message']}")
        logger.error(f"  Duración   : {result['duration_seconds']}s")
    logger.info("=" * 60)

    # Output JSON a stdout para que Ansible capture el resultado
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # Exit code según resultado
    sys.exit(0 if result["status"] == "OK" else 1)


if __name__ == "__main__":
    main()
