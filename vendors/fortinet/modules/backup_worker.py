#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backup_worker.py - Worker de backup para firewalls Fortinet (FortiOS).

Responsabilidades:
  1. Conexión autenticada vía REST API de FortiOS (login por credenciales o API Token)
  2. Descarga de running configuration global (/api/v2/monitor/system/config/backup)
  3. Validación estructural del archivo de respaldo (marcadores 'config ', 'end', 'set ')
  4. Doble verificación de integridad SHA-256 (hash en memoria vs hash en disco)
  5. Detección automática de cambios contra el respaldo histórico anterior
  6. Rotación de historial local según política de retención
"""

from __future__ import annotations

import glob
import hashlib
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple

from resources.logger import logger
from .connection import get_fortinet_api_connection

# Configuración desde variables de entorno
DEFAULT_BASE_FOLDER = os.getenv("BASE_FOLDER", r"\\<ip-ficticia>\F$\Respaldos_PYTHON_SOC")
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "30"))
BACKUP_HISTORY_LIMIT = int(os.getenv("BACKUP_HISTORY_LIMIT", "1"))
MIN_CONFIG_SIZE = 500
FORTINET_STRUCTURAL_MARKERS = ["config ", "end", "set "]


def calculate_sha256(content: str | bytes) -> str:
    """Calcula SHA-256 de un string o bytes."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def sha256_file(file_path: str | Path) -> str:
    """Calcula SHA-256 leyendo un archivo en bloques desde disco."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_content(content: str | bytes) -> str:
    """
    Normaliza el contenido del backup de Fortinet para comparación de hashes.
    Elimina comentarios y líneas dinámicas (tokens, revisiones, timestamps).
    """
    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    dynamic_patterns = (
        "set uuid",
        "set last-updated",
        "set revision",
        "set cfg-save-time",
        "set fortiscribe-id",
        "set sync-status",
        "set checksum",
        "set v-checksum",
        "set device-id",
        "set version",
        "set admin-session-id",
        "set session-id",
    )

    filtered_lines = []
    for line in content.splitlines():
        line_clean = line.strip()
        if not line_clean or len(line_clean) < 2 or line_clean.startswith("#"):
            continue
        lower_line = line_clean.lower()
        if any(pat in lower_line for pat in dynamic_patterns):
            continue
        filtered_lines.append(" ".join(line_clean.split()))

    return "\n".join(filtered_lines)


def validate_config_structure(config_text: str, hostname: str) -> Tuple[bool, str]:
    """
    Valida que el contenido descargado tenga estructura de configuración
    Fortinet legítima, detectando respuestas erróneas en HTML o JSON.
    """
    errors = []

    if len(config_text) < MIN_CONFIG_SIZE:
        errors.append(f"Tamaño insuficiente ({len(config_text)} bytes, mín: {MIN_CONFIG_SIZE})")

    first_500 = config_text[:500].strip().lower()
    if first_500.startswith(("<!doctype", "<html", "{")):
        errors.append("El contenido es una respuesta HTML o JSON, no una configuración Fortinet")

    missing = [f"'{m.strip()}'" for m in FORTINET_STRUCTURAL_MARKERS if m not in config_text]
    if missing:
        errors.append(f"Marcadores obligatorios ausentes: {', '.join(missing)}")

    if errors:
        return False, "; ".join(errors)
    return True, ""


def verify_disk_integrity(file_path: Path, memory_hash: str, hostname: str) -> Tuple[bool, str]:
    """Verifica que el archivo escrito a disco sea idéntico al buffer en memoria."""
    try:
        disk_hash = sha256_file(file_path)
        if disk_hash != memory_hash:
            logger.error(f"[{hostname}] Hash memoria ({memory_hash[:16]}…) != disco ({disk_hash[:16]}…)")
            return False, disk_hash
        return True, disk_hash
    except Exception as e:
        logger.error(f"[{hostname}] Error al verificar integridad en disco: {e}")
        return False, ""


def get_latest_backup(folder_path: Path, hostname: str) -> Tuple[Optional[Path], Optional[str]]:
    """Obtiene el backup más reciente para detectar cambios de configuración."""
    if not folder_path.exists():
        return None, None

    pattern = folder_path / f"{hostname}_*.conf"
    files = sorted(glob.glob(str(pattern)), reverse=True)
    if not files:
        # Intentar también con formato backup-{hostname}-*.conf
        pattern2 = folder_path / f"backup-{hostname}-*.conf"
        files = sorted(glob.glob(str(pattern2)), reverse=True)

    if not files:
        return None, None

    latest_file = Path(files[0])
    try:
        with open(latest_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        normalized = normalize_content(content)
        return latest_file, calculate_sha256(normalized)
    except Exception as e:
        logger.warning(f"[{hostname}] No se pudo leer backup anterior {latest_file.name}: {e}")
        return None, None


def cleanup_old_backups(folder_path: Path, hostname: str, limit: int = BACKUP_HISTORY_LIMIT) -> None:
    """Elimina respaldos históricos excedentes para mantener limpio el almacenamiento."""
    try:
        patterns = [f"{hostname}_*.conf", f"backup-{hostname}-*.conf"]
        all_files = []
        for pat in patterns:
            all_files.extend(folder_path.glob(pat))

        sorted_files = sorted(set(all_files), key=lambda p: p.stat().st_mtime, reverse=True)
        for old_file in sorted_files[limit:]:
            try:
                old_file.unlink()
                logger.debug(f"[{hostname}] Backup antiguo eliminado: {old_file.name}")
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"[{hostname}] Error en rotación de respaldos: {e}")


def process_equipo(equipo: Dict, base_folder: str | Path | None = None, api_token: str | None = None) -> Dict:
    """
    Worker principal para procesar un equipo Fortinet vía REST API.
    Compatible con ejecución masiva (main.py) y ejecución individual (backup_fortinet_CS.py).
    """
    start_time = time.time()
    ip = equipo["ip"]
    hostname = equipo.get("hostname") or ip
    user = equipo.get("username") or equipo.get("user") or "admin"
    password = equipo.get("password") or ""
    grupo = equipo.get("grupo") or "SOC"
    tmo = int(equipo.get("timeout") or os.getenv("DEFAULT_TIMEOUT", "60"))

    folder_root = Path(base_folder or DEFAULT_BASE_FOLDER)

    result = dict(
        equipo,
        hostname=hostname,
        ip=ip,
        grupo=grupo,
        status="ERROR",
        error_detail="",
        sha256_local="N/A",
        sha256="N/A",
        backup_file="N/A",
        method="REST-API",
        changes="Sin Cambios",
        change_status="SIN_CAMBIOS",
        elapsed=0.0,
        file_size=0,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    api = None
    try:
        logger.info(f"[{hostname}] Iniciando respaldo Fortinet ({ip}) vía REST API…")

        # 1. Conexión con reintentos
        api = get_fortinet_api_connection(ip, token=api_token, username=user, password=password)
        if not api:
            result["error_detail"] = f"Fallo de autenticación o conexión a FortiOS REST API ({ip})"
            return result

        # 2. Descarga de configuración
        backup_url = f"{api.base_url}/monitor/system/config/backup"
        params = {"scope": "global"}

        try:
            response = api.session.get(backup_url, params=params, timeout=tmo)
        except Exception as e_req:
            result["error_detail"] = f"Error en descarga HTTP REST API: {type(e_req).__name__}: {str(e_req)}"
            return result

        if response.status_code != 200:
            result["error_detail"] = f"Error API Backup HTTP {response.status_code}: {response.text[:200]}"
            return result

        raw_bytes = response.content
        try:
            config_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            config_text = response.text

        # 3. Validación estructural
        is_valid, validation_errors = validate_config_structure(config_text, hostname)
        if not is_valid:
            result["error_detail"] = f"Validación estructural fallida: {validation_errors}"
            result["status"] = "INTEGRITY_WARN"
            return result

        # 4. Directorio de guardado y hash en memoria
        local_dir = folder_root / grupo / hostname
        local_dir.mkdir(parents=True, exist_ok=True)

        # Buscar backup previo para comparar cambios antes de guardar el nuevo
        _, prev_normalized_hash = get_latest_backup(local_dir, hostname)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{hostname}_{ts}.conf"
        local_path = local_dir / filename

        # Hash en memoria de los bytes exactos descargados
        memory_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Escribir en modo binario ('wb') para preservar exactamente los bytes sin conversión de saltos de línea (CRLF) en Windows
        with open(local_path, "wb") as f:
            f.write(raw_bytes)

        # 5. Verificación de integridad: Memoria vs Disco
        integrity_ok, disk_hash = verify_disk_integrity(local_path, memory_hash, hostname)
        if not integrity_ok:
            result["error_detail"] = f"Integridad comprometida: memoria={memory_hash[:16]}… != disco={disk_hash[:16]}…"
            result["status"] = "INTEGRITY_WARN"
            return result

        # 6. Detección de cambios
        normalized_new = normalize_content(config_text)
        new_normalized_hash = calculate_sha256(normalized_new)

        if prev_normalized_hash is None:
            change_status = "PRIMER_BACKUP"
            changes_label = "Primer Backup"
        elif prev_normalized_hash == new_normalized_hash:
            change_status = "SIN_CAMBIOS"
            changes_label = "Sin Cambios"
        else:
            change_status = "CON_CAMBIOS"
            changes_label = "Con Cambios"

        # 7. Rotación de respaldos históricos
        cleanup_old_backups(local_dir, hostname, limit=BACKUP_HISTORY_LIMIT)

        elapsed = round(time.time() - start_time, 1)
        file_size = local_path.stat().st_size

        logger.info(
            f"✅ [{hostname}] Backup Fortinet OK vía REST-API. SHA-256: {memory_hash[:16]}… "
            f"({file_size / 1024:.1f} KB, {elapsed}s, {changes_label})"
        )

        result.update({
            "status": "OK",
            "sha256_local": memory_hash,
            "sha256": memory_hash,
            "backup_file": str(local_path),
            "changes": changes_label,
            "change_status": change_status,
            "elapsed": elapsed,
            "file_size": file_size,
        })

    except Exception as e:
        detailed_error = f"{type(e).__name__}: {str(e)}"
        logger.error(f"❌ [{hostname}] Error en proceso de backup: {detailed_error}")
        result["error_detail"] = detailed_error

    finally:
        if api:
            try:
                api.logout()
            except Exception:
                pass

    return result
