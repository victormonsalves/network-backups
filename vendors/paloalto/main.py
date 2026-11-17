#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py - Orquestador de Backup Palo Alto Networks (PAN-OS).

Integra:
  - Logging centralizado (resources.logger)
  - Envío de correos SMTP (resources.email_client)
  - Gestión de tickets RITM en ServiceNow (resources.servicenow_client)

Flujo:
  1. Carga inventario de equipos (CSV/DPAPI)
  2. Resuelve datos del cliente desde lista_clientes.json
  3. Crea RITM en ServiceNow → Work in Progress
  4. Ejecuta backups en paralelo con validación SHA-256
  5. Envía reportes por correo con formato SOC estándar
  6. Cierra RITM con resumen
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# ─── Carga de .env ───────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    _ENV_PATH = Path(__file__).resolve().parent / ".env"
    if _ENV_PATH.exists():
        load_dotenv(_ENV_PATH)
except Exception:
    pass

# ─── Imports del skill y módulos propios ─────────────────────────
from resources.logger import logger
from resources.servicenow_client import ServiceNowClient
from modules.csv_parser import parse_equipos_csv
from modules.backup_worker import process_equipo
from modules.client_resolver import resolve_client, resolve_clients_for_groups
from modules.email_reports import send_backup_reports, send_consolidated_summary
from modules.dpapi import hide_csv_to_dpapi, reveal_dpapi_to_csv
from backup_palo_alto_CS import run_backup_cs

# ─── Configuración ───────────────────────────────────────────────
EQUIPOS_FILE = os.getenv("EQUIPOS_FILE", "equipos_paloalto.dpapi")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "5"))
ENABLE_MAIL = os.getenv("ENABLE_MAIL", "true").lower() in ("1", "true", "yes")
ENABLE_CONSOLIDATED_MAIL = os.getenv("ENABLE_CONSOLIDATED_MAIL", "false").lower() in ("1", "true", "yes")
ENABLE_SERVICENOW = os.getenv("ENABLE_SERVICENOW", "true").lower() in ("1", "true", "yes")


def _create_ritm(sn_client: ServiceNowClient, client_data: Dict, total_equipos: int, hostname: str = "") -> dict | None:
    """Crea un RITM en ServiceNow con los datos del cliente."""
    subj_host = f" - {hostname}" if hostname else ""
    short_desc = f"Backup Palo Alto - {client_data['shortname']}{subj_host} - {datetime.now():%Y-%m-%d}"
    
    desc_host = f"Equipo: {hostname}\n" if hostname else f"Total equipos: {total_equipos}\n"
    description = (
        f"Ejecución automática de backup para equipos Palo Alto Networks.\n"
        f"Cliente: {client_data['shortname']}\n"
        f"Empresa: {client_data['nombre_sn']}\n"
        f"{desc_host}"
        f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}"
    )

    additional_fields = {
        "company": client_data["nombre_sn"],
        "requested_for": client_data["representante"],
    }

    ritm = sn_client.create_ritm(
        short_description=short_desc,
        description=description,
        additional_fields=additional_fields,
    )
    return ritm


def _get_ritm_number(ritm: dict | None) -> str:
    """Extrae el número RITM del resultado de creación."""
    if not ritm:
        return ""
    number = ritm.get("number", "")
    if isinstance(number, dict):
        return number.get("display_value", "")
    return str(number)


def _get_ritm_sys_id(ritm: dict | None) -> str:
    """Extrae el sys_id del RITM."""
    if not ritm:
        return ""
    sys_id = ritm.get("sys_id", "")
    if isinstance(sys_id, dict):
        return str(sys_id.get("value") or sys_id.get("display_value", "")).strip()
    return str(sys_id).strip()


def run_backups() -> int:
    """Flujo principal de backup."""
    start = time.time()
    logger.info("=" * 60)
    logger.info("Iniciando proceso de Backup Palo Alto Networks (Modo Masivo/Individual)")
    logger.info(f"Inventario: {EQUIPOS_FILE}")
    logger.info("=" * 60)

    # ─── 1. Cargar inventario ────────────────────────────────────
    try:
        equipos = parse_equipos_csv(EQUIPOS_FILE)
    except FileNotFoundError as e:
        logger.error(f"Inventario no encontrado: {e}")
        return 1

    if not equipos:
        logger.error("No se encontraron equipos válidos en el inventario.")
        return 1

    # ─── 2. Resolver datos del cliente ───────────────────────────
    client_map = {}
    try:
        grupos = list(set(eq["grupo"] for eq in equipos))
        client_map = resolve_clients_for_groups(grupos)
    except Exception as e_res:
        logger.warning(f"Error resolviendo datos de clientes desde JSON: {e_res}. Se usará default.")

    # Clientes para cada equipo
    processed_tasks = []
    for eq in equipos:
        client_data = client_map.get(eq.get("grupo", ""), {
            "shortname": eq.get("grupo", "Empresa SOC TI"),
            "nombre_sn": "Empresa S.A",
            "representante": "Empresa Chile Representante",
        })
        processed_tasks.append((eq, client_data))

    # ─── 3. Ejecución en paralelo ────────────────────────────────
    results: List[Dict] = []
    
    sn_client = None
    if ENABLE_SERVICENOW:
        try:
            sn_client = ServiceNowClient()
        except Exception as e_sn_init:
            logger.warning(f"No se pudo inicializar ServiceNowClient ({e_sn_init}). Se continuará con el backup sin RITM.")

    def _full_backup_task(eq: Dict, client_data: Dict) -> Dict:
        """Ciclo completo por equipo: RITM -> Backup -> Mail -> Close/Pending."""
        # A. Crear RITM (opcional / no bloqueante)
        ritm_number = ""
        ritm_sys_id = ""
        if sn_client:
            try:
                ritm = _create_ritm(sn_client, client_data, 1, hostname=eq['hostname'])
                ritm_number = _get_ritm_number(ritm)
                ritm_sys_id = _get_ritm_sys_id(ritm)
                if ritm_sys_id:
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="2",
                        work_notes=f"Iniciando backup individual para {eq['hostname']} ({eq['ip']}).",
                    )
            except Exception as e:
                logger.warning(f"Error en gestión inicial de RITM para {eq.get('hostname')}: {e}. Continuando con backup...")

        # B. Ejecutar Backup
        try:
            result = process_equipo(eq)
        except Exception as e_proc:
            logger.error(f"Excepción no controlada en proceso de backup para {eq.get('hostname')}: {e_proc}")
            result = dict(eq, status="ERROR", error_detail=str(e_proc))

        result["ritm_number"] = ritm_number

        # C. Cerrar o dejar en falla el RITM
        if sn_client and ritm_sys_id:
            try:
                raw_elapsed = result.get("elapsed", 0)
                try:
                    duracion_seg = int(round(float(raw_elapsed) + 1e-9))
                except Exception:
                    duracion_seg = 0

                if result.get("status") == "OK":
                    work_notes = (
                        f"Backup Palo Alto finalizado exitosamente.\n"
                        f"Estado: Terminado\n"
                        f"Equipo: {result.get('hostname', eq['hostname'])}\n"
                        f"IP: {result.get('ip', eq.get('ip', 'N/A'))}\n"
                        f"Archivo: {result.get('backup_file', 'N/A')}\n"
                        f"SHA-256: {result.get('sha256_local', 'N/A')}\n"
                        f"Método: {result.get('method', '?')}\n"
                        f"Trabajo efectivo (u_effective_work): {duracion_seg} segundos\n"
                        f"Duración: {duracion_seg}s\n"
                        f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}"
                    )
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="3",  # Terminado
                        work_notes=work_notes,
                        u_effective_work=duracion_seg,
                        additional_fields={
                            "assignment_group": sn_client.assignment_group,
                        }
                    )
                    logger.info(f"🎫 RITM {ritm_number} → Terminado (OK) en {sn_client.assignment_group}")
                else:
                    fail_group = getattr(sn_client, "fail_assignment_group", "Adm_Soc_grupo")
                    work_notes = (
                        f"Backup Palo Alto NO EJECUTADO / FALLIDO.\n"
                        f"Estado: Abierto\n"
                        f"Grupo resolutor: {fail_group}\n"
                        f"Equipo: {result.get('hostname', eq['hostname'])}\n"
                        f"IP: {result.get('ip', eq.get('ip', 'N/A'))}\n"
                        f"Método intentado: {result.get('method', 'N/A')}\n"
                        f"Error: {result.get('error_detail', 'Error desconocido')}\n"
                        f"Duración intento: {duracion_seg}s\n"
                        f"Fecha ejecución: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
                        f"Información de ejecución: Falló durante el proceso de respaldo. Requiere intervención técnica."
                    )
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="1",  # Abierto
                        work_notes=work_notes,
                        u_effective_work=duracion_seg,
                        additional_fields={
                            "assigned_to": "",
                            "assignment_group": fail_group,
                        }
                    )
                    logger.info(f"🎫 RITM {ritm_number} → Abierto (Falla) en grupo resolutor {fail_group}")
            except Exception as e:
                logger.warning(f"Error actualizando RITM final para {eq.get('hostname')}: {e}")

        return result

    logger.info(f"Procesando {len(equipos)} equipos Palo Alto con {MAX_WORKERS} workers…")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(_full_backup_task, task[0], task[1]) for task in processed_tasks]
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.append(res)
                st = res.get("status", "?")
                logger.info(f"Fin proceso {res.get('hostname')} -> {st}")
            except Exception as e:
                logger.error(f"Error no capturado en hilo de ejecución: {e}")

    # ─── 4. Resumen final y Correo Consolidado ──────────────────
    total_ok = sum(1 for r in results if r.get("status") == "OK")
    total_err = sum(1 for r in results if r.get("status") != "OK")
    elapsed = time.time() - start

    logger.info("=" * 60)
    logger.info(f"RESUMEN FINAL: OK={total_ok}, ERROR={total_err}, Total={len(results)}")
    logger.info(f"Tiempo total: {elapsed:.1f} seg")
    logger.info("=" * 60)

    if ENABLE_MAIL:
        try:
            logger.info("📧 Enviando correo consolidado final con el resumen de todos los equipos...")
            send_consolidated_summary(results)
            logger.info("✅ Correo consolidado final procesado.")
        except Exception as e_cons:
            logger.error(f"❌ Error al enviar correo consolidado final: {e_cons}")

    return 0 if total_err == 0 else 1


def main():
    # Soporte directo e intuitivo: si se pasa una cadena con comas como primer argumento
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-") and sys.argv[1] not in ("hide", "reveal", "run", "single"):
        datos = sys.argv[1]
        result, exit_code = run_backup_cs(datos)
        print(json.dumps(result, indent=4))
        return exit_code

    parser = argparse.ArgumentParser(
        description="Backups Palo Alto Networks con ServiceNow y Correo (Inventario masivo o equipo individual)."
    )
    sub = parser.add_subparsers(dest="cmd")

    # Subcomando hide
    p_hide = sub.add_parser("hide", help="Cifra un CSV y lo guarda como .dpapi.")
    p_hide.add_argument("--in", dest="in_path", default="equipos_paloalto.csv")
    p_hide.add_argument("--out", dest="out_path", default="equipos_paloalto.dpapi")
    p_hide.add_argument("--keep-csv", action="store_true")

    # Subcomando reveal
    p_reveal = sub.add_parser("reveal", help="Descifra un .dpapi a CSV.")
    p_reveal.add_argument("--in", dest="in_path", default="equipos_paloalto.dpapi")
    p_reveal.add_argument("--out", dest="out_path", default="equipos_paloalto.csv")

    # Subcomando single (para equipo individual por CLI)
    p_single = sub.add_parser("single", help="Ejecuta respaldo de un equipo individual por línea de comandos.")
    p_single.add_argument("datos_equipo", help='Datos separados por coma ej: "SOC_PROYECTO, <ip-ficticia>, cliente-pa-01.cliente.cl, user:pass"')

    # Subcomando run (por defecto para inventario masivo)
    p_run = sub.add_parser("run", help="Ejecuta respaldos del inventario (default).")

    # Flag opcional para equipo individual sin subcomando
    parser.add_argument("-e", "--equipo", dest="equipo_str", default=None, help="Datos de un equipo individual separados por coma")

    args = parser.parse_args()

    if args.equipo_str:
        result, exit_code = run_backup_cs(args.equipo_str)
        print(json.dumps(result, indent=4))
        return exit_code
    elif args.cmd == "single":
        result, exit_code = run_backup_cs(args.datos_equipo)
        print(json.dumps(result, indent=4))
        return exit_code
    elif args.cmd == "hide":
        hide_csv_to_dpapi(args.in_path, args.out_path, delete_plain=not args.keep_csv)
        print(f"[OK] Inventario cifrado: {args.out_path}")
        if not args.keep_csv:
            print("[OK] CSV en claro eliminado.")
        return 0
    elif args.cmd == "reveal":
        reveal_dpapi_to_csv(args.in_path, args.out_path)
        print(f"[OK] CSV en claro generado: {args.out_path}")
        print("[WARN] Vuelve a cifrarlo luego con: python main.py hide")
        return 0
    else:
        return run_backups()


if __name__ == "__main__":
    sys.exit(main())
