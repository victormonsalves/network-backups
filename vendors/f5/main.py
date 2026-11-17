#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py - Orquestador de Backup UCS F5 BIG-IP.

Integra el skill empresa-automation-base para:
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
from resources.servicenow_client import ServiceNowClient, format_effective_work
from modules.csv_parser import parse_equipos_csv
from modules.backup_worker import process_equipo
from modules.client_resolver import resolve_client, resolve_clients_for_groups
from modules.email_reports import send_backup_reports, send_consolidated_summary
from modules.dpapi import hide_csv_to_dpapi, reveal_dpapi_to_csv

from resources.env_helper import get_env_var

# ─── Configuración ───────────────────────────────────────────────
EQUIPOS_FILE = get_env_var("EQUIPOS_FILE", "equipos_f5.dpapi")
MAX_WORKERS = int(get_env_var("MAX_WORKERS", "5"))
ENABLE_MAIL = get_env_var("ENABLE_MAIL", "true").lower() in ("1", "true", "yes")
ENABLE_CONSOLIDATED_MAIL = get_env_var("ENABLE_CONSOLIDATED_MAIL", "false").lower() in ("1", "true", "yes")
ENABLE_SERVICENOW = get_env_var("ENABLE_SERVICENOW", "true").lower() in ("1", "true", "yes")
SN_U_GBL_TA = (
    get_env_var("SN_U_GBL_TA")
    or get_env_var("SERVICENOW_U_GBL_TA")
    or "NNDD-SyR-30"
)


def _create_ritm(sn_client: ServiceNowClient, client_data: Dict, total_equipos: int, hostname: str = "") -> dict | None:
    """Crea un RITM en ServiceNow con los datos del cliente y el tag de actividad."""
    subj_host = f" - {hostname}" if hostname else ""
    tag_ta = (
        get_env_var("SN_U_GBL_TA")
        or get_env_var("SERVICENOW_U_GBL_TA")
        or sn_client.u_gbl_ta
        or SN_U_GBL_TA
    )
    short_desc = f"Backup F5 UCS - {client_data['shortname']}{subj_host} - {datetime.now():%Y-%m-%d}"
    
    desc_host = f"Equipo: {hostname}\n" if hostname else f"Total equipos: {total_equipos}\n"
    description = (
        f"Ejecución automática de backup UCS para equipos F5.\n"
        f"Cliente: {client_data['shortname']}\n"
        f"Empresa: {client_data['nombre_sn']}\n"
        f"Tag / Tipo de Actividad (TA): {tag_ta}\n"
        f"{desc_host}"
        f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}"
    )

    additional_fields = {
        "company": client_data["nombre_sn"],
        "requested_for": client_data["representante"],
        "u_gbl_tag": tag_ta,
        "u_gbl_ta": tag_ta,
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
        return sys_id.get("display_value", sys_id.get("value", ""))
    return str(sys_id)


def run_backups() -> int:
    """Flujo principal de backup."""
    start = time.time()
    logger.info("=" * 60)
    logger.info("Iniciando proceso de Backup F5 UCS (Modo Individual)")
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
        """Ciclo completo por equipo: RITM -> Backup -> Mail -> Close/Pending.
        
        Objetivo primordial: Crear, extraer e incorporar al servidor el archivo de backup.
        Cualquier error externo (ServiceNow, Correo, etc.) se salta y se registra en el log.
        """
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
                        work_notes=f"Iniciando backup individual para {eq['hostname']} ({eq['ip']}).",
                    )
            except Exception as e:
                logger.warning(f"Error en gestión inicial de RITM para {eq.get('hostname')}: {e}. Continuando con backup...")

        # B. Ejecutar Backup (Núcleo crítico: Crear -> Extraer -> Incorporar)
        task_start = time.time()
        try:
            result = process_equipo(eq)
        except Exception as e_proc:
            logger.error(f"Excepción no controlada en proceso de backup para {eq.get('hostname')}: {e_proc}")
            result = dict(eq, status="ERROR", error_detail=str(e_proc))

        result["ritm_number"] = ritm_number

        # Calcular tiempo efectivo transcurrido
        task_elapsed = result.get("elapsed", time.time() - task_start)
        sn_effective_work, text_effective_work = format_effective_work(task_elapsed)

        # D. Cerrar (OK) en auto_soc o dejar Abierto (ERROR) en Adm_Soc_grupo
        if sn_client:
            try:
                fail_group = getattr(sn_client, "fail_assignment_group", "Adm_Soc_grupo")
                success_group = getattr(sn_client, "assignment_group", "grupo-asignacion-soc")

                if result.get("status") == "OK":
                    work_notes = (
                        f"Backup finalizado exitosamente.\n"
                        f"Equipo: {result.get('hostname', eq['hostname'])}\n"
                        f"IP: {eq.get('ip', 'N/A')}\n"
                        f"SHA-256: {result.get('sha256_local', 'N/A')}\n"
                        f"Método: {result.get('method', '?')}\n"
                        f"Ruta: {result.get('backup_file', 'N/A')}\n"
                        f"Duración: {task_elapsed:.1f}s\n"
                        f"Trabajo efectivo (u_effective_work): {text_effective_work}"
                    )
                    if ritm_sys_id:
                        sn_client.update_ritm(
                            ritm_sys_id,
                            state="3",  # Terminado (Closed Complete)
                            work_notes=work_notes,
                            u_effective_work=sn_effective_work,
                            additional_fields={
                                "assignment_group": success_group
                            }
                        )
                        logger.info(f"🎫 RITM {ritm_number} → Terminado (OK) en {success_group} [u_effective_work: {sn_effective_work}]")
                    else:
                        new_ritm = _create_ritm(sn_client, client_data, 1, hostname=eq['hostname'])
                        r_sys = _get_ritm_sys_id(new_ritm)
                        r_num = _get_ritm_number(new_ritm)
                        result["ritm_number"] = r_num
                        if r_sys:
                            sn_client.update_ritm(
                                r_sys,
                                state="3",
                                work_notes=work_notes,
                                u_effective_work=sn_effective_work,
                                additional_fields={"assignment_group": success_group}
                            )
                            logger.info(f"🎫 RITM {r_num} creado y Terminado (OK) en {success_group} [u_effective_work: {sn_effective_work}]")
                else:
                    # Backup que NO se ejecutó / fallido
                    status_desc = result.get("status", "ERROR")
                    error_msg = result.get("error_detail") or "Falla no especificada durante el proceso de backup."
                    method_tried = result.get("method", "N/A")
                    backup_file = result.get("backup_file", "No generado")
                    work_notes = (
                        f"ESTADO DE EJECUCIÓN: {status_desc} (NO EJECUTADO / FALLIDO)\n"
                        f"Equipo: {result.get('hostname', eq['hostname'])}\n"
                        f"IP: {eq.get('ip', 'N/A')}\n"
                        f"Cliente: {client_data.get('shortname', 'N/A')}\n"
                        f"Método intentado: {method_tried}\n"
                        f"Archivo: {backup_file}\n"
                        f"Duración transcurrida: {task_elapsed:.1f}s\n"
                        f"Fecha y hora: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n"
                        f"DETALLE DEL ERROR:\n{error_msg}\n\n"
                        f"ACCIÓN: El backup no se ejecutó. El ticket queda en estado Abierto asignado al grupo resolutor {fail_group} para revisión y remediación operativa."
                    )
                    if ritm_sys_id:
                        sn_client.update_ritm(
                            ritm_sys_id,
                            state="1",  # Abierto (Open / New)
                            work_notes=work_notes,
                            additional_fields={
                                "assignment_group": fail_group,
                                "assigned_to": ""
                            }
                        )
                        logger.info(f"🎫 RITM {ritm_number} → Abierto (Falla) asignado al grupo resolutor {fail_group} (State=1)")
                    else:
                        tag_ta = (
                            get_env_var("SN_U_GBL_TA")
                            or get_env_var("SERVICENOW_U_GBL_TA")
                            or getattr(sn_client, "u_gbl_ta", "")
                            or SN_U_GBL_TA
                        )
                        short_desc = f"[FALLA] Backup F5 UCS - {client_data['shortname']} - {eq['hostname']} - {datetime.now():%Y-%m-%d}"
                        desc = (
                            f"Falla en la ejecución de backup UCS F5.\n"
                            f"Equipo: {eq['hostname']} ({eq.get('ip', 'N/A')})\n"
                            f"Cliente: {client_data['shortname']}\n"
                            f"Empresa: {client_data['nombre_sn']}\n"
                            f"Tag / Tipo de Actividad (TA): {tag_ta}\n"
                            f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n"
                            f"DETALLE DEL ERROR:\n{error_msg}"
                        )
                        add_fields = {
                            "company": client_data["nombre_sn"],
                            "requested_for": client_data["representante"],
                            "assignment_group": fail_group,
                            "assigned_to": "",
                            "state": "1",
                            "u_gbl_tag": tag_ta,
                            "u_gbl_ta": tag_ta,
                        }
                        new_ritm = sn_client.create_ritm(short_desc, desc, additional_fields=add_fields)
                        r_sys = _get_ritm_sys_id(new_ritm)
                        r_num = _get_ritm_number(new_ritm)
                        result["ritm_number"] = r_num
                        if r_sys:
                            sn_client.update_ritm(
                                r_sys,
                                state="1",
                                work_notes=work_notes,
                                additional_fields={"assignment_group": fail_group, "assigned_to": ""}
                            )
                            logger.info(f"🎫 RITM {r_num} creado en estado Abierto y asignado al grupo resolutor {fail_group}")
            except Exception as e:
                logger.warning(f"Error gestionando RITM final para {eq.get('hostname')}: {e}")

        return result

    logger.info(f"Procesando {len(equipos)} equipos con {MAX_WORKERS} workers…")
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

    # Correo consolidado general que se envía SIEMPRE al terminar todos los equipos
    if ENABLE_MAIL:
        try:
            logger.info("📧 Enviando correo consolidado final con el resumen de todos los equipos...")
            send_consolidated_summary(results)
            logger.info("✅ Correo consolidado final procesado.")
        except Exception as e_cons:
            logger.error(f"❌ Error al enviar correo consolidado final: {e_cons}")

    return 0 if total_err == 0 else 1


from backup_f5_CS import run_backup_cs
import json


def main():
    # Soporte directo e intuitivo: si se pasa una cadena con comas como primer argumento (ej: "SOC_PROYECTO, ...")
    # ejecutar inmediatamente el respaldo individual con ServiceNow y Correo.
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-") and sys.argv[1] not in ("hide", "reveal", "run", "single"):
        datos = sys.argv[1]
        result, exit_code = run_backup_cs(datos)
        print(json.dumps(result, indent=4))
        return exit_code

    parser = argparse.ArgumentParser(
        description="Backups UCS F5 con ServiceNow y Correo (Inventario masivo o equipo individual)."
    )
    sub = parser.add_subparsers(dest="cmd")

    # Subcomando hide
    p_hide = sub.add_parser("hide", help="Cifra un CSV y lo guarda como .dpapi.")
    p_hide.add_argument("--in", dest="in_path", default="equipos_f5.csv")
    p_hide.add_argument("--out", dest="out_path", default="equipos_f5.dpapi")
    p_hide.add_argument("--keep-csv", action="store_true")

    # Subcomando reveal
    p_reveal = sub.add_parser("reveal", help="Descifra un .dpapi a CSV.")
    p_reveal.add_argument("--in", dest="in_path", default="equipos_f5.dpapi")
    p_reveal.add_argument("--out", dest="out_path", default="equipos_f5.csv")

    # Subcomando single (para equipo individual por CLI)
    p_single = sub.add_parser("single", help="Ejecuta respaldo de un equipo individual por línea de comandos.")
    p_single.add_argument("datos_equipo", help='Datos separados por coma ej: "SOC_PROYECTO, AMUF5..., 10.x.x.x, user, pass"')

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
