#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py - Orquestador principal de Backup Fortinet (FortiOS).

Implementa la arquitectura unificada y las mejoras del flujo de Palo Alto:
  - Logging centralizado rotativo (resources.logger)
  - Envío de correos SMTP estándar SOC con tabla Outlook (resources.email_client, modules.email_reports)
  - Gestión de tickets RITM en ServiceNow (resources.servicenow_client)
  - Cifrado seguro DPAPI para credenciales en reposo (modules.dpapi)
  - Parser dinámico y tolerante a formatos (modules.inventory_parser)
  - Subcomandos CLI: run, single, hide, reveal

Uso:
  python main.py                                      # Ejecuta con el inventario configurado en .env
  python main.py run "equipo_fortinet.dpapi"          # Ejecuta inventario específico
  python main.py single "SOC_SEDE, <ip-ficticia>, ..."    # Ejecuta equipo individual
  python main.py hide --in archivo.csv                # Cifra CSV a DPAPI
  python main.py reveal --in archivo.dpapi            # Descifra DPAPI a CSV
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

# ─── Carga de variables de entorno ───────────────────────────────
try:
    from dotenv import load_dotenv
    _LOCAL_ENV = Path(__file__).resolve().parent / ".env"
    _PARENT_ENV = Path(__file__).resolve().parent.parent / ".env"
    if _LOCAL_ENV.exists():
        load_dotenv(_LOCAL_ENV)
    elif _PARENT_ENV.exists():
        load_dotenv(_PARENT_ENV)
except Exception:
    pass

# ─── Imports de módulos y recursos ───────────────────────────────
from resources.logger import logger
from resources.servicenow_client import ServiceNowClient
from modules.inventory_parser import parse_inventario, parse_equipo_string
from modules.backup_worker import process_equipo
from modules.client_resolver import resolve_client, resolve_clients_for_groups
from modules.email_reports import send_backup_reports, send_consolidated_summary
from modules.dpapi import hide_csv_to_dpapi, reveal_dpapi_to_csv
from backup_fortinet_CS import run_backup_cs

# ─── Configuración general ───────────────────────────────────────
EQUIPOS_FILE = os.getenv("EQUIPOS_FILE", "equipo_fortinet.dpapi")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "5"))
WORKER_TIMEOUT = int(os.getenv("WORKER_TIMEOUT", "300"))
ENABLE_MAIL = os.getenv("ENABLE_MAIL", "true").lower() in ("1", "true", "yes")
ENABLE_CONSOLIDATED_MAIL = os.getenv("ENABLE_CONSOLIDATED_MAIL", "true").lower() in ("1", "true", "yes")
DEVICE_FLOW_MAIL = os.getenv("DEVICE_FLOW_MAIL", "false").lower() in ("1", "true", "yes")
ENABLE_SERVICENOW = os.getenv("ENABLE_SERVICENOW", "true").lower() in ("1", "true", "yes")
LISTA_CLIENTES_PATH = os.getenv("LISTA_CLIENTES_PATH")


def _find_inventory_file(specified_path: str | None = None) -> Path | None:
    """Busca el archivo de inventario en la ruta actual o en rutas relativas comunes."""
    candidates = []
    if specified_path:
        candidates.append(Path(specified_path))

    # Candidatos por defecto
    current_dir = Path(__file__).resolve().parent
    parent_dir = current_dir.parent

    for name in [EQUIPOS_FILE, "equipo_fortinet.dpapi", "equipo_fortinet.csv"]:
        candidates.append(current_dir / name)
        candidates.append(parent_dir / name)
        candidates.append(Path(name))

    for p in candidates:
        if p.exists() and p.is_file():
            return p.resolve()

    return None


def _create_ritm(sn_client: ServiceNowClient, client_data: Dict, hostname: str, ip: str) -> dict | None:
    """Crea un ticket RITM en ServiceNow."""
    fecha_hoy = datetime.now().strftime("%Y-%m-%d")
    short_desc = f"Backup Fortinet - {client_data['shortname']} - {hostname} - {fecha_hoy}"
    description = (
        f"Ejecución automática de backup para equipo Fortinet.\n"
        f"Cliente: {client_data['shortname']}\n"
        f"Empresa: {client_data['nombre_sn']}\n"
        f"Equipo: {hostname}\n"
        f"IP: {ip}\n"
        f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}"
    )
    additional_fields = {
        "company": client_data["nombre_sn"],
        "requested_for": client_data["representante"],
    }
    return sn_client.create_ritm(short_description=short_desc, description=description, additional_fields=additional_fields)


def _get_field(data: dict | None, field: str) -> str:
    """Extrae campo de ServiceNow tolerando dicts o strings."""
    if not data:
        return ""
    val = data.get(field, "")
    if isinstance(val, dict):
        return str(val.get("display_value") or val.get("value") or "").strip()
    return str(val).strip()


def run_backups(inventory_path: str | None = None, workers: int | None = None) -> int:
    """Flujo principal de backup masivo."""
    start_time = time.time()
    effective_workers = workers or MAX_WORKERS

    inv_path = _find_inventory_file(inventory_path)
    if not inv_path:
        logger.error(f"No se encontró el archivo de inventario: {inventory_path or EQUIPOS_FILE}")
        return 1

    logger.info("=" * 70)
    logger.info("INICIO — Proceso de Backup Fortinet Automatizado (Flujo SOC)")
    logger.info(f"Inventario: {inv_path}")
    logger.info(f"Workers: {effective_workers} | Timeout/equipo: {WORKER_TIMEOUT}s")
    logger.info("=" * 70)

    # 1. Cargar inventario
    equipos = parse_inventario(str(inv_path))
    if not equipos:
        logger.error("No se encontraron equipos válidos en el inventario. Abortando.")
        return 1

    # 2. Resolver clientes para los grupos presentes
    grupos = [eq.get("grupo", "SOC") for eq in equipos]
    client_map = resolve_clients_for_groups(grupos, LISTA_CLIENTES_PATH)

    # 3. Inicializar ServiceNow si está habilitado
    sn_client = None
    if ENABLE_SERVICENOW:
        try:
            sn_client = ServiceNowClient()
            logger.info("ServiceNow Client inicializado correctamente.")
        except Exception as e:
            logger.warning(f"No se pudo inicializar ServiceNowClient ({e}). Se continuará sin tickets.")

    # 4. Función de tarea por equipo
    def _process_single(eq: Dict) -> Dict:
        hostname = eq.get("hostname", eq.get("ip"))
        ip = eq.get("ip")
        grupo = eq.get("grupo", "SOC")
        client_data = client_map.get(grupo, {
            "shortname": grupo,
            "nombre_sn": "Empresa S.A",
            "representante": "Empresa Chile Representante",
        })

        # A. Crear RITM
        ritm_sys_id = ""
        ritm_number = ""
        if sn_client:
            try:
                ritm = _create_ritm(sn_client, client_data, hostname, ip)
                ritm_sys_id = _get_field(ritm, "sys_id")
                ritm_number = _get_field(ritm, "number")
                if ritm_sys_id:
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="2",  # Work in Progress
                        work_notes=f"Iniciando backup individual para {hostname} ({ip}).",
                    )
            except Exception as e_sn_init:
                logger.warning(f"[{hostname}] Error al crear RITM inicial: {e_sn_init}")

        # B. Ejecutar Backup
        try:
            result = process_equipo(eq)
        except Exception as e_proc:
            logger.error(f"[{hostname}] Excepción en worker de backup: {e_proc}")
            result = dict(eq, status="ERROR", error_detail=str(e_proc))

        result["ritm_number"] = ritm_number

        # C. Enviar correo individual si aplica
        if ENABLE_MAIL and DEVICE_FLOW_MAIL:
            try:
                send_backup_reports([result], ritm_number=ritm_number, vendor="Fortinet")
            except Exception as e_m:
                logger.error(f"[{hostname}] Error al enviar correo individual: {e_m}")

        # D. Cierre o escalamiento del RITM
        if sn_client and ritm_sys_id:
            try:
                raw_elapsed = result.get("elapsed", 0)
                try:
                    duracion_seg = int(round(float(raw_elapsed) + 1e-9))
                except Exception:
                    duracion_seg = 0

                if result.get("status") == "OK":
                    work_notes = (
                        f"Backup Fortinet finalizado exitosamente.\n"
                        f"Estado: Terminado\n"
                        f"Equipo: {hostname}\n"
                        f"IP: {ip}\n"
                        f"Archivo: {result.get('backup_file', 'N/A')}\n"
                        f"SHA-256: {result.get('sha256_local', 'N/A')}\n"
                        f"Cambios: {result.get('changes', 'N/A')}\n"
                        f"Método: {result.get('method', 'REST-API')}\n"
                        f"Trabajo efectivo (u_effective_work): {duracion_seg} segundos\n"
                        f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}"
                    )
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="3",  # Terminado
                        work_notes=work_notes,
                        u_effective_work=duracion_seg,
                        additional_fields={"assignment_group": sn_client.assignment_group},
                    )
                    logger.info(f"🎫 [{hostname}] RITM {ritm_number} → Terminado (OK)")

                else:
                    fail_group = getattr(sn_client, "fail_assignment_group", "Adm_Soc_grupo")
                    work_notes = (
                        f"Backup Fortinet FALLIDO / NO EJECUTADO.\n"
                        f"Estado: Abierto\n"
                        f"Grupo resolutor: {fail_group}\n"
                        f"Equipo: {hostname}\n"
                        f"IP: {ip}\n"
                        f"Error: {result.get('error_detail', 'Error desconocido')}\n"
                        f"Duración intento: {duracion_seg}s\n"
                        f"Fecha: {datetime.now():%Y-%m-%d %H:%M:%S}\n"
                        f"Requiere intervención técnica del especialista."
                    )
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="1",  # Abierto
                        work_notes=work_notes,
                        u_effective_work=duracion_seg,
                        additional_fields={
                            "assigned_to": "",
                            "assignment_group": fail_group,
                        },
                    )
                    logger.info(f"🎫 [{hostname}] RITM {ritm_number} → Abierto (Falla) en grupo {fail_group}")

            except Exception as e_sn_close:
                logger.error(f"[{hostname}] Error al actualizar RITM final: {e_sn_close}")

        return result

    # 5. Ejecución paralela
    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        futures = {pool.submit(_process_single, eq): eq for eq in equipos}
        for fut in as_completed(futures):
            eq_ref = futures[fut]
            h_ref = eq_ref.get("hostname", eq_ref.get("ip"))
            try:
                res = fut.result(timeout=WORKER_TIMEOUT)
                results.append(res)
            except TimeoutError:
                logger.error(f"[{h_ref}] TIMEOUT: Procesamiento excedió {WORKER_TIMEOUT}s.")
                results.append(dict(
                    eq_ref,
                    status="ERROR",
                    error_detail=f"Timeout de procesamiento ({WORKER_TIMEOUT}s excedido)",
                    elapsed=WORKER_TIMEOUT,
                ))
            except Exception as e:
                logger.error(f"[{h_ref}] Excepción no controlada: {e}")
                results.append(dict(
                    eq_ref,
                    status="ERROR",
                    error_detail=f"Excepción: {type(e).__name__}: {str(e)}",
                ))

    # 6. Resumen Ejecutivo
    elapsed_total = round(time.time() - start_time, 1)
    total_ok = sum(1 for r in results if r.get("status") == "OK")
    total_err = sum(1 for r in results if r.get("status") != "OK")

    logger.info("=" * 70)
    logger.info("RESUMEN EJECUTIVO — Backup Fortinet")
    logger.info(f"  Total procesados : {len(results)}")
    logger.info(f"  ✔ Exitosos      : {total_ok}")
    logger.info(f"  ✖ Errores       : {total_err}")
    logger.info(f"  Tiempo total     : {elapsed_total}s")
    logger.info("=" * 70)

    # 7. Correo Consolidado
    if ENABLE_MAIL and ENABLE_CONSOLIDATED_MAIL:
        try:
            logger.info("📧 Enviando reporte consolidado final...")
            send_consolidated_summary(results, vendor="Fortinet")
            logger.info("✅ Reporte consolidado enviado exitosamente.")
        except Exception as e_cons:
            logger.error(f"Error al enviar reporte consolidado: {e_cons}")

    logger.info("FIN — Proceso de Backup Fortinet Automatizado.")
    return 0 if total_err == 0 else 1


def main():
    # Soporte directo: si se pasa un string con comas directamente por línea de comandos
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-") and sys.argv[1] not in ("run", "single", "hide", "reveal", "-h", "--help"):
        arg_val = sys.argv[1]
        if "," in arg_val or ";" in arg_val:
            result, exit_code = run_backup_cs(arg_val)
            print(json.dumps(result, indent=4, ensure_ascii=False))
            return exit_code
        elif arg_val.endswith((".dpapi", ".csv")):
            return run_backups(arg_val)

    parser = argparse.ArgumentParser(
        description="Backup Fortinet Automatizado con ServiceNow, Integridad SHA-256 y Cifrado DPAPI."
    )
    sub = parser.add_subparsers(dest="cmd")

    # Subcomando run
    p_run = sub.add_parser("run", help="Ejecutar backup del inventario (por defecto).")
    p_run.add_argument("inventory", nargs="?", default=None, help="Ruta al archivo CSV o DPAPI de inventario")
    p_run.add_argument("--workers", type=int, default=MAX_WORKERS, help="Cantidad de hilos concurrentes")

    # Subcomando single
    p_single = sub.add_parser("single", help="Ejecutar respaldo para un único equipo.")
    p_single.add_argument("datos_equipo", help='Datos del equipo ej: "SOC_SEDE, <ip-ficticia>, <sede>_fgt, user:pass"')

    # Subcomando hide
    p_hide = sub.add_parser("hide", help="Cifrar un archivo CSV a formato DPAPI.")
    p_hide.add_argument("--in", dest="in_path", default="equipo_fortinet.csv", help="Archivo CSV de entrada")
    p_hide.add_argument("--out", dest="out_path", default="equipo_fortinet.dpapi", help="Archivo DPAPI de salida")
    p_hide.add_argument("--keep", action="store_true", help="Mantener el archivo CSV original en claro")

    # Subcomando reveal
    p_reveal = sub.add_parser("reveal", help="Descifrar un archivo DPAPI a formato CSV.")
    p_reveal.add_argument("--in", dest="in_path", default="equipo_fortinet.dpapi", help="Archivo DPAPI de entrada")
    p_reveal.add_argument("--out", dest="out_path", default="equipo_fortinet.csv", help="Archivo CSV de salida")

    # Flag opcional -e para equipo individual
    parser.add_argument("-e", "--equipo", dest="equipo_str", default=None, help="Datos de equipo individual")

    args = parser.parse_args()

    if args.equipo_str:
        result, exit_code = run_backup_cs(args.equipo_str)
        print(json.dumps(result, indent=4, ensure_ascii=False))
        return exit_code
    elif args.cmd == "single":
        result, exit_code = run_backup_cs(args.datos_equipo)
        print(json.dumps(result, indent=4, ensure_ascii=False))
        return exit_code
    elif args.cmd == "hide":
        out = args.out_path
        hide_csv_to_dpapi(args.in_path, out, delete_plain=not args.keep)
        print(f"[OK] Archivo cifrado exitosamente: {out}")
        if not args.keep:
            print("[OK] Archivo en texto claro eliminado por seguridad.")
        return 0
    elif args.cmd == "reveal":
        out = args.out_path
        reveal_dpapi_to_csv(args.in_path, out)
        print(f"[OK] Archivo descifrado exitosamente: {out}")
        print("[WARN] Recuerda volver a cifrarlo con: python main.py hide")
        return 0
    elif args.cmd == "run":
        return run_backups(args.inventory, args.workers)
    else:
        # Ejecución por defecto
        return run_backups()


if __name__ == "__main__":
    sys.exit(main())
