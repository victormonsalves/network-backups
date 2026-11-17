import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# Añadir directorios al path para importaciones
SCRIPT_DIR = Path(__file__).parent.resolve()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.append(str(SCRIPT_DIR))

# Cargar configuración desde el Registro de Windows y .env
from resources.env_helper import load_system_and_env
load_system_and_env()

from resources.logger import logger, setup_logger
from resources.email_client import EmailClient
from resources.servicenow_client import ServiceNowClient
from modules.inventory_parser import parse_inventario
from modules.client_resolver import resolve_client
from modules.backup_worker import process_equipo
from modules.email_reports import get_html_report

def calculate_effective_work(seconds: float | int) -> tuple[str, str]:
    """
    Calcula el trabajo efectivo redondeado al minuto más cercano (mínimo 1 minuto).
    Retorna:
      - glide_str: Formato '1970-01-01 HH:MM:00' para el campo glide_duration (u_effective_work) en ServiceNow.
      - human_str: Texto amigable para notas de trabajo (work_notes), ej. '22 minutos'.
    """
    total_minutes = max(1, round(float(seconds or 0) / 60))
    hours = total_minutes // 60
    minutes = total_minutes % 60
    days = hours // 24
    hours_rem = hours % 24
    
    if days > 0:
        glide_str = f"{days} {hours_rem:02d}:{minutes:02d}:00"
    else:
        glide_str = f"1970-01-01 {hours:02d}:{minutes:02d}:00"
        
    if hours == 0:
        human_str = f"{minutes} minuto{'s' if minutes > 1 else ''}"
    elif minutes == 0:
        human_str = f"{hours} hora{'s' if hours > 1 else ''}"
    else:
        human_str = f"{hours} hora{'s' if hours > 1 else ''} {minutes} minuto{'s' if minutes > 1 else ''}"
        
    return glide_str, human_str

def process_equipo_with_ticket(eq: dict, base_folder: Path, sn_client: ServiceNowClient | None, enable_sn: bool, vendor: str, fecha: str, logger: logging.Logger) -> dict:
    """
    Procesa el backup de un equipo y gestiona su ticket RITM individual en ServiceNow cumpliendo el ciclo:
    1. Creación en estado "Abierto | 1"
    2. Cambio de estado a "Trabajo en curso | 2" informando la tarea
    3. Finalización en estado "Terminado | 3" (o "Pendiente | 4" en caso de falla)
       con detalle, duración y campo u_effective_work.
    """
    host = eq["hostname"]
    ip = eq["ip"]
    grupo = eq.get("grupo", "SIN_GRUPO")
    
    # Resolver datos del cliente para el grupo específico del equipo
    client_data = resolve_client(grupo, os.getenv("LISTA_CLIENTES_PATH"))
    
    ritm_id = "N/A"
    ritm_sys_id = None
    
    # Resolver tag global (asegurando prefijo '#' requerido por choices de ServiceNow)
    raw_tag = os.getenv("SN_U_GBL_TAG") or os.getenv("SN_U_GBL_TA", "NNDD-SyR-30")
    tag = (raw_tag if raw_tag.startswith("#") else f"#{raw_tag}") if raw_tag else "#NNDD-SyR-30"
    
    # 1. Crear RITM individual en estado "Abierto | 1"
    if enable_sn and sn_client:
        try:
            logger.info(f"[{host}] Solicitando creación de ticket RITM en ServiceNow (Estado: Abierto | 1, Cliente: {client_data.get('shortname')}, Tag: {tag})...")
            ritm_data = sn_client.create_ritm(
                short_description=f"Backup {vendor} - {client_data.get('shortname', '')} - {host} - {fecha}",
                description=(
                    f"Ejecución automática de backup para {vendor}.\n"
                    f"Cliente: {client_data.get('shortname', 'N/A')}\n"
                    f"Empresa: {client_data.get('nombre_sn', 'Empresa S.A')}\n"
                    f"Equipo: {host}\n"
                    f"IP: {ip}\n"
                    f"Grupo: {grupo}\n"
                    f"Fecha: {fecha}"
                ),
                additional_fields={
                    "company": client_data.get("nombre_sn", "Empresa S.A"),
                    "u_customer": client_data.get("nombre_sn", "Empresa S.A"),
                    "requested_for": client_data.get("representante", "SOAR"),
                    "u_gbl_tag": tag,
                    "state": "1"  # Abierto | 1
                }
            )
            if ritm_data:
                num_field = ritm_data.get('number', 'N/A')
                ritm_id = num_field.get('display_value', num_field.get('value', 'N/A')) if isinstance(num_field, dict) else str(num_field)
                
                sys_field = ritm_data.get('sys_id', None)
                ritm_sys_id = sys_field.get('display_value', sys_field.get('value', None)) if isinstance(sys_field, dict) else (str(sys_field) if sys_field else None)
                
                logger.info(f"[{host}] Ticket RITM creado: {ritm_id} en estado Abierto | 1")
                
                # 2. Cambiar estado a "Trabajo en curso | 2" informando lo que se está realizando
                if ritm_sys_id:
                    sn_client.update_ritm(
                        ritm_sys_id,
                        state="2",  # Trabajo en curso | 2
                        work_notes=f"Estado cambiado a 'Trabajo en curso | 2'. Iniciando proceso de backup para equipo {host} ({ip}) vía {vendor}."
                    )
                    logger.info(f"[{host}] RITM {ritm_id} -> Estado actualizado a Trabajo en curso | 2")
            else:
                logger.warning(f"[{host}] No se pudo crear RITM en ServiceNow. Se continúa backup sin ticket.")
        except Exception as e:
            logger.warning(f"[{host}] Error al comunicarse con ServiceNow para crear ticket: {e}")

    # Ejecutar backup del equipo
    res = process_equipo(eq, base_folder)
    
    # Asignar ticket a los resultados del equipo
    res["ritm_number"] = ritm_id
    res["ritm_sys_id"] = ritm_sys_id

    # 3. Finalizar ticket RITM individual con la información de lo realizado, estado y trabajo efectivo
    if enable_sn and sn_client and ritm_sys_id:
        try:
            duracion_segundos = res.get('duration', 0)
            glide_work, human_work = calculate_effective_work(duracion_segundos)
            
            if res["status"] == "OK":
                work_notes = (
                    f"Backup finalizado exitosamente (Estado: Terminado | 3).\n"
                    f"- Equipo: {host}\n"
                    f"- IP: {ip}\n"
                    f"- Archivo: {res.get('filename', 'N/A')}\n"
                    f"- Ruta: {res.get('backup_file', 'N/A')}\n"
                    f"- Tamaño: {res.get('size_human', 'N/A')} ({res.get('size_mb', 0)} MB)\n"
                    f"- SHA-256: {res.get('sha256_local', 'N/A')}\n"
                    f"- Método: {res.get('method', 'N/A')}\n"
                    f"- Duración: {duracion_segundos}s\n"
                    f"- Trabajo Efectivo (u_effective_work): {human_work}"
                )
                sn_client.update_ritm(
                    ritm_sys_id,
                    state="3",  # Terminado | 3
                    work_notes=work_notes,
                    additional_fields={
                        "u_effective_work": glide_work
                    }
                )
                logger.info(f"[{host}] RITM {ritm_id} -> Finalizado en Terminado | 3 con u_effective_work={glide_work} ({human_work})")
            else:
                work_notes = (
                    f"Backup FALLIDO.\n"
                    f"- Equipo: {host}\n"
                    f"- IP: {ip}\n"
                    f"- Tipo de Error: {res.get('error_type', 'N/A')}\n"
                    f"- Detalle: {res.get('detail', 'Error desconocido')}\n"
                    f"- Duración: {duracion_segundos}s\n"
                    f"- Trabajo Efectivo (u_effective_work): {human_work}"
                )
                sn_client.update_ritm(
                    ritm_sys_id,
                    state="4",  # Pendiente | 4
                    work_notes=work_notes,
                    additional_fields={
                        "assigned_to": "SOAR",
                        "assignment_group": "adm_socgrupo",
                        "u_effective_work": glide_work
                    }
                )
                logger.info(f"[{host}] RITM {ritm_id} -> Pendiente (Falla) en adm_socgrupo / SOAR con u_effective_work={glide_work} ({human_work})")
        except Exception as e:
            logger.warning(f"[{host}] Error al actualizar/cerrar RITM {ritm_id}: {e}")

    return res

def main(inventory_file=None):
    # 0. Inicializar Logger
    logger = setup_logger("automation_logger")
    logger.info("🚀 Iniciando automatización de Backup Checkpoint GAIA")

    # Parámetros desde .env
    inventory_path = inventory_file or os.getenv("INVENTARIO_FILE")
    # Si es solo un nombre de archivo, buscarlo en el directorio del script o en el anterior
    if not os.path.isabs(inventory_path):
        potential_path = SCRIPT_DIR / inventory_path
        if not potential_path.exists():
            # Intentar en el nivel superior si no está en backup_checkpoint
            potential_path = SCRIPT_DIR.parent / inventory_path
        inventory_path = str(potential_path)

    base_folder = Path(os.getenv("BASE_FOLDER", "E:\\Respaldos_new"))
    max_workers = int(os.getenv("MAX_WORKERS", "4"))
    enable_sn = os.getenv("ENABLE_SERVICENOW", "false").lower() == "true"
    enable_mail = os.getenv("ENABLE_MAIL", "true").lower() == "true"
    
    vendor = "Checkpoint GAIA"
    fecha = datetime.now().strftime("%Y-%m-%d")

    logger.info(f"Configuración: ENABLE_SERVICENOW={enable_sn} | SN_USER={os.getenv('SN_USER')} | SN_URL={os.getenv('SN_URL')}")

    # Paso 0.1: Validar carpeta de destino
    try:
        base_folder.mkdir(parents=True, exist_ok=True)
        test_file = base_folder / ".write_test"
        test_file.touch()
        test_file.unlink()
    except Exception as e:
        logger.error(f"Falla crítica: No se tiene acceso de escritura en {base_folder}: {e}")
        return 1

    # Paso 1: Cargar Inventario
    equipos = parse_inventario(inventory_path)
    if not equipos:
        logger.error("No se encontraron equipos para procesar o el inventario es inválido. Abortando.")
        return 1

    # Paso 2: Preparar cliente ServiceNow si está habilitado
    sn_client = None
    if enable_sn:
        try:
            sn_client = ServiceNowClient()
            logger.info("Cliente ServiceNow inicializado correctamente.")
        except Exception as e:
            logger.warning(f"No se pudo inicializar ServiceNow: {e}. Se continuará sin tickets.")
            enable_sn = False

    # Paso 3: Ejecutar Backups en Paralelo con ticket individual por hostname
    results = []
    logger.info(f"Procesando {len(equipos)} equipos con {max_workers} hilos (tickets individuales por hostname)...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                process_equipo_with_ticket, eq, base_folder, sn_client, enable_sn, vendor, fecha, logger
            ): eq for eq in equipos
        }
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
                icon = "✅" if res["status"] == "OK" else "❌"
                ticket_info = res.get("ritm_number") or "N/A"
                logger.info(f"{icon} {res['hostname']}: {res['status']} | Ticket: {ticket_info} - {res['detail']}")
            except Exception as e:
                logger.error(f"Error fatal procesando hilo: {e}")

    # Paso 4: Resumen y Reporte Consolidado
    exit_status = 0
    failures = [r for r in results if r["status"] != "OK"]
    successes = [r for r in results if r["status"] == "OK"]

    if len(failures) == 0 and len(results) > 0:
        estado_consolidado = "OK"
    elif len(successes) > 0:
        estado_consolidado = "PARCIAL"
    else:
        estado_consolidado = "FALLO"

    logger.info(f"=== RESUMEN === | Total: {len(results)} | OK: {len(successes)} | FALLAS: {len(failures)} | Estado: {estado_consolidado}")
    for r in results:
        logger.info(f" - {r['hostname']} ({r['ip']}): {r['status']} | Ticket RITM: {r.get('ritm_number', 'N/A')}")
    
    if enable_mail:
        try:
            email_client = EmailClient()
            subject = f"[Tarea automatizada] || Backup {vendor} || Resumen Consolidado ({estado_consolidado})"
            html_body = get_html_report(results, vendor=vendor)
            email_client.send_email(
                subject=subject,
                body=html_body,
                to=os.getenv("EMAIL_TO"),
                cc=os.getenv("EMAIL_CC")
            )
            logger.info(f"Reporte de correo consolidado enviado: {subject}")
        except Exception as e:
            logger.error(f"Error enviando correo: {e}")

    logger.info("🏁 Fin de la automatización.")
    return 0 if not failures else 1

if __name__ == "__main__":
    # Si se pasa un argumento, se usa como archivo de inventario
    inv_arg = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(main(inv_arg))
