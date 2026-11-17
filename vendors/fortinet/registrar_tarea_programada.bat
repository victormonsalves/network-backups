@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

:: ==============================================================================
:: Script: registrar_tarea_programada.bat
:: Propósito: Registra la tarea programada en Windows Task Scheduler
::            para Backup Fortinet bajo el contexto del usuario actual
::            SIN privilegios de Administrador (sin elevación).
:: ==============================================================================

set "TASK_NAME=SOC_Backup_Fortinet"
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

:: Determinar el ejecutable de Python
set "PYTHON_EXE="
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "delims=" %%I in ('where python') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%I"
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] No se encontro Python en el PATH del sistema.
    echo Por favor especifica la ruta completa a python.exe.
    pause
    exit /b 1
)

set "SCRIPT_PATH=%PROJECT_DIR%\main.py"

if not exist "%SCRIPT_PATH%" (
    echo [ERROR] No se encuentra el archivo main.py en:
    echo "%SCRIPT_PATH%"
    pause
    exit /b 1
)

:: Generar el runner wrapper .bat para asegurar que el working directory sea correcto
set "RUNNER_BAT=%PROJECT_DIR%\ejecutar_backup.bat"
(
    echo @echo off
    echo cd /d "%PROJECT_DIR%"
    echo "%PYTHON_EXE%" "%SCRIPT_PATH%" %%*
) > "%RUNNER_BAT%"

:: Parámetros de programación: Semanal, Lunes y Jueves a la 02:00 AM
set "SCHEDULE_FREQ=WEEKLY"
set "SCHEDULE_DAYS=MON,THU"
set "SCHEDULE_DAYS_ES=LUN,JUE"
set "START_TIME=02:00"

echo ==============================================================================
echo CONFIGURACION DE LA TAREA PROGRAMADA
echo ==============================================================================
echo  Nombre de tarea : %TASK_NAME%
echo  Directorio      : %PROJECT_DIR%
echo  Python          : %PYTHON_EXE%
echo  Runner Wrapper  : %RUNNER_BAT%
echo  Frecuencia      : Semanal (Lunes y Jueves a las %START_TIME% AM)
echo  Usuario         : %USERNAME% (Sin elevacion)
echo ==============================================================================
echo.

echo Registrando la tarea en Task Scheduler...

:: Intento 1: Códigos en Inglés (MON,THU)
schtasks /create /tn "%TASK_NAME%" /tr "\"%RUNNER_BAT%\"" /sc %SCHEDULE_FREQ% /d %SCHEDULE_DAYS% /st %START_TIME% /f >nul 2>&1
if %ERRORLEVEL% neq 0 (
    :: Intento 2: Fallback localizado en Español (LUN,JUE)
    schtasks /create /tn "%TASK_NAME%" /tr "\"%RUNNER_BAT%\"" /sc %SCHEDULE_FREQ% /d %SCHEDULE_DAYS_ES% /st %START_TIME% /f
)

if %ERRORLEVEL% equ 0 (
    echo.
    echo ==============================================================================
    echo [EXITO] Tarea "%TASK_NAME%" registrada correctamente en Windows Task Scheduler.
    echo Horario: Lunes y Jueves a las %START_TIME% AM.
    echo.
    echo Comandos utiles:
    echo   - Probar ejecucion inmediata : schtasks /run /tn "%TASK_NAME%"
    echo   - Consultar estado           : schtasks /query /tn "%TASK_NAME%" /fo LIST /v
    echo   - Eliminar tarea             : schtasks /delete /tn "%TASK_NAME%" /f
    echo ==============================================================================
) else (
    echo.
    echo [ERROR] Ocurrio un problema al registrar la tarea con schtasks.
)

echo.
pause
