@echo off
setlocal enabledelayedexpansion

:: ==============================================================
:: Script de Ejecución Automática - Backup Checkpoint
:: ==============================================================

:: Cambiar al directorio donde reside este script
cd /d "%~dp0"

:: Crear directorio de logs si no existe
if not exist "logs" mkdir "logs"

set "LOGFILE=%~dp0logs\scheduler_run.log"

echo ====================================================== >> "%LOGFILE%"
echo [%DATE% %TIME%] Inicio de ejecucion programada >> "%LOGFILE%"
echo Directorio de trabajo: %CD% >> "%LOGFILE%"

:: Verificar que exista Python en el entorno
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] No se encontro el ejecutable de Python en el PATH del sistema. >> "%LOGFILE%"
    echo [ERROR] No se encontro Python en el PATH. Revisa logs\scheduler_run.log
    exit /b 1
)

:: Ejecutar el script principal de backup (con modo unbuffered -u para volcado inmediato a logs)
set "PYTHONUNBUFFERED=1"
set "PYTHONIOENCODING=utf-8"
python -u main.py %* >> "%LOGFILE%" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if %EXIT_CODE% equ 0 (
    echo [%DATE% %TIME%] Ejecucion finalizada EXITOSAMENTE (ExitCode: %EXIT_CODE%) >> "%LOGFILE%"
) else (
    echo [%DATE% %TIME%] Ejecucion finalizo con ERRORES (ExitCode: %EXIT_CODE%) >> "%LOGFILE%"
)
echo ====================================================== >> "%LOGFILE%"

exit /b %EXIT_CODE%
