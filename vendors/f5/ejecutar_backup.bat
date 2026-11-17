@echo off
setlocal enabledelayedexpansion

:: ==============================================================================
:: Script: ejecutar_backup.bat
:: Descripcion: Ejecuta el orquestador de backup F5 BIG-IP (main.py)
:: Ubicacion: Se posiciona dinamicamente en el directorio donde reside este script
:: ==============================================================================

:: Cambiar al directorio donde se encuentra este archivo .bat
cd /d "%~dp0"

:: Asegurar que exista carpeta de logs para la ejecucion programada
if not exist "logs" mkdir "logs"

set "LOG_FILE=%~dp0logs\tarea_programada_%date:~-4%%date:~3,2%%date:~0,2%.log"

echo ======================================================== >> "%LOG_FILE%" 2>&1
echo [%date% %time%] Iniciando ejecucion programada de Backup F5 >> "%LOG_FILE%" 2>&1
echo Directorio de trabajo: %cd% >> "%LOG_FILE%" 2>&1

:: Detectar ejecutable de Python (entorno virtual o global)
set "PYTHON_EXE=python"
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
)

echo Usando Python: !PYTHON_EXE! >> "%LOG_FILE%" 2>&1

:: Ejecutar el script principal
"!PYTHON_EXE!" main.py >> "%LOG_FILE%" 2>&1
set EXIT_CODE=%ERRORLEVEL%

if !EXIT_CODE! equ 0 (
    echo [%date% %time%] Backup finalizado exitosamente. >> "%LOG_FILE%" 2>&1
) else (
    echo [%date% %time%] Backup finalizado con errores. Codigo: !EXIT_CODE! >> "%LOG_FILE%" 2>&1
)
echo ======================================================== >> "%LOG_FILE%" 2>&1

exit /b !EXIT_CODE!
