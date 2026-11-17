@echo off
setlocal

:: Nombre de la tarea en el Programador de Tareas
set "TASK_NAME=Backup_Checkpoint_Semanal"
set "SCRIPT_TO_RUN=%~dp0ejecutar_backup.bat"

echo ======================================================================
echo    CONFIGURACION DE TAREA PROGRAMADA - BACKUP CHECKPOINT
echo ======================================================================
echo.
echo Tarea a registrar : %TASK_NAME%
echo Script a ejecutar: "%SCRIPT_TO_RUN%"
echo Frecuencia       : Semanal - Martes y Miercoles
echo Hora de inicio   : 05:00 AM
echo.

:: Verificar si el script ejecutable existe
if not exist "%SCRIPT_TO_RUN%" (
    echo [ERROR] No se encuentra el archivo: "%SCRIPT_TO_RUN%"
    echo Por favor asegurese de que "ejecutar_backup.bat" este en la misma carpeta.
    pause
    exit /b 1
)

:: Crear o reemplazar la tarea programada
schtasks /create /tn "%TASK_NAME%" /tr "\"%SCRIPT_TO_RUN%\"" /sc weekly /d TUE,WED /st 05:00 /f

if %ERRORLEVEL% equ 0 (
    echo.
    echo ======================================================================
    echo [OK] Tarea programada creada con exito.
    echo Se ejecutara todos los martes y miercoles a las 05:00 AM.
    echo Puede verificarla en el Programador de Tareas de Windows [taskschd.msc].
    echo ======================================================================
) else (
    echo.
    echo ======================================================================
    echo [ERROR] Hubo un problema al crear la tarea programada.
    echo Si requiere privilegios de Administrador, intente hacer clic derecho
    echo sobre este archivo .bat y seleccione "Ejecutar como administrador".
    echo ======================================================================
)

echo.
pause
