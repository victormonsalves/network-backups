@echo off
setlocal

:: ==============================================================================
:: Script: crear_tarea_programada.bat
:: Descripcion: Registra la tarea programada en Windows a nivel de usuario estandar
::              (sin requerir permisos de Administrador).
:: ==============================================================================

echo ========================================================
echo   Configuracion de Tarea Programada: Backup F5 BIG-IP
echo   Frecuencia: Semanal (Jueves a las 01:00 AM)
echo   Modo: Usuario Estandar (Sin permisos de Administrador)
echo ========================================================
echo.

set "TASK_NAME=Backup_F5_BIGIP_Semanal"
set "ACTION_PATH=%~dp0ejecutar_backup.bat"

if not exist "%ACTION_PATH%" (
    echo [ERROR] No se encontro el archivo: "%ACTION_PATH%"
    echo Asegurate de que ejecutar_backup.bat este en la misma carpeta.
    goto :fin
)

echo Creando tarea programada: "%TASK_NAME%"...
echo Accion: "%ACTION_PATH%"
echo Horario: Jueves a las 01:00 AM
echo.

:: 1. Intentar con nomenclatura en ingles (THU) sin elevacion (/rl LIMITED)
schtasks /create /tn "%TASK_NAME%" /tr "\"%ACTION_PATH%\"" /sc weekly /d THU /st 01:00 /f >nul 2>&1
if %errorlevel% equ 0 (
    goto :exito
)

:: 2. Si falla por idioma regional, intentar con nomenclatura en espanol (JUE)
schtasks /create /tn "%TASK_NAME%" /tr "\"%ACTION_PATH%\"" /sc weekly /d JUE /st 01:00 /f >nul 2>&1
if %errorlevel% equ 0 (
    goto :exito
)

echo [ERROR] No se pudo crear la tarea con schtasks.
echo Codigo de salida: %errorlevel%
echo.
echo Posibles causas:
echo  - Formato de dia u hora incompatible con la configuracion regional.
echo  - Restricciones de directiva en la cuenta de usuario.
goto :fin

:exito
echo ========================================================
echo [OK] Tarea programada creada exitosamente como usuario estandar.
echo Nombre : %TASK_NAME%
echo Dias   : Jueves
echo Hora   : 01:00 AM
echo Accion : %ACTION_PATH%
echo ========================================================
echo.
echo Para verificar la tarea en Windows puedes ejecutar:
echo   schtasks /query /tn "%TASK_NAME%" /fo LIST /v
echo O abrir: taskschd.msc

:fin
echo.
pause
