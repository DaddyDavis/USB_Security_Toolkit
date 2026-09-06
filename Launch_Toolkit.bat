@echo off
setlocal EnableDelayedExpansion
title USB Security Toolkit - Master Field Console
cd /d "%~dp0"
set "IN_TOOLKIT_LOOP=1"

:: Set Neon Green Hacker Palette (0A = Bright Neon Green on Black)
color 0A

:: Detect Elevation
net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PRIV_STATUS=[HIGH INTEGRITY: ELEVATED ADMIN]"
) else (
    set "PRIV_STATUS=[MEDIUM INTEGRITY: STANDARD USER]"
)

:: Detect Python Engine
if exist "%~dp0python_embed\python.exe" (
    set "PY_CMD=%~dp0python_embed\python.exe"
    set "PY_INFO=USB Portable Python (Embeddable 3.12)"
) else (
    where python >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "PY_CMD=python"
        set "PY_INFO=Host System Python"
    ) else (
        set "PY_CMD="
        set "PY_INFO=Not Detected (PowerShell Mode Active)"
    )
)

:MENU
cls
echo ==============================================================================================
echo       __  _______ ____     _____                          _ __         
echo      / / / / ___// __ )   / ___/___  _______  ___________(_) /___  __  
echo     / / / /\__ \/ __  /   \__ \/ _ \/ ___/ / / / ___/ ___/ / __/ / / / 
echo    / /_/ /___/ / /_/ /   ___/ /  __/ /__/ /_/ / /  / /  / / /_ / /_/ /  
echo    \____//____/_____/   /____/\___/\___/\__,_/_/  /_/  /_/\__/ \__, /   
echo                                                               /____/    
echo                     TACTICAL LIVE INCIDENT AND DFIR CONSOLE
echo ==============================================================================================
echo  Privilege: !PRIV_STATUS!
echo  Python:    !PY_INFO!
echo  Directory: %~dp0
echo ==============================================================================================
echo.
echo    --- TRIAGE AND AUDIT MODULES ---
echo    [1] Quick Windows Live Triage            (PowerShell - Host, AV, Firewall, Ports)
echo    [2] Comprehensive Audit Suite and JSON   (Python - Full Structured Telemetry)
echo    [3] USB Historical Connection Forensics  (PowerShell - USBSTOR, Serials, Volumes)
echo    [4] Advanced Persistence Hunter          (PowerShell - Tasks, Staged Services, WMI)
echo    [5] Volatile Evidence Snapshot           (PowerShell - DNS Cache, ARP, Sockets)
echo    [6] File Hasher and IOC Malware Scanner  (Python - SHA256/MD5 Manifest)
echo    [7] Security Event Log Hunter            (PowerShell - Failed Logons, Backdoors)
echo    [8] Wi-Fi Profiles and Stored Keys       (PowerShell - SSID Passwords, Open Networks)
echo    [9] Browser History and Downloads        (Python - Edge/Chrome SQLite Extracts)
echo    [S] ShimCache Execution Forensics        (Python - Historical Runs, Deleted Binaries)
echo    [T] Process Tree and Anomaly Hunter      (PowerShell - Parent-Child, Encoded Cmds)
echo    [D] Domain and Network Share Recon       (PowerShell - Kerberos, SMB Shares)
echo.
echo    --- AUTOMATION AND REMEDIATION ---
echo    [A] FULL AUTOMATED FIELD SWEEP (Run all forensic modules in automated sequence)
echo    [R] Quick Host Remediation and Hardening (Disable Guest, Fix Defender, Flush DNS)
echo    [O] Open Reports Folder in Windows Explorer
echo    [P] Setup / Repair USB Portable Python Environment
echo    [0] Exit / Pause Console
echo.
echo ==============================================================================================

set "USER_CHOICE="
set /p "USER_CHOICE=  [?] Select an option [1-9, S, T, D, A, R, O, P, 0]: "

if not defined USER_CHOICE goto MENU
set "USER_CHOICE=!USER_CHOICE: =!"

if /i "!USER_CHOICE!"=="1" goto OP_1
if /i "!USER_CHOICE!"=="2" goto OP_2
if /i "!USER_CHOICE!"=="3" goto OP_3
if /i "!USER_CHOICE!"=="4" goto OP_4
if /i "!USER_CHOICE!"=="5" goto OP_5
if /i "!USER_CHOICE!"=="6" goto OP_6
if /i "!USER_CHOICE!"=="7" goto OP_7
if /i "!USER_CHOICE!"=="8" goto OP_8
if /i "!USER_CHOICE!"=="9" goto OP_9
if /i "!USER_CHOICE!"=="S" goto OP_SHIM
if /i "!USER_CHOICE!"=="T" goto OP_TREE
if /i "!USER_CHOICE!"=="D" goto OP_DOMAIN
if /i "!USER_CHOICE!"=="A" goto OP_SWEEP
if /i "!USER_CHOICE!"=="R" goto OP_REMEDIATE
if /i "!USER_CHOICE!"=="O" goto OP_OPEN_REPORTS
if /i "!USER_CHOICE!"=="P" goto OP_SETUP_PY
if /i "!USER_CHOICE!"=="0" goto OP_EXIT
if /i "!USER_CHOICE!"=="X" goto OP_EXIT
goto MENU

:OP_1
cls
echo [*] Executing 01_Triage_Windows.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp001_Triage_Windows.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_2
cls
if "!PY_CMD!"=="" (
    echo [-] Python not detected. Running PowerShell triage fallback...
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp001_Triage_Windows.ps1"
) else (
    echo [*] Executing 02_Audit_Suite.py with !PY_CMD!...
    "!PY_CMD!" "%~dp002_Audit_Suite.py"
)
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_3
cls
echo [*] Executing 03_USB_Forensics.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp003_USB_Forensics.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_4
cls
echo [*] Executing 04_Persistence_Hunter.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp004_Persistence_Hunter.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_5
cls
echo [*] Executing 05_Volatile_Evidence.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp005_Volatile_Evidence.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_6
cls
if "!PY_CMD!"=="" (
    echo [-] Python is required for the File Hasher and IOC Scanner.
    echo [*] Run option [P] to install portable Python onto this USB.
    echo.
    set "DUMMY="
    set /p "DUMMY=  Press Enter to return to menu... "
    goto MENU
)
set "SCAN_PATH="
set /p "SCAN_PATH=  Enter folder to scan (or press Enter for Temp folder): "
if "!SCAN_PATH!"=="" (
    "!PY_CMD!" "%~dp006_File_Hasher_IOC.py"
) else (
    "!PY_CMD!" "%~dp006_File_Hasher_IOC.py" "!SCAN_PATH!"
)
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_7
cls
echo [*] Executing 07_Event_Log_Hunter.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp007_Event_Log_Hunter.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_8
cls
echo [*] Executing 08_WiFi_Forensics.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp008_WiFi_Forensics.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_9
cls
if "!PY_CMD!"=="" (
    echo [-] Python runtime required for Browser Artifacts. Run option [P] first.
    echo.
    set "DUMMY="
    set /p "DUMMY=  Press Enter to return to menu... "
    goto MENU
)
echo [*] Executing 09_Browser_Artifacts.py...
"!PY_CMD!" "%~dp009_Browser_Artifacts.py"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_SHIM
cls
if "!PY_CMD!"=="" (
    echo [-] Python runtime required for ShimCache Forensics. Run option [P] first.
    echo.
    set "DUMMY="
    set /p "DUMMY=  Press Enter to return to menu... "
    goto MENU
)
echo [*] Executing 11_ShimCache_Parser.py...
"!PY_CMD!" "%~dp011_ShimCache_Parser.py"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_TREE
cls
echo [*] Executing 12_Process_Tree_Hunter.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp012_Process_Tree_Hunter.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_DOMAIN
cls
echo [*] Executing 13_Domain_Recon.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp013_Domain_Recon.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_SWEEP
cls
echo ==============================================================================================
echo   [*] COMMENCING FULL AUTOMATED FORENSIC AND TRIAGE FIELD SWEEP
echo ==============================================================================================
echo.
echo [1/10] Running Live Host Posture Triage...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp001_Triage_Windows.ps1"
echo.
echo [2/10] Running USB Connection Forensics...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp003_USB_Forensics.ps1"
echo.
echo [3/10] Running Advanced Persistence Hunter...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp004_Persistence_Hunter.ps1"
echo.
echo [4/10] Running Volatile Memory and Session Snapshot...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp005_Volatile_Evidence.ps1"
echo.
echo [5/10] Running Windows Security Event Log Hunter...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp007_Event_Log_Hunter.ps1"
echo.
echo [6/10] Running Wi-Fi Profiles and Stored Credentials...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp008_WiFi_Forensics.ps1"
echo.
echo [7/10] Running Process Tree and Anomaly Hunter...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp012_Process_Tree_Hunter.ps1"
echo.
echo [8/10] Running Domain and Network Share Recon...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp013_Domain_Recon.ps1"
echo.
if "!PY_CMD!"=="" goto SKIP_SWEEP_PY
echo [9/10] Running Browser History and Download Artifacts...
"!PY_CMD!" "%~dp009_Browser_Artifacts.py"
echo.
echo [10/10] Running ShimCache Execution Forensics...
"!PY_CMD!" "%~dp011_ShimCache_Parser.py"
goto END_SWEEP_PY

:SKIP_SWEEP_PY
echo [9/10] Skipping Browser and ShimCache Artifacts - Python runtime not detected.

:END_SWEEP_PY
echo.
echo ==============================================================================================
echo   [+] ALL FIELD SWEEP MODULES COMPLETED SUCCESSFULLY!
echo   [+] Comprehensive reports and CSV spreadsheets saved to: %~dp0Reports\
echo ==============================================================================================
echo.
set "DUMMY="
set /p "DUMMY=  [*] SWEEP COMPLETE! Press Enter to return to the menu (or close window): "
goto MENU

:OP_REMEDIATE
cls
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp010_Quick_Remediate.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to the interactive toolkit menu... "
goto MENU

:OP_OPEN_REPORTS
explorer.exe "%~dp0Reports"
goto MENU

:OP_SETUP_PY
cls
echo [*] Launching Portable Python Installer...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0Setup_Portable_Python.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to the interactive toolkit menu... "
goto MENU

:OP_EXIT
cls
echo ==============================================================================================
echo   [*] Terminal Session Paused. Window is preserved and will NOT close.
echo       Press Enter to return to the interactive toolkit menu,
echo       or manually close this window when you are completely finished.
echo ==============================================================================================
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:: Ultimate fallback
cmd /k
