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
echo    __  _______ ____     _____ ______ ______  ______  __________________  __
echo   / / / / ___// __ )   / ___// ____// ____/ / / / / / / / __ \_  __/\ \/ /
echo  / / / /\__ \/ __  /   \__ \/ __/  / /     / / / / / / / /_/ // /    \  / 
echo / /_/ /___/ / /_/ /   ___/ / /___ / /___  / /_/ / /_/ / _, _// /     / /  
echo  \____//____/_____/   /____/_____/ \____/  \____/\____/_/ ^|_^|/_/     /_/   
echo.
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
echo    [F] Prefetch Execution Forensics         (PowerShell - MAM Decompress, Run Counts)
echo    [E] Defense Evasion and Tampering Hunter (PowerShell - Defender, Firewall, Logging)
echo    [B] BAM/DAM User Execution Forensics     (PowerShell - Per-User Registry Ledgers)
echo    [C] Network Beacon and C2 Socket Hunter  (PowerShell - WAN Sockets, Port Audits)
echo    [U] User Activity and Removable Media    (PowerShell - LNKs, JumpLists, USB Trails)
echo    [W] Live Field Sentinel Watch Mode       (PowerShell - Real-Time Process and USB HUD)
echo    [Z] Automated SOC Analyst Briefing       (Python - Threat Scoring and Remediation)
echo    [H] Generate Executive HTML Report       (Python - Unified Threat Dashboard)
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
set /p "USER_CHOICE=  [?] Select an option [1-9, S, T, D, F, E, B, C, U, W, Z, H, A, R, O, P, 0]: "

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
if /i "!USER_CHOICE!"=="F" goto OP_PREFETCH
if /i "!USER_CHOICE!"=="E" goto OP_DEFENSE
if /i "!USER_CHOICE!"=="B" goto OP_BAM
if /i "!USER_CHOICE!"=="C" goto OP_BEACON
if /i "!USER_CHOICE!"=="U" goto OP_USERACT
if /i "!USER_CHOICE!"=="W" goto OP_SENTINEL
if /i "!USER_CHOICE!"=="Z" goto OP_ANALYZE
if /i "!USER_CHOICE!"=="H" goto OP_HTML
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

:OP_PREFETCH
cls
echo [*] Executing 14_Prefetch_Hunter.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp014_Prefetch_Hunter.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_DEFENSE
cls
echo [*] Executing 15_Defense_Evasion.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp015_Defense_Evasion.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_BAM
cls
echo [*] Executing 16_BAM_Hunter.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp016_BAM_Hunter.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_BEACON
cls
echo [*] Executing 17_Beacon_Hunter.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp017_Beacon_Hunter.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_USERACT
cls
echo [*] Executing 18_User_Activity.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp018_User_Activity.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_SENTINEL
cls
echo [*] Executing 19_Live_Sentinel.ps1...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp019_Live_Sentinel.ps1"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_ANALYZE
cls
if "!PY_CMD!"=="" (
    where python >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "PY_CMD=python"
    ) else (
        echo [-] Python runtime required for Automated Threat Analyst. Run option [P] first.
        echo.
        set "DUMMY="
        set /p "DUMMY=  Press Enter to return to menu... "
        goto MENU
    )
)
echo [*] Executing Automated DFIR SOC Analyst Engine with !PY_CMD!...
"!PY_CMD!" "%~dp0Analyze_Reports.py"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_HTML
cls
if "!PY_CMD!"=="" (
    where python >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "PY_CMD=python"
    ) else (
        echo [-] Python runtime required to compile HTML dashboard. Run option [P] first.
        echo.
        set "DUMMY="
        set /p "DUMMY=  Press Enter to return to menu... "
        goto MENU
    )
)
echo [*] Compiling unified executive HTML dashboard with !PY_CMD!...
"!PY_CMD!" "%~dp0Generate_HTML_Report.py"
echo.
set "DUMMY="
set /p "DUMMY=  Press Enter to return to menu... "
goto MENU

:OP_SWEEP
cls
echo ==============================================================================================
echo   [*] COMMENCING FULL AUTOMATED FORENSIC AND TRIAGE FIELD SWEEP
echo   [*] Note: 19_Live_Sentinel and 10_Quick_Remediate are interactive and excluded from sweep.
echo ==============================================================================================
echo.
set "SWEEP_FAILS=0"

echo [1/15] Running Live Host Posture Triage...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp001_Triage_Windows.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 01_Triage_Windows returned error code !ERRORLEVEL! )
echo.

echo [2/15] Running USB Connection Forensics...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp003_USB_Forensics.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 03_USB_Forensics returned error code !ERRORLEVEL! )
echo.

echo [3/15] Running Advanced Persistence Hunter...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp004_Persistence_Hunter.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 04_Persistence_Hunter returned error code !ERRORLEVEL! )
echo.

echo [4/15] Running Volatile Memory and Session Snapshot...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp005_Volatile_Evidence.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 05_Volatile_Evidence returned error code !ERRORLEVEL! )
echo.

echo [5/15] Running Windows Security Event Log Hunter...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp007_Event_Log_Hunter.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 07_Event_Log_Hunter returned error code !ERRORLEVEL! )
echo.

echo [6/15] Running Wi-Fi Profiles and Stored Credentials (REDACTED OPSEC MODE)...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp008_WiFi_Forensics.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 08_WiFi_Forensics returned error code !ERRORLEVEL! )
echo.

echo [7/15] Running Process Tree and Anomaly Hunter...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp012_Process_Tree_Hunter.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 12_Process_Tree_Hunter returned error code !ERRORLEVEL! )
echo.

echo [8/15] Running Domain and Network Share Recon...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp013_Domain_Recon.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 13_Domain_Recon returned error code !ERRORLEVEL! )
echo.

echo [9/15] Running Prefetch Execution Forensics...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp014_Prefetch_Hunter.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 14_Prefetch_Hunter returned error code !ERRORLEVEL! )
echo.

echo [10/15] Running Defense Evasion and Tampering Audit...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp015_Defense_Evasion.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 15_Defense_Evasion returned error code !ERRORLEVEL! )
echo.

echo [11/15] Running BAM/DAM User Execution Forensics...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp016_BAM_Hunter.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 16_BAM_Hunter returned error code !ERRORLEVEL! )
echo.

echo [12/15] Running Network Beaconing and C2 Socket Audit...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp017_Beacon_Hunter.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 17_Beacon_Hunter returned error code !ERRORLEVEL! )
echo.

echo [13/15] Running User Activity and Removable Media Footprints...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp018_User_Activity.ps1"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 & echo [!] WARNING: 18_User_Activity returned error code !ERRORLEVEL! )
echo.

if "!PY_CMD!"=="" goto SKIP_SWEEP_PY
echo [14/15] Running Browser Artifacts, ShimCache Parser, and File Hasher / IOC Matcher...
"!PY_CMD!" "%~dp009_Browser_Artifacts.py"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 )
"!PY_CMD!" "%~dp011_ShimCache_Parser.py"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 )
"!PY_CMD!" "%~dp006_File_Hasher_IOC.py"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 )
echo.

echo [15/15] Running Automated Threat Analyst Engine & Executive HTML Dashboard...
"!PY_CMD!" "%~dp0Analyze_Reports.py"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 )
"!PY_CMD!" "%~dp0Generate_HTML_Report.py"
if !ERRORLEVEL! neq 0 ( set /a SWEEP_FAILS+=1 )
goto END_SWEEP_PY

:SKIP_SWEEP_PY
echo [!] Skipping Python modules (06_Hasher, 09_Browser, 11_ShimCache, Analyze, HTML) - Python not detected.

:END_SWEEP_PY
echo.
echo ==============================================================================================
if !SWEEP_FAILS! equ 0 (
    echo   [+] ALL FIELD SWEEP MODULES COMPLETED SUCCESSFULLY WITH 0 FAILURES!
) else (
    echo   [!] SWEEP FINISHED WITH !SWEEP_FAILS! MODULE ERRORS - CHECK LOGS ABOVE.
)
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
echo   [*] Exiting USB Security Toolkit Console. Stay safe!
echo ==============================================================================================
exit /b 0
