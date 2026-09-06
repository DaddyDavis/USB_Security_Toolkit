@echo off
setlocal
cd /d "%~dp0"
title USB Security Audit Suite (Python)
color 0A

echo =======================================================
echo   Launching USB Security Audit Suite...
echo =======================================================

if exist "%~dp0python_embed\python.exe" (
    echo [*] Using USB Portable Python Engine...
    "%~dp0python_embed\python.exe" "%~dp002_Audit_Suite.py"
    goto END
)

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [*] Using Host System Python...
    python "%~dp002_Audit_Suite.py"
    goto END
)

echo [-] No portable or system Python detected!
echo [*] Launching Native PowerShell Auditor fallback...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp001_Triage_Windows.ps1"

:END
echo.
echo =======================================================
echo   Execution complete. Window kept open.
echo =======================================================
pause
cmd /k
