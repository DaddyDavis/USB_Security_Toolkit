@echo off
setlocal
cd /d "%~dp0"
title USB Live Windows Triage (PowerShell)
color 0A

echo =======================================================
echo   Launching USB Windows Triage (Native PowerShell)...
echo =======================================================

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp001_Triage_Windows.ps1"

echo.
echo =======================================================
echo   Execution complete. Window kept open.
echo =======================================================
pause
cmd /k
