<#
.SYNOPSIS
    Field Remediation & Host Hardening Assistant (PowerShell)
    Rapidly addresses vulnerabilities discovered during audit:
    - Disables inactive/active Guest account
    - Re-enables Windows Defender Real-Time Protection
    - Flushes client DNS cache
    - Checks and restricts listening inbound ports (22, 80)
.OUTPUTS
    Console visual confirmation of remediation actions
#>

[CmdletBinding()]
param(
    [switch]$AutoAll
)

function Write-Banner {
    Clear-Host
    Write-Host "==============================================================================" -ForegroundColor Green
    Write-Host "         FIELD REMEDIATION & RAPID HOST HARDENING UTILITY                    " -ForegroundColor Yellow
    Write-Host "==============================================================================" -ForegroundColor Green
}

Write-Banner

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n  [-] ERROR: Administrative elevation required to execute host hardening!" -ForegroundColor Red
    Write-Host "      Please right-click Launch_Toolkit.bat and select 'Run as Administrator'.`n" -ForegroundColor Yellow
    pause
    exit 1
}

function Fix-GuestAccount {
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name "Guest" -ErrorAction Stop
            Write-Host "  [+] SUCCESS: Guest account has been DISABLED." -ForegroundColor Green
        } else {
            Write-Host "  [+] VERIFIED: Guest account is already disabled." -ForegroundColor Green
        }
    } catch {
        Write-Host "  [-] Failed to disable Guest account: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Fix-DefenderRealtime {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host "  [+] SUCCESS: Windows Defender Real-Time Protection re-enabled." -ForegroundColor Green
    } catch {
        Write-Host "  [-] Failed to update Defender policy: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Fix-FlushDNS {
    try {
        Clear-DnsClientCache -ErrorAction Stop
        Write-Host "  [+] SUCCESS: DNS Client Cache flushed successfully." -ForegroundColor Green
    } catch {
        Write-Host "  [-] Failed flushing DNS cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Audit-FirewallPorts {
    Write-Host "  [*] Inspecting inbound firewall rules for Port 22 (SSH) and Port 80 (HTTP)..." -ForegroundColor Cyan
    $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | Where-Object {
        $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $portFilter.LocalPort -in @('22', '80')
    }
    if ($rules) {
        foreach ($r in $rules) {
            Write-Host "      Rule: $($r.DisplayName) [Action: $($r.Action)] Profile: $($r.Profile)" -ForegroundColor Yellow
        }
        Write-Host "  [!] Notice: You can disable or restrict these rules in Windows Defender Firewall." -ForegroundColor Cyan
    } else {
        Write-Host "  [+] No active permissive inbound firewall rules for port 22/80." -ForegroundColor Green
    }
}

if ($AutoAll) {
    Write-Host "`n[*] Executing all automated hardening fixes..." -ForegroundColor Cyan
    Fix-GuestAccount
    Fix-DefenderRealtime
    Fix-FlushDNS
    Audit-FirewallPorts
    Write-Host "`n[+] Hardening sequence finished." -ForegroundColor Green
    exit 0
}

Write-Host "`n  Select remediation actions to execute:" -ForegroundColor Cyan
Write-Host "    [1] Disable Built-In Guest Account"
Write-Host "    [2] Re-Enable Windows Defender Real-Time Protection"
Write-Host "    [3] Flush DNS Client Cache"
Write-Host "    [4] Check Port 22/80 Inbound Firewall Exposure"
Write-Host "    [5] RUN ALL HARDENING ACTIONS"
Write-Host "    [0] Return to Main Menu`n"

$choice = Read-Host "  [?] Selection [1-5, 0]"

switch ($choice) {
    "1" { Fix-GuestAccount }
    "2" { Fix-DefenderRealtime }
    "3" { Fix-FlushDNS }
    "4" { Audit-FirewallPorts }
    "5" { 
        Fix-GuestAccount
        Fix-DefenderRealtime
        Fix-FlushDNS
        Audit-FirewallPorts
    }
    default { Write-Host "Returning to menu..." }
}

Write-Host "`n"
pause
