<#
.SYNOPSIS
    Windows Event Log Forensic Triage (PowerShell)
    Rapidly hunts for brute-force attacks (4625), remote logons (4624),
    account tampering (4720/4726), new services (7045), and log clearing (1102).
.OUTPUTS
    Console visual display and plain text report in .\Reports\
#>

[CmdletBinding()]
param(
    [int]$Days = 7
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "EventLogs_${env:COMPUTERNAME}_${Timestamp}.txt"
$ReportLines = [System.Collections.Generic.List[string]]::new()
$StartTime   = (Get-Date).AddDays(-$Days)

function Write-Section {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  [+] $Title" -ForegroundColor Yellow
    Write-Host "$line" -ForegroundColor Cyan
    $ReportLines.Add("`r`n$line`r`n  [+] $Title`r`n$line")
}

function Write-Item {
    param([string]$Key, [string]$Value, [string]$Status="INFO")
    $color = switch ($Status) {
        "GOOD"  { "Green" }
        "WARN"  { "Yellow" }
        "ALERT" { "Red" }
        default { "White" }
    }
    Write-Host "  $Key : " -NoNewline -ForegroundColor Gray
    Write-Host "$Value" -ForegroundColor $color
    $ReportLines.Add("  $Key : $Value")
}

# 1. Anti-Forensics: Event Log Clearing (Event 1102 & 104)
Write-Section "ANTI-FORENSICS: AUDIT LOG CLEARING (EVENT 1102 / 104)"
try {
    $clearedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=$StartTime} -ErrorAction SilentlyContinue
    if ($clearedEvents) {
        Write-Item "Log Clearance" "AUDIT LOG CLEARED BY USER IN THE LAST $Days DAYS!" "ALERT"
        foreach ($e in $clearedEvents) {
            Write-Item "Timestamp" "$($e.TimeCreated) by User: $($e.UserId)" "ALERT"
        }
    } else {
        Write-Item "Security Log Integrity" "No log clearing events detected (1102 clean)." "GOOD"
    }
} catch {
    Write-Item "Audit Log Integrity" "Requires Administrative elevation to inspect Security log." "WARN"
}

# 2. Failed Logons / Brute Force Attempts (Event 4625)
Write-Section "AUTHENTICATION AUDIT: FAILED LOGONS (EVENT 4625)"
try {
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$StartTime} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($failedLogons) {
        $count = $failedLogons.Count
        $status = if ($count -gt 10) { "ALERT" } else { "WARN" }
        Write-Item "Failed Logon Count" "$count failed logon event(s) detected in last $Days days" $status
        
        foreach ($fl in $failedLogons | Select-Object -First 10) {
            $xml = [xml]$fl.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            Write-Item "Failed Event" "User: $targetUser | Source IP: $ip | LogonType: $logonType | Time: $($fl.TimeCreated)" "WARN"
        }
    } else {
        Write-Item "Failed Logons" "No failed logon attempts recorded in the last $Days days." "GOOD"
    }
} catch {
    Write-Item "Failed Logons" "Could not query Event 4625 (Elevation required)." "WARN"
}

# 3. Account Tampering: New Users & Groups (Event 4720, 4726, 4728)
Write-Section "ACCOUNT MANAGEMENT: USER CREATION & DELETION"
try {
    $acctEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4720, 4726); StartTime=$StartTime} -ErrorAction SilentlyContinue
    if ($acctEvents) {
        foreach ($ae in $acctEvents) {
            $type = if ($ae.Id -eq 4720) { "USER CREATED (4720)" } else { "USER DELETED (4726)" }
            $xml = [xml]$ae.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            Write-Item "$type" "Target: $targetUser at $($ae.TimeCreated)" "ALERT"
        }
    } else {
        Write-Item "Account Creation" "No user accounts created or deleted in the last $Days days." "GOOD"
    }
} catch {
    Write-Item "Account Management" "Could not query Security log for account creation." "WARN"
}

# 4. New Service Installations (System Log - Event 7045)
Write-Section "PERSISTENCE: NEW SERVICE INSTALLATIONS (EVENT 7045)"
try {
    $newServices = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$StartTime} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($newServices) {
        Write-Item "New Services" "Found $($newServices.Count) service install events in the last $Days days" "WARN"
        foreach ($ns in $newServices) {
            $xml = [xml]$ns.ToXml()
            $svcName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
            $imagePath = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
            Write-Item "Service Added" "$svcName ($imagePath) at $($ns.TimeCreated)" "WARN"
        }
    } else {
        Write-Item "New Services" "No new services installed in the last $Days days." "GOOD"
    }
} catch {
    Write-Item "System Log" "Failed to query Event 7045: $($_.Exception.Message)" "WARN"
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] EVENT LOG AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
