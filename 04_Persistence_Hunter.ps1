<#
.SYNOPSIS
    Advanced Persistence Hunter (Windows PowerShell)
    Audits Scheduled Tasks (non-Microsoft), Non-Standard Services, Unquoted Service Paths,
    and WMI Permanent Event Subscriptions.
.OUTPUTS
    Console visual display and plain text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Persistence_${env:COMPUTERNAME}_${Timestamp}.txt"
$ReportLines = [System.Collections.Generic.List[string]]::new()

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

# 1. Scheduled Tasks (Third-Party / Non-Microsoft)
Write-Section "PERSISTENCE: THIRD-PARTY SCHEDULED TASKS"
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
        $_.TaskPath -notmatch '^\\Microsoft\\Windows\\' -and $_.State -ne 'Disabled'
    }

    if ($tasks) {
        Write-Item "Active Non-OS Tasks" "Found $($tasks.Count) non-core scheduled tasks" "INFO"
        foreach ($t in $tasks) {
            $actions = ($t.Actions | ForEach-Object { 
                if ($_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } else { "Custom Action" }
            }) -join " ; "

            # Suspicious task checks: scripts, staging paths
            $isSus = if ($actions -match '(\.vbs|\.ps1|\.bat|\.cmd|powershell|cmd\.exe|wscript|cscript|temp|appdata|public)') { "ALERT" } else { "WARN" }

            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "Task Name" "$($t.TaskPath)$($t.TaskName)" $isSus
            Write-Item "State" "$($t.State)" "INFO"
            Write-Item "Action Executed" "$actions" $isSus
        }
    } else {
        Write-Item "Scheduled Tasks" "No active third-party scheduled tasks discovered." "GOOD"
    }
} catch {
    Write-Item "Scheduled Tasks" "Error enumerating scheduled tasks: $($_.Exception.Message)" "WARN"
}

# 2. Windows Services (Non-System32 & Staging Folders)
Write-Section "PERSISTENCE: HIGH-RISK & NON-SYSTEM32 SERVICES"
try {
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    $susServices = @()
    $unquotedServices = @()

    foreach ($s in $services) {
        if (-not $s.PathName) { continue }
        $cleanPath = $s.PathName.Trim()

        # Check for Unquoted Service Paths with spaces (Privilege Escalation CWE-428 / MITRE T1574.009)
        if ($cleanPath -notmatch '^"' -and $cleanPath -match '\.exe' -and $cleanPath.Split('.exe')[0] -match '\s') {
            $unquotedServices += [PSCustomObject]@{
                Name = $s.Name
                DisplayName = $s.DisplayName
                PathName = $cleanPath
                StartMode = $s.StartMode
            }
        }

        # Check for service running from user profile, Temp, ProgramData, or Downloads
        if ($cleanPath -match '(\\Users\\|\\Temp\\|\\AppData\\|\\ProgramData\\|\\Public\\)') {
            $susServices += [PSCustomObject]@{
                Name = $s.Name
                DisplayName = $s.DisplayName
                PathName = $cleanPath
                State = $s.State
                StartMode = $s.StartMode
            }
        }
    }

    if ($susServices.Count -gt 0) {
        Write-Item "Staged Services" "Found $($susServices.Count) service(s) executing from user/staging locations!" "ALERT"
        foreach ($ss in $susServices) {
            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "Service Name" "$($ss.Name) ($($ss.DisplayName))" "ALERT"
            Write-Item "Executable" "$($ss.PathName)" "ALERT"
            Write-Item "Run Status" "$($ss.State) [Mode: $($ss.StartMode)]" "INFO"
        }
    } else {
        Write-Item "Staged Services" "No services found running from user directories or Temp." "GOOD"
    }

    # Unquoted Service Path Vulnerabilities
    Write-Host "`n"
    if ($unquotedServices.Count -gt 0) {
        Write-Item "Unquoted Service Paths" "Found $($unquotedServices.Count) service(s) vulnerable to unquoted path hijacking (T1574.009)" "ALERT"
        foreach ($us in $unquotedServices) {
            Write-Item "Vulnerable Service" "$($us.Name) -> $($us.PathName)" "WARN"
        }
    } else {
        Write-Item "Unquoted Service Paths" "No vulnerable unquoted service binary paths detected." "GOOD"
    }
} catch {
    Write-Item "Service Audit" "Failed to audit Win32_Service: $($_.Exception.Message)" "WARN"
}

# 3. WMI Permanent Event Subscriptions (Fileless Persistence)
Write-Section "PERSISTENCE: WMI PERMANENT EVENT CONSUMERS & BINDINGS"
try {
    $filters = Get-CimInstance -Namespace "root\subscription" -ClassName "__EventFilter" -ErrorAction SilentlyContinue
    $consumers = Get-CimInstance -Namespace "root\subscription" -ClassName "__EventConsumer" -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace "root\subscription" -ClassName "__FilterToConsumerBinding" -ErrorAction SilentlyContinue

    if ($bindings) {
        Write-Item "WMI Persistence" "ACTIVE WMI EVENT BINDINGS DETECTED!" "ALERT"
        foreach ($b in $bindings) {
            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "Binding Filter" "$($b.Filter)" "ALERT"
            Write-Item "Binding Consumer" "$($b.Consumer)" "ALERT"
        }
    } else {
        Write-Item "WMI Event Bindings" "Clean (No permanent WMI consumer bindings found)." "GOOD"
    }

    if ($consumers) {
        foreach ($c in $consumers) {
            $cmd = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptText) { $c.ScriptText } else { "N/A" }
            Write-Item "WMI Consumer" "$($c.Name) -> $cmd" "WARN"
        }
    }
} catch {
    Write-Item "WMI Audit" "Could not query root\subscription namespace (Requires elevation)." "WARN"
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] PERSISTENCE AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
