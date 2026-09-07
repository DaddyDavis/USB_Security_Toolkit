<#
.SYNOPSIS
    Real-Time Field Watch Sentinel (PowerShell)
    Continuous threat monitoring engine tracking live process creation, USB drive insertion/removal,
    and new outbound network sockets with an interactive tactical HUD.
.PARAMETER DurationSeconds
    Optional monitoring duration in seconds. Default is 0 (runs until 'Q' or Ctrl+C is pressed).
.OUTPUTS
    Interactive console visual HUD and event ledger text report in .\Reports\
#>

[CmdletBinding()]
param(
    [int]$DurationSeconds = 0
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Live_Sentinel_${env:COMPUTERNAME}_${Timestamp}.txt"
$EventLog    = [System.Collections.Generic.List[string]]::new()

function Log-Event {
    param(
        [string]$Category,
        [string]$Description,
        [string]$Severity = "INFO"
    )
    $timeStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "[$timeStr] [$Severity] [$Category] $Description"
    $EventLog.Add($logLine)

    $color = switch ($Severity) {
        "ALERT" { "Red" }
        "WARN"  { "Yellow" }
        "GOOD"  { "Green" }
        default { "Cyan" }
    }
    Write-Host "  [$timeStr] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$Category] " -NoNewline -ForegroundColor $color
    Write-Host "$Description" -ForegroundColor White
}

# Clear and draw Tactical HUD Header
Clear-Host
$banner = @"
======================================================================
  [+] LIVE FIELD SENTINEL - REAL-TIME ENDPOINT & USB WATCH MODE
======================================================================
  Host       : $env:COMPUTERNAME | User: $env:USERNAME
  Targeting  : Process Spawns, USB Storage Insertions, Outbound Sockets
  Controls   : Press [Q] to Stop and Save Forensic Event Ledger
======================================================================
"@
Write-Host $banner -ForegroundColor Cyan
Log-Event "SENTINEL" "Live Sentinel initialized on $env:COMPUTERNAME" "INFO"

# Baseline 1: Logical Disks & USB Removable Media
$knownDisks = @{}
try {
    Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        $knownDisks[$_.DeviceID] = [PSCustomObject]@{
            VolumeName = $_.VolumeName
            DriveType  = $_.DriveType
            Size       = $_.Size
        }
    }
} catch {}
Log-Event "STORAGE" "Baselined $($knownDisks.Count) mounted logical drive(s)" "INFO"

# Baseline 2: Active Processes
$knownPids = [System.Collections.Generic.HashSet[int]]::new()
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        [void]$knownPids.Add($_.ProcessId)
    }
} catch {
    Get-Process | ForEach-Object { [void]$knownPids.Add($_.Id) }
}
Log-Event "PROCESS" "Baselined $($knownPids.Count) running process instances" "INFO"

# Baseline 3: Active Outbound TCP Sockets
$knownSockets = [System.Collections.Generic.HashSet[string]]::new()
try {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])|::1)') {
            [void]$knownSockets.Add("$($_.RemoteAddress):$($_.RemotePort)")
        }
    }
} catch {}
Log-Event "NETWORK" "Baselined $($knownSockets.Count) external WAN socket(s)" "INFO"

Write-Host "`n  [*] Sentinel is actively scanning. Listening for events...`n" -ForegroundColor Green

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$running = $true

while ($running) {
    # Check exit conditions
    if ($DurationSeconds -gt 0 -and $stopwatch.Elapsed.TotalSeconds -ge $DurationSeconds) {
        Log-Event "SENTINEL" "Specified watch duration reached ($DurationSeconds seconds)." "INFO"
        break
    }

    if (-not [Console]::IsInputRedirected) {
        try {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Q -or $key.KeyChar -eq 'q') {
                    Log-Event "SENTINEL" "Operator requested shutdown (Key: Q)." "INFO"
                    break
                }
            }
        } catch {}
    }

    # 1. Audit USB & Storage Devices
    try {
        $currentDisks = @{}
        Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
            $currentDisks[$_.DeviceID] = [PSCustomObject]@{
                VolumeName = $_.VolumeName
                DriveType  = $_.DriveType
                Size       = $_.Size
            }
        }

        # Check for newly arrived drives
        foreach ($dId in $currentDisks.Keys) {
            if (-not $knownDisks.ContainsKey($dId)) {
                $disk = $currentDisks[$dId]
                $typeStr = if ($disk.DriveType -eq 2) { "REMOVABLE USB DRIVE" } else { "STORAGE VOLUME" }
                $label = if ($disk.VolumeName) { $disk.VolumeName } else { "NO_LABEL" }
                $sizeGB = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 2) } else { 0 }
                
                Log-Event "USB_ALERT" "HARDWARE INSERTION DETECTED: Drive $dId [$typeStr] Label: '$label' Size: ${sizeGB}GB" "ALERT"
                $knownDisks[$dId] = $disk
            }
        }

        # Check for removed drives
        $removedKeys = @()
        foreach ($dId in $knownDisks.Keys) {
            if (-not $currentDisks.ContainsKey($dId)) {
                Log-Event "USB_ALERT" "DEVICE REMOVED: Drive $dId was disconnected from host." "WARN"
                $removedKeys += $dId
            }
        }
        foreach ($rk in $removedKeys) { [void]$knownDisks.Remove($rk) }
    } catch {}

    # 2. Audit Process Spawns
    try {
        $currProc = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($p in $currProc) {
            if (-not $knownPids.Contains($p.ProcessId)) {
                [void]$knownPids.Add($p.ProcessId)
                
                $pName = $p.Name
                $pPath = if ($p.ExecutablePath) { $p.ExecutablePath } else { "Unknown" }
                $pCmd  = if ($p.CommandLine) { $p.CommandLine } else { "N/A" }
                $ppid  = $p.ParentProcessId

                $isSuspicious = $false
                $reasons = @()

                if ($pPath -match '(\\|\/)(Temp|AppData\\Local\\Temp)(\\|\/)') {
                    $isSuspicious = $true
                    $reasons += "Spawned from Temp"
                }
                if ($pPath -match '^[D-Z]:') {
                    $isSuspicious = $true
                    $reasons += "Executed from External Drive ($($pPath.Substring(0,2)))"
                }
                if ($pCmd -match '(-enc|-encodedcommand|downloadstring|bypass|hidden|iex)') {
                    $isSuspicious = $true
                    $reasons += "Suspicious CLI execution switches"
                }

                $sev = if ($isSuspicious) { "ALERT" } else { "INFO" }
                $detail = if ($isSuspicious) {
                    "SPAWN: $pName [PID: $($p.ProcessId) Parent: $ppid] Path: '$pPath' Flags: ($($reasons -join ', '))"
                } else {
                    "SPAWN: $pName [PID: $($p.ProcessId) Parent: $ppid] Path: '$pPath'"
                }
                Log-Event "PROCESS" $detail $sev
            }
        }
    } catch {}

    # 3. Audit Outbound Network Connections
    try {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
            $rIp   = $_.RemoteAddress
            $rPort = $_.RemotePort
            $sockKey = "$rIp`:$rPort"

            if ($rIp -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])|::1)' -and -not $knownSockets.Contains($sockKey)) {
                [void]$knownSockets.Add($sockKey)
                $ownerPid = $_.OwningProcess
                $ownerName = (Get-Process -Id $ownerPid -ErrorAction SilentlyContinue).ProcessName
                $sev = if ($rPort -in @(4444, 1337, 8888, 9001, 7070)) { "ALERT" } else { "INFO" }
                Log-Event "SOCKET" "NEW OUTBOUND WAN CONNECTION: -> $sockKey by $ownerName [PID: $ownerPid]" $sev
            }
        }
    } catch {}

    Start-Sleep -Milliseconds 1200
}

# Write final report
$reportContent = [System.Collections.Generic.List[string]]::new()
$reportContent.Add("======================================================================")
$reportContent.Add("  [+] LIVE SENTINEL FORENSIC EVENT LEDGER")
$reportContent.Add("======================================================================")
$reportContent.Add("  Host     : $env:COMPUTERNAME")
$reportContent.Add("  User     : $env:USERNAME")
$reportContent.Add("  Started  : $Timestamp")
$reportContent.Add("  Duration : $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) seconds")
$reportContent.Add("  Total Logged Events : $($EventLog.Count)")
$reportContent.Add("======================================================================`r`n")
foreach ($e in $EventLog) {
    $reportContent.Add($e)
}

[System.IO.File]::WriteAllLines($ReportFile, $reportContent, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] SENTINEL WATCH HALTED! Event ledger saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP -and -not [Console]::IsInputRedirected) { 
    try { Read-Host "  Press Enter to close window..." } catch {} 
}
