<#
.SYNOPSIS
    Volatile Incident Response & Network Artifacts Collector (Windows PowerShell)
    Captures live volatile state: DNS cache, ARP table, active connections,
    logged-in sessions, and recently accessed files.
.OUTPUTS
    Console visual display and plain text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Volatile_Evidence_${env:COMPUTERNAME}_${Timestamp}.txt"
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

# 1. DNS Client Cache (Recently Queried Hostnames & C2 Beacons)
Write-Section "VOLATILE TELEMETRY: CLIENT DNS CACHE"
try {
    $dnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { 
        $_.Entry -notmatch '(\.local|\.arpa|localhost|msftconnecttest)' 
    } | Sort-Object -Property Entry -Unique

    if ($dnsEntries) {
        Write-Item "DNS Cache Count" "Captured $($dnsEntries.Count) unique resolved domains" "INFO"
        foreach ($d in $dnsEntries | Select-Object -First 40) {
            $recordData = if ($d.Data) { $d.Data } else { "Type $($d.Type)" }
            $status = if ($d.Entry -match '(\.ru|\.xyz|\.top|\.tk|\.cn|ngrok|duckdns|no-ip)') { "ALERT" } else { "INFO" }
            Write-Item "DNS Entry" "$($d.Entry) -> $recordData" $status
        }
        if ($dnsEntries.Count -gt 40) {
            Write-Item "DNS Truncated" "Displaying top 40 in console; all $($dnsEntries.Count) saved to report." "WARN"
            foreach ($d in $dnsEntries | Select-Object -Skip 40) {
                $ReportLines.Add("  DNS Entry : $($d.Entry) -> $($d.Data)")
            }
        }
    } else {
        Write-Item "DNS Cache" "Cache is empty or flushed." "GOOD"
    }
} catch {
    Write-Item "DNS Cache" "Failed to retrieve DNS cache: $($_.Exception.Message)" "WARN"
}

# 2. Local Network Neighbors (ARP Table)
Write-Section "NETWORK TELEMETRY: ARP NEIGHBOR TABLE"
try {
    $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.State -in @('Reachable', 'Permanent', 'Stale') -and $_.IPAddress -notmatch '^(224\.|239\.|255\.)'
    }

    if ($neighbors) {
        foreach ($n in $neighbors) {
            Write-Item "Subnet Node" "$($n.IPAddress) [MAC: $($n.LinkLayerAddress)] State: $($n.State)" "INFO"
        }
    } else {
        $arp = arp.exe -a
        foreach ($line in $arp) {
            if ($line.Trim() -and $line -notmatch 'Interface:') {
                Write-Item "ARP Node" "$($line.Trim())" "INFO"
            }
        }
    }
} catch {
    Write-Item "ARP Neighbors" "Unable to query network neighbors." "WARN"
}

# 3. Active Established Outbound/Inbound Connections
Write-Section "ACTIVE ESTABLISHED TCP SESSIONS & PROCESS MAPPING"
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $procCache = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procCache[$_.Id] = $_.ProcessName }

    if ($conns) {
        foreach ($c in $conns) {
            # Skip loopback to loopback noise
            if ($c.RemoteAddress -eq '127.0.0.1' -or $c.RemoteAddress -eq '::1') { continue }
            $pName = if ($procCache.ContainsKey($c.OwningProcess)) { $procCache[$c.OwningProcess] } else { 
                try { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { "System/Protected" }
            }
            if (-not $pName) { $pName = "System/Protected" }
            $danger = if ($c.RemotePort -in 4444, 1337, 8888, 6667, 3389) { "ALERT" } else { "INFO" }
            Write-Item "Established" "$($c.LocalAddress):$($c.LocalPort) <-> $($c.RemoteAddress):$($c.RemotePort) [PID: $($c.OwningProcess) - $pName]" $danger
        }
    } else {
        Write-Item "Active Sockets" "No non-loopback established TCP connections." "INFO"
    }
} catch {
    Write-Item "Active Sockets" "Failed to enumerate established connections." "WARN"
}

# 4. Interactive & Remote User Sessions
Write-Section "ACTIVE USER SESSIONS & LOGONS"
try {
    $hasQuser = Get-Command "quser.exe" -ErrorAction SilentlyContinue
    if ($hasQuser) {
        $quserOutput = & $hasQuser 2>&1
        foreach ($line in ($quserOutput | Out-String).Trim().Split("`n")) {
            if ($line.Trim()) {
                Write-Item "User Session" "$($line.Trim())" "INFO"
            }
        }
    } else {
        # Universal fallback for Windows Home/Core: Win32_LogonSession & Win32_LoggedOnUser
        $logonSessions = Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue | Where-Object {
            $_.LogonType -in 2, 10 # 2 = Interactive (Console), 10 = RemoteInteractive (RDP)
        }
        if ($logonSessions) {
            foreach ($ls in $logonSessions) {
                $typeStr = switch ($ls.LogonType) {
                    2  { "Interactive (Local Console)" }
                    10 { "RemoteInteractive (RDP Session)" }
                    default { "Type $($ls.LogonType)" }
                }
                Write-Item "Logon Session" "ID: $($ls.LogonId) | $typeStr | Started: $($ls.StartTime)" "INFO"
            }
        } else {
            Write-Item "Active Sessions" "$env:USERDOMAIN\$env:USERNAME (Current interactive logon)" "INFO"
        }
    }
} catch {
    Write-Item "User Sessions" "Unable to enumerate sessions: $($_.Exception.Message)" "WARN"
}

# 5. Recent File Execution Artifacts (Shell Recent Folder)
Write-Section "RECENT USER ACTIVITY: RECENTLY ACCESSED ARTIFACTS"
$recentFolder = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Recent")
if (Test-Path $recentFolder) {
    $recentFiles = Get-ChildItem -Path $recentFolder -File -ErrorAction SilentlyContinue | 
        Sort-Object -Property LastWriteTime -Descending | Select-Object -First 15
    
    if ($recentFiles) {
        foreach ($rf in $recentFiles) {
            Write-Item "Recent File" "$($rf.Name) (Modified: $($rf.LastWriteTime))" "INFO"
        }
    } else {
        Write-Item "Recent Items" "Recent directory is empty." "GOOD"
    }
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] VOLATILE SNAPSHOT COMPLETE! Telemetry written to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
