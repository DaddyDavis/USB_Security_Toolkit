<#
.SYNOPSIS
    Network Beaconing & C2 Socket Threat Hunter (PowerShell)
    Audits live outbound sockets and listening endpoints for Command & Control (C2)
    framework ports, dynamic DNS indicators, unverified process owners, and reverse-DNS anomalies.
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Beacon_Hunter_${env:COMPUTERNAME}_${Timestamp}.txt"
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

Write-Section "NETWORK BEACONING & C2 FRAMEWORK SOCKET INSPECTION"

# Common C2 Framework Default Ports (Metasploit, Cobalt Strike, Mythic, Sliver, Havoc)
$c2Ports = @(4444, 1337, 8888, 7070, 9001, 9999, 31337, 6667, 8088, 8848, 50050, 4443)

# Suspicious TLD / Dynamic DNS patterns
$suspiciousDomainPatterns = '(\.xyz|\.top|\.tk|\.cc|\.ru|\.su|\.onion|\.biz|ngrok|duckdns|no-ip|trycloudflare)'

$tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$procCache = @{ 0 = [PSCustomObject]@{ Name = "Idle"; Path = "System" }; 4 = [PSCustomObject]@{ Name = "System"; Path = "System" } }
$dnsCache  = @{}
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $procCache[$_.ProcessId] = [PSCustomObject]@{
            Name = $_.Name
            Path = if ($_.ExecutablePath) { $_.ExecutablePath } else { "System/Protected" }
        }
    }
} catch {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { 
        $procCache[$_.Id] = [PSCustomObject]@{ Name = $_.ProcessName; Path = "Unknown" }
    }
}


$suspiciousSockets = [System.Collections.Generic.List[PSCustomObject]]::new()
$externalSockets   = [System.Collections.Generic.List[PSCustomObject]]::new()
$listeningServices = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($conn in $tcpConnections) {
    $remoteIp = $conn.RemoteAddress
    $remotePort = $conn.RemotePort
    $localIp = $conn.LocalAddress
    $localPort = $conn.LocalPort
    $pidNum = $conn.OwningProcess
    $state = $conn.State

    # Skip loopback & link-local
    if ($remoteIp -in @('0.0.0.0', '127.0.0.1', '::', '::1') -and $state -ne "Listen") { continue }
    if ($remoteIp -match '^(169\.254\.|fe80:)') { continue }

    $procName = if ($procCache.ContainsKey($pidNum)) { $procCache[$pidNum].Name } else { "Exited" }
    $procPath = if ($procCache.ContainsKey($pidNum)) { 
        try { $procCache[$pidNum].Path } catch { "System/Protected" } 
    } else { "Unknown" }

    # Track External Listening Ports
    if ($state -eq "Listen" -and ($localIp -in @('0.0.0.0', '::', '::1') -or $localIp -match '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))')) {
        $listeningServices.Add([PSCustomObject]@{
            LocalPort = $localPort
            LocalIp   = $localIp
            PID       = $pidNum
            Process   = $procName
            Path      = $procPath
        })
    }

    # Track Active Outbound Connections
    if ($state -eq "Established" -and $remoteIp -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])|::1)') {
        # Perform non-blocking reverse DNS lookup with strict 400ms timeout
        $hostname = $remoteIp
        if ($dnsCache.ContainsKey($remoteIp)) {
            $hostname = $dnsCache[$remoteIp]
        } else {
            try {
                $dnsTask = [System.Net.Dns]::GetHostEntryAsync($remoteIp)
                if ($dnsTask.Wait(400)) {
                    $hostname = $dnsTask.Result.HostName
                }
            } catch {}
            $dnsCache[$remoteIp] = $hostname
        }

        $entry = [PSCustomObject]@{
            Process    = $procName
            PID        = $pidNum
            Path       = $procPath
            RemoteIp   = $remoteIp
            RemotePort = $remotePort
            HostName   = $hostname
            State      = $state
        }
        $externalSockets.Add($entry)

        # Flag known C2 ports or suspicious domains
        $isC2Port = ($remotePort -in $c2Ports)
        $isSuspiciousDomain = ($hostname -match $suspiciousDomainPatterns)
        $isUnverifiedBin = ($procPath -match '(\\temp\\|\\appdata\\local\\temp|\.tmp$)')

        if ($isC2Port -or $isSuspiciousDomain -or $isUnverifiedBin) {
            $flagReason = if ($isC2Port) { "Standard C2 Framework Port ($remotePort)" } elseif ($isSuspiciousDomain) { "Suspicious Dynamic DNS / TLD ($hostname)" } else { "Socket from Unverified Temp Binary" }
            $entry | Add-Member -NotePropertyName "FlagReason" -NotePropertyValue $flagReason
            $suspiciousSockets.Add($entry)
        }
    }
}


# Section 1: Active External Connections
Write-Section "ACTIVE EXTERNAL INTERNET CONNECTIONS"
Write-Item "Total Active Outbound Sockets" "$($externalSockets.Count) established WAN connection(s)" "INFO"
foreach ($s in ($externalSockets | Select-Object -First 15)) {
    Write-Item "$($s.Process) [PID: $($s.PID)]" "-> $($s.HostName):$($s.RemotePort)" "INFO"
}

# Section 2: Flagged C2 & Suspicious Sockets
Write-Section "C2 & SUSPICIOUS BEACONING ANOMALIES"
if ($suspiciousSockets.Count -gt 0) {
    Write-Item "C2 Indicator Alerts" "DETECTED $($suspiciousSockets.Count) SUSPICIOUS NETWORK SOCKET(S)!" "ALERT"
    foreach ($ss in $suspiciousSockets) {
        Write-Item "Alert Type" "$($ss.FlagReason)" "ALERT"
        Write-Item "Process" "$($ss.Process) [PID: $($ss.PID)] at $($ss.Path)" "WARN"
        Write-Item "Destination" "$($ss.RemoteIp):$($ss.RemotePort) ($($ss.HostName))" "ALERT"
    }
} else {
    Write-Item "C2 Beacon Inspection" "Clean (Zero established sockets to known C2 ports or dynamic DNS hosts)." "GOOD"
}

# Section 3: External Listening Services
Write-Section "EXTERNAL LISTENING SERVICES (ATTACK SURFACE)"
$uniqueListeners = $listeningServices | Sort-Object LocalPort -Unique
foreach ($ls in ($uniqueListeners | Select-Object -First 15)) {
    $status = if ($ls.LocalPort -in @(22, 80, 445, 3389)) { "WARN" } else { "INFO" }
    Write-Item "Port $($ls.LocalPort)" "Bound to $($ls.LocalIp) -> $($ls.Process) [PID: $($ls.PID)]" $status
}

# Flush report buffer
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] BEACONING AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP -and -not [Console]::IsInputRedirected) { 
    try { Read-Host "`n  Press Enter to close window..." } catch {} 
}
