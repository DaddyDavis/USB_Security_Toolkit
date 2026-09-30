<#
.SYNOPSIS
    USB Live Triage & Security Audit Script (Native Windows PowerShell)
    Designed for zero-dependency, read-only field inspections.
.OUTPUTS
    Writes colored output to console and saves report to .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Triage_${env:COMPUTERNAME}_${Timestamp}.txt"
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
        "GOOD" { "Green" }
        "WARN" { "Yellow" }
        "ALERT" { "Red" }
        default { "White" }
    }
    Write-Host "  $Key : " -NoNewline -ForegroundColor Gray
    Write-Host "$Value" -ForegroundColor $color
    $ReportLines.Add("  $Key : $Value")
}

# Start Triage Logging
Write-Section "HOST IDENTITY & PRIVILEGE POSTURE"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Item "Execution Privilege" "ELEVATED (High Integrity / Administrator)" "GOOD"
} else {
    Write-Item "Execution Privilege" "LIMITED (Standard User / Medium Integrity Token)" "WARN"
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Item "Computer Name" $env:COMPUTERNAME
Write-Item "Current User" "$env:USERDOMAIN\$env:USERNAME"
Write-Item "OS Version" "$($os.Caption) (Build $($os.BuildNumber))"
Write-Item "Architecture" $os.OSArchitecture
Write-Item "Last Boot Time" "$($os.LastBootUpTime)"

# Defensive Posture & Antivirus
Write-Section "DEFENSIVE POSTURE & ANTIVIRUS TELEMETRY"

# Authoritative Defender Status via Get-MpComputerStatus
$mpChecked = $false
try {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $mpChecked = $true
        $rtpEnabled = $mp.RealTimeProtectionEnabled -eq $true
        $rtStatus = if ($rtpEnabled) { "GOOD" } else { "ALERT" }
        Write-Item "Antivirus Engine" "Microsoft Defender Antivirus (Mode: $($mp.AMRunningMode))" "INFO"
        Write-Item "Real-Time Protection" $(if ($rtpEnabled) { "ENABLED (Active Telemetry)" } else { "DISABLED / TAMPERED" }) $rtStatus
        Write-Item "Engine Version" "$($mp.AMEngineVersion)" "INFO"

        if ($mp.AntivirusSignatureLastUpdated) {
            $sigAge = (New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).Days
            $sigStatus = if ($sigAge -le 3) { "GOOD" } elseif ($sigAge -le 7) { "WARN" } else { "ALERT" }
            Write-Item "Signatures Updated" "$($mp.AntivirusSignatureLastUpdated) ($sigAge days old)" $sigStatus
        }
    }
} catch {}

# Secondary / Third-Party SecurityCenter2 Telemetry
try {
    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntivirusProduct" -ErrorAction SilentlyContinue
    if ($avProducts) {
        foreach ($av in $avProducts) {
            if (-not $mpChecked -or $av.displayName -notmatch "Windows Defender") {
                $hex = "{0:X6}" -f [int]$av.productState
                $scannerByte = $hex.Substring(2, 2)
                $realtime = if ($scannerByte -in "10", "11") { "ENABLED" } else { "DISABLED/SUSPENDED" }
                $rtStatus = if ($realtime -eq "ENABLED") { "GOOD" } else { "ALERT" }
                Write-Item "Third-Party AV" "$($av.displayName)" "INFO"
                Write-Item "Protection Status" "$realtime (State: 0x$hex)" $rtStatus
            }
        }
    }
} catch {
    Write-Item "Antivirus WMI" "Unable to query SecurityCenter2 (May require elevation or Server OS)" "WARN"
}


# BitLocker & Drive Encryption
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bl) {
        $blStatus = if ($bl.ProtectionStatus -eq "On") { "GOOD" } else { "ALERT" }
        Write-Item "C: Encryption (BitLocker)" "$($bl.ProtectionStatus) ($($bl.VolumeStatus))" $blStatus
    }
} catch {}

# Firewall Status
Write-Section "FIREWALL PROFILES"
try {
    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($fw) {
        foreach ($p in $fw) {
            $fwStat = if ($p.Enabled -eq $true) { "GOOD" } else { "ALERT" }
            Write-Item "$($p.Name) Profile" $(if ($p.Enabled) { "ENABLED" } else { "DISABLED" }) $fwStat
        }
    }
} catch {}

# Account Hygiene
Write-Section "LOCAL ACCOUNT HYGIENE"
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    foreach ($admin in $admins) {
        Write-Item "Local Administrator" "$($admin.Name) (Principal: $($admin.ObjectClass))" "WARN"
    }

    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest) {
        $gStat = if ($guest.Enabled) { "ALERT" } else { "GOOD" }
        Write-Item "Guest Account" $(if ($guest.Enabled) { "ACTIVE (High Risk!)" } else { "DISABLED" }) $gStat
    }
} catch {
    Write-Item "Local Accounts" "Requires administrative elevation to enumerate local accounts." "WARN"
}

# Network Exposure (Listening Ports)
Write-Section "LISTENING TCP PORTS & OWNING PROCESSES"
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object -Property LocalPort
    $procCache = @{}
    Get-Process | ForEach-Object { $procCache[$_.Id] = $_.ProcessName }

    foreach ($conn in $listeners) {
        $pName = if ($procCache.ContainsKey($conn.OwningProcess)) { $procCache[$conn.OwningProcess] } else { "Unknown" }
        $danger = if ($conn.LocalPort -in 445, 3389, 5985, 22, 23, 21) { "ALERT" } else { "INFO" }
        Write-Item "Port $($conn.LocalPort)" "$($conn.LocalAddress):$($conn.LocalPort) -> [PID: $($conn.OwningProcess)] $pName" $danger
    }
} catch {
    Write-Item "Network Listeners" "Failed to enumerate network listeners." "WARN"
}

# Persistence - Registry Run Keys
Write-Section "PERSISTENCE: REGISTRY AUTORUN KEYS"
$runPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($rp in $runPaths) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        $names = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS.*' }
        foreach ($item in $names) {
            Write-Item "Autorun ($rp)" "$($item.Name) = $($item.Value)" "WARN"
        }
    }
}

# Persistence - Startup Folders
Write-Section "PERSISTENCE: STARTUP DIRECTORIES"
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($sd in $startupDirs) {
    if (Test-Path $sd) {
        $files = Get-ChildItem -Path $sd -File -ErrorAction SilentlyContinue
        if ($files.Count -eq 0) {
            Write-Item "Startup Directory" "Empty ($sd)" "GOOD"
        } else {
            foreach ($f in $files) {
                Write-Item "Startup File" "$($f.Name) (Path: $($f.FullName))" "WARN"
            }
        }
    }
}

# Hosts File Integrity
Write-Section "HOSTS FILE INTEGRITY CHECK"
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $hostsEntries = Get-Content $hostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
    if ($hostsEntries) {
        foreach ($entry in $hostsEntries) {
            Write-Item "Custom Entry" "$entry" "WARN"
        }
    } else {
        Write-Item "Hosts File" "Default (No custom overrides)" "GOOD"
    }
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
