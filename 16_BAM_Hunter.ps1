<#
.SYNOPSIS
    Background Activity Moderator (BAM/DAM) Execution Forensics Hunter (PowerShell)
    Extracts binary execution ledgers directly from Windows BAM/DAM registry services.
    Maps NT volume paths to drive letters, decodes 64-bit FILETIME execution timestamps,
    resolves user SIDs to usernames, and flags removable/USB executions.
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "BAM_Execution_Hunter_${env:COMPUTERNAME}_${Timestamp}.txt"
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

Write-Section "BACKGROUND ACTIVITY MODERATOR (BAM/DAM) EXECUTION FORENSICS"

# Check elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Item "Privilege Notice" "BAM registry paths require Administrator privileges for complete visibility." "WARN"
}

# Build NT Volume Device to Drive Letter Mapping
$volumeMap = @{}
try {
    $volumes = Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue
    foreach ($vol in $volumes) {
        if ($vol.DriveLetter -and $vol.DeviceID) {
            # DeviceID format: \\?\Volume{guid}\
            # Query DosDevices
            $guid = $vol.DeviceID.Replace("\\?\", "").TrimEnd("\")
            $volLetter = $vol.DriveLetter
            $volumeMap[$guid] = $volLetter
        }
    }
    # Also map HarddiskVolume numbers via Mountvol
    $mountOut = mountvol.exe
    $currentVol = ""
    foreach ($mLine in ($mountOut -split "`r?`n")) {
        $clean = $mLine.Trim()
        if ($clean -match '^\\\\\\\?\\Volume\{([a-f0-9\-]+)\}\\$') {
            $currentVol = $matches[1]
        } elseif ($clean -match '^([A-Z]:)\\$' -and $currentVol) {
            $volumeMap[$currentVol] = $matches[1]
            $currentVol = ""
        }
    }
} catch {}

function Resolve-PathName {
    param([string]$ntPath)
    # Convert \Device\HarddiskVolumeX\...
    if ($ntPath -match '^\\Device\\HarddiskVolume(\d+)(.*)') {
        $volNum = $matches[1]
        $rest = $matches[2]
        return "Vol$($volNum):$rest"
    }

    return $ntPath
}

$bamBasePaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
)

$parsedExecutions = [System.Collections.Generic.List[PSCustomObject]]::new()
$usbExecutions    = [System.Collections.Generic.List[PSCustomObject]]::new()
$tempExecutions   = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($base in $bamBasePaths) {
    if (-not (Test-Path $base)) { continue }
    $svcType = if ($base -match '\\bam\\') { "BAM" } else { "DAM" }

    $sidSubkeys = Get-ChildItem -Path $base -ErrorAction SilentlyContinue
    foreach ($sidKey in $sidSubkeys) {
        $sidStr = $sidKey.PSChildName
        $userName = $sidStr
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
            $userName = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        } catch {}

        $props = Get-ItemProperty -Path $sidKey.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS.*') { continue }
            $rawBytes = $p.Value
            if ($rawBytes -is [byte[]] -and $rawBytes.Length -ge 8) {
                try {
                    $fileTime = [BitConverter]::ToInt64($rawBytes, 0)
                    if ($fileTime -gt 0) {
                        $dt = [DateTime]::FromFileTimeUtc($fileTime)
                        if ($dt.Year -ge 2000 -and $dt.Year -le 2100) {
                            $resolvedPath = Resolve-PathName $p.Name
                            $entry = [PSCustomObject]@{
                                ServiceType   = $svcType
                                UserAccount   = $userName
                                UserSID       = $sidStr
                                RawPath       = $p.Name
                                ResolvedPath  = $resolvedPath
                                ExeName       = [System.IO.Path]::GetFileName($p.Name).ToUpper()
                                ExecutedUtc   = $dt
                            }
                            $parsedExecutions.Add($entry)

                            # Check if executed from removable drive / secondary volumes
                            if ($p.Name -match '(\\Device\\HarddiskVolume[4-9]|\\Device\\HarddiskVolume[1-9][0-9])' -or $resolvedPath -match '^[D-Z]:') {
                                $usbExecutions.Add($entry)
                            }

                            # Check if executed from Temp or AppData
                            if ($p.Name -match '(\\temp\\|\\tmp\\|\\appdata\\local\\temp)' -or $resolvedPath -match '(\\temp\\|\\tmp\\)') {
                                $tempExecutions.Add($entry)
                            }
                        }
                    }
                } catch {}
            }
        }
    }
}

Write-Item "Total Historical Binaries" "$($parsedExecutions.Count) verified user-initiated execution entries" "GOOD"

# Sort by Execution Date Descending
$sorted = $parsedExecutions | Sort-Object ExecutedUtc -Descending

# Section 1: Top 25 Most Recent BAM Executions
Write-Section "TOP 25 RECENT USER-INITIATED EXECUTIONS (BAM/DAM)"
$top25 = $sorted | Select-Object -First 25
foreach ($item in $top25) {
    $timeStr = $item.ExecutedUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    $status = if ($item -in $usbExecutions) { "WARN" } else { "INFO" }

    Write-Item "$($item.ExeName)" "User: $($item.UserAccount) | Run Time: $timeStr | Path: $($item.ResolvedPath)" $status
}

# Section 2: Secondary / Removable Drive Executions
Write-Section "REMOVABLE / SECONDARY VOLUME EXECUTIONS"
if ($usbExecutions.Count -gt 0) {
    Write-Item "Removable Runs" "Found $($usbExecutions.Count) execution(s) from secondary or external volumes!" "WARN"
    foreach ($ue in ($usbExecutions | Sort-Object ExecutedUtc -Descending | Select-Object -First 15)) {
        $timeStr = $ue.ExecutedUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        Write-Item "$($ue.ExeName)" "User: $($ue.UserAccount) | Time: $timeStr | Path: $($ue.RawPath)" "ALERT"
    }
} else {
    Write-Item "Removable Volume Forensics" "Clean (No executions recorded from non-system drives)." "GOOD"
}

# Section 3: Temp Directory Executions
Write-Section "TEMP DIRECTORY EXECUTION AUDIT"
if ($tempExecutions.Count -gt 0) {
    Write-Item "Temp Directory Runs" "Found $($tempExecutions.Count) binary execution(s) originating from Temp paths!" "WARN"
    foreach ($te in ($tempExecutions | Sort-Object ExecutedUtc -Descending | Select-Object -First 15)) {
        $timeStr = $te.ExecutedUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        Write-Item "$($te.ExeName)" "Time: $timeStr | Path: $($te.RawPath)" "WARN"
    }
} else {
    Write-Item "Temp Path Forensics" "Clean (No suspicious binaries launched from Temp folders)." "GOOD"
}

# Flush report buffer
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] BAM EXECUTION AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP -and -not [Console]::IsInputRedirected) { 
    try { Read-Host "`n  Press Enter to close window..." } catch {} 
}
