<#
.SYNOPSIS
    Wireless Profile & Cleartext Credential Forensics (PowerShell)
    Audits saved Wi-Fi profiles, extracts passwords (key=clear), authentication ciphers,
    and identifies insecure open networks.
.OUTPUTS
    Console visual display, text report, and CSV manifest in .\Reports\
#>

[CmdletBinding()]
param(
    [switch]$DumpPlaintext
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "WiFi_Forensics_${env:COMPUTERNAME}_${Timestamp}.txt"
$CsvFile     = Join-Path $ReportDir "WiFi_Forensics_${env:COMPUTERNAME}_${Timestamp}.csv"
$ReportLines = [System.Collections.Generic.List[string]]::new()
$wifiRecords = [System.Collections.Generic.List[PSObject]]::new()

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

Write-Section "WIRELESS NETWORK PROFILES & STORED CREDENTIALS"

try {
    $profileRaw = (netsh.exe wlan show profiles) -join "`n"
    $profileMatches = [regex]::Matches($profileRaw, 'All User Profile\s*:\s*(.+)')

    if ($profileMatches.Count -gt 0) {
        Write-Item "Discovered Profiles" "Found $($profileMatches.Count) saved wireless networks" "INFO"

        foreach ($pm in $profileMatches) {
            $ssid = $pm.Groups[1].Value.Trim()
            if (-not $ssid) { continue }

            $detailRaw = (netsh.exe wlan show profile name="$ssid" key=clear) -join "`n"

            $authMatch = [regex]::Match($detailRaw, 'Authentication\s*:\s*(.+)')
            $auth = if ($authMatch.Success) { $authMatch.Groups[1].Value.Trim() } else { "Unknown" }

            $cipherMatch = [regex]::Match($detailRaw, 'Cipher\s*:\s*(.+)')
            $cipher = if ($cipherMatch.Success) { $cipherMatch.Groups[1].Value.Trim() } else { "Unknown" }

            $keyMatch = [regex]::Match($detailRaw, 'Key Content\s*:\s*(.+)')
            $hasKey = [regex]::Match($detailRaw, 'Security key\s*:\s*(.+)')

            if ($keyMatch.Success) {
                $rawPass = $keyMatch.Groups[1].Value.Trim()
                $password = if ($DumpPlaintext) { $rawPass } else { "[STORED: REDACTED (Use -DumpPlaintext)]" }
                $status = "GOOD"
            } elseif ($hasKey.Success -and $hasKey.Groups[1].Value.Trim() -match 'Absent') {
                $password = "[INSECURE: OPEN NETWORK]"
                $status = "ALERT"
            } else {
                $password = "[NO STORED KEY / ENTERPRISE]"
                $status = "WARN"
            }

            $record = [PSCustomObject]@{
                SSID           = $ssid
                Authentication = $auth
                Cipher         = $cipher
                Password       = $password
            }
            $wifiRecords.Add($record)

            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "SSID / Network" $ssid "GOOD"
            Write-Item "Authentication" "$auth ($cipher)" "INFO"
            Write-Item "Key Content" $password $status
        }
    } else {
        Write-Item "Wi-Fi Profiles" "No wireless network profiles stored on this host." "INFO"
    }
} catch {
    Write-Item "Wi-Fi Forensics" "Failed enumerating WLAN profiles: $($_.Exception.Message)" "WARN"
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

# Export structured CSV
if ($wifiRecords.Count -gt 0) {
    $wifiRecords | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
}

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] WI-FI AUDIT COMPLETE! Discovered $($wifiRecords.Count) stored network profiles." -ForegroundColor Green
Write-Host "      Report: $ReportFile" -ForegroundColor Yellow
if ($wifiRecords.Count -gt 0) {
    Write-Host "      CSV:    $CsvFile" -ForegroundColor Yellow
}
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
