<#
.SYNOPSIS
    USB Historical Connection & Device Forensics Auditor (Windows PowerShell)
    Recovers historical USB drive connections, serial numbers, volume GUIDs,
    and timestamps from Windows Registry hives (USBSTOR, MountedDevices, USB).
.OUTPUTS
    Console visual display, plain text report, and structured CSV manifest.
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "USB_Forensics_${env:COMPUTERNAME}_${Timestamp}.txt"
$CsvFile     = Join-Path $ReportDir "USB_Forensics_${env:COMPUTERNAME}_${Timestamp}.csv"
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

Write-Section "USB DEVICE ARTIFACTS: USBSTOR HISTORICAL INVENTORY"

$usbRecords = [System.Collections.Generic.List[PSObject]]::new()
$usbstorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

if (Test-Path $usbstorPath) {
    $deviceTypes = Get-ChildItem -Path $usbstorPath -ErrorAction SilentlyContinue
    
    foreach ($typeKey in $deviceTypes) {
        $deviceSubkeys = Get-ChildItem -Path $typeKey.PSPath -ErrorAction SilentlyContinue
        
        foreach ($sub in $deviceSubkeys) {
            $serial = $sub.PSChildName
            $isHardwareSerial = if ($serial -notmatch '&') { "True (Physical SN)" } else { "False (Windows Assigned)" }
            
            $friendlyName = (Get-ItemProperty -Path $sub.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
            if (-not $friendlyName) {
                $friendlyName = (Get-ItemProperty -Path $sub.PSPath -Name "DeviceDesc" -ErrorAction SilentlyContinue).DeviceDesc
            }
            if (-not $friendlyName) { $friendlyName = "Generic USB Mass Storage Device" }
            
            $mfg = (Get-ItemProperty -Path $sub.PSPath -Name "Mfg" -ErrorAction SilentlyContinue).Mfg
            $containerId = (Get-ItemProperty -Path $sub.PSPath -Name "ContainerID" -ErrorAction SilentlyContinue).ContainerID
            
            $ven = if ($typeKey.PSChildName -match 'Ven_([^&]+)') { $Matches[1].Trim() } else { "Unknown" }
            $prod = if ($typeKey.PSChildName -match 'Prod_([^&]+)') { $Matches[1].Trim() } else { "Unknown" }
            $rev = if ($typeKey.PSChildName -match 'Rev_([^&]+)') { $Matches[1].Trim() } else { "" }

            $record = [PSCustomObject]@{
                FriendlyName     = $friendlyName
                Vendor           = $ven
                Product          = $prod
                Revision         = $rev
                SerialNumber     = $serial
                HardwareSerial   = $isHardwareSerial
                Mfg              = $mfg
                ContainerID      = $containerId
                DeviceClassKey   = $typeKey.PSChildName
            }
            $usbRecords.Add($record)

            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "Device Name" $friendlyName "GOOD"
            Write-Item "Vendor / Model" "$ven / $prod $rev" "INFO"
            Write-Item "Serial Number" "$serial ($isHardwareSerial)" "WARN"
            Write-Item "Class String" $typeKey.PSChildName "INFO"
            if ($containerId) { Write-Item "Container ID" $containerId "INFO" }
        }
    }
} else {
    Write-Item "USBSTOR Hive" "No USB mass storage devices discovered in registry." "GOOD"
}

# Mount Points & Assigned Drive Letters (MountedDevices)
Write-Section "MOUNTED STORAGE VOLUMES & DRIVE LETTER MAPPINGS"
$mountedPath = "HKLM:\SYSTEM\MountedDevices"
if (Test-Path $mountedPath) {
    $props = Get-ItemProperty -Path $mountedPath -ErrorAction SilentlyContinue
    $volumeProps = $props.PSObject.Properties | Where-Object { $_.Name -match '^\\(DosDevices\\[A-Z]:|\\\\\?\\Volume)' }
    
    foreach ($v in $volumeProps) {
        $rawBytes = $v.Value
        $signature = ""
        try {
            $strVal = [System.Text.Encoding]::Unicode.GetString($rawBytes)
            if ($strVal -match 'USBSTOR|Volume') {
                $signature = $strVal -replace "[^\x20-\x7E]", ""
            } else {
                $signature = ($rawBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""
            }
        } catch {
            $signature = "Binary Descriptor"
        }

        $tag = if ($v.Name -match 'DosDevices') { "GOOD" } else { "INFO" }
        Write-Item "$($v.Name)" $signature $tag
    }
}

# First Install Timestamps from setupapi.dev.log
Write-Section "SETUPAPI DEVICE INSTALLATION LOG ANALYSIS"
$setupLog = "$env:SystemRoot\inf\setupapi.dev.log"
if (Test-Path $setupLog) {
    Write-Item "SetupAPI Log" "Found ($setupLog) - Scanning for USBSTOR installation events..." "INFO"
    try {
        $logMatches = Select-String -Path $setupLog -Pattern ">>>\s+\[Device Install \(Hardware initiated\) - USBSTOR\\" -Context 0,2 -ErrorAction SilentlyContinue
        if ($logMatches) {
            foreach ($match in $logMatches | Select-Object -Last 10) {
                $devLine = $match.Line.Trim()
                $timeLine = if ($match.Context.PostContext) { $match.Context.PostContext[0].Trim() } else { "Unknown Time" }
                Write-Item "Device Event" $devLine "WARN"
                Write-Item "Install Timestamp" $timeLine "INFO"
            }
        } else {
            Write-Item "SetupAPI Events" "No recent hardware-initiated USBSTOR install events in log." "GOOD"
        }
    } catch {
        Write-Item "SetupAPI Analysis" "Error parsing setupapi.dev.log: $($_.Exception.Message)" "WARN"
    }
} else {
    Write-Item "SetupAPI Log" "Log not present at default path." "INFO"
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

# Export structured CSV
if ($usbRecords.Count -gt 0) {
    $usbRecords | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
}

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] USB FORENSICS COMPLETE! Discovered $($usbRecords.Count) historical storage devices." -ForegroundColor Green
Write-Host "      Report: $ReportFile" -ForegroundColor Yellow
if ($usbRecords.Count -gt 0) {
    Write-Host "      CSV:    $CsvFile" -ForegroundColor Yellow
}
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
