<#
.SYNOPSIS
    User Activity & Removable Media Forensic Footprint Hunter (PowerShell)
    Audits Shell LNK shortcuts, JumpLists, Explorer TypedPaths, UserAssist ROT13 execution records,
    and isolates removable USB drive browsing and file access footprints.
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "User_Activity_${env:COMPUTERNAME}_${Timestamp}.txt"
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

function Decode-Rot13 {
    param([string]$InputText)
    if ([string]::IsNullOrEmpty($InputText)) { return $InputText }
    $chars = $InputText.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int]$chars[$i]
        if ($c -ge 65 -and $c -le 90) {
            $chars[$i] = [char]((($c - 65 + 13) % 26) + 65)
        } elseif ($c -ge 97 -and $c -le 122) {
            $chars[$i] = [char]((($c - 97 + 13) % 26) + 97)
        }
    }
    return -join $chars
}

Write-Section "USER ACTIVITY & REMOVABLE MEDIA FORENSIC AUDIT"
Write-Item "Audited Host" "$env:COMPUTERNAME" "INFO"
Write-Item "Audited User" "$env:USERNAME" "INFO"
Write-Item "Audit Time" "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" "INFO"

# 1. Map Mounted Drives and Removable Media
$mountedDisks = @{}
$removableDrives = [System.Collections.Generic.List[string]]::new()
try {
    Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        $mountedDisks[$_.DeviceID] = $_
        if ($_.DriveType -eq 2) {
            $removableDrives.Add($_.DeviceID)
        }
    }
} catch {}

if ($removableDrives.Count -gt 0) {
    Write-Item "Active Removable Volumes" ($removableDrives -join ", ") "WARN"
} else {
    Write-Item "Active Removable Volumes" "None currently mounted" "GOOD"
}

# 2. Parse Recent LNK Shortcuts
$recentPath = [Environment]::GetFolderPath('Recent')
$lnkFiles = @()
if (Test-Path $recentPath) {
    $lnkFiles = Get-ChildItem -Path $recentPath -Filter "*.lnk" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
}

Write-Item "Recent Shell Shortcuts" "$($lnkFiles.Count) LNK item(s) found in user profile" "INFO"

$wscriptShell = $null
try {
    $wscriptShell = New-Object -ComObject WScript.Shell
} catch {}

$removableLnkList = [System.Collections.Generic.List[PSCustomObject]]::new()
$highRiskLnkList  = [System.Collections.Generic.List[PSCustomObject]]::new()
$documentLnkList  = [System.Collections.Generic.List[PSCustomObject]]::new()

$riskExtensions = @('.exe', '.dll', '.sys', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr', '.iso', '.img', '.vhd')
$docExtensions  = @('.docx', '.doc', '.xlsx', '.xls', '.pptx', '.pdf', '.zip', '.rar', '.7z', '.kdbx', '.txt', '.csv')

if ($wscriptShell) {
    foreach ($lnk in $lnkFiles) {
        try {
            $shortcut = $wscriptShell.CreateShortcut($lnk.FullName)
            $target = $shortcut.TargetPath
            if ([string]::IsNullOrWhiteSpace($target)) { continue }

            $ext = [System.IO.Path]::GetExtension($target).ToLower()
            $drive = if ($target.Length -ge 2 -and $target[1] -eq ':') { $target.Substring(0, 2).ToUpper() } else { "" }
            
            $isRemovable = $false
            $isOrphanDrive = $false

            if ($drive) {
                if ($removableDrives.Contains($drive)) {
                    $isRemovable = $true
                } elseif ($drive -ne "C:" -and -not $mountedDisks.ContainsKey($drive)) {
                    # Drive letter is not C: and currently not mounted -> disconnected USB/external drive!
                    $isOrphanDrive = $true
                    $isRemovable = $true
                } elseif ($drive -ne "C:") {
                    $isRemovable = $true
                }
            } elseif ($target -match '^\\\\') {
                $isRemovable = $true
            }

            $itemObj = [PSCustomObject]@{
                ShortcutName = $lnk.Name
                TargetPath   = $target
                Arguments    = $shortcut.Arguments
                WorkingDir   = $shortcut.WorkingDirectory
                LastModified = $lnk.LastWriteTime
                IsOrphan     = $isOrphanDrive
                Drive        = $drive
                Extension    = $ext
            }

            if ($isRemovable) {
                $removableLnkList.Add($itemObj)
            }

            if ($ext -in $riskExtensions) {
                $highRiskLnkList.Add($itemObj)
            } elseif ($ext -in $docExtensions) {
                $documentLnkList.Add($itemObj)
            }
        } catch {}
    }
}

# Section: Removable Drive Access Footprints
Write-Section "REMOVABLE MEDIA & EXTERNAL DRIVE ACCESS FOOTPRINTS"
if ($removableLnkList.Count -gt 0) {
    Write-Item "Removable Media Trails" "DETECTED $($removableLnkList.Count) RECENT LNK SHORTCUT(S) POINTING TO EXTERNAL/USB VOLUMES!" "ALERT"
    foreach ($r in ($removableLnkList | Select-Object -First 25)) {
        $orphanTag = if ($r.IsOrphan) { "[UNMOUNTED/OFFLINE USB DRIVE $($r.Drive)]" } else { "[DRIVE $($r.Drive)]" }
        Write-Item "$orphanTag $($r.ShortcutName)" "$($r.TargetPath) (Accessed: $($r.LastModified.ToString('yyyy-MM-dd HH:mm:ss')))" "WARN"
    }
} else {
    Write-Item "Removable Media Trails" "Clean (No recent shell shortcuts pointing to removable or orphaned drive letters)." "GOOD"
}

# Section: High-Risk Script & Binary Access Footprints
Write-Section "RECENT EXECUTABLE & SCRIPT SHORTCUTS"
if ($highRiskLnkList.Count -gt 0) {
    Write-Item "Binary/Script Shortcuts" "Found $($highRiskLnkList.Count) executable or script shortcut(s)" "WARN"
    foreach ($h in ($highRiskLnkList | Select-Object -First 20)) {
        $status = if ($h.TargetPath -match '(\\|\/)(AppData|Temp|Public|Downloads)(\\|\/)') { "ALERT" } else { "INFO" }
        Write-Item "$($h.ShortcutName)" "$($h.TargetPath) (Accessed: $($h.LastModified.ToString('yyyy-MM-dd HH:mm:ss')))" $status
    }
} else {
    Write-Item "Binary/Script Shortcuts" "Zero high-risk standalone scripts or portable binaries in recent links." "GOOD"
}

# Section: Recent Documents & Archives
Write-Section "RECENT DOCUMENTS & DATA ARCHIVES"
Write-Item "Document Trails" "Found $($documentLnkList.Count) document/archive access record(s)" "INFO"
foreach ($d in ($documentLnkList | Select-Object -First 15)) {
    Write-Item "$($d.ShortcutName)" "$($d.TargetPath) ($($d.LastModified.ToString('yyyy-MM-dd HH:mm:ss')))" "INFO"
}

# Section: Explorer TypedPaths History
Write-Section "EXPLORER TYPED PATHS (USER-NAVIGATED DIRECTORIES)"
$typedPathKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
$typedPaths = @()
if (Test-Path $typedPathKey) {
    $props = Get-ItemProperty -Path $typedPathKey -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.Name -match '^url\d+$' } | ForEach-Object {
            $typedPaths += $_.Value
            $status = if ($_.Value -match '^[D-Z]:' -or $_.Value -match '^\\\\') { "ALERT" } else { "INFO" }
            Write-Item "$($_.Name)" "$($_.Value)" $status
        }
    }
}
if ($typedPaths.Count -eq 0) {
    Write-Item "TypedPaths Ledger" "No manual explorer path entries recorded." "GOOD"
}

# Section: JumpLists Activity
Write-Section "JUMPLISTS RECENT BURST ACTIVITY"
$jumpListDir = Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations"
if (Test-Path $jumpListDir) {
    $jumpFiles = Get-ChildItem -Path $jumpListDir -Filter "*.automaticDestinations-ms" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    Write-Item "JumpLists Cataloged" "$($jumpFiles.Count) AppID destination streams" "INFO"
    foreach ($jf in ($jumpFiles | Select-Object -First 8)) {
        Write-Item "AppID $($jf.BaseName)" "Updated: $($jf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Round($jf.Length / 1KB, 1)) KB)" "INFO"
    }
} else {
    Write-Item "JumpLists Status" "AutomaticDestinations directory not found or empty." "INFO"
}

# Section: UserAssist ROT13 Execution Ledger
Write-Section "USERASSIST GUI EXECUTION ARTIFACTS (ROT13 DECODED)"
$uaBasePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
$uaExecList = [System.Collections.Generic.List[PSCustomObject]]::new()

if (Test-Path $uaBasePath) {
    Get-ChildItem -Path $uaBasePath -ErrorAction SilentlyContinue | ForEach-Object {
        $countKey = Join-Path $_.PSPath "Count"
        if (Test-Path $countKey) {
            $props = Get-ItemProperty -Path $countKey -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
                    $decoded = Decode-Rot13 $p.Name
                    if ($p.Value -is [byte[]] -and $p.Value.Length -ge 72) {
                        try {
                            $runCount = [BitConverter]::ToInt32($p.Value, 4)
                            $rawTime  = [BitConverter]::ToInt64($p.Value, 60)
                            $lastRun  = if ($rawTime -gt 0) { [DateTime]::FromFileTime($rawTime) } else { [DateTime]::MinValue }
                            
                            if ($runCount -gt 0) {
                                $uaExecList.Add([PSCustomObject]@{
                                    Program  = $decoded
                                    RunCount = $runCount
                                    LastRun  = $lastRun
                                })
                            }
                        } catch {}
                    }
                }
            }
        }
    }
}

if ($uaExecList.Count -gt 0) {
    Write-Item "UserAssist Ledger" "Parsed $($uaExecList.Count) decoded program executions" "INFO"
    $topExec = $uaExecList | Sort-Object LastRun -Descending | Select-Object -First 15
    foreach ($ue in $topExec) {
        $timeStr = if ($ue.LastRun -gt [DateTime]::MinValue) { $ue.LastRun.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
        $status = if ($ue.Program -match '^[D-Z]:' -or $ue.Program -match '(\\|\/)(AppData|Temp)(\\|\/)') { "ALERT" } else { "INFO" }
        Write-Item "$($ue.Program)" "Executions: $($ue.RunCount) | Last Run: $timeStr" $status
    }
} else {
    Write-Item "UserAssist Status" "No active UserAssist count values located." "INFO"
}

# Flush report buffer
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] USER ACTIVITY AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP -and -not [Console]::IsInputRedirected) { 
    try { Read-Host "`n  Press Enter to close window..." } catch {} 
}
