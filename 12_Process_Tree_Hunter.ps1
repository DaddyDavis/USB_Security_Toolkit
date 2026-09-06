<#
.SYNOPSIS
    Process Tree & Command-Line Anomaly Hunter (PowerShell)
    Detects anomalous parent-child process lineages (Office/Browser -> Shell),
    Base64 encoded commands, download cradles, and masqueraded system binaries.
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Process_Hunter_${env:COMPUTERNAME}_${Timestamp}.txt"
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

Write-Section "PROCESS ANOMALY & LINEAGE TELEMETRY"

try {
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $procMap = @{}
    foreach ($p in $processes) { $procMap[$p.ProcessId] = $p }

    $flaggedLineage = @()
    $flaggedCommands = @()
    $masqueradedProcs = @()

    $shellExes = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe')
    $officeExes = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'acrord32.exe', 'acrobat.exe')
    $browserExes = @('chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe')
    $coreSystemExes = @('svchost.exe', 'lsass.exe', 'services.exe', 'smss.exe', 'csrss.exe', 'wininit.exe', 'spoolsv.exe')

    foreach ($p in $processes) {
        $pName = if ($p.Name) { $p.Name.ToLower() } else { "" }
        $pPath = if ($p.ExecutablePath) { $p.ExecutablePath.ToLower() } else { "" }
        $pCmd  = if ($p.CommandLine) { $p.CommandLine } else { "" }
        $parentId = $p.ParentProcessId
        $parentName = if ($procMap.ContainsKey($parentId) -and $procMap[$parentId].Name) { $procMap[$parentId].Name.ToLower() } else { "Exited (PID: $parentId)" }

        # 1. Anomalous Parent-Child Execution (MITRE T1059 / T1204)
        $isOfficeParent = ($parentName -in $officeExes) -and ($pName -in $shellExes)
        $isBrowserParent = ($parentName -in $browserExes) -and ($pName -in $shellExes)

        if ($isOfficeParent -or $isBrowserParent) {
            $reason = if ($isOfficeParent) { "Office document spawned shell (Macro / Exploit)" } else { "Browser spawned script interpreter (Drive-by download)" }
            $flaggedLineage += [PSCustomObject]@{
                PID        = $p.ProcessId
                Process    = $p.Name
                ParentPID  = $parentId
                Parent     = $parentName
                Reason     = $reason
                Command    = $pCmd
            }
        }

        # 2. Suspicious Command-Line Flags (Encoded PowerShell, Download Cradles, Hidden windows)
        if ($pCmd) {
            $cmdLower = $pCmd.ToLower()
            $hasEncoded = $cmdLower -match '(-enc\s+|-encodedcommand\s+|-e\s+[a-za-z0-9+/=]{20,})'
            $hasDownload = $cmdLower -match '(downloadstring|downloadfile|invoke-webrequest|\bcurl\b.*-o|\bcertutil\b.*-urlcache)'
            $hasBypass = $cmdLower -match '(-executionpolicy\s+bypass|-w\s+hidden|-windowstyle\s+hidden)'

            if ($hasEncoded -or $hasDownload) {
                $cType = if ($hasEncoded) { "BASE64 ENCODED COMMAND" } else { "DOWNLOAD CRADLE" }
                $flaggedCommands += [PSCustomObject]@{
                    PID     = $p.ProcessId
                    Process = $p.Name
                    Type    = $cType
                    Command = $pCmd
                }
            }
        }

        # 3. System Binary Masquerading (MITRE T1036)
        if ($pName -in $coreSystemExes -and $pPath) {
            if ($pPath -notmatch '(\\windows\\system32\\|\\windows\\syswow64\\)') {
                $masqueradedProcs += [PSCustomObject]@{
                    PID      = $p.ProcessId
                    Process  = $p.Name
                    FakePath = $p.ExecutablePath
                    Command  = $pCmd
                }
            }
        }
    }

    # Output Lineage Findings
    if ($flaggedLineage.Count -gt 0) {
        Write-Item "Anomalous Process Lineage" "DETECTED $($flaggedLineage.Count) SUSPICIOUS PARENT-CHILD PAIR(S)!" "ALERT"
        foreach ($fl in $flaggedLineage) {
            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "Alert Type" $fl.Reason "ALERT"
            Write-Item "Process" "$($fl.Process) [PID: $($fl.PID)]" "ALERT"
            Write-Item "Parent" "$($fl.Parent) [Parent PID: $($fl.ParentPID)]" "WARN"
            Write-Item "CommandLine" $fl.Command "INFO"
        }
    } else {
        Write-Item "Process Lineage" "Clean (No Office/Browser spawned shell anomalies)." "GOOD"
    }

    # Output Command-Line Findings
    Write-Host "`n"
    if ($flaggedCommands.Count -gt 0) {
        Write-Item "Command-Line Anomalies" "Found $($flaggedCommands.Count) obfuscated or download command(s)!" "ALERT"
        foreach ($fc in $flaggedCommands) {
            Write-Host "`n  --------------------------------------------------" -ForegroundColor DarkGray
            Write-Item "Flag Type" $fc.Type "ALERT"
            Write-Item "Process" "$($fc.Process) [PID: $($fc.PID)]" "WARN"
            Write-Item "Command" $fc.Command "INFO"
        }
    } else {
        Write-Item "Command Inspection" "No active Base64 encoded or download cradle commands detected." "GOOD"
    }

    # Output Masquerading Findings
    Write-Host "`n"
    if ($masqueradedProcs.Count -gt 0) {
        Write-Item "Masquerading Alert" "CRITICAL: System binaries running outside System32!" "ALERT"
        foreach ($mp in $masqueradedProcs) {
            Write-Item "Masqueraded Exe" "$($mp.Process) [PID: $($mp.PID)] at $($mp.FakePath)" "ALERT"
        }
    } else {
        Write-Item "Binary Masquerading" "Clean (Core system processes executing from valid System32 paths)." "GOOD"
    }

} catch {
    Write-Item "Process Hunter" "Error during process analysis: $($_.Exception.Message)" "WARN"
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] PROCESS TREE AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
