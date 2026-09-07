<#
.SYNOPSIS
    Windows Prefetch Execution Forensics Hunter (PowerShell)
    Natively decompresses Windows 10/11 MAM-compressed Prefetch files (.pf)
    using in-memory ntdll!RtlDecompressBufferEx. Extracts execution run counts,
    timestamps, and flags high-risk/suspicious execution artifacts (LOLBins, Temp paths).
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Prefetch_Hunter_${env:COMPUTERNAME}_${Timestamp}.txt"
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

# 1. Native C# In-Memory Decompressor for Windows 10/11 MAM Prefetch
$NativeDecompressorCode = @"
using System;
using System.Runtime.InteropServices;

public class NativePrefetchHelper {
    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat,
        byte[] UncompressedBuffer,
        int UncompressedBufferSize,
        byte[] CompressedBuffer,
        int CompressedBufferSize,
        out int FinalUncompressedSize,
        byte[] WorkSpace
    );

    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormat,
        out int NeededBufferSize,
        out int Unknown
    );

    public static byte[] Decompress(byte[] src) {
        if (src == null || src.Length < 8) return null;
        // Check for 'MAM\x04' header
        if (src[0] == 'M' && src[1] == 'A' && src[2] == 'M') {
            int uncompressedSize = BitConverter.ToInt32(src, 4);
            int workspaceSize = 0, unk = 0;
            RtlGetCompressionWorkSpaceSize(0x0004, out workspaceSize, out unk);
            byte[] workspace = new byte[workspaceSize];
            byte[] dest = new byte[uncompressedSize];
            byte[] compressedData = new byte[src.Length - 8];
            Array.Copy(src, 8, compressedData, 0, compressedData.Length);
            int finalSize = 0;
            uint status = RtlDecompressBufferEx(0x0004, dest, uncompressedSize, compressedData, compressedData.Length, out finalSize, workspace);
            if (status == 0) return dest;
            return null;
        }
        // Uncompressed prefetch
        return src;
    }
}
"@

try {
    Add-Type -TypeDefinition $NativeDecompressorCode -ErrorAction SilentlyContinue
} catch {}

Write-Section "WINDOWS PREFETCH EXECUTION TIMELINE & ANOMALY HUNTER"

# Check Admin Elevation (required for C:\Windows\Prefetch)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Item "Privilege Warning" "RUNNING WITHOUT ELEVATED PRIVILEGES. C:\Windows\Prefetch typically requires Administrator access." "WARN"
}

$PrefetchDir = "C:\Windows\Prefetch"
if (-not (Test-Path $PrefetchDir)) {
    Write-Item "Prefetch Status" "Directory $PrefetchDir not found or disabled on this system." "WARN"
    [System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)
    exit
}

$pfFiles = Get-ChildItem -Path $PrefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue
if (-not $pfFiles -or $pfFiles.Count -eq 0) {
    Write-Item "Prefetch Files" "No .pf files accessible. Ensure script is running as Administrator." "WARN"
    [System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)
    exit
}

Write-Item "Total Prefetch Files" "$($pfFiles.Count) historical execution files found" "GOOD"

# List of high-interest LOLBins (Living-off-the-Land Binaries)
$lolBins = @(
    'certutil.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'vssadmin.exe', 
    'wmic.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'rundll32.exe', 
    'mshta.exe', 'reg.exe', 'schtasks.exe', 'sc.exe', 'cscript.exe', 
    'wscript.exe', 'bitsadmin.exe', 'nltest.exe', 'regsvr32.exe', 'at.exe',
    'psexec.exe', 'procdump.exe', 'mimikatz.exe', 'lazagne.exe', 'rclone.exe'
)

$parsedArtifacts = [System.Collections.Generic.List[PSCustomObject]]::new()
$flaggedLolBins  = [System.Collections.Generic.List[PSCustomObject]]::new()
$flaggedTempRuns = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "  [*] Parsing and decompressing prefetch records..." -ForegroundColor DarkGray

foreach ($file in $pfFiles) {
    try {
        $rawBytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $data = [NativePrefetchHelper]::Decompress($rawBytes)

        if (-not $data -or $data.Length -lt 0x90) {
            # Fallback to filesystem timestamps if header cannot be parsed
            $parsedArtifacts.Add([PSCustomObject]@{
                ExeName       = $file.Name.Split("-")[0].ToUpper()
                PrefetchFile  = $file.Name
                RunCount      = 1
                LastRunUtc    = $file.LastWriteTimeUtc
                AllRunsUtc    = @($file.LastWriteTimeUtc)
                FileSize      = $file.Length
            })
            continue
        }

        # Check signature 'SCCA' at offset 0x04
        $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
        $version = [BitConverter]::ToInt32($data, 0)

        # Parse Executable Name from Unicode string at offset 0x10 (max 60 bytes / 30 chars)
        $exeName = [System.Text.Encoding]::Unicode.GetString($data, 0x10, 60).Split("`0")[0].Trim().ToUpper()
        if (-not $exeName) {
            $exeName = $file.Name.Split("-")[0].ToUpper()
        }

        # Parse Run Count: Win10/11 (ver 30/31) is at 0xD0. Win8/8.1 (ver 26) is at 0xD0. Win7 (ver 23) is at 0x98.
        $runCountOffset = if ($version -ge 26) { 0xD0 } else { 0x98 }
        $runCount = if ($data.Length -ge ($runCountOffset + 4)) { [BitConverter]::ToInt32($data, $runCountOffset) } else { 1 }

        # Parse Last Execution Timestamps (up to 8 FILETIME entries in Win10/11 at 0x80)
        $timestamps = [System.Collections.Generic.List[DateTime]]::new()
        $tsOffset = if ($version -ge 26) { 0x80 } else { 0x78 }
        $maxTs = if ($version -ge 26) { 8 } else { 1 }

        for ($i = 0; $i -lt $maxTs; $i++) {
            $pos = $tsOffset + ($i * 8)
            if ($data.Length -ge ($pos + 8)) {
                $ft = [BitConverter]::ToInt64($data, $pos)
                if ($ft -gt 0) {
                    try {
                        $dt = [DateTime]::FromFileTimeUtc($ft)
                        if ($dt.Year -ge 2000 -and $dt.Year -le 2100) {
                            $timestamps.Add($dt)
                        }
                    } catch {}
                }
            }
        }

        $lastRun = if ($timestamps.Count -gt 0) { $timestamps[0] } else { $file.LastWriteTimeUtc }

        $artifact = [PSCustomObject]@{
            ExeName      = $exeName
            PrefetchFile = $file.Name
            RunCount     = $runCount
            LastRunUtc   = $lastRun
            AllRunsUtc   = $timestamps
            FileSize     = $file.Length
        }
        $parsedArtifacts.Add($artifact)

        # Check for LOLBin execution
        if ($exeName.ToLower() -in $lolBins) {
            $flaggedLolBins.Add($artifact)
        }

        # Check for suspicious temp / random naming patterns
        if ($exeName -match '(_IU.*\.TMP|~.*\.TMP|\.TMP$|^[A-Z0-9]{8,12}\.EXE$)' -and $exeName -notmatch '^(SETUP|INSTALL)') {
            $flaggedTempRuns.Add($artifact)
        }

    } catch {
        # Fallback to basic file metadata
        $parsedArtifacts.Add([PSCustomObject]@{
            ExeName      = $file.Name.Split("-")[0].ToUpper()
            PrefetchFile = $file.Name
            RunCount     = 1
            LastRunUtc   = $file.LastWriteTimeUtc
            AllRunsUtc   = @($file.LastWriteTimeUtc)
            FileSize     = $file.Length
        })
    }
}

# Sort chronologically by most recent execution
$sortedArtifacts = $parsedArtifacts | Sort-Object LastRunUtc -Descending

# Section 1: Top 20 Most Recently Executed Binaries
Write-Section "TOP 20 RECENTLY EXECUTED PROGRAMS"
$top20 = $sortedArtifacts | Select-Object -First 20
foreach ($item in $top20) {
    $timeStr = $item.LastRunUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    $status = if ($item.ExeName.ToLower() -in $lolBins) { "WARN" } else { "INFO" }
    Write-Item "$($item.ExeName)" "Runs: $($item.RunCount) | Last Run: $timeStr | File: $($item.PrefetchFile)" $status
}

# Section 2: Flagged LOLBins (Living-off-the-Land Binaries)
Write-Section "SUSPICIOUS DUAL-USE & LOLBINS EXECUTIONS"
if ($flaggedLolBins.Count -gt 0) {
    Write-Item "LOLBins Detected" "Found $($flaggedLolBins.Count) dual-use administrative/scripting tools executed!" "WARN"
    foreach ($lb in ($flaggedLolBins | Sort-Object LastRunUtc -Descending)) {
        $timeStr = $lb.LastRunUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        Write-Item "$($lb.ExeName)" "Executed $($lb.RunCount) time(s) - Last: $timeStr" "ALERT"
        if ($lb.AllRunsUtc.Count -gt 1) {
            $history = ($lb.AllRunsUtc | ForEach-Object { $_.ToString("HH:mm:ss") }) -join ", "
            $ReportLines.Add("    [Historical Runs Today]: $history")
        }
    }
} else {
    Write-Item "LOLBin Forensics" "No high-risk dual-use binaries recorded in Prefetch." "GOOD"
}

# Section 3: Suspicious Temporary/Dropper Artifacts
Write-Section "TEMPORARY / DROPPER ARTIFACT ANOMALIES"
if ($flaggedTempRuns.Count -gt 0) {
    Write-Item "Dropper Artifacts" "Found $($flaggedTempRuns.Count) temporary or randomized installer artifacts!" "WARN"
    foreach ($tr in ($flaggedTempRuns | Sort-Object LastRunUtc -Descending)) {
        $timeStr = $tr.LastRunUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        Write-Item "$($tr.ExeName)" "Run Count: $($tr.RunCount) | Last Executed: $timeStr" "WARN"
    }
} else {
    Write-Item "Dropper Inspection" "Clean (No randomized temporary execution artifacts found)." "GOOD"
}

# Flush report buffer to disk
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] PREFETCH FORENSICS COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP -and -not [Console]::IsInputRedirected) { 
    try { Read-Host "`n  Press Enter to close window..." } catch {} 
}
