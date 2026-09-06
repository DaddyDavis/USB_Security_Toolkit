<#
.SYNOPSIS
    Active Directory & Domain Reconnaissance Auditor (PowerShell)
    Inspects domain-join status, Domain Controllers, Kerberos tickets (klist),
    active SMB network shares, and exposed network sessions.
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Domain_Recon_${env:COMPUTERNAME}_${Timestamp}.txt"
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

# 1. Host Join Status & Identity
Write-Section "DOMAIN & WORKGROUP TOPOLOGY"
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $isDomain = $cs.PartOfDomain
    $domainOrWg = $cs.Domain

    if ($isDomain) {
        Write-Item "Domain Posture" "DOMAIN-JOINED (Active Directory Environment)" "WARN"
        Write-Item "Domain Name" $domainOrWg "INFO"
        Write-Item "Logon Server" "$env:LOGONSERVER" "INFO"
        
        # Query Domain Controller
        try {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            Write-Item "PDC Emulator" "$($domainObj.PdcRoleOwner.Name)" "INFO"
            Write-Item "Domain Forest" "$($domainObj.Forest.Name)" "INFO"
        } catch {
            Write-Item "Active Directory" "Domain joined but Domain Controller not reachable currently." "WARN"
        }
    } else {
        Write-Item "Domain Posture" "STANDALONE / WORKGROUP (Non-Domain Joined)" "GOOD"
        Write-Item "Workgroup Name" $domainOrWg "INFO"
    }
} catch {
    Write-Item "Domain Query" "Failed querying domain posture: $($_.Exception.Message)" "WARN"
}

# 2. Kerberos Ticket Cache (klist)
Write-Section "KERBEROS TICKET CACHE (KLIST)"
try {
    $klistOutput = klist.exe 2>&1
    if ($LASTEXITCODE -eq 0 -and ($klistOutput | Out-String) -notmatch 'no tickets') {
        Write-Item "Kerberos Status" "Active Kerberos tickets discovered in memory" "WARN"
        foreach ($line in ($klistOutput | Out-String).Trim().Split("`n")) {
            if ($line.Trim() -and $line -match '(Server:|Client:|End Time:|Ticket Flags:)') {
                Write-Item "Ticket Entry" "$($line.Trim())" "INFO"
            }
        }
    } else {
        Write-Item "Kerberos Tickets" "No active Kerberos tickets cached (Typical for local/workgroup logons)." "GOOD"
    }
} catch {
    Write-Item "Kerberos Audit" "Unable to execute klist: $($_.Exception.Message)" "WARN"
}

# 3. Active Mapped Network Shares (Outbound SMB)
Write-Section "MOUNTED NETWORK SHARES (OUTBOUND SMB)"
try {
    $mappings = Get-SmbMapping -ErrorAction SilentlyContinue
    if ($mappings) {
        foreach ($m in $mappings) {
            Write-Item "Mapped Share" "$($m.LocalPath) -> $($m.RemotePath) [Status: $($m.Status)]" "WARN"
        }
    } else {
        $netUse = net.exe use 2>&1
        $hasShares = $false
        foreach ($line in ($netUse | Out-String).Trim().Split("`n")) {
            if ($line -match '\\\\[a-zA-Z0-9_.-]+\\') {
                Write-Item "Net Use Share" "$($line.Trim())" "WARN"
                $hasShares = $true
            }
        }
        if (-not $hasShares) {
            Write-Item "Outbound SMB" "No remote network shares or mapped drives currently connected." "GOOD"
        }
    }
} catch {
    Write-Item "Network Shares" "Unable to query SMB mappings: $($_.Exception.Message)" "WARN"
}

# 4. Inbound SMB Shares Hosted on This Machine
Write-Section "HOSTED SMB SHARES (INBOUND NETWORK EXPOSURE)"
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    if ($shares) {
        foreach ($s in $shares) {
            # Distinguish default admin shares from custom user shares
            $isDefault = $s.Name -in @('ADMIN$', 'C$', 'IPC$')
            $status = if ($isDefault) { "INFO" } else { "ALERT" }
            Write-Item "Exposed Share" "$($s.Name) -> $($s.Path) [Description: $($s.Description)]" $status
        }
    } else {
        Write-Item "Hosted Shares" "No active SMB shares discovered." "GOOD"
    }
} catch {
    Write-Item "Hosted Shares" "Unable to query Get-SmbShare: $($_.Exception.Message)" "WARN"
}

# Flush report buffer atomically
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] DOMAIN & SHARE RECON COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP) { Read-Host "`n  Press Enter to close window..." }
