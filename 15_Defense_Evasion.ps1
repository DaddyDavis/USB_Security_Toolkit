<#
.SYNOPSIS
    Defense Evasion & Security Tampering Hunter (PowerShell)
    Audits Windows host for signs of security control impairment (MITRE ATT&CK T1562).
    Inspects Windows Defender real-time disabling, malicious exclusions, firewall bypasses,
    WDigest plaintext credential caching, EventLog silencing, and UAC crippling.
.OUTPUTS
    Console visual display and text report in .\Reports\
#>

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ReportDir = Join-Path $ScriptDir "Reports"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile  = Join-Path $ReportDir "Defense_Evasion_${env:COMPUTERNAME}_${Timestamp}.txt"
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

function Get-RegVal {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            return $val
        }
    } catch {}
    return $null
}

Write-Section "DEFENSE EVASION & SECURITY CONTROLS TAMPERING AUDIT"

$alertCount = 0

# -----------------------------------------------------------------------------
# 1. WINDOWS DEFENDER ANTIVIRUS & REAL-TIME MONITORING (T1562.001)
# -----------------------------------------------------------------------------
Write-Section "1. WINDOWS DEFENDER STATUS & POLICY OVERRIDES"

# Service check
$defSvc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
if ($defSvc) {
    $svcStatus = if ($defSvc.Status -eq "Running") { "GOOD" } else { $alertCount++; "ALERT" }
    Write-Item "WinDefend Service" "$($defSvc.Status) (Startup: $($defSvc.StartType))" $svcStatus
} else {
    Write-Item "WinDefend Service" "Not Found (Third-party EDR/AV likely installed)" "INFO"
}

# Policy disables
$defPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$rtpPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

$disAntiSpy = Get-RegVal $defPolicyPath "DisableAntiSpyware"
if ($disAntiSpy -eq 1) {
    Write-Item "DisableAntiSpyware" "ENABLED in GPO (Defender AntiSpyware is KILLED)!" "ALERT"
    $alertCount++
} else {
    Write-Item "DisableAntiSpyware" "Clean (Not disabled by policy)" "GOOD"
}

$disRealtime = Get-RegVal $rtpPolicyPath "DisableRealtimeMonitoring"
if ($disRealtime -eq 1) {
    Write-Item "DisableRealtimeMonitoring" "CRITICAL: Real-time AV monitoring is explicitly DISABLED!" "ALERT"
    $alertCount++
} else {
    Write-Item "Real-Time Monitoring" "Active / Default enforcement" "GOOD"
}

$disBehavior = Get-RegVal $rtpPolicyPath "DisableBehaviorMonitoring"
if ($disBehavior -eq 1) {
    Write-Item "Behavior Monitoring" "CRITICAL: Behavioral heuristics DISABLED via Registry!" "ALERT"
    $alertCount++
} else {
    Write-Item "Behavior Monitoring" "Active (Heuristic behavioral defense enabled)" "GOOD"
}

$disIOAV = Get-RegVal $rtpPolicyPath "DisableIOAVProtection"
if ($disIOAV -eq 1) {
    Write-Item "IOAV Download Scan" "CRITICAL: Downloaded file scanning is DISABLED!" "ALERT"
    $alertCount++
} else {
    Write-Item "IOAV Download Scan" "Active (Downloads & attachments scanned)" "GOOD"
}

# -----------------------------------------------------------------------------
# 2. MALICIOUS DEFENDER EXCLUSIONS (T1562.001)
# -----------------------------------------------------------------------------
Write-Section "2. DEFENDER EXCLUSIONS AUDIT (PATH, PROCESS, EXTENSION)"

$exclBasePath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions"
$foundExclusions = @()

foreach ($cat in @('Paths', 'Processes', 'Extensions')) {
    $cPath = "$exclBasePath\$cat"
    if (Test-Path $cPath) {
        $props = Get-ItemProperty -Path $cPath -ErrorAction SilentlyContinue
        if ($props) {
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch '^PS.*') {
                    $foundExclusions += [PSCustomObject]@{ Category = $cat; Item = $p.Name; Value = $p.Value }
                }
            }
        }
    }
}

if ($foundExclusions.Count -gt 0) {
    Write-Item "Exclusions Detected" "WARNING: Found $($foundExclusions.Count) active exclusion rule(s)!" "WARN"
    foreach ($ex in $foundExclusions) {
        $isHighRisk = ($ex.Item -match '(\\temp|\\users|\\appdata|\\programdata|^c:\\$|\.bat$|\.ps1$|\.vbs$)')
        $status = if ($isHighRisk) { $alertCount++; "ALERT" } else { "WARN" }
        Write-Item "[$($ex.Category)]" "$($ex.Item)" $status
    }
} else {
    Write-Item "Defender Exclusions" "Clean (Zero global directory/extension exclusions configured)" "GOOD"
}

# -----------------------------------------------------------------------------
# 3. WINDOWS FIREWALL TAMPERING (T1562.004)
# -----------------------------------------------------------------------------
Write-Section "3. WINDOWS FIREWALL INTEGRITY"

$fwProfiles = @{
    "Domain Profile"   = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
    "Private Profile"  = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
    "Public Profile"   = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
}

foreach ($pName in $fwProfiles.Keys) {
    $pKey = $fwProfiles[$pName]
    $enVal = Get-RegVal $pKey "EnableFirewall"
    if ($enVal -eq 0) {
        Write-Item "$pName" "CRITICAL: Firewall is DISABLED!" "ALERT"
        $alertCount++
    } elseif ($enVal -eq 1) {
        Write-Item "$pName" "Enabled (Active packet inspection)" "GOOD"
    } else {
        Write-Item "$pName" "Default Windows Managed" "INFO"
    }
}

# -----------------------------------------------------------------------------
# 4. CREDENTIAL CACHING & LSASS PROTECTION (T1003.001 / T1562)
# -----------------------------------------------------------------------------
Write-Section "4. CREDENTIAL PROTECTION & LSASS HARDENING"

# WDigest Plaintext Caching
$wdigestVal = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
if ($wdigestVal -eq 1) {
    Write-Item "WDigest Plaintext" "CRITICAL: Plaintext passwords actively cached in LSASS memory (Mimikatz vulnerable)!" "ALERT"
    $alertCount++
} else {
    Write-Item "WDigest Plaintext" "Hardened (Plaintext password caching disabled)" "GOOD"
}

# LSA Protected Process Light (RunAsPPL)
$pplVal = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
if ($pplVal -eq 1 -or $pplVal -eq 2) {
    Write-Item "LSA RunAsPPL" "Hardened (LSASS running as Protected Process Light)" "GOOD"
} else {
    Write-Item "LSA RunAsPPL" "Unprotected (LSASS memory vulnerable to admin-level process dumping)" "WARN"
}

# -----------------------------------------------------------------------------
# 5. AUDIT LOGGING & EVENT TAMPERING (T1562.002)
# -----------------------------------------------------------------------------
Write-Section "5. EVENT LOGGING & SCRIPT AUDIT ENFORCEMENT"

# EventLog Service
$evtSvc = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
if ($evtSvc) {
    $evtStatus = if ($evtSvc.Status -eq "Running") { "GOOD" } else { $alertCount++; "ALERT" }
    Write-Item "EventLog Service" "$($evtSvc.Status) (Startup: $($evtSvc.StartType))" $evtStatus
} else {
    Write-Item "EventLog Service" "CRITICAL: Windows Event Log service missing or corrupted!" "ALERT"
    $alertCount++
}

# PowerShell ScriptBlock Logging (EID 4104)
$sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sbVal = Get-RegVal $sbPath "EnableScriptBlockLogging"
if ($sbVal -eq 1) {
    Write-Item "ScriptBlock Logging" "Active (Captures all PowerShell executions & obfuscated payloads)" "GOOD"
} else {
    Write-Item "ScriptBlock Logging" "Not Enforced via Policy (Attacker scripts may bypass event capture)" "WARN"
}

# -----------------------------------------------------------------------------
# 6. UAC INTEGRITY & RECOVERY SHADOWS (T1548.002 / T1490)
# -----------------------------------------------------------------------------
Write-Section "6. UAC ELEVATION & SHADOW COPY TAMPERING"

# UAC Check (EnableLUA)
$uacLua = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
if ($uacLua -eq 0) {
    Write-Item "UAC (EnableLUA)" "CRITICAL: User Account Control is COMPLETELY DISABLED!" "ALERT"
    $alertCount++
} else {
    Write-Item "UAC (EnableLUA)" "Active (Admin privilege boundary enforced)" "GOOD"
}

# ConsentPromptBehaviorAdmin (0 = Elevate without prompt)
$uacConsent = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
if ($uacConsent -eq 0) {
    Write-Item "UAC Elevation Prompt" "CRITICAL: Admin processes auto-elevate SILENTLY without consent!" "ALERT"
    $alertCount++
} else {
    Write-Item "UAC Elevation Prompt" "Normal (Prompts administrator for credential/consent)" "GOOD"
}

# Volume Shadow Copies Check
try {
    $shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($shadows -and $shadows.Count -gt 0) {
        Write-Item "Volume Shadow Copies" "$($shadows.Count) restore snapshot(s) verified on disk" "GOOD"
    } else {
        Write-Item "Volume Shadow Copies" "No VSS snapshots found (Check if ransomware purged backups)" "WARN"
    }
} catch {
    Write-Item "Volume Shadow Copies" "Query error: $($_.Exception.Message)" "WARN"
}

# -----------------------------------------------------------------------------
# SUMMARY REPORT
# -----------------------------------------------------------------------------
Write-Section "DEFENSE TAMPERING AUDIT SUMMARY"
if ($alertCount -gt 0) {
    Write-Item "TAMPERING ASSESSMENT" "CRITICAL: Found $alertCount active defense impairment indicator(s)!" "ALERT"
} else {
    Write-Item "TAMPERING ASSESSMENT" "CLEAN: All core security controls and AV protections verified intact." "GOOD"
}

# Flush report buffer
[System.IO.File]::WriteAllLines($ReportFile, $ReportLines, [System.Text.Encoding]::UTF8)

Write-Host "`n" + ("=" * 70) -ForegroundColor Green
Write-Host "  [+] DEFENSE EVASION AUDIT COMPLETE! Full report saved to:" -ForegroundColor Green
Write-Host "      $ReportFile" -ForegroundColor Yellow
Write-Host ("=" * 70) + "`n" -ForegroundColor Green

if (-not $env:IN_TOOLKIT_LOOP -and -not [Console]::IsInputRedirected) { 
    try { Read-Host "`n  Press Enter to close window..." } catch {} 
}
