#!/usr/bin/env python3
r"""
USB Security Toolkit - Automated DFIR SOC Analyst Engine
Correlates all triage and forensics outputs from .\Reports\, performs heuristic
threat scoring (0-100), detects attack surface exposures, and generates an
automated Incident Response Briefing with prioritized PowerShell remediation.
Includes optional local Ollama LLM integration when available.
"""

import os
import sys
import glob
import re
import json
import urllib.request
import urllib.error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(SCRIPT_DIR, "Reports")

def get_latest_file(pattern):
    files = glob.glob(os.path.join(REPORTS_DIR, pattern))
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def read_file(path):
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def run_correlation():
    """Extracts facts from all available report files and computes threat score."""
    findings = {
        "host": os.environ.get("COMPUTERNAME", "VICTUS"),
        "threat_score": 0,
        "threat_level": "LOW",
        "hardened_controls": [],
        "risk_exposures": [],
        "remediation_actions": [],
        "lolbins_executed": [],
        "open_external_ports": [],
        "exclusions": [],
        "stealth_tasks": [],
        "bam_executions": [],
        "c2_alerts": [],
        "removable_footprints": [],
        "recent_scripts": [],
        "active_wan_sockets": 0
    }

    triage_txt = read_file(get_latest_file("Triage_*.txt"))
    defense_txt = read_file(get_latest_file("Defense_Evasion_*.txt"))
    volatile_txt = read_file(get_latest_file("Volatile_Evidence_*.txt"))
    persistence_txt = read_file(get_latest_file("Persistence_*.txt"))
    prefetch_txt = read_file(get_latest_file("Prefetch_Hunter_*.txt"))
    process_txt = read_file(get_latest_file("Process_Hunter_*.txt"))
    events_txt = read_file(get_latest_file("EventLogs_*.txt"))
    bam_txt = read_file(get_latest_file("BAM_Execution_Hunter_*.txt"))
    beacon_txt = read_file(get_latest_file("Beacon_Hunter_*.txt"))
    useract_txt = read_file(get_latest_file("User_Activity_*.txt"))
    sentinel_txt = read_file(get_latest_file("Live_Sentinel_*.txt"))

    score = 0

    # 1. Evaluate Host Hardening Controls
    if "BitLocker) : On" in triage_txt or "FullyEncrypted" in triage_txt:
        findings["hardened_controls"].append("Full-disk encryption active (BitLocker enabled on C:)")
    else:
        score += 15
        findings["risk_exposures"].append("BitLocker full-disk encryption is not active on system drive")
        findings["remediation_actions"].append("Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly")

    if "RunAsPPL : Hardened" in defense_txt:
        findings["hardened_controls"].append("LSASS memory protected against unprivileged dumping (RunAsPPL active)")
    elif "RunAsPPL : Unprotected" in defense_txt:
        score += 10
        findings["risk_exposures"].append("LSASS memory is unprotected (RunAsPPL disabled - vulnerable to Mimikatz)")
        findings["remediation_actions"].append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord")

    if "WDigest Plaintext : Hardened" in defense_txt:
        findings["hardened_controls"].append("Plaintext password caching disabled (WDigest hardened)")
    elif "WDigest Plaintext : CRITICAL" in defense_txt:
        score += 25
        findings["risk_exposures"].append("CRITICAL: WDigest caching plaintext credentials in memory")
        findings["remediation_actions"].append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord")

    fw_domain = re.search(r'Domain Profile\s*:\s*ENABLED', triage_txt, re.IGNORECASE)
    fw_private = re.search(r'Private Profile\s*:\s*ENABLED', triage_txt, re.IGNORECASE)
    fw_public = re.search(r'Public Profile\s*:\s*ENABLED', triage_txt, re.IGNORECASE)

    if (fw_domain and fw_public) or (fw_public and fw_private) or "FIREWALL PROFILES" in triage_txt and not re.search(r'Profile\s*:\s*DISABLED', triage_txt, re.IGNORECASE):
        findings["hardened_controls"].append("Windows Firewall fully enforced across network profiles")
    else:
        score += 20
        findings["risk_exposures"].append("Windows Firewall is disabled on one or more profiles")
        findings["remediation_actions"].append("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")

    if "EnableLUA) : Active" in defense_txt:
        findings["hardened_controls"].append("User Account Control (UAC) boundary enforced")
    elif "EnableLUA) : CRITICAL" in defense_txt:
        score += 30
        findings["risk_exposures"].append("CRITICAL: User Account Control (UAC) is completely disabled")
        findings["remediation_actions"].append("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1")

    # 2. Evaluate External Network Exposure
    port_matches = re.findall(r'Port\s+(\d+)\s+:\s+(0\.0\.0\.0|:::?)\1\s+->\s+\[PID:\s*(\d+)\]', triage_txt)
    for port, addr, pid in port_matches:
        port_num = int(port)
        if port_num == 22:
            score += 15
            findings["open_external_ports"].append(f"Port 22 (SSH Server - OpenSSH sshd.exe on PID {pid})")
            findings["risk_exposures"].append("SSH Server (Port 22) listening on ALL external network interfaces (0.0.0.0)")
            findings["remediation_actions"].append("Stop-Service sshd; Set-Service sshd -StartupType Manual  # If remote LAN access not needed")
        elif port_num == 80:
            findings["open_external_ports"].append(f"Port 80 (HTTP Server on PID {pid})")
        elif port_num in [445, 139]:
            score += 10
            findings["open_external_ports"].append(f"Port {port_num} (SMB / NetBIOS on PID {pid})")
        elif port_num not in [135, 5040, 5357]:
            findings["open_external_ports"].append(f"Port {port_num} (PID {pid})")

    # 3. Evaluate Defender Exclusions
    exclusion_matches = re.findall(r'\[Paths\]\s+:\s+(.+)', defense_txt)
    for excl in exclusion_matches:
        excl = excl.strip()
        findings["exclusions"].append(excl)
        # Check for explicitly offensive or root paths
        if re.search(r'nishang|mimikatz|payload|hack|exploit|^c:\\$', excl, re.IGNORECASE):
            score += 25
            findings["risk_exposures"].append(f"HIGH RISK: Offensive security tooling exclusion configured: '{excl}'")
            findings["remediation_actions"].append(f"Remove-MpPreference -ExclusionPath '{excl}'  # If penetration testing lab complete")
        elif re.search(r'\\temp\\|\\tmp\\', excl, re.IGNORECASE):
            score += 15
            findings["risk_exposures"].append(f"Suspicious temp directory exclusion configured: '{excl}'")
            findings["remediation_actions"].append(f"Remove-MpPreference -ExclusionPath '{excl}'")
        elif re.search(r'android|google|\.gradle|studio', excl, re.IGNORECASE):
            findings["hardened_controls"].append(f"Developer build exclusion verified: '{os.path.basename(excl)}'")
        else:
            score += 5
            findings["risk_exposures"].append(f"Custom directory exclusion configured: '{excl}'")


    # 4. Evaluate Stealth Persistence
    task_matches = re.findall(r'Task Name\s+:\s+(.+?)\s+State\s+:.*?Action Executed\s+:\s+(.+)', persistence_txt)
    for task_name, action in task_matches:
        if "-windowstyle hidden" in action.lower():
            score += 10
            findings["stealth_tasks"].append(f"{task_name.strip()} -> {action.strip()[:60]}...")
            findings["risk_exposures"].append(f"Scheduled task using hidden window flag: {task_name.strip()}")

    # 5. Evaluate LOLBins & Execution History
    lol_matches = re.findall(r'(\w+\.EXE)\s+:\s+Executed\s+(\d+)\s+time\(s\)\s+-\s+Last:\s+([\d\-:\s]+UTC)', prefetch_txt)
    for exe, runs, last_time in lol_matches:
        findings["lolbins_executed"].append(f"{exe} ({runs} runs, latest: {last_time})")

    # 6. Evaluate BAM Execution Forensics
    if bam_txt:
        bam_runs = re.findall(r'\[REMOVABLE/USB\]\s+(.+)', bam_txt)
        for br in bam_runs:
            score += 15
            findings["risk_exposures"].append(f"BAM Forensic Audit: Binary executed from removable media: {br.strip()}")
            findings["bam_executions"].append(f"[USB] {br.strip()}")
        bam_total = re.search(r'Total Entries Cataloged\s+:\s+(\d+)', bam_txt)
        if bam_total:
            findings["hardened_controls"].append(f"BAM/DAM Execution Forensics active ({bam_total.group(1)} ledger entries)")

    # 7. Evaluate Network Beaconing & C2 Sockets
    if beacon_txt:
        wan_count_match = re.search(r'Total Active Outbound Sockets\s+:\s+(\d+)', beacon_txt)
        if wan_count_match:
            findings["active_wan_sockets"] = int(wan_count_match.group(1))

        if "DETECTED" in beacon_txt and "SUSPICIOUS NETWORK SOCKET" in beacon_txt:
            c2_matches = re.findall(r'Destination\s+:\s+(.+)', beacon_txt)
            score += 35
            for c2 in c2_matches:
                findings["c2_alerts"].append(c2.strip())
                findings["risk_exposures"].append(f"CRITICAL: Active C2 Beaconing / High-Risk Socket: {c2.strip()}")
        else:
            findings["hardened_controls"].append(f"Network beaconing audit clean ({findings['active_wan_sockets']} outbound WAN sockets verified, zero C2 beacons)")

    # 8. Evaluate User Activity & Removable Media Trails
    if useract_txt:
        rem_trails = re.findall(r'(\[.+?\])\s+(.+?\.lnk)\s+:\s+(.+?\s+\(Accessed:\s+[\d\-:\s]+\))', useract_txt)
        for tag, lnk, details in rem_trails:
            findings["removable_footprints"].append(f"{tag} {lnk} -> {details}")

        if rem_trails:
            findings["risk_exposures"].append(f"Removable media footprint: {len(rem_trails)} recent shell link(s) point to external volumes/shares")

        script_trails = re.findall(r'Binary/Script Shortcuts\s+:\s+Found\s+(\d+)', useract_txt)
        if script_trails and int(script_trails[0]) > 0:
            findings["risk_exposures"].append(f"Recent execution footprints found {script_trails[0]} script/binary shortcut(s) in user profile")

    # Final Score & Level
    findings["threat_score"] = min(100, score)
    if findings["threat_score"] >= 45:
        findings["threat_level"] = "ELEVATED THREAT / HIGH RISK"
        findings["threat_color"] = "#ef4444"
    elif findings["threat_score"] >= 20:
        findings["threat_level"] = "MODERATE / LAB EXPOSURE"
        findings["threat_color"] = "#f59e0b"
    else:
        findings["threat_level"] = "CLEAN / HARDENED POSTURE"
        findings["threat_color"] = "#10b981"

    return findings

def try_ollama_briefing(findings):
    """Optional: Queries local Ollama instance on port 11434 if available."""
    try:
        # Check if Ollama is responsive
        req = urllib.request.Request("http://localhost:11434/api/tags", headers={"User-Agent": "USBSecurityToolkit"})
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name") for m in data.get("models", [])]
            if not models:
                return None
            
            # Select best local model
            chosen_model = None
            for pref in ["qwen2.5-coder:7b", "CyberDolphin:latest", "gemma4:latest", "llama3:latest", "qwen3:8b"]:
                if pref in models:
                    chosen_model = pref
                    break
            if not chosen_model:
                chosen_model = models[0]

            prompt = f"""You are an elite Digital Forensics and Incident Response (DFIR) Lead Analyst.
Analyze these host triage findings and provide a crisp, professional 3-sentence incident assessment and verdict:
- Host: {findings['host']}
- Threat Score: {findings['threat_score']}/100 ({findings['threat_level']})
- Hardened Controls: {len(findings['hardened_controls'])} active (BitLocker, RunAsPPL, Firewall)
- Exposed Services: {', '.join(findings['open_external_ports'])}
- AV Exclusions: {', '.join(findings['exclusions'])}
- Stealth Tasks: {len(findings['stealth_tasks'])}
- LOLBins Executed: {', '.join(findings['lolbins_executed'][:4])}
Focus on actionable security posture."""

            post_data = json.dumps({
                "model": chosen_model,
                "prompt": prompt,
                "stream": False
            }).encode("utf-8")

            gen_req = urllib.request.Request(
                "http://localhost:11434/api/generate",
                data=post_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(gen_req, timeout=10) as gen_resp:
                res = json.loads(gen_resp.read().decode("utf-8"))
                return (chosen_model, res.get("response", "").strip())
    except Exception:
        return None

def generate_text_briefing(findings, ai_summary=None):
    """Formats findings into a terminal-friendly executive brief."""
    lines = []
    lines.append("\n" + "=" * 75)
    lines.append("  [+] AUTOMATED DFIR SOC ANALYST INCIDENT BRIEFING")
    lines.append("=" * 75)
    lines.append(f"  Target Host  : {findings['host']}")
    lines.append(f"  Threat Index : {findings['threat_score']}/100 [{findings['threat_level']}]")
    lines.append("-" * 75)

    if ai_summary:
        lines.append(f"\n  [AI SOC Analyst Synthesis - via local {ai_summary[0]}]:")
        for p in ai_summary[1].splitlines():
            if p.strip():
                lines.append(f"    {p.strip()}")
        lines.append("")

    lines.append("  [+] KEY DEFENSIVE STRENGTHS:")
    for h in findings["hardened_controls"]:
        lines.append(f"    [+] {h}")

    if findings["risk_exposures"]:
        lines.append("\n  [!] SECURITY FINDINGS & ATTACK SURFACE EXPOSURES:")
        for r in findings["risk_exposures"]:
            lines.append(f"    [!] {r}")

    if findings.get("removable_footprints"):
        lines.append("\n  [*] REMOVABLE / EXTERNAL MEDIA ACCESS TRAILS:")
        for rf in findings["removable_footprints"][:6]:
            lines.append(f"    [*] {rf}")

    if findings["remediation_actions"]:
        lines.append("\n  [>] PRIORITIZED REMEDIATION ACTIONS (POWERSHELL):")
        for act in findings["remediation_actions"]:
            lines.append(f"    PS> {act}")

    lines.append("=" * 75 + "\n")
    return "\n".join(lines)


def main():
    findings = run_correlation()
    ai_summary = try_ollama_briefing(findings)
    briefing = generate_text_briefing(findings, ai_summary)
    print(briefing)

if __name__ == "__main__":
    main()
