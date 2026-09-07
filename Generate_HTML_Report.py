#!/usr/bin/env python3
r"""
USB Security Toolkit - Executive Tactical HTML Dashboard Generator
Parses all triage and forensics outputs from .\Reports\ and compiles
a unified, dark-mode, single-file offline forensic report with KPI metrics
and MITRE ATT&CK technique mapping.
"""


import os
import sys
import glob
import re
import json
import datetime
import html
import webbrowser

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(SCRIPT_DIR, "Reports")

def get_latest_file(pattern):
    files = glob.glob(os.path.join(REPORTS_DIR, pattern))
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def read_file_content(path):
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

def count_occurrences(text, regex):
    return len(re.findall(regex, text, re.IGNORECASE))

def parse_report_sections(content):
    """Splits custom console-style text reports into structured sections."""
    sections = []
    current_title = "General Telemetry"
    current_lines = []
    
    for line in content.splitlines():
        clean_line = line.strip()
        if clean_line.startswith("[+]"):
            if current_lines:
                sections.append((current_title, "\n".join(current_lines)))
                current_lines = []
            current_title = clean_line.replace("[+]", "").strip()
        elif clean_line.startswith("===") or clean_line.startswith("---"):
            continue
        else:
            if clean_line:
                current_lines.append(line)
                
    if current_lines:
        sections.append((current_title, "\n".join(current_lines)))
        
    return sections

def generate_dashboard():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    hostname = os.environ.get("COMPUTERNAME", "VICTUS-HOST")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Gather Latest Reports
    report_map = {
        "triage": get_latest_file("Windows_Triage_*.txt"),
        "audit_json": get_latest_file("Audit_*.json"),
        "usb": get_latest_file("USB_Forensics_*.txt"),
        "persistence": get_latest_file("Persistence_*.txt"),
        "volatile": get_latest_file("Volatile_Evidence_*.txt"),
        "events": get_latest_file("Event_Log_*.txt"),
        "wifi": get_latest_file("WiFi_Forensics_*.txt"),
        "browser": get_latest_file("Browser_*.txt") or get_latest_file("Browser_*.json"),
        "shimcache": get_latest_file("ShimCache_*.txt"),
        "tree": get_latest_file("Process_Hunter_*.txt"),
        "domain": get_latest_file("Domain_Recon_*.txt"),
        "prefetch": get_latest_file("Prefetch_Hunter_*.txt"),
        "defense": get_latest_file("Defense_Evasion_*.txt"),
        "ioc": get_latest_file("IOC_Scan_*.txt"),
        "bam": get_latest_file("BAM_Execution_Hunter_*.txt"),
        "beacon": get_latest_file("Beacon_Hunter_*.txt"),
        "user_activity": get_latest_file("User_Activity_*.txt"),
        "sentinel": get_latest_file("Live_Sentinel_*.txt")
    }

    # 2. Run Automated SOC Threat Analyst Correlation
    try:
        import Analyze_Reports
        analyst_findings = Analyze_Reports.run_correlation()
        ai_brief = Analyze_Reports.try_ollama_briefing(analyst_findings)
    except Exception as e:
        analyst_findings = None
        ai_brief = None

    # 3. Extract Key Threat Indicators & Metrics
    total_artifacts = 0
    high_alerts = 0
    medium_warns = 0

    combined_text = ""
    for k, p in report_map.items():
        if p and p.endswith(".txt"):
            txt = read_file_content(p)
            combined_text += "\n" + txt
            total_artifacts += 1
            high_alerts += count_occurrences(txt, r'ALERT|CRITICAL|SUSPICIOUS|MALICIOUS')
            medium_warns += count_occurrences(txt, r'WARN|EXCLUSION')

    # Threat Assessment
    if analyst_findings:
        overall_status = analyst_findings["threat_level"]
        status_color = analyst_findings["threat_color"]
        status_badge = f"THREAT INDEX: {analyst_findings['threat_score']}/100"
    elif high_alerts > 5:
        overall_status = "CRITICAL ELEVATED THREAT"
        status_color = "#ef4444"
        status_badge = "CRITICAL COMPROMISE RISK"
    elif high_alerts > 0 or medium_warns > 3:
        overall_status = "SUSPICIOUS ACTIVITY DETECTED"
        status_color = "#f59e0b"
        status_badge = "ATTENTION REQUIRED"
    else:
        overall_status = "SYSTEM INTEGRITY CLEAN"
        status_color = "#10b981"
        status_badge = "LOW RISK"

    # 4. Generate HTML Content
    output_html_file = os.path.join(REPORTS_DIR, f"Executive_Forensic_Report_{hostname}_{timestamp_file}.html")

    html_parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DFIR Executive Report - {hostname}</title>
<style>
  :root {{
    --bg: #090d16;
    --surface: #111827;
    --surface-card: #1e293b;
    --border: #334155;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --cyan: #06b6d4;
    --green: #10b981;
    --amber: #f59e0b;
    --red: #ef4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }}
  body {{ background-color: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
  .header-left h1 {{ font-size: 26px; font-weight: 800; color: #fff; letter-spacing: 0.5px; }}
  .header-left h1 span {{ color: var(--cyan); }}
  .header-meta {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; }}
  
  /* KPI Cards */
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .kpi-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }}
  .kpi-title {{ font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .kpi-value {{ font-size: 30px; font-weight: 800; margin-top: 4px; }}

  /* MITRE ATT&CK Matrix */
  .mitre-bar {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin-bottom: 28px; }}
  .mitre-title {{ font-size: 13px; font-weight: 700; text-transform: uppercase; color: var(--cyan); margin-bottom: 10px; }}
  .tags-wrapper {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .mitre-tag {{ background: #0f172a; border: 1px solid var(--cyan); color: #38bdf8; font-size: 11px; padding: 4px 10px; border-radius: 4px; font-weight: 600; }}

  /* Accordion Module Cards */
  .module-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  .module-header {{ background: #1e293b; padding: 14px 20px; font-weight: 700; font-size: 15px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
  .module-header:hover {{ background: #283548; }}
  .module-body {{ padding: 18px 20px; font-size: 13px; color: #cbd5e1; white-space: pre-wrap; word-break: break-word; max-height: 450px; overflow-y: auto; background: #0b1120; }}
  
  /* Log styling */
  .log-line {{ margin-bottom: 3px; }}
  .log-alert {{ color: var(--red); font-weight: 700; }}
  .log-warn {{ color: var(--amber); font-weight: 600; }}
  .log-good {{ color: var(--green); }}
  .log-info {{ color: #94a3b8; }}

  .footer {{ text-align: center; margin-top: 40px; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 16px; }}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>USB FORENSICS &bull; <span>LIVE TRIAGE DASHBOARD</span></h1>
      <div class="header-meta">HOST: <strong>{hostname}</strong> &bull; GENERATED: <strong>{now_str}</strong> &bull; ANALYST: <strong>Austin Davis</strong></div>
    </div>
    <div>
      <span class="badge" style="background: {status_color}22; color: {status_color}; border: 1px solid {status_color};">
        {status_badge}
      </span>
    </div>
  </div>

  <!-- KPI Grid -->
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Host Integrity Status</div>
      <div class="kpi-value" style="color: {status_color}; font-size: 18px; margin-top: 10px;">{overall_status}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Critical / Alert Flags</div>
      <div class="kpi-value" style="color: var(--red);">{high_alerts}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Suspicious Warnings</div>
      <div class="kpi-value" style="color: var(--amber);">{medium_warns}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Forensic Modules Compiled</div>
      <div class="kpi-value" style="color: var(--cyan);">{total_artifacts}</div>
    </div>
  </div>

  <!-- MITRE ATT&CK Techniques Tracked -->
  <div class="mitre-bar">
    <div class="mitre-title">Mapped MITRE ATT&CK Enterprise Techniques</div>
    <div class="tags-wrapper">
      <span class="mitre-tag">T1059: Command & Scripting Interpreters</span>
      <span class="mitre-tag">T1562: Impair Defenses (AV / Firewall / Logging)</span>
      <span class="mitre-tag">T1547: Boot or Logon Autostart Execution (Persistence)</span>
      <span class="mitre-tag">T1036: Masquerading System Binaries</span>
      <span class="mitre-tag">T1003.001: OS Credential Dumping (LSASS / WDigest)</span>
      <span class="mitre-tag">T1052: Exfiltration Over Physical Medium (USBSTOR)</span>
      <span class="mitre-tag">T1082: System Information Discovery</span>
      <span class="mitre-tag">T1049: System Network Connections Discovery</span>
      <span class="mitre-tag">T1071: C2 Socket & Beaconing Inspection</span>
      <span class="mitre-tag">T1083: File & Directory Discovery (User LNK / JumpLists)</span>
      <span class="mitre-tag">T1204: User Execution (BAM / DAM Ledgers)</span>
    </div>
  </div>
"""]

    # Render Automated SOC Analyst Briefing Card
    if analyst_findings:
        strengths_html = "".join([f'<li style="color: #10b981; margin-bottom: 4px;">✓ {html.escape(s)}</li>' for s in analyst_findings["hardened_controls"]])
        findings_html = "".join([f'<li style="color: #f87171; margin-bottom: 4px;">⚠ {html.escape(f)}</li>' for f in analyst_findings["risk_exposures"]])
        remediation_html = "".join([f'<div style="background: #090d16; border-left: 3px solid #06b6d4; padding: 6px 10px; margin-bottom: 6px; font-family: monospace; color: #38bdf8; font-size: 12px;">PS&gt; {html.escape(r)}</div>' for r in analyst_findings["remediation_actions"]])
        
        ai_banner = ""
        if ai_brief:
            ai_banner = f"""
      <div style="background: #1e1b4b; border: 1px solid #6366f1; border-radius: 6px; padding: 12px; margin-bottom: 16px;">
        <div style="font-size: 11px; font-weight: 700; color: #a5b4fc; text-transform: uppercase; margin-bottom: 4px;">
          🤖 Local AI SOC Analyst Synthesis (via {ai_brief[0]})
        </div>
        <div style="font-size: 13px; color: #e0e7ff; line-height: 1.4;">{html.escape(ai_brief[1])}</div>
      </div>
"""

        html_parts.append(f"""
  <!-- SOC Threat Analyst Briefing Card -->
  <div style="background: var(--surface); border: 2px solid {status_color}; border-radius: 8px; padding: 20px; margin-bottom: 24px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h2 style="font-size: 17px; font-weight: 800; color: #fff;">
        🛡️ AUTOMATED DFIR SOC ANALYST BRIEFING
      </h2>
      <span class="badge" style="background: {status_color}22; color: {status_color}; border: 1px solid {status_color};">
        THREAT SCORE: {analyst_findings['threat_score']}/100
      </span>
    </div>

    {ai_banner}

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
      <div>
        <h3 style="font-size: 13px; text-transform: uppercase; color: #10b981; margin-bottom: 8px;">Defensive Strengths Verified</h3>
        <ul style="list-style: none; font-size: 13px;">
          {strengths_html}
        </ul>
      </div>
      <div>
        <h3 style="font-size: 13px; text-transform: uppercase; color: #ef4444; margin-bottom: 8px;">Security Exposures &amp; Blind Spots</h3>
        <ul style="list-style: none; font-size: 13px;">
          {findings_html if findings_html else '<li style="color: #10b981;">✓ Zero critical risk exposures identified.</li>'}
        </ul>
      </div>
    </div>

    <div>
      <h3 style="font-size: 13px; text-transform: uppercase; color: #06b6d4; margin-bottom: 8px;">Prioritized Remediation Action Plan (PowerShell)</h3>
      {remediation_html if remediation_html else '<div style="color: #94a3b8; font-size: 13px;">No immediate remediation actions required. System hardened.</div>'}
    </div>
  </div>
""")

    # Module definitions to display
    display_modules = [
        ("BAM/DAM Execution Forensics (Per-User Registry Ledger)", report_map.get("bam"), "T1204 / T1059"),
        ("Network Beaconing & C2 Socket Threat Hunter", report_map.get("beacon"), "T1071 / T1049"),
        ("User Activity & Removable Media Forensic Trails", report_map.get("user_activity"), "T1052 / T1083"),
        ("Live Field Sentinel Real-Time Watch Ledger", report_map.get("sentinel"), "T1059 / T1052"),
        ("Prefetch Execution Forensics (MAM Decompression)", report_map["prefetch"], "T1059 / T1204"),
        ("Defense Evasion & Security Tampering Audit", report_map["defense"], "T1562"),
        ("Process Tree & Anomaly Lineage Hunter", report_map["tree"], "T1059 / T1036"),
        ("ShimCache (AppCompatCache) Historical Executions", report_map["shimcache"], "T1082"),
        ("USB Historical Storage Artifacts (USBSTOR)", report_map["usb"], "T1052"),
        ("Persistence Hunter (Run Keys, Services, Tasks, WMI)", report_map["persistence"], "T1547"),
        ("Volatile Evidence Snapshot (Memory, Sockets, ARP)", report_map["volatile"], "T1049"),
        ("Event Log Hunter (Logon Failures, PowerShell 4104)", report_map["events"], "T1562.002"),
        ("Wireless Network Profiles & Credentials", report_map["wifi"], "T1082"),
        ("Quick Windows Baseline Triage", report_map["triage"], "T1082"),
        ("Domain Reconnaissance & SMB Shares", report_map["domain"], "T1087")
    ]

    for title, filepath, mitre in display_modules:
        if not filepath or not os.path.exists(filepath):
            continue
        raw_text = read_file_content(filepath)
        filename = os.path.basename(filepath)
        
        # Colorize logs
        formatted_lines = []
        for line in raw_text.splitlines():
            safe_line = html.escape(line)
            if re.search(r'ALERT|CRITICAL|DETECTED|FLAGGED', safe_line, re.IGNORECASE):
                formatted_lines.append(f'<div class="log-line log-alert">{safe_line}</div>')
            elif re.search(r'WARN|EXCLUSION', safe_line, re.IGNORECASE):
                formatted_lines.append(f'<div class="log-line log-warn">{safe_line}</div>')
            elif re.search(r'Clean|Hardened|Normal|Enabled|Active|Good', safe_line, re.IGNORECASE):
                formatted_lines.append(f'<div class="log-line log-good">{safe_line}</div>')
            else:
                formatted_lines.append(f'<div class="log-line log-info">{safe_line}</div>')
        
        body_content = "\n".join(formatted_lines)
        
        html_parts.append(f"""
  <div class="module-card">
    <div class="module-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
      <span>📁 {title}</span>
      <span style="font-size: 11px; color: var(--cyan); font-weight: 600;">{mitre} &bull; {filename} [Toggle]</span>
    </div>
    <div class="module-body">
{body_content}
    </div>
  </div>
""")

    html_parts.append("""
  <div class="footer">
    USB Security &amp; Digital Forensics Incident Response Toolkit &bull; Portable Live Triage Framework &bull; Austin Davis
  </div>
</div>
</body>
</html>
""")

    full_html = "\n".join(html_parts)
    with open(output_html_file, "w", encoding="utf-8") as f:
        f.write(full_html)
        
    print(f"[+] SUCCESS: Executive HTML Report generated at:\n    {output_html_file}")
    
    # Open report automatically in default browser if interactive
    try:
        webbrowser.open(f"file:///{output_html_file.replace(os.sep, '/')}")
    except Exception:
        pass
        
    return output_html_file

if __name__ == "__main__":
    generate_dashboard()
