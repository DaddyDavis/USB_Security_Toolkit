# USB Security and Forensics Incident Response Toolkit

A modular, standalone Windows Incident Response (IR) and Digital Forensics triage framework engineered to run directly from a portable USB drive. Built for rapid, live-host artifact collection, forensic triage, and malicious persistence hunting without leaving a heavy footprint on the target system.

---

## Key Features

* **Zero-Install Portable Architecture**: Executes natively using PowerShell 5.1/7+ and optional portable Python 3.12 (via `python_embed`).
* **Live Volatile Evidence Collection**: Captures running processes, established network connections, ARP tables, logged-on sessions, and DNS cache prior to host shutdown.
* **Deep Persistence and Evasion Hunting**: Audits Run keys, Tasks, WMI persistence, plus Windows Defender tampering, firewall drops, WDigest plaintext caching, and UAC crippling.
* **Forensic Artifact Parsing**: Extracts USB connection history (`USBSTOR`), BAM/DAM execution ledgers, UserAssist ROT13, LNK shortcuts, JumpLists, ShimCache (`AppCompatCache`), WLAN profiles, browser history, and in-memory decompressed Prefetch (`.pf`) run counts.
* **Network Beaconing and C2 Sockets**: Audits live outbound TCP WAN sockets against standard C2 ports (Cobalt Strike, Metasploit, Sliver, Mythic), dynamic DNS indicators, and listening attack surfaces.
* **Live Field Sentinel Watch Mode**: Real-time tactical HUD continuously monitoring live process creation, removable USB insertions/removals, and new network connections.
* **Executive Tactical HTML Dashboard**: Compiles all host telemetry into an interactive, offline single-file dark-mode HTML dashboard mapped against the MITRE ATT&CK matrix.
* **Automated IOC Hash Matching**: Hashes files across target paths (MD5/SHA-256) and flags matches against known Indicators of Compromise.
* **Interactive CLI Master Console**: Unified launcher (`Launch_Toolkit.bat`) providing interactive or single-click automated full-suite execution (15 integrated modules).

---

## Module Architecture

| Module | Engine | Description |
| :--- | :--- | :--- |
| `01_Triage_Windows.ps1` | PowerShell | System baseline, OS build, hotfixes/patches, uptime, and environment variables. |
| `02_Audit_Suite.py` | Python | Deep host audit: user accounts, local groups, listening ports, and installed software. |
| `03_USB_Forensics.ps1` | PowerShell | Enumerates `USBSTOR` registry, mounted volume GUIDs, friendly device names, and serials. |
| `04_Persistence_Hunter.ps1` | PowerShell | Scans Registry Run keys, Task Scheduler, Startup directories, and WMI persistence. |
| `05_Volatile_Evidence.ps1` | PowerShell | Dumps volatile memory triage, active TCP/UDP sockets, process owner mapping, and ARP cache. |
| `06_File_Hasher_IOC.py` | Python | Multithreaded MD5/SHA-256 file hashing against `ioc_hashes.txt` threat signatures. |
| `07_Event_Log_Hunter.ps1` | PowerShell | Queries Windows Event Logs for critical Event IDs (4624/4625 logons, 4688 process creation, 4104 script blocks). |
| `08_WiFi_Forensics.ps1` | PowerShell | Extracts wireless network profiles, SSIDs, connection history, and authentication types. |
| `09_Browser_Artifacts.py` | Python | Triages Chromium, Edge, and Firefox history, downloads, and search terms. |
| `10_Quick_Remediate.ps1` | PowerShell | Rapid containment module: terminate suspicious processes, disable NICs, or isolate host. |
| `11_ShimCache_Parser.py` | Python | Parses `AppCompatCache` from the SYSTEM hive to identify historical program execution. |
| `12_Process_Tree_Hunter.ps1` | PowerShell | Maps parent-child process relationships, flagging anomalies (e.g., Office spawning PowerShell/cmd). |
| `13_Domain_Recon.ps1` | PowerShell | Active Directory reconnaissance: Domain Controllers, domain trusts, and AD forest structure. |
| `14_Prefetch_Hunter.ps1` | PowerShell | In-memory MAM decompression for Windows 10/11 Prefetch (`.pf`), run counts, and timeline analysis. |
| `15_Defense_Evasion.ps1` | PowerShell | Audits security control tampering: Defender real-time bypasses, injected exclusions, WDigest, and UAC. |
| `16_BAM_Hunter.ps1` | PowerShell | Background Activity Moderator (BAM/DAM) execution ledger: decodes FILETIME timestamps, resolves user SIDs, and flags USB binaries. |
| `17_Beacon_Hunter.ps1` | PowerShell | Audits live outbound TCP sockets for C2 ports, dynamic DNS TLDs, and external listening attack surface. |
| `18_User_Activity.ps1` | PowerShell | Forensically parses LNK shell shortcuts, JumpLists, Explorer TypedPaths, and ROT13 UserAssist records for USB trails. |
| `19_Live_Sentinel.ps1` | PowerShell | Interactive real-time tactical HUD monitoring process creation, removable USB insertions, and new sockets. |
| `Analyze_Reports.py` | Python | Automated DFIR threat correlation engine: heuristic scoring (0-100), attack surface exposures, and prioritized remediation. |
| `Generate_HTML_Report.py` | Python | Compiles all triage logs into a dark-mode, single-file offline HTML executive forensic dashboard. |

---

## Getting Started

### Portable USB Deployment
1. Clone or copy this repository to the root of your USB drive:
   ```bash
   git clone https://github.com/DaddyDavis/USB_Security_Toolkit.git
   ```
2. (Optional) Run `Setup_Portable_Python.ps1` to download the standalone embeddable Python package directly to the drive:
   ```powershell
   .\Setup_Portable_Python.ps1
   ```
3. Insert the USB drive into the target Windows host and launch as Administrator:
   * **Full Interactive Menu**: Double-click `Launch_Toolkit.bat`
   * **PowerShell Only Triage**: Double-click `Run_PowerShell_Audit.bat`
   * **Python Only Triage**: Double-click `Run_Python_Audit.bat`

All triage logs and reports are automatically timestamped and exported into the `Reports/` directory.

---

## License and Disclaimer

This toolkit is designed for authorized digital forensics, security auditing, and educational use by cybersecurity professionals, system administrators, and incident response personnel. Ensure proper authorization before analyzing systems you do not own.
