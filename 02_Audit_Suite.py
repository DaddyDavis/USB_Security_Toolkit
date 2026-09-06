"""USB Security Audit Suite (Python Standard Library - Zero External Dependencies)

Performs live system triage, persistence detection, suspicious process
auditing,
network exposure analysis, and generates both Human-Readable (.txt) and JSON
(.json) reports.
"""

import os
import sys
import ctypes
import platform
import subprocess
import datetime
import json
import winreg


def get_base_paths():
  script_dir = os.path.dirname(os.path.abspath(__file__))
  report_dir = os.path.join(script_dir, "Reports")
  os.makedirs(report_dir, exist_ok=True)
  timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
  hostname = os.environ.get("COMPUTERNAME", "UNKNOWN_HOST")
  return (
      report_dir,
      os.path.join(report_dir, f"Audit_{hostname}_{timestamp}.txt"),
      os.path.join(report_dir, f"Audit_{hostname}_{timestamp}.json"),
  )


def audit_privileges():
  try:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
  except Exception:
    is_admin = False

  return {
      "hostname": os.environ.get("COMPUTERNAME", "N/A"),
      "current_user": os.environ.get("USERNAME", "N/A"),
      "is_admin": is_admin,
      "integrity": (
          "High Integrity (Elevated Admin)"
          if is_admin
          else "Medium Integrity (Standard User)"
      ),
      "os_version": platform.platform(),
  }


def audit_persistence_registry():
  findings = []
  locations = [
      (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
      (
          winreg.HKEY_LOCAL_MACHINE,
          r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
      ),
      (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
      (
          winreg.HKEY_CURRENT_USER,
          r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
      ),
  ]

  for hive, subkey in locations:
    hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
    try:
      with winreg.OpenKey(hive, subkey) as key:
        count = winreg.QueryInfoKey(key)[1]
        for i in range(count):
          name, val, _ = winreg.EnumValue(key, i)
          findings.append({
              "location": f"{hive_name}\\{subkey}",
              "name": name,
              "command": str(val),
          })
    except (FileNotFoundError, PermissionError):
      continue

  return findings


def audit_suspicious_processes():
  suspicious_indicators = ["appdata", "temp", "public", "downloads"]
  flagged = []

  try:
    cmd = ["wmic", "process", "get", "ProcessId,Name,ExecutablePath", "/format:csv"]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    lines = res.stdout.strip().splitlines()

    for line in lines[1:]:
      parts = [p.strip() for p in line.split(",") if p.strip()]
      if len(parts) >= 3:
        exe_path = parts[1]
        name = parts[2]
        pid = parts[3] if len(parts) > 3 else "N/A"

        path_lower = exe_path.lower()
        if any(ind in path_lower for ind in suspicious_indicators):
          flagged.append({"pid": pid, "name": name, "path": exe_path})
  except Exception:
    pass

  return flagged


def audit_listening_ports():
  listeners = []
  try:
    res = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True, timeout=10
    )
    for line in res.stdout.splitlines():
      tokens = line.split()
      if len(tokens) >= 5 and tokens[0].upper() == "TCP" and tokens[3] == "LISTENING":
        listeners.append({
            "proto": "TCP",
            "local_address": tokens[1],
            "state": tokens[3],
            "pid": tokens[4],
        })
  except Exception:
    pass
  return listeners


def audit_hosts_file():
  hosts_path = os.path.join(
      os.environ.get("SystemRoot", r"C:\Windows"),
      r"System32\drivers\etc\hosts",
  )
  custom_entries = []
  if os.path.exists(hosts_path):
    try:
      with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
          clean = line.strip()
          if clean and not clean.startswith("#"):
            custom_entries.append(clean)
    except Exception as e:
      custom_entries.append(f"Error reading hosts file: {e}")
  return custom_entries


def run_full_audit():
  report_dir, txt_report, json_report = get_base_paths()

  print("=" * 65)
  print("  [*] RUNNING USB SECURITY AUDIT SUITE (PYTHON STANDALONE)")
  print("=" * 65)

  privs = audit_privileges()
  reg_persist = audit_persistence_registry()
  sus_procs = audit_suspicious_processes()
  network = audit_listening_ports()
  hosts = audit_hosts_file()

  data = {
      "timestamp": datetime.datetime.now().isoformat(),
      "system_identity": privs,
      "registry_persistence": reg_persist,
      "suspicious_process_paths": sus_procs,
      "listening_ports": network,
      "hosts_tampering": hosts,
  }

  # Export JSON
  with open(json_report, "w", encoding="utf-8") as jf:
    json.dump(data, jf, indent=2)

  # Export Human-Readable TXT
  with open(txt_report, "w", encoding="utf-8") as tf:
    tf.write("=" * 65 + "\n")
    tf.write(f"  USB SECURITY AUDIT REPORT: {privs['hostname']}\n")
    tf.write(f"  Generated: {data['timestamp']}\n")
    tf.write("=" * 65 + "\n\n")

    tf.write(f"[1] HOST PRIVILEGES\n")
    tf.write(f"    User:      {privs['current_user']}\n")
    tf.write(f"    Elevation: {privs['integrity']}\n")
    tf.write(f"    OS:        {privs['os_version']}\n\n")

    tf.write(f"[2] REGISTRY AUTORUNS ({len(reg_persist)} entries)\n")
    for r in reg_persist:
      tf.write(f"    [{r['location']}] {r['name']} -> {r['command']}\n")
    tf.write("\n")

    tf.write(
        f"[3] SUSPICIOUS PROCESS LOCATIONS ({len(sus_procs)} flagged in"
        " AppData/Temp)\n"
    )
    if not sus_procs:
      tf.write("    None detected in common staging directories.\n")
    for sp in sus_procs:
      tf.write(f"    [PID: {sp['pid']}] {sp['name']} ({sp['path']})\n")
    tf.write("\n")

    tf.write(f"[4] LISTENING PORTS ({len(network)} ports)\n")
    for net in network:
      tf.write(f"    {net['local_address']} -> PID: {net['pid']}\n")
    tf.write("\n")

    tf.write(f"[5] HOSTS FILE INTEGRITY\n")
    if not hosts:
      tf.write("    Standard hosts file (No custom redirects).\n")
    for h in hosts:
      tf.write(f"    Entry: {h}\n")
    tf.write("\n" + "=" * 65 + "\n")

  # Console summary
  print(f"[+] User:         {privs['current_user']}")
  print(f"[+] Privilege:    {privs['integrity']}")
  print(f"[+] Persistence:  {len(reg_persist)} autorun keys discovered")
  print(f"[+] Staged Exes:  {len(sus_procs)} processes running from AppData/Temp")
  print(f"[+] Ports Open:   {len(network)} listening sockets")
  print(f"[+] Hosts File:   {'CLEAN' if not hosts else 'CUSTOM ENTRIES FOUND'}")
  print("=" * 65)
  print(f"[+] Reports saved to:")
  print(f"    TXT:  {txt_report}")
  print(f"    JSON: {json_report}")
  print("=" * 65)


if __name__ == "__main__":
  run_full_audit()
  if not os.environ.get("IN_TOOLKIT_LOOP"):
    try:
      input("\nPress Enter to close window...")
    except Exception:
      pass
