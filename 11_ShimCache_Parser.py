"""
ShimCache (AppCompatCache) Forensic Parser (Python Standard Library - Zero External Dependencies)
Parses the Windows Application Compatibility Cache from HKLM SYSTEM hive.
Recovers historical executable execution evidence, timestamps, and detects deleted/staged binaries.
"""

import os
import sys
import winreg
import struct
import datetime
import csv

def get_report_paths():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(script_dir, "Reports")
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN_HOST")
    return (
        os.path.join(report_dir, f"ShimCache_{hostname}_{timestamp}.txt"),
        os.path.join(report_dir, f"ShimCache_{hostname}_{timestamp}.csv"),
        report_dir
    )

def filetime_to_dt(ft_int):
    if ft_int <= 0:
        return "N/A"
    try:
        epoch = datetime.datetime(1601, 1, 1)
        return (epoch + datetime.timedelta(microseconds=ft_int // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"

def parse_shimcache():
    txt_file, csv_file, _ = get_report_paths()

    print("=" * 65)
    print("  [*] SHIMCACHE (APPCOMPATCACHE) EXECUTION FORENSICS")
    print(f"  [*] Host: {os.environ.get('COMPUTERNAME', 'N/A')}")
    print("=" * 65)

    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            raw_data, _ = winreg.QueryValueEx(k, "AppCompatCache")
    except Exception as e:
        print(f"[-] Error accessing AppCompatCache registry key: {e}")
        return

    records = []
    deleted_executables = []
    
    # Windows 10/11 10ts format parsing
    pos = 0
    while pos < len(raw_data) - 14:
        next_sig = raw_data.find(b"10ts", pos)
        if next_sig == -1:
            break
        pos = next_sig

        try:
            entry_size = struct.unpack("<I", raw_data[pos+8:pos+12])[0]
            path_len = struct.unpack("<H", raw_data[pos+12:pos+14])[0]
            if path_len == 0 or path_len > 4096:
                pos += 4
                continue

            path = raw_data[pos+14:pos+14+path_len].decode("utf-16le", errors="ignore")
            ft_offset = pos + 14 + path_len
            filetime = struct.unpack("<Q", raw_data[ft_offset:ft_offset+8])[0]
            dt_str = filetime_to_dt(filetime)

            # Filter out non-file package identifiers (e.g. metadata strings with tabs)
            if "\t" not in path and ("\\" in path or "/" in path):
                exists_on_disk = os.path.exists(path)
                status = "EXISTS" if exists_on_disk else "DELETED / REMOVED"
                
                # Check for suspicious execution paths
                path_lower = path.lower()
                is_staged = any(s in path_lower for s in ["\\temp\\", "\\appdata\\", "\\users\\public\\", "\\downloads\\"])
                
                rec = {
                    "LastModifiedTime": dt_str,
                    "FilePath": path,
                    "FileName": os.path.basename(path),
                    "OnDisk": status,
                    "StagingPath": "ALERT_STAGED" if is_staged else "STANDARD"
                }
                records.append(rec)

                if not exists_on_disk and (".exe" in path_lower or ".dll" in path_lower or ".bat" in path_lower):
                    deleted_executables.append(rec)

            pos += entry_size + 12
        except Exception:
            pos += 4

    # Console display highlights
    print(f"[+] Total ShimCache entries recovered: {len(records)}")
    print(f"[+] Executables not found on disk (Deleted/Staged): {len(deleted_executables)}")
    
    if deleted_executables:
        print("\n  --- NOTABLE DELETED / STAGED HISTORICAL EXECUTABLES ---")
        for d in deleted_executables[:15]:
            print(f"  [HISTORICAL RUN] {d['LastModifiedTime']} | {d['FilePath']}")

    # Export CSV
    if records:
        fieldnames = ["LastModifiedTime", "FileName", "FilePath", "OnDisk", "StagingPath"]
        with open(csv_file, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)

    # Export TXT
    with open(txt_file, "w", encoding="utf-8") as tf:
        tf.write("=" * 65 + "\n")
        tf.write(f"  WINDOWS SHIMCACHE FORENSIC EXECUTION REPORT\n")
        tf.write(f"  Host: {os.environ.get('COMPUTERNAME', 'N/A')}\n")
        tf.write(f"  Generated: {datetime.datetime.now().isoformat()}\n")
        tf.write(f"  Total Records: {len(records)} | Deleted/Missing on Disk: {len(deleted_executables)}\n")
        tf.write("=" * 65 + "\n\n")

        if deleted_executables:
            tf.write("!!! EXECUTABLES RUN HISTORICALLY BUT REMOVED FROM DISK !!!\n")
            for d in deleted_executables:
                tf.write(f"  [{d['LastModifiedTime']}] {d['FilePath']} (Staging: {d['StagingPath']})\n")
            tf.write("\n" + "-" * 65 + "\n\n")

        tf.write("--- ALL HISTORICAL EXECUTION RECORDS ---\n")
        for r in records:
            tf.write(f"  [{r['LastModifiedTime']}] [{r['OnDisk']}] {r['FilePath']}\n")

    print("\n" + "=" * 65)
    print("  [+] SHIMCACHE AUDIT COMPLETE!")
    print(f"      Report:   {txt_file}")
    print(f"      Manifest: {csv_file}")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    parse_shimcache()
    if not os.environ.get("IN_TOOLKIT_LOOP"):
        try:
            input("\nPress Enter to close window...")
        except Exception:
            pass
