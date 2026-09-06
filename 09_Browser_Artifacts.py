"""
Browser Forensic Artifacts Auditor (Python Standard Library - Zero Dependencies)
Safely extracts recent downloads and web navigation history from Microsoft Edge
and Google Chrome SQLite databases without locking active browser sessions.
"""

import os
import sys
import sqlite3
import shutil
import tempfile
import csv
import datetime

def get_report_paths():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(script_dir, "Reports")
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN_HOST")
    return (
        os.path.join(report_dir, f"Browser_Artifacts_{hostname}_{timestamp}.txt"),
        os.path.join(report_dir, f"Browser_Downloads_{hostname}_{timestamp}.csv"),
        report_dir
    )

def webkit_to_datetime(webkit_timestamp):
    """Converts Chromium WebKit microseconds timestamp to readable UTC string."""
    try:
        if not webkit_timestamp:
            return "N/A"
        epoch_start = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=int(webkit_timestamp))
        return (epoch_start + delta).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Unknown Date"

def extract_from_browser(browser_name, history_path, txt_lines, csv_records):
    if not os.path.exists(history_path):
        return

    txt_lines.append(f"\n[{browser_name.upper()} FORENSIC ARTIFACTS]")
    print(f"\n[*] Inspecting {browser_name} database...")

    # Copy to temp file to bypass browser database locks
    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "History_Copy.db")
    try:
        shutil.copy2(history_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # 1. Extract Recent File Downloads
        try:
            cursor.execute("""
                SELECT target_path, tab_url, total_bytes, start_time 
                FROM downloads 
                ORDER BY start_time DESC LIMIT 25
            """)
            rows = cursor.fetchall()
            txt_lines.append(f"  --- RECENT DOWNLOADS ({len(rows)} entries) ---")
            if rows:
                for row in rows:
                    target_path = row[0]
                    url = row[1]
                    size_mb = round((row[2] or 0) / (1024 * 1024), 2)
                    dl_time = webkit_to_datetime(row[3])
                    fname = os.path.basename(target_path)

                    txt_lines.append(f"  [DOWNLOAD] {fname} ({size_mb} MB) at {dl_time}")
                    txt_lines.append(f"             Source: {url}")
                    txt_lines.append(f"             Path:   {target_path}\n")

                    csv_records.append({
                        "Browser": browser_name,
                        "Type": "Download",
                        "File": fname,
                        "SizeMB": size_mb,
                        "Time": dl_time,
                        "URL": url,
                        "TargetPath": target_path
                    })
                    print(f"  [+] Download: {fname} ({size_mb} MB) from {url[:60]}")
            else:
                txt_lines.append("  No recorded downloads in database.\n")
        except Exception as e:
            txt_lines.append(f"  Error reading downloads table: {e}\n")

        # 2. Extract Recent Visited URLs
        try:
            cursor.execute("""
                SELECT url, title, last_visit_time 
                FROM urls 
                ORDER BY last_visit_time DESC LIMIT 25
            """)
            url_rows = cursor.fetchall()
            txt_lines.append(f"  --- RECENT WEB ACTIVITY ({len(url_rows)} entries) ---")
            for u in url_rows:
                url_str = u[0]
                title_str = (u[1] or "No Title").strip()
                v_time = webkit_to_datetime(u[2])
                txt_lines.append(f"  [VISIT] {v_time} | {title_str[:50]}")
                txt_lines.append(f"          URL: {url_str}\n")
        except Exception as e:
            txt_lines.append(f"  Error reading urls table: {e}\n")

        conn.close()
    except Exception as e:
        txt_lines.append(f"  Failed opening {browser_name} database: {e}\n")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def audit_browsers():
    txt_report, csv_report, _ = get_report_paths()
    txt_lines = [
        "=" * 65,
        "  USB BROWSER HISTORY & DOWNLOAD FORENSICS",
        f"  Host: {os.environ.get('COMPUTERNAME', 'N/A')}",
        f"  Generated: {datetime.datetime.now().isoformat()}",
        "=" * 65
    ]
    csv_records = []

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    targets = [
        ("Microsoft Edge", os.path.join(local_app_data, r"Microsoft\Edge\User Data\Default\History")),
        ("Google Chrome", os.path.join(local_app_data, r"Google\Chrome\User Data\Default\History"))
    ]

    for name, path in targets:
        extract_from_browser(name, path, txt_lines, csv_records)

    # Save TXT report
    with open(txt_report, "w", encoding="utf-8", errors="ignore") as tf:
        tf.write("\n".join(txt_lines))

    # Save CSV downloads
    if csv_records:
        fieldnames = ["Browser", "Type", "File", "SizeMB", "Time", "URL", "TargetPath"]
        with open(csv_report, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_records)

    print("\n" + "=" * 65)
    print("  [+] BROWSER ARTIFACT AUDIT COMPLETE!")
    print(f"      Report:   {txt_report}")
    if csv_records:
        print(f"      Manifest: {csv_report}")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    audit_browsers()
    if not os.environ.get("IN_TOOLKIT_LOOP"):
        try:
            input("\nPress Enter to close window...")
        except Exception:
            pass
