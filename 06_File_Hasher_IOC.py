"""
USB File Hasher & IOC Matcher (Python Standard Library - Zero Dependencies)
Computes SHA-256 and MD5 cryptographic hashes for files in target paths,
detects known malicious IOC hashes from 'ioc_hashes.txt', and exports CSV manifests.
"""

import os
import sys
import hashlib
import csv
import datetime

BUFFER_SIZE = 65536  # 64 KB read blocks for fast memory-efficient hashing

def get_report_paths():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(script_dir, "Reports")
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN_HOST")
    return (
        os.path.join(report_dir, f"File_Hashes_{hostname}_{timestamp}.csv"),
        os.path.join(report_dir, f"File_Hashes_{hostname}_{timestamp}.txt"),
        script_dir
    )

def load_ioc_hashes(script_dir):
    ioc_path = os.path.join(script_dir, "ioc_hashes.txt")
    iocs = set()
    if os.path.exists(ioc_path):
        try:
            with open(ioc_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip().lower()
                    if clean and not clean.startswith("#"):
                        # Extract hash token (in case lines have comments or filenames)
                        hash_val = clean.split()[0]
                        iocs.add(hash_val)
        except Exception as e:
            print(f"[-] Warning: Failed reading ioc_hashes.txt: {e}")
    return iocs

def hash_file(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(BUFFER_SIZE):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest().lower(), sha256.hexdigest().lower(), None
    except Exception as e:
        return None, None, str(e)

def scan_target(target_dir, iocs):
    csv_file, txt_file, script_dir = get_report_paths()
    results = []
    ioc_hits = []

    print("=" * 65)
    print("  [*] USB FORENSIC FILE HASHER & IOC SCANNER")
    print(f"  [*] Target Directory: {target_dir}")
    print(f"  [*] Loaded IOC Signatures: {len(iocs)} hashes")
    print("=" * 65)

    if not os.path.exists(target_dir):
        print(f"[-] Error: Target path '{target_dir}' does not exist.")
        return

    scanned_count = 0
    error_count = 0

    for root, _, files in os.walk(target_dir):
        for file in files:
            full_path = os.path.join(root, file)
            scanned_count += 1
            try:
                size_bytes = os.path.getsize(full_path)
            except Exception:
                size_bytes = 0

            # Cap individual file scan at 250 MB for live field triage speed
            if size_bytes > 250 * 1024 * 1024:
                continue

            md5_val, sha256_val, err = hash_file(full_path)
            if err:
                error_count += 1
                continue

            is_ioc = (md5_val in iocs) or (sha256_val in iocs)
            if is_ioc:
                ioc_hits.append({
                    "path": full_path,
                    "sha256": sha256_val,
                    "md5": md5_val
                })
                print(f"  [ALERT! IOC MATCH] {full_path}")
                print(f"                     SHA256: {sha256_val}")

            results.append({
                "Filename": file,
                "FullPath": full_path,
                "SizeBytes": size_bytes,
                "MD5": md5_val,
                "SHA256": sha256_val,
                "IOC_Match": "ALERT_MATCH" if is_ioc else "CLEAN"
            })

    # Write CSV
    if results:
        fieldnames = ["Filename", "FullPath", "SizeBytes", "MD5", "SHA256", "IOC_Match"]
        with open(csv_file, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

    # Write TXT Summary
    with open(txt_file, "w", encoding="utf-8") as tf:
        tf.write("=" * 65 + "\n")
        tf.write(f"  USB FILE INTEGRITY & IOC AUDIT REPORT\n")
        tf.write(f"  Target:  {target_dir}\n")
        tf.write(f"  Time:    {datetime.datetime.now().isoformat()}\n")
        tf.write(f"  Scanned: {scanned_count} files | Errors: {error_count}\n")
        tf.write(f"  IOC Matches: {len(ioc_hits)}\n")
        tf.write("=" * 65 + "\n\n")

        if ioc_hits:
            tf.write("!!! [CRITICAL] KNOWN MALICIOUS IOC HASH MATCHES !!!\n")
            for hit in ioc_hits:
                tf.write(f"  Path:   {hit['path']}\n")
                tf.write(f"  SHA256: {hit['sha256']}\n")
                tf.write(f"  MD5:    {hit['md5']}\n\n")
        else:
            tf.write("[+] No known malicious IOC hashes detected.\n")

    print("\n" + "=" * 65)
    print(f"[+] HASHING COMPLETE: Scanned {scanned_count} files.")
    if ioc_hits:
        print(f"[!] DANGER: {len(ioc_hits)} IOC MATCHES FOUND!")
    else:
        print("[+] IOC Status: No known malicious signatures identified.")
    print(f"[+] Manifest: {csv_file}")
    print(f"[+] Summary:  {txt_file}")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    script_directory = os.path.dirname(os.path.abspath(__file__))
    known_iocs = load_ioc_hashes(script_directory)

    # If target passed via CLI, use it; otherwise ask or default to AppData\Local\Temp
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        default_dir = os.environ.get("TEMP", os.path.expanduser("~"))
        print(f"[*] Defaulting scan target to staging directory: {default_dir}")
        print("    (Tip: Pass target folder as argument, e.g.: python 06_File_Hasher_IOC.py C:\\Users\\TargetFolder)\n")
        target = default_dir

    scan_target(target, known_iocs)
    if not os.environ.get("IN_TOOLKIT_LOOP"):
        try:
            input("\nPress Enter to close window...")
        except Exception:
            pass
