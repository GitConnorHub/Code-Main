"""
Browser Anti-Forensic Residue Analyzer (Chrome only)

Examines three Chrome browser artifact sources on a given profile folder:
  1. Site permission grants (Secure Preferences / Preferences JSON)
  2. Autofill form data (Web Data SQLite database)
  3. Service Worker Cache Storage (directory inventory)

Produces a consolidated, human-readable residue report showing what
browsing-related evidence remains recoverable.

Usage:
    python residue_analyzer.py --profile-path "C:\\path\\to\\Default" --output report.txt

If --profile-path is not given, the script attempts to locate the live
local Chrome "Default" profile automatically (Windows only).
"""

import argparse
import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def find_chrome_profile_path(profile_name="Default", base_path=None):
    """
    Returns the path to a Chrome profile folder.
    If base_path is given, uses that directly (e.g. a copied evidence folder).
    Otherwise attempts to locate the live local Chrome profile (Windows).
    """
    if base_path:
        return Path(base_path)

    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        raise EnvironmentError(
            "LOCALAPPDATA environment variable not found. "
            "Automatic profile detection only works on Windows; "
            "use --profile-path to specify a folder manually."
        )
    return Path(local_appdata) / "Google" / "Chrome" / "User Data" / profile_name


def chrome_time_to_iso(chrome_timestamp):
    """
    Converts a Chrome/WebKit timestamp (microseconds since 1601-01-01 UTC)
    into a readable ISO 8601 UTC string. Returns None if the value is
    missing, zero, or invalid.
    """
    if not chrome_timestamp:
        return None
    try:
        epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
        seconds_since_epoch_start = int(chrome_timestamp) / 1_000_000
        actual_time = epoch_start + timedelta(seconds=seconds_since_epoch_start)
        return actual_time.isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def parse_permissions(profile_path):
    """
    Parses site permission grants from Chrome's 'Secure Preferences' and/or
    'Preferences' JSON files. Returns a list of dicts, one per grant.
    """
    results = []
    candidate_filenames = ["Secure Preferences", "Preferences"]

    for filename in candidate_filenames:
        file_path = profile_path / filename
        if not file_path.exists():
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"  [!] Could not parse {filename}: {e}")
            continue

        exceptions = (
            data.get("profile", {})
            .get("content_settings", {})
            .get("exceptions", {})
        )

        for permission_type, sites in exceptions.items():
            if not isinstance(sites, dict):
                continue
            for site_pattern, details in sites.items():
                if not isinstance(details, dict):
                    continue
                results.append({
                    "source_file": filename,
                    "permission_type": permission_type,
                    "site": site_pattern,
                    "setting": details.get("setting"),
                    "last_used": chrome_time_to_iso(details.get("last_used")),
                    "last_modified": chrome_time_to_iso(details.get("last_modified")),
                })

    return results


def parse_autofill(profile_path, work_dir):
    """
    Parses stored autofill entries from Chrome's 'Web Data' SQLite database.
    The database is copied to a working directory first, both to avoid
    file-lock issues while Chrome is running and to avoid modifying
    original evidence in place.
    """
    results = []
    source_db = profile_path / "Web Data"

    if not source_db.exists():
        print("  [!] 'Web Data' file not found in profile.")
        return results

    working_copy = Path(work_dir) / "Web Data"
    try:
        shutil.copy2(source_db, working_copy)
    except OSError as e:
        print(f"  [!] Could not copy 'Web Data' (is Chrome running?): {e}")
        return results

    # Also copy WAL/SHM companion files if present - uncommitted recent
    # changes can live here before being flushed into the main DB file.
    for ext in ["-wal", "-shm"]:
        companion = Path(str(source_db) + ext)
        if companion.exists():
            shutil.copy2(companion, str(working_copy) + ext)

    try:
        conn = sqlite3.connect(str(working_copy))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name, value, count, date_created, date_last_used FROM autofill"
        )
        for name, value, count, date_created, date_last_used in cursor.fetchall():
            results.append({
                "field_name": name,
                "value": value,
                "use_count": count,
                "date_created": chrome_time_to_iso(date_created),
                "date_last_used": chrome_time_to_iso(date_last_used),
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"  [!] Error reading autofill table: {e}")

    return results


def inventory_service_worker_cache(profile_path):
    """
    Enumerates the Service Worker Cache Storage directory and reports,
    per cached origin folder, an entry count and approximate total size.
    Does not attempt to parse individual cached response content.
    """
    results = []
    cache_root = profile_path / "Service Worker" / "CacheStorage"

    if not cache_root.exists():
        print("  [!] 'Service Worker/CacheStorage' directory not found.")
        return results

    for origin_folder in cache_root.iterdir():
        if not origin_folder.is_dir():
            continue

        file_count = 0
        total_size = 0
        for root, _dirs, files in os.walk(origin_folder):
            for filename in files:
                file_path = Path(root) / filename
                try:
                    total_size += file_path.stat().st_size
                    file_count += 1
                except OSError:
                    continue

        results.append({
            "cache_folder_hash": origin_folder.name,
            "file_count": file_count,
            "approx_size_bytes": total_size,
        })

    return results


def generate_report(permissions, autofill_entries, cache_inventory, output_path):
    """
    Writes a consolidated, human-readable residue report to a text file
    and prints it to the console.
    """
    lines = []
    lines.append("=" * 70)
    lines.append("BROWSER ANTI-FORENSIC RESIDUE REPORT")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("=" * 70)

    lines.append("\n--- SITE PERMISSION GRANTS ---")
    if permissions:
        for entry in permissions:
            lines.append(
                f"[{entry['permission_type']}] {entry['site']} -> "
                f"setting={entry['setting']} "
                f"(last_used={entry['last_used']}, source={entry['source_file']})"
            )
    else:
        lines.append("No permission grants found.")

    lines.append("\n--- AUTOFILL ENTRIES ---")
    if autofill_entries:
        for entry in autofill_entries:
            lines.append(
                f"Field: {entry['field_name']} | Value: {entry['value']} | "
                f"Used: {entry['use_count']}x | Last used: {entry['date_last_used']}"
            )
    else:
        lines.append("No autofill entries found.")

    lines.append("\n--- SERVICE WORKER CACHE INVENTORY ---")
    if cache_inventory:
        for entry in cache_inventory:
            lines.append(
                f"Cache folder: {entry['cache_folder_hash']} | "
                f"Files: {entry['file_count']} | "
                f"Approx size: {entry['approx_size_bytes']} bytes"
            )
    else:
        lines.append("No Service Worker cache data found.")

    report_text = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(report_text)
    print(f"\n[+] Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Browser Anti-Forensic Residue Analyzer (Chrome only)"
    )
    parser.add_argument(
        "--profile-path",
        help=(
            "Path to a Chrome profile folder (e.g. a copied evidence folder "
            "containing 'Preferences', 'Web Data', and 'Service Worker'). "
            "If omitted, attempts to use the live local Chrome 'Default' profile."
        ),
        default=None,
    )
    parser.add_argument(
        "--output",
        help="Path to save the output report (default: residue_report.txt)",
        default="residue_report.txt",
    )
    args = parser.parse_args()

    profile_path = (
        Path(args.profile_path) if args.profile_path else find_chrome_profile_path()
    )

    if not profile_path.exists():
        print(f"[!] Profile path does not exist: {profile_path}")
        return

    print(f"[*] Using profile path: {profile_path}")

    with tempfile.TemporaryDirectory() as work_dir:
        print("[*] Parsing site permissions...")
        permissions = parse_permissions(profile_path)

        print("[*] Parsing autofill data...")
        autofill_entries = parse_autofill(profile_path, work_dir)

        print("[*] Inventorying Service Worker cache...")
        cache_inventory = inventory_service_worker_cache(profile_path)

        generate_report(permissions, autofill_entries, cache_inventory, args.output)


if __name__ == "__main__":
    main()
