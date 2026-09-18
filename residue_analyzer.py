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


def _as_dict(value):
    """Returns value if it's a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def parse_permissions(profile_path):
    """
    Parses site permission grants from Chrome's 'Secure Preferences' and/or
    'Preferences' JSON files. Returns a list of dicts, one per grant.

    The same exception can appear in both files; when it does, the
    'Secure Preferences' copy takes priority, since it's Chrome's
    integrity-protected store.
    """
    results = []
    seen = set()
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

        # Walked defensively: a well-formed Preferences file always nests
        # exceptions this way, but a corrupted or hand-edited one might
        # have a non-dict value at any level (e.g. the whole file is a
        # JSON array), which would otherwise crash the plain .get() chain.
        profile = _as_dict(data).get("profile")
        content_settings = _as_dict(profile).get("content_settings")
        exceptions = _as_dict(content_settings).get("exceptions")
        exceptions = _as_dict(exceptions)

        for permission_type, sites in exceptions.items():
            if not isinstance(sites, dict):
                continue
            for site_pattern, details in sites.items():
                if not isinstance(details, dict):
                    continue
                dedup_key = (permission_type, site_pattern)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
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


# Human-readable labels for the permission types that represent a real
# allow/block decision a person made (or a site prompted for), as opposed
# to Chrome's internal per-site bookkeeping (engagement scores, hints, etc).
PERMISSION_LABELS = {
    "geolocation": "Location access",
    "media_stream_camera": "Camera access",
    "media_stream_mic": "Microphone access",
    "notifications": "Notifications",
    "midi_sysex": "MIDI device access (full control)",
    "midi": "MIDI device access",
    "durable_storage": "Persistent storage",
    "push_messaging": "Push messaging",
    "popups": "Pop-ups",
    "javascript": "JavaScript",
    "images": "Images",
    "cookies": "Cookies",
    "automatic_downloads": "Automatic downloads",
    "clipboard": "Clipboard access",
    "sensors": "Motion/orientation sensors",
    "usb_guard": "USB device access",
    "serial_guard": "Serial device access",
    "hid_guard": "HID device access",
    "bluetooth_guard": "Bluetooth device access",
    "window_placement": "Multi-screen window placement",
    "background_sync": "Background sync",
    "payment_handler": "Payment handler",
    "ar": "Augmented reality",
    "vr": "Virtual reality",
    "storage_access": "Cross-site storage access",
}

# Chrome's ContentSetting enum values.
SETTING_LABELS = {
    0: "Default (not explicitly set)",
    1: "Allowed",
    2: "Blocked",
    3: "Ask every time",
    4: "Allowed for this browsing session only",
    5: "Allowed for important content only",
}

# One-line plain-English explanation for permission types that are internal
# Chrome bookkeeping rather than a real allow/block decision.
BOOKKEEPING_GLOSSARY = {
    "client_hints": "Technical details Chrome shares with this site about your device/browser.",
    "cookie_controls_metadata": "Internal tracking-protection bookkeeping for this site.",
    "fedcm_idp_signin": "Records that you're signed in via this site's federated login service.",
    "media_engagement": "Chrome's internal score for how much audio/video you've played on this site.",
    "permission_autoblocking_data": "Tracks repeated permission denials so Chrome can auto-block future prompts.",
    "site_engagement": "Chrome's internal 'how often do you use this site' score.",
}


def clean_site_name(site_pattern):
    """
    Turns a raw Chrome content-setting site pattern (e.g.
    "https://[*.]example.com:443,*") into a plain hostname
    (e.g. "example.com") for display to non-technical readers.
    """
    name = site_pattern.split(",")[0]

    for prefix in ("https://", "http://"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    name = name.replace("[*.]", "")

    if ":" in name:
        host, _, rest = name.partition(":")
        port, _, tail = rest.partition("/")
        if port.isdigit():
            name = host + (("/" + tail) if tail else "")

    return name or site_pattern


# Alias kept for compatibility with tooling/tests written against the
# other draft's naming; identical behavior to clean_site_name().
friendly_site_name = clean_site_name


def friendly_permission_type(permission_type):
    """
    Looks up a human-readable label for a raw Chrome permission_type key,
    falling back to a title-cased version of the key when unmapped.
    """
    return PERMISSION_LABELS.get(
        permission_type, permission_type.replace("_", " ").capitalize()
    )


def summarize_permissions_by_site(permissions):
    """
    Groups raw permission entries by site into real allow/block
    "decisions" and internal Chrome "metadata" (engagement scores,
    hints, etc.). Returns {site: {"decisions": [...], "metadata": [...]}}.
    """
    sites = {}
    for entry in permissions:
        site = clean_site_name(entry["site"])
        sites.setdefault(site, {"decisions": [], "metadata": []})

        permission_type = entry["permission_type"]
        setting = entry["setting"]

        if isinstance(setting, int):
            label = friendly_permission_type(permission_type)
            setting_text = SETTING_LABELS.get(setting, f"Unknown setting ({setting})")
            detail = f"{label}: {setting_text}"
            if entry.get("last_used"):
                detail += f" (last used {entry['last_used']})"
            sites[site]["decisions"].append(detail)
        else:
            label = permission_type.replace("_", " ").capitalize()
            gloss = BOOKKEEPING_GLOSSARY.get(
                permission_type, "Internal browser data Chrome keeps for this site."
            )
            if isinstance(setting, dict):
                if permission_type == "site_engagement" and setting.get("rawScore") is not None:
                    gloss += f" (current score: {setting['rawScore']:.1f})"
                elif permission_type == "media_engagement" and setting.get("visits"):
                    gloss += f" ({setting['visits']} visit(s) recorded)"
            sites[site]["metadata"].append(f"{label} — {gloss}")

    return sites


def format_permissions_section(permissions):
    """
    Builds a plain-English, per-site rendering of permission grants:
    real allow/block decisions first, with internal Chrome bookkeeping
    (engagement scores, hints, etc.) grouped separately underneath.
    """
    lines = []

    if not permissions:
        lines.append("No permission grants found.")
        return lines

    sites = summarize_permissions_by_site(permissions)

    for site in sorted(sites):
        lines.append(f"\n{site}")
        group = sites[site]

        if group["decisions"]:
            for decision in group["decisions"]:
                lines.append(f"    - {decision}")
        else:
            lines.append("    (no explicit allow/block permissions found)")

        if group["metadata"]:
            lines.append("    Other browser bookkeeping (not a permission you granted):")
            for note in group["metadata"]:
                lines.append(f"      - {note}")

    return lines


def generate_report(permissions, autofill_entries, cache_inventory, output_path):
    """
    Writes a consolidated, human-readable residue report to a text file
    and prints it to the console.
    """
    lines = []
    lines.append("=" * 70)
    lines.append("BROWSER RESIDUE REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append(
        "\nThis report summarizes traces left behind in a Chrome browser "
        "profile: what permissions sites were given, what form data Chrome "
        "remembered, and what cached files remain from web apps."
    )

    lines.append("\n--- SITE PERMISSIONS (what sites are allowed to do) ---")
    lines.append(
        "What each site was allowed or blocked from doing (camera, "
        "microphone, location, etc.), grouped by website."
    )
    lines.extend(format_permissions_section(permissions))

    lines.append("\n--- SAVED FORM DATA (AUTOFILL) ---")
    lines.append(
        "Text that Chrome remembered from forms you've filled in before "
        "(names, addresses, search terms typed into forms, etc.)."
    )
    if autofill_entries:
        for entry in autofill_entries:
            times_word = "time" if entry["use_count"] == 1 else "times"
            last_used = entry["date_last_used"] or "not recorded"
            lines.append(
                f"\nField \"{entry['field_name']}\" = \"{entry['value']}\"\n"
                f"    - Used {entry['use_count']} {times_word}; last used {last_used}"
            )
    else:
        lines.append("\nNo saved form data found.")

    lines.append("\n--- CACHED WEB APP DATA ---")
    lines.append(
        "Files that websites' background 'service workers' have stored "
        "locally (e.g. for offline use or faster loading). Contents "
        "aren't inspected here, just counted."
    )
    if cache_inventory:
        for entry in cache_inventory:
            size_kb = entry["approx_size_bytes"] / 1024
            lines.append(
                f"Cache ID {entry['cache_folder_hash'][:12]}... "
                f"({entry['file_count']} file(s), about {size_kb:.1f} KB)"
            )
    else:
        lines.append("No cached web app data found.")

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
        help=(
            "Path to save the output report. If omitted, saves "
            "'residue_report.txt' in the folder the script is run from."
        ),
        default=None,
    )
    args = parser.parse_args()

    output_path = Path(args.output) if args.output else Path.cwd() / "residue_report.txt"

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

        generate_report(permissions, autofill_entries, cache_inventory, output_path)


if __name__ == "__main__":
    main()
