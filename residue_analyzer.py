"""
Browser Anti-Forensic Residue Analyzer (Chrome only)

Examines five Chrome browser artifact sources on a given profile folder:
  1. Site permission grants (Secure Preferences / Preferences JSON)
  2. Autofill form data (Web Data SQLite database)
  3. Saved addresses/contact profiles (Web Data SQLite database)
  4. Saved payment method metadata (Web Data SQLite database) - card
     number and any locally cached security code are excluded, since
     both are OS-encrypted and this tool never attempts to decrypt them
  5. Service Worker Cache Storage (directory inventory)

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


def unix_time_to_iso(unix_timestamp):
    """
    Converts a Unix epoch timestamp (seconds since 1970-01-01 UTC) into a
    readable ISO 8601 UTC string. Unlike most Chrome data (Preferences,
    site/media engagement), the autofill table's date_created/
    date_last_used columns are stored in this format, not the WebKit
    epoch used by chrome_time_to_iso(). Returns None if the value is
    missing, zero, or invalid.
    """
    if not unix_timestamp:
        return None
    try:
        return datetime.fromtimestamp(int(unix_timestamp), tz=timezone.utc).isoformat()
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
    integrity-protected store. If the two files disagree on the actual
    setting for the same grant, the kept entry's "conflict_note" field
    is set to a warning string (otherwise it's None) so this can be
    surfaced to the investigator rather than silently resolved.
    """
    results = []
    kept_by_key = {}
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
                setting = details.get("setting")

                if dedup_key in kept_by_key:
                    kept_entry = kept_by_key[dedup_key]
                    if setting != kept_entry["setting"]:
                        kept_entry["conflict_note"] = (
                            f"{filename} has a different value for this grant "
                            f"(setting={setting!r} vs {kept_entry['setting']!r} "
                            f"in {kept_entry['source_file']}); "
                            f"{kept_entry['source_file']} was used since it's "
                            f"Chrome's integrity-protected store."
                        )
                    continue

                new_entry = {
                    "source_file": filename,
                    "permission_type": permission_type,
                    "site": site_pattern,
                    "setting": setting,
                    "last_used": chrome_time_to_iso(details.get("last_used")),
                    "last_modified": chrome_time_to_iso(details.get("last_modified")),
                    "conflict_note": None,
                }
                kept_by_key[dedup_key] = new_entry
                results.append(new_entry)

    return results


def _copy_web_data(profile_path, work_dir):
    """
    Copies Chrome's 'Web Data' SQLite database (plus WAL/SHM companions,
    if present) into work_dir, both to avoid file-lock issues while
    Chrome is running and to avoid modifying original evidence in place.
    Returns the path to the copy, or None if the source file is missing
    or couldn't be copied.
    """
    source_db = profile_path / "Web Data"

    if not source_db.exists():
        print("  [!] 'Web Data' file not found in profile.")
        return None

    working_copy = Path(work_dir) / "Web Data"
    try:
        shutil.copy2(source_db, working_copy)
    except OSError as e:
        print(f"  [!] Could not copy 'Web Data' (is Chrome running?): {e}")
        return None

    # Also copy WAL/SHM companion files if present - uncommitted recent
    # changes can live here before being flushed into the main DB file.
    for ext in ["-wal", "-shm"]:
        companion = Path(str(source_db) + ext)
        if companion.exists():
            shutil.copy2(companion, str(working_copy) + ext)

    return working_copy


def _rows_as_dicts(cursor, table_name):
    """
    Selects every column from table_name and returns each row as a plain
    dict, so callers can look up fields defensively with .get() instead
    of crashing on a column that was renamed or doesn't exist in a given
    Chrome version. Returns [] if the table is missing or the query
    otherwise fails. table_name is always one of our own hardcoded
    literals, never external input, so building the query with an
    f-string here is safe.
    """
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    except sqlite3.Error:
        return []


def parse_autofill(profile_path, work_dir):
    """
    Parses stored autofill entries from Chrome's 'Web Data' SQLite database.
    The database is copied to a working directory first, both to avoid
    file-lock issues while Chrome is running and to avoid modifying
    original evidence in place.
    """
    results = []
    working_copy = _copy_web_data(profile_path, work_dir)
    if working_copy is None:
        return results

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
                "date_created": unix_time_to_iso(date_created),
                "date_last_used": unix_time_to_iso(date_last_used),
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"  [!] Error reading autofill table: {e}")

    return results


def parse_autofill_profiles(profile_path, work_dir):
    """
    Parses saved address/contact profiles ("Addresses and more" in
    Chrome's autofill settings) from the 'Web Data' SQLite database.
    Like the plain autofill table, these aren't tied to a specific
    website - Chrome offers them as suggestions on any site with a
    matching form field.
    """
    results = []
    working_copy = _copy_web_data(profile_path, work_dir)
    if working_copy is None:
        return results

    try:
        conn = sqlite3.connect(str(working_copy))
        cursor = conn.cursor()

        names_by_guid = {
            row["guid"]: row["full_name"]
            for row in _rows_as_dicts(cursor, "autofill_profile_names")
            if row.get("full_name")
        }
        emails_by_guid = {
            row["guid"]: row["email"]
            for row in _rows_as_dicts(cursor, "autofill_profile_emails")
            if row.get("email")
        }
        phones_by_guid = {
            row["guid"]: row["number"]
            for row in _rows_as_dicts(cursor, "autofill_profile_phones")
            if row.get("number")
        }

        for row in _rows_as_dicts(cursor, "autofill_profiles"):
            guid = row.get("guid")
            results.append({
                "guid": guid,
                "name": names_by_guid.get(guid),
                "email": emails_by_guid.get(guid),
                "phone": phones_by_guid.get(guid),
                "company_name": row.get("company_name"),
                "street_address": row.get("street_address"),
                "city": row.get("city"),
                "state": row.get("state"),
                "zipcode": row.get("zipcode"),
                "country_code": row.get("country_code"),
                "use_count": row.get("use_count"),
                "use_date": unix_time_to_iso(row.get("use_date")),
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"  [!] Error reading autofill_profiles table: {e}")

    return results


def parse_credit_cards(profile_path, work_dir):
    """
    Parses saved payment method *metadata* from the 'Web Data' SQLite
    database: name on card, expiration, nickname, and usage stats.

    Deliberately does not read or attempt to decrypt the card number
    (card_number_encrypted) or any locally cached security code
    (local_stored_cvc, on Chrome versions that have it). Both are
    encrypted with the OS user's own credentials (Windows DPAPI plus a
    Chrome-managed AES key) - only the same Windows user account on the
    same machine can decrypt them, so recovering them isn't something
    this tool attempts.
    """
    results = []
    working_copy = _copy_web_data(profile_path, work_dir)
    if working_copy is None:
        return results

    try:
        conn = sqlite3.connect(str(working_copy))
        cursor = conn.cursor()
        for row in _rows_as_dicts(cursor, "credit_cards"):
            results.append({
                "guid": row.get("guid"),
                "name_on_card": row.get("name_on_card"),
                "expiration_month": row.get("expiration_month"),
                "expiration_year": row.get("expiration_year"),
                "nickname": row.get("nickname"),
                "use_count": row.get("use_count"),
                "use_date": unix_time_to_iso(row.get("use_date")),
                "billing_address_id": row.get("billing_address_id"),
                "origin": row.get("origin"),
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"  [!] Error reading credit_cards table: {e}")

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


# Substrings of a plain autofill field's name that suggest it's part of
# an address, based on common HTML autocomplete tokens/naming
# conventions (e.g. "address-line1", "postal-code", "address-level2").
ADDRESS_LIKE_AUTOFILL_KEYWORDS = (
    "address", "street", "city", "postal", "postcode", "zip",
    "state", "province", "county", "country",
)


def is_address_like_autofill_field(field_name):
    """
    Heuristically flags a plain autofill field name as address-related.
    This is a guess, not a Chrome-confirmed address: the plain autofill
    table has no concept of which fields were submitted together on the
    same form, so entries flagged this way may come from different
    forms or different points in time and aren't guaranteed to describe
    one single real address, unlike an entry from autofill_profiles
    (Chrome's own explicitly-saved "Addresses and more").
    """
    if not field_name:
        return False
    lowered = field_name.lower()
    return any(keyword in lowered for keyword in ADDRESS_LIKE_AUTOFILL_KEYWORDS)


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
        conflict_note = entry.get("conflict_note")

        if isinstance(setting, int):
            label = friendly_permission_type(permission_type)
            setting_text = SETTING_LABELS.get(setting, f"Unknown setting ({setting})")
            detail = f"{label}: {setting_text}"
            if entry.get("last_used"):
                detail += f" (last used {entry['last_used']})"
            if conflict_note:
                detail += f" [WARNING: {conflict_note}]"
            sites[site]["decisions"].append(detail)
        else:
            label = permission_type.replace("_", " ").capitalize()
            gloss = BOOKKEEPING_GLOSSARY.get(
                permission_type, "Internal browser data Chrome keeps for this site."
            )
            if isinstance(setting, dict):
                if permission_type == "site_engagement":
                    if setting.get("rawScore") is not None:
                        gloss += f" (current score: {setting['rawScore']:.1f})"
                    last_active = chrome_time_to_iso(setting.get("lastEngagementTime"))
                    if last_active:
                        gloss += f"; last active {last_active}"
                elif permission_type == "media_engagement":
                    if setting.get("visits"):
                        gloss += f" ({setting['visits']} visit(s) recorded)"
                    last_played = chrome_time_to_iso(setting.get("lastMediaPlaybackTime"))
                    if last_played:
                        gloss += f"; media last played {last_played}"
                elif permission_type == "fedcm_idp_signin":
                    chosen_objects = setting.get("chosen-objects")
                    if isinstance(chosen_objects, list):
                        identities = []
                        for obj in chosen_objects:
                            if not isinstance(obj, dict):
                                continue
                            idp = obj.get("idp-origin", "unknown identity provider")
                            status = "currently signed in" if obj.get("idp-signin-status") else "not currently signed in"
                            identities.append(f"{idp}, {status}")
                        if identities:
                            gloss += " (" + "; ".join(identities) + ")"
            if conflict_note:
                gloss += f" [WARNING: {conflict_note}]"
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


def generate_report(
    permissions,
    autofill_entries,
    cache_inventory,
    output_path,
    addresses=None,
    credit_cards=None,
):
    """
    Writes a consolidated, human-readable residue report to a text file
    and prints it to the console.
    """
    addresses = addresses or []
    credit_cards = credit_cards or []
    address_like_autofill = [
        entry for entry in autofill_entries
        if is_address_like_autofill_field(entry["field_name"])
    ]
    plain_autofill_entries = [
        entry for entry in autofill_entries
        if not is_address_like_autofill_field(entry["field_name"])
    ]

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
    if plain_autofill_entries:
        for entry in plain_autofill_entries:
            times_word = "time" if entry["use_count"] == 1 else "times"
            last_used = entry["date_last_used"] or "not recorded"
            lines.append(
                f"\nField \"{entry['field_name']}\" = \"{entry['value']}\"\n"
                f"    - Used {entry['use_count']} {times_word}; last used {last_used}"
            )
    else:
        lines.append("\nNo saved form data found.")

    lines.append("\n--- SAVED ADDRESSES ---")
    lines.append(
        "Contact and address details Chrome offers to autofill into "
        "forms (not tied to any specific website)."
    )
    if addresses:
        for entry in addresses:
            header_parts = [entry["name"]] if entry.get("name") else []
            contact_bits = [
                bit for bit in (entry.get("email"), entry.get("phone")) if bit
            ]
            if contact_bits:
                header_parts.append("(" + ", ".join(contact_bits) + ")")
            header = " ".join(header_parts) if header_parts else "(no name on file)"
            lines.append(f"\n{header}")

            street_address = (entry.get("street_address") or "").replace("\n", ", ")
            address_bits = [
                bit for bit in (
                    street_address,
                    entry.get("city"),
                    entry.get("state"),
                    entry.get("zipcode"),
                    entry.get("country_code"),
                ) if bit
            ]
            if address_bits:
                lines.append(f"    {', '.join(address_bits)}")
            if entry.get("company_name"):
                lines.append(f"    Company: {entry['company_name']}")

            usage_bits = []
            if entry.get("use_count"):
                usage_bits.append(f"used {entry['use_count']} time(s)")
            if entry.get("use_date"):
                usage_bits.append(f"last used {entry['use_date']}")
            if usage_bits:
                lines.append(f"    ({'; '.join(usage_bits)})")

    if address_like_autofill:
        lines.append(
            "\nAddress-like form field values (recovered from form "
            "history, not a single address Chrome explicitly saved -- "
            "these may come from different forms or different times, "
            "so they aren't guaranteed to belong together):"
        )
        for entry in address_like_autofill:
            times_word = "time" if entry["use_count"] == 1 else "times"
            last_used = entry["date_last_used"] or "not recorded"
            lines.append(
                f"    - \"{entry['field_name']}\" = \"{entry['value']}\" "
                f"(used {entry['use_count']} {times_word}; last used {last_used})"
            )

    if not addresses and not address_like_autofill:
        lines.append("\nNo saved addresses found.")

    lines.append("\n--- SAVED PAYMENT METHODS ---")
    lines.append(
        "Payment cards Chrome has saved. Only card metadata is shown "
        "here -- the full card number (and any locally cached security "
        "code) is encrypted and is not read by this tool."
    )
    if credit_cards:
        for entry in credit_cards:
            name = entry.get("name_on_card") or "(no name on file)"
            header = f"\nName on card: {name}"
            month = entry.get("expiration_month")
            year = entry.get("expiration_year")
            if month and year:
                header += f" — expires {int(month):02d}/{int(year)}"
            lines.append(header)

            if entry.get("nickname"):
                lines.append(f"    Nickname: \"{entry['nickname']}\"")

            usage_bits = []
            if entry.get("use_count"):
                usage_bits.append(f"used {entry['use_count']} time(s)")
            if entry.get("use_date"):
                usage_bits.append(f"last used {entry['use_date']}")
            if usage_bits:
                lines.append(f"    ({'; '.join(usage_bits)})")
    else:
        lines.append("\nNo saved payment methods found.")

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

        print("[*] Parsing saved addresses...")
        addresses = parse_autofill_profiles(profile_path, work_dir)

        print("[*] Parsing saved payment methods...")
        credit_cards = parse_credit_cards(profile_path, work_dir)

        print("[*] Inventorying Service Worker cache...")
        cache_inventory = inventory_service_worker_cache(profile_path)

        generate_report(
            permissions,
            autofill_entries,
            cache_inventory,
            output_path,
            addresses=addresses,
            credit_cards=credit_cards,
        )


if __name__ == "__main__":
    main()
