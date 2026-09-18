"""
Test suite for residue_analyzer.py, written for pytest.

Pytest was chosen as the test framework because it discovers and runs
plain functions named test_* automatically, reports a clear pass/fail
summary and a readable diff when an assertion fails, and provides the
built-in `tmp_path` fixture used throughout this file to give each test
its own private temporary directory without needing to manage
`tempfile.TemporaryDirectory()` context managers by hand.

Every check in this file is still a plain Python `assert` statement --
pytest does not require or use a special assertion API, it simply
rewrites `assert` internally to produce more informative failure output.
This means the assertion-based testing approach covered in the module is
retained; pytest is layered on top as the framework that discovers,
runs, and reports on those assertions, rather than replacing them.

The first section below is one contributor's test suite, kept verbatim
(test names and bodies unchanged). The "Additional coverage" section
that follows adds tests for behavior the first section doesn't exercise
(e.g. LOCALAPPDATA-based profile lookup, WAL/SHM copying, a locked
autofill database, and the raw format_permissions_section()/
generate_report() text output) -- overlapping tests were removed rather
than duplicated.

Setup:
    pip install pytest

Run with:
    pytest tests/test_residue_analyzer.py -v

The -v (verbose) flag prints one line per test with its outcome, similar
in spirit to the PASS lines a hand-rolled runner would print.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from residue_analyzer import (
    chrome_time_to_iso,
    find_chrome_profile_path,
    friendly_permission_type,
    friendly_site_name,
    generate_report,
    inventory_service_worker_cache,
    parse_autofill,
    parse_permissions,
    summarize_permissions_by_site,
)

import residue_analyzer as ra


# ---------------------------------------------------------------------------
# chrome_time_to_iso
# ---------------------------------------------------------------------------

def test_chrome_time_to_iso_known_value():
    # 13,432,214,034,262,918 microseconds since 1601-01-01 UTC is a real
    # value taken from the sample report's site_engagement data, and is
    # independently known to fall on 2026-08-26. Rather than re-deriving
    # the conversion arithmetic (which would just be testing itself),
    # this checks the output lands on the correct calendar date.
    result = chrome_time_to_iso(13432214034262918)
    assert result is not None
    assert result.startswith("2026-08-26")


def test_chrome_time_to_iso_epoch_zero():
    # A raw value of 0 is Chrome's convention for "unset", not a literal
    # 1601-01-01 timestamp, so the function must treat it as missing data.
    assert chrome_time_to_iso(0) is None


def test_chrome_time_to_iso_none_input():
    assert chrome_time_to_iso(None) is None


def test_chrome_time_to_iso_invalid_input():
    # Non-numeric / corrupted values (e.g. from a damaged or hand-edited
    # evidence file) must not crash the analyzer.
    assert chrome_time_to_iso("not_a_number") is None


def test_chrome_time_to_iso_extreme_overflow_value():
    # Extreme edge case: a timestamp so large it would represent a date
    # far beyond what Python's datetime can represent (year 9999 is the
    # practical ceiling). Data corruption, a bit-flip, or a deliberately
    # crafted evidence file could produce a value like this. The function
    # must catch the resulting OverflowError and return None, rather than
    # letting it propagate and crash the whole analysis.
    absurdly_large_value = 10 ** 30
    assert chrome_time_to_iso(absurdly_large_value) is None


def test_chrome_time_to_iso_negative_value():
    # A negative microsecond count is not something Chrome should ever
    # produce, but corrupted or tampered data might contain one. The
    # function should not raise, whatever it decides to return.
    result = chrome_time_to_iso(-1)
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# find_chrome_profile_path
# ---------------------------------------------------------------------------

def test_find_chrome_profile_path_explicit_base_path():
    # This is the code path used for forensic work: the examiner supplies
    # a profile path pointing at a copy of the evidence, so live-profile
    # auto-detection must be bypassed entirely.
    result = find_chrome_profile_path(base_path="C:\\evidence\\Default")
    assert result == Path("C:\\evidence\\Default")


# ---------------------------------------------------------------------------
# parse_permissions
# ---------------------------------------------------------------------------

def test_parse_permissions_reads_known_grant(tmp_path):
    prefs = {
        "profile": {"content_settings": {"exceptions": {
            "media_stream_camera": {
                "https://discord.com:443,*": {
                    "setting": 1,
                    "last_used": 13432214034262918,
                    "last_modified": 13432214034262918,
                }
            }
        }}}
    }
    (tmp_path / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")

    results = parse_permissions(tmp_path)

    assert len(results) == 1
    entry = results[0]
    assert entry["permission_type"] == "media_stream_camera"
    assert entry["site"] == "https://discord.com:443,*"
    assert entry["setting"] == 1
    assert entry["last_used"] is not None


def test_parse_permissions_handles_missing_files(tmp_path):
    # No Preferences / Secure Preferences at all: e.g. a fresh profile,
    # or an evidence folder where only some artifact types were copied.
    assert parse_permissions(tmp_path) == []


def test_parse_permissions_skips_malformed_json(tmp_path):
    # A corrupted or truncated file (common when evidence is imaged from
    # a device that was powered off mid-write) must not crash the run.
    (tmp_path / "Preferences").write_text("{not valid json", encoding="utf-8")
    assert parse_permissions(tmp_path) == []


def test_parse_permissions_handles_empty_file(tmp_path):
    # Extreme edge case: a zero-byte file. This can happen if evidence
    # acquisition was interrupted or a file was truncated to nothing.
    # json.load() raises a JSONDecodeError on empty content, which must
    # be caught the same way a malformed-but-nonempty file is.
    (tmp_path / "Preferences").write_text("", encoding="utf-8")
    assert parse_permissions(tmp_path) == []


def test_parse_permissions_handles_non_dict_top_level_json(tmp_path):
    # Extreme edge case: the file contains syntactically valid JSON, but
    # the outermost value isn't an object at all -- e.g. a JSON array.
    # The original implementation called .get("profile", {}) directly on
    # whatever json.load() returned, which raised an AttributeError here
    # ('list' object has no attribute 'get'), since only dictionaries
    # have a .get() method. This is a genuine bug found while extending
    # the test suite, not a hypothetical one, and is fixed by walking the
    # expected structure defensively via _as_dict().
    (tmp_path / "Preferences").write_text("[]", encoding="utf-8")
    assert parse_permissions(tmp_path) == []


def test_parse_permissions_handles_non_dict_profile_value(tmp_path):
    # Extreme edge case, one level deeper than the above: the top level
    # is a proper dictionary, but the "profile" key itself holds
    # something other than a dictionary (e.g. a plain string). This would
    # crash on data.get("profile", {}).get("content_settings", {}) the
    # same way, since the result of the first .get() would be a string,
    # which also has no .get() method.
    (tmp_path / "Preferences").write_text(
        json.dumps({"profile": "unexpected_string_value"}), encoding="utf-8"
    )
    assert parse_permissions(tmp_path) == []


def test_parse_permissions_deduplicates_across_both_files(tmp_path):
    # Regression/edge-case test: modern Chrome can store the same
    # content-setting exception in both 'Secure Preferences' and
    # 'Preferences'. Without deduplication, the same grant would be
    # reported twice, overstating the evidence. 'Secure Preferences' is
    # expected to take priority when the two disagree, since it is
    # Chrome's integrity-protected store.
    secure_prefs = {
        "profile": {"content_settings": {"exceptions": {
            "geolocation": {"https://example.com:443,*": {"setting": 1}}
        }}}
    }
    regular_prefs = {
        "profile": {"content_settings": {"exceptions": {
            "geolocation": {"https://example.com:443,*": {"setting": 2}}
        }}}
    }
    (tmp_path / "Secure Preferences").write_text(json.dumps(secure_prefs), encoding="utf-8")
    (tmp_path / "Preferences").write_text(json.dumps(regular_prefs), encoding="utf-8")

    results = parse_permissions(tmp_path)

    assert len(results) == 1
    assert results[0]["setting"] == 1


def test_parse_permissions_handles_non_dict_exception_values(tmp_path):
    # Regression test for the schema-inconsistency bug found during
    # development: some permission_type entries under
    # content_settings.exceptions map to a list or other non-dict value
    # instead of the usual {site_pattern: {...}} mapping, which previously
    # caused an AttributeError when the code assumed .items() was always
    # available on "sites".
    prefs = {
        "profile": {"content_settings": {"exceptions": {
            "some_unexpected_type": ["not", "a", "dict"],
            "geolocation": {"https://example.com:443,*": {"setting": 1}},
        }}}
    }
    (tmp_path / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")

    results = parse_permissions(tmp_path)

    # The well-formed geolocation entry should still be extracted.
    assert len(results) == 1
    assert results[0]["permission_type"] == "geolocation"


# ---------------------------------------------------------------------------
# parse_autofill
# ---------------------------------------------------------------------------

def _make_web_data_db(path, rows=None):
    if rows is None:
        rows = [("email", "j.smith@example.com", 3, 13432214034262918, 13432214034262918)]
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER, "
        "date_created INTEGER, date_last_used INTEGER)"
    )
    conn.executemany("INSERT INTO autofill VALUES (?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()


def test_parse_autofill_reads_known_entry(tmp_path):
    profile_dir = tmp_path / "profile"
    work_dir = tmp_path / "work"
    profile_dir.mkdir()
    work_dir.mkdir()
    _make_web_data_db(profile_dir / "Web Data")

    results = parse_autofill(profile_dir, str(work_dir))

    assert len(results) == 1
    entry = results[0]
    assert entry["field_name"] == "email"
    assert entry["value"] == "j.smith@example.com"
    assert entry["use_count"] == 3
    assert entry["date_last_used"] is not None


def test_parse_autofill_multiple_distinct_entries_all_kept(tmp_path):
    # Edge case: Chrome's autofill table can contain several distinct
    # (name, value) rows, including different values submitted for the
    # same field name. Both must be preserved, not collapsed into one.
    profile_dir = tmp_path / "profile"
    work_dir = tmp_path / "work"
    profile_dir.mkdir()
    work_dir.mkdir()
    _make_web_data_db(profile_dir / "Web Data", rows=[
        ("email", "j.smith@example.com", 3, 1, 1),
        ("email", "jane.smith@example.com", 1, 1, 1),
        ("search_query", "train times", 5, 1, 1),
    ])

    results = parse_autofill(profile_dir, str(work_dir))

    assert len(results) == 3
    values = {entry["value"] for entry in results}
    assert values == {"j.smith@example.com", "jane.smith@example.com", "train times"}


def test_parse_autofill_missing_db_returns_empty(tmp_path):
    profile_dir = tmp_path / "profile"
    work_dir = tmp_path / "work"
    profile_dir.mkdir()
    work_dir.mkdir()
    assert parse_autofill(profile_dir, str(work_dir)) == []


def test_parse_autofill_handles_null_database_values(tmp_path):
    # Extreme edge case: SQLite allows NULL in any column regardless of
    # declared type, so a row could have a NULL field name or value (for
    # example, from a browser extension writing to the table in an
    # unexpected way). The function must not crash trying to process
    # these -- it should simply pass the None values through.
    profile_dir = tmp_path / "profile"
    work_dir = tmp_path / "work"
    profile_dir.mkdir()
    work_dir.mkdir()
    db_path = profile_dir / "Web Data"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER, "
        "date_created INTEGER, date_last_used INTEGER)"
    )
    conn.execute("INSERT INTO autofill VALUES (NULL, NULL, 1, NULL, NULL)")
    conn.commit()
    conn.close()

    results = parse_autofill(profile_dir, str(work_dir))

    assert len(results) == 1
    assert results[0]["field_name"] is None
    assert results[0]["value"] is None


def test_parse_autofill_copies_db_rather_than_reading_in_place(tmp_path):
    # Forensic-soundness check: the function must operate on a copy, and
    # the original evidence file must be left untouched (same bytes)
    # after parsing.
    profile_dir = tmp_path / "profile"
    work_dir = tmp_path / "work"
    profile_dir.mkdir()
    work_dir.mkdir()
    original_db = profile_dir / "Web Data"
    _make_web_data_db(original_db)
    original_bytes = original_db.read_bytes()

    parse_autofill(profile_dir, str(work_dir))

    assert original_db.read_bytes() == original_bytes
    assert (work_dir / "Web Data").exists()


# ---------------------------------------------------------------------------
# inventory_service_worker_cache
# ---------------------------------------------------------------------------

def test_inventory_service_worker_cache_counts_files_and_size(tmp_path):
    cache_dir = tmp_path / "Service Worker" / "CacheStorage" / "abc123hash"
    cache_dir.mkdir(parents=True)
    (cache_dir / "file1.bin").write_bytes(b"x" * 100)
    (cache_dir / "file2.bin").write_bytes(b"y" * 250)

    results = inventory_service_worker_cache(tmp_path)

    assert len(results) == 1
    entry = results[0]
    assert entry["cache_folder_hash"] == "abc123hash"
    assert entry["file_count"] == 2
    assert entry["approx_size_bytes"] == 350


def test_inventory_service_worker_cache_multiple_origins_and_nesting(tmp_path):
    # Edge case: a real profile will usually have more than one cached
    # origin, and an origin's cache can itself contain subfolders. This
    # checks that os.walk()'s recursive traversal is actually needed and
    # working, not just a single-level directory listing.
    cache_root = tmp_path / "Service Worker" / "CacheStorage"

    origin_a = cache_root / "origin_a_hash"
    (origin_a / "subfolder").mkdir(parents=True)
    (origin_a / "file_top.bin").write_bytes(b"a" * 10)
    (origin_a / "subfolder" / "file_nested.bin").write_bytes(b"b" * 20)

    origin_b = cache_root / "origin_b_hash"
    origin_b.mkdir(parents=True)
    (origin_b / "file_only.bin").write_bytes(b"c" * 5)

    results = inventory_service_worker_cache(tmp_path)
    by_hash = {entry["cache_folder_hash"]: entry for entry in results}

    assert len(results) == 2
    assert by_hash["origin_a_hash"]["file_count"] == 2
    assert by_hash["origin_a_hash"]["approx_size_bytes"] == 30
    assert by_hash["origin_b_hash"]["file_count"] == 1
    assert by_hash["origin_b_hash"]["approx_size_bytes"] == 5


def test_inventory_service_worker_cache_missing_dir_returns_empty(tmp_path):
    assert inventory_service_worker_cache(tmp_path) == []


def test_inventory_service_worker_cache_empty_origin_folder(tmp_path):
    # Edge case: an origin folder exists (Chrome has cached something
    # for this site at some point) but currently contains zero files --
    # e.g. its cache was cleared. This should still be reported as an
    # entry with zero files and zero size, rather than being skipped
    # entirely, since the folder's existence is itself potential evidence
    # that the site was previously active.
    origin = tmp_path / "Service Worker" / "CacheStorage" / "emptyhash"
    origin.mkdir(parents=True)

    results = inventory_service_worker_cache(tmp_path)

    assert len(results) == 1
    assert results[0]["cache_folder_hash"] == "emptyhash"
    assert results[0]["file_count"] == 0
    assert results[0]["approx_size_bytes"] == 0


def test_inventory_service_worker_cache_ignores_stray_files(tmp_path):
    # Only subdirectories of CacheStorage represent per-origin caches; a
    # stray file directly inside CacheStorage should not be counted as a
    # cache folder.
    cache_root = tmp_path / "Service Worker" / "CacheStorage"
    cache_root.mkdir(parents=True)
    (cache_root / "index").write_text("not a folder", encoding="utf-8")

    assert inventory_service_worker_cache(tmp_path) == []


# ---------------------------------------------------------------------------
# Readability layer: friendly_permission_type / friendly_site_name /
# summarize_permissions_by_site
# ---------------------------------------------------------------------------

def test_friendly_permission_type_known_and_unknown():
    assert friendly_permission_type("media_stream_camera") == "Camera access"
    # Unknown/unmapped keys must still degrade gracefully rather than
    # showing a raw snake_case string.
    assert friendly_permission_type("some_new_permission") == "Some new permission"


def test_friendly_site_name_strips_pattern_syntax():
    assert friendly_site_name("https://discord.com:443,*") == "discord.com"
    assert friendly_site_name("https://[*.]google.com,*") == "google.com"


def test_summarize_permissions_by_site_separates_decisions_from_metadata():
    permissions = [
        {
            "permission_type": "media_stream_camera",
            "site": "https://discord.com:443,*",
            "setting": 1,
            "last_used": None,
            "last_modified": None,
        },
        {
            "permission_type": "site_engagement",
            "site": "https://discord.com:443,*",
            "setting": {"rawScore": 2.1},
            "last_used": None,
            "last_modified": None,
        },
    ]
    by_site = summarize_permissions_by_site(permissions)

    assert "discord.com" in by_site
    assert len(by_site["discord.com"]["decisions"]) == 1
    assert len(by_site["discord.com"]["metadata"]) == 1
    assert "Camera access" in by_site["discord.com"]["decisions"][0]


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------

def test_end_to_end_full_profile_produces_expected_report(tmp_path):
    # Unlike the tests above, which each test one function in isolation,
    # this test builds a single synthetic profile containing all three
    # artifact types and runs the full pipeline (all three parsers plus
    # generate_report) together, then checks the resulting report file
    # contains the expected content from each section. This guards
    # against integration bugs that unit tests targeting one function at
    # a time cannot catch, e.g. a mismatch between the dict keys one
    # function produces and what generate_report() expects to read.
    profile_dir = tmp_path / "profile"
    work_dir = tmp_path / "work"
    profile_dir.mkdir()
    work_dir.mkdir()

    prefs = {
        "profile": {"content_settings": {"exceptions": {
            "media_stream_camera": {"https://discord.com:443,*": {"setting": 1}}
        }}}
    }
    (profile_dir / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")

    _make_web_data_db(profile_dir / "Web Data")

    cache_dir = profile_dir / "Service Worker" / "CacheStorage" / "somehash123"
    cache_dir.mkdir(parents=True)
    (cache_dir / "f.bin").write_bytes(b"z" * 42)

    permissions = parse_permissions(profile_dir)
    autofill_entries = parse_autofill(profile_dir, str(work_dir))
    cache_inventory = inventory_service_worker_cache(profile_dir)

    output_path = work_dir / "report.txt"
    generate_report(permissions, autofill_entries, cache_inventory, str(output_path))

    report_text = output_path.read_text(encoding="utf-8")

    assert "discord.com" in report_text
    assert "Camera access" in report_text
    assert "j.smith@example.com" in report_text
    assert "somehash123"[:12] in report_text


# ---------------------------------------------------------------------------
# Additional coverage retained from an earlier pass, targeting behavior
# not exercised above (LOCALAPPDATA-based profile lookup, a non-dict
# per-site "details" value, WAL/SHM copying, a locked autofill database,
# the raw format_permissions_section()/generate_report() text output,
# and main()'s CLI wiring including the nonexistent-profile-path case).
# ---------------------------------------------------------------------------

class TestFindChromeProfilePathLiveDetection:
    def test_uses_localappdata_when_no_base_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        result = ra.find_chrome_profile_path()
        assert result == tmp_path / "Google" / "Chrome" / "User Data" / "Default"

    def test_uses_custom_profile_name(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        result = ra.find_chrome_profile_path(profile_name="Profile 1")
        assert result == tmp_path / "Google" / "Chrome" / "User Data" / "Profile 1"

    def test_raises_when_localappdata_missing(self, monkeypatch):
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        with pytest.raises(EnvironmentError):
            ra.find_chrome_profile_path()


class TestParsePermissionsAdditional:
    def test_skips_non_dict_details_value(self, tmp_path):
        prefs = {
            "profile": {"content_settings": {"exceptions": {
                "geolocation": {"https://example.com,*": "not-a-dict"}
            }}}
        }
        (tmp_path / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")

        results = ra.parse_permissions(tmp_path)

        assert results == []

    def test_merges_distinct_entries_from_both_files(self, tmp_path):
        secure_prefs = {
            "profile": {"content_settings": {"exceptions": {
                "geolocation": {"https://a.com,*": {"setting": 1}}
            }}}
        }
        regular_prefs = {
            "profile": {"content_settings": {"exceptions": {
                "notifications": {"https://b.com,*": {"setting": 2}}
            }}}
        }
        (tmp_path / "Secure Preferences").write_text(json.dumps(secure_prefs), encoding="utf-8")
        (tmp_path / "Preferences").write_text(json.dumps(regular_prefs), encoding="utf-8")

        results = ra.parse_permissions(tmp_path)

        sources = {entry["source_file"] for entry in results}
        assert len(results) == 2
        assert sources == {"Secure Preferences", "Preferences"}


class TestParseAutofillAdditional:
    def test_copies_wal_and_shm_companion_files(self, tmp_path, monkeypatch):
        source_db = tmp_path / "Web Data"
        _make_web_data_db(source_db, rows=[])
        (tmp_path / "Web Data-wal").write_bytes(b"wal-data")
        (tmp_path / "Web Data-shm").write_bytes(b"shm-data")
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        # Prevent sqlite3 from opening the working copy: our placeholder
        # WAL/SHM content isn't a real WAL journal for this database, and
        # SQLite discards an invalid WAL file as part of opening the
        # connection. Blocking the open lets us verify the copy step in
        # isolation, before SQLite would ever touch those files.
        def raise_sqlite_error(*args, **kwargs):
            raise sqlite3.OperationalError("blocked for test")

        monkeypatch.setattr(ra.sqlite3, "connect", raise_sqlite_error)

        ra.parse_autofill(tmp_path, str(work_dir))

        assert (work_dir / "Web Data-wal").read_bytes() == b"wal-data"
        assert (work_dir / "Web Data-shm").read_bytes() == b"shm-data"

    def test_copy_failure_returns_empty_list(self, tmp_path, monkeypatch, capsys):
        _make_web_data_db(tmp_path / "Web Data", rows=[])
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        def raise_oserror(*args, **kwargs):
            raise OSError("file is locked")

        monkeypatch.setattr(ra.shutil, "copy2", raise_oserror)

        results = ra.parse_autofill(tmp_path, str(work_dir))

        assert results == []
        assert "Could not copy" in capsys.readouterr().out


class TestCleanSiteNameAdditional:
    def test_strips_http_prefix(self):
        assert ra.clean_site_name("http://example.com,*") == "example.com"

    def test_leaves_chrome_internal_urls_recognizable(self):
        assert ra.clean_site_name("chrome://newtab/,*") == "chrome://newtab/"

    def test_already_clean_name_is_unchanged(self):
        assert ra.clean_site_name("example.com") == "example.com"


class TestFormatPermissionsSection:
    def test_empty_permissions_returns_placeholder_message(self):
        assert ra.format_permissions_section([]) == ["No permission grants found."]

    def test_known_decision_uses_plain_english_labels(self):
        permissions = [
            {
                "permission_type": "media_stream_camera",
                "site": "https://discord.com:443,*",
                "setting": 1,
                "last_used": None,
            }
        ]

        text = "\n".join(ra.format_permissions_section(permissions))

        assert "discord.com" in text
        assert "Camera access: Allowed" in text

    def test_unknown_permission_type_falls_back_to_titleized_name(self):
        permissions = [
            {
                "permission_type": "some_new_permission",
                "site": "https://example.com,*",
                "setting": 2,
                "last_used": None,
            }
        ]

        text = "\n".join(ra.format_permissions_section(permissions))

        assert "Some new permission: Blocked" in text

    def test_dict_setting_is_routed_to_bookkeeping_with_gloss(self):
        permissions = [
            {
                "permission_type": "site_engagement",
                "site": "https://example.com,*",
                "setting": {"rawScore": 3.6},
                "last_used": None,
            }
        ]

        text = "\n".join(ra.format_permissions_section(permissions))

        assert "no explicit allow/block permissions found" in text
        assert "Site engagement" in text
        assert "how often do you use this site" in text
        assert "current score: 3.6" in text

    def test_sites_without_decisions_show_placeholder(self):
        permissions = [
            {
                "permission_type": "client_hints",
                "site": "https://example.com,*",
                "setting": {"client_hints": [1, 2]},
                "last_used": None,
            }
        ]

        text = "\n".join(ra.format_permissions_section(permissions))

        assert "(no explicit allow/block permissions found)" in text

    def test_multiple_sites_are_grouped_and_sorted(self):
        permissions = [
            {
                "permission_type": "geolocation",
                "site": "https://zzz.com,*",
                "setting": 1,
                "last_used": None,
            },
            {
                "permission_type": "geolocation",
                "site": "https://aaa.com,*",
                "setting": 2,
                "last_used": None,
            },
        ]

        lines = ra.format_permissions_section(permissions)
        site_headers = [line[1:] for line in lines if line.startswith("\n")]

        assert site_headers.index("aaa.com") < site_headers.index("zzz.com")


class TestGenerateReport:
    def test_writes_report_with_all_sections_populated(self, tmp_path):
        output_path = tmp_path / "report.txt"
        permissions = [
            {
                "permission_type": "geolocation",
                "site": "https://discord.com:443,*",
                "setting": 1,
                "last_used": None,
            }
        ]
        autofill_entries = [
            {
                "field_name": "email",
                "value": "user@example.com",
                "use_count": 2,
                "date_last_used": None,
            }
        ]
        cache_inventory = [
            {"cache_folder_hash": "abc123", "file_count": 5, "approx_size_bytes": 370}
        ]

        ra.generate_report(permissions, autofill_entries, cache_inventory, str(output_path))

        text = output_path.read_text(encoding="utf-8")
        assert "BROWSER RESIDUE REPORT" in text
        assert "discord.com" in text
        assert "Location access: Allowed" in text
        assert 'Field "email" = "user@example.com"' in text
        assert "Used 2 times; last used not recorded" in text
        assert "Cache ID abc123... (5 file(s), about 0.4 KB)" in text

    def test_writes_placeholder_messages_when_all_empty(self, tmp_path):
        output_path = tmp_path / "report.txt"

        ra.generate_report([], [], [], str(output_path))

        text = output_path.read_text(encoding="utf-8")
        assert "No permission grants found." in text
        assert "No saved form data found." in text
        assert "No cached web app data found." in text


class TestMainEndToEnd:
    def _build_fake_profile(self, profile_dir):
        profile_dir.mkdir(parents=True, exist_ok=True)

        preferences = {
            "profile": {
                "content_settings": {
                    "exceptions": {
                        "media_stream_camera": {
                            "https://discord.com:443,*": {"setting": 1}
                        },
                        "site_engagement": {
                            "chrome://newtab/,*": {"rawScore": 3.6}
                        },
                        "some_corrupted_flag": True,
                    }
                }
            }
        }
        (profile_dir / "Preferences").write_text(
            json.dumps(preferences), encoding="utf-8"
        )

        conn = sqlite3.connect(str(profile_dir / "Web Data"))
        conn.execute(
            "CREATE TABLE autofill "
            "(name TEXT, value TEXT, count INTEGER, "
            "date_created INTEGER, date_last_used INTEGER)"
        )
        conn.execute(
            "INSERT INTO autofill VALUES (?, ?, ?, ?, ?)",
            ("username", "jdoe", 4, 0, 0),
        )
        conn.commit()
        conn.close()

        cache_folder = profile_dir / "Service Worker" / "CacheStorage" / "hash1"
        cache_folder.mkdir(parents=True)
        (cache_folder / "entry").write_bytes(b"12345")

    def test_full_pipeline_produces_readable_report(self, tmp_path, monkeypatch):
        profile_dir = tmp_path / "profile"
        self._build_fake_profile(profile_dir)
        output_path = tmp_path / "residue_report.txt"

        monkeypatch.setattr(
            "sys.argv",
            [
                "residue_analyzer.py",
                "--profile-path",
                str(profile_dir),
                "--output",
                str(output_path),
            ],
        )

        ra.main()

        text = output_path.read_text(encoding="utf-8")
        assert "discord.com" in text
        assert "Camera access: Allowed" in text
        assert "Other browser bookkeeping" in text
        assert 'Field "username" = "jdoe"' in text
        assert "Cache ID hash1... (1 file(s)" in text

    def test_nonexistent_profile_path_does_not_crash(self, tmp_path, monkeypatch, capsys):
        missing_path = tmp_path / "does-not-exist"
        output_path = tmp_path / "residue_report.txt"

        monkeypatch.setattr(
            "sys.argv",
            [
                "residue_analyzer.py",
                "--profile-path",
                str(missing_path),
                "--output",
                str(output_path),
            ],
        )

        ra.main()

        assert not output_path.exists()
        assert "does not exist" in capsys.readouterr().out
