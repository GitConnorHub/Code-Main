import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

import residue_analyzer as ra


# ---------------------------------------------------------------------------
# find_chrome_profile_path
# ---------------------------------------------------------------------------

class TestFindChromeProfilePath:
    def test_returns_base_path_directly_when_given(self, tmp_path):
        result = ra.find_chrome_profile_path(base_path=str(tmp_path))
        assert result == Path(tmp_path)

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


# ---------------------------------------------------------------------------
# chrome_time_to_iso
# ---------------------------------------------------------------------------

class TestChromeTimeToIso:
    def test_none_returns_none(self):
        assert ra.chrome_time_to_iso(None) is None

    def test_zero_returns_none(self):
        assert ra.chrome_time_to_iso(0) is None

    def test_valid_timestamp_converts_correctly(self):
        target = datetime(2021, 1, 1, tzinfo=timezone.utc)
        epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)
        chrome_timestamp = int((target - epoch_start).total_seconds() * 1_000_000)

        assert ra.chrome_time_to_iso(chrome_timestamp) == target.isoformat()

    def test_non_numeric_string_returns_none(self):
        assert ra.chrome_time_to_iso("not-a-number") is None

    def test_absurdly_large_value_returns_none(self):
        assert ra.chrome_time_to_iso(10**30) is None


# ---------------------------------------------------------------------------
# parse_permissions
# ---------------------------------------------------------------------------

class TestParsePermissions:
    def _write_preferences(self, profile_dir, exceptions, filename="Preferences"):
        data = {"profile": {"content_settings": {"exceptions": exceptions}}}
        (profile_dir / filename).write_text(json.dumps(data), encoding="utf-8")

    def test_no_preference_files_returns_empty_list(self, tmp_path):
        assert ra.parse_permissions(tmp_path) == []

    def test_parses_well_formed_exception(self, tmp_path):
        self._write_preferences(
            tmp_path,
            {
                "geolocation": {
                    "https://discord.com:443,*": {
                        "setting": 1,
                        "last_used": 0,
                        "last_modified": 0,
                    }
                }
            },
        )

        results = ra.parse_permissions(tmp_path)

        assert len(results) == 1
        entry = results[0]
        assert entry["permission_type"] == "geolocation"
        assert entry["site"] == "https://discord.com:443,*"
        assert entry["setting"] == 1
        assert entry["source_file"] == "Preferences"

    def test_skips_non_dict_sites_value_regression(self, tmp_path):
        # Regression test: a permission type whose value is a bool (rather
        # than a dict of site patterns) previously crashed with
        # AttributeError: 'bool' object has no attribute 'items'.
        self._write_preferences(tmp_path, {"some_flag": True})

        results = ra.parse_permissions(tmp_path)

        assert results == []

    def test_skips_non_dict_details_value(self, tmp_path):
        self._write_preferences(
            tmp_path, {"geolocation": {"https://example.com,*": "not-a-dict"}}
        )

        results = ra.parse_permissions(tmp_path)

        assert results == []

    def test_merges_secure_preferences_and_preferences(self, tmp_path):
        self._write_preferences(
            tmp_path,
            {"geolocation": {"https://a.com,*": {"setting": 1}}},
            filename="Secure Preferences",
        )
        self._write_preferences(
            tmp_path,
            {"notifications": {"https://b.com,*": {"setting": 2}}},
            filename="Preferences",
        )

        results = ra.parse_permissions(tmp_path)

        sources = {entry["source_file"] for entry in results}
        assert len(results) == 2
        assert sources == {"Secure Preferences", "Preferences"}

    def test_invalid_json_is_skipped_without_crashing(self, tmp_path, capsys):
        (tmp_path / "Preferences").write_text("{not valid json", encoding="utf-8")

        results = ra.parse_permissions(tmp_path)

        assert results == []
        assert "Could not parse" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# parse_autofill
# ---------------------------------------------------------------------------

class TestParseAutofill:
    def _make_web_data_db(self, path, rows):
        conn = sqlite3.connect(str(path))
        conn.execute(
            "CREATE TABLE autofill "
            "(name TEXT, value TEXT, count INTEGER, "
            "date_created INTEGER, date_last_used INTEGER)"
        )
        conn.executemany(
            "INSERT INTO autofill VALUES (?, ?, ?, ?, ?)", rows
        )
        conn.commit()
        conn.close()

    def test_missing_web_data_returns_empty_list(self, tmp_path):
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        assert ra.parse_autofill(tmp_path, str(work_dir)) == []

    def test_parses_autofill_rows(self, tmp_path):
        self._make_web_data_db(
            tmp_path / "Web Data", [("email", "user@example.com", 3, 0, 0)]
        )
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        results = ra.parse_autofill(tmp_path, str(work_dir))

        assert len(results) == 1
        entry = results[0]
        assert entry["field_name"] == "email"
        assert entry["value"] == "user@example.com"
        assert entry["use_count"] == 3

    def test_does_not_modify_original_database(self, tmp_path):
        source_db = tmp_path / "Web Data"
        self._make_web_data_db(source_db, [("name", "value", 1, 0, 0)])
        original_bytes = source_db.read_bytes()
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        ra.parse_autofill(tmp_path, str(work_dir))

        assert source_db.read_bytes() == original_bytes

    def test_copies_wal_and_shm_companion_files(self, tmp_path, monkeypatch):
        source_db = tmp_path / "Web Data"
        self._make_web_data_db(source_db, [])
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
        self._make_web_data_db(tmp_path / "Web Data", [])
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        def raise_oserror(*args, **kwargs):
            raise OSError("file is locked")

        monkeypatch.setattr(ra.shutil, "copy2", raise_oserror)

        results = ra.parse_autofill(tmp_path, str(work_dir))

        assert results == []
        assert "Could not copy" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# inventory_service_worker_cache
# ---------------------------------------------------------------------------

class TestInventoryServiceWorkerCache:
    def test_missing_directory_returns_empty_list(self, tmp_path):
        assert ra.inventory_service_worker_cache(tmp_path) == []

    def test_counts_files_and_size_per_origin_folder(self, tmp_path):
        cache_root = tmp_path / "Service Worker" / "CacheStorage"
        origin_folder = cache_root / "abc123"
        origin_folder.mkdir(parents=True)
        (origin_folder / "file1").write_bytes(b"12345")
        (origin_folder / "file2").write_bytes(b"1234567890")

        results = ra.inventory_service_worker_cache(tmp_path)

        assert len(results) == 1
        entry = results[0]
        assert entry["cache_folder_hash"] == "abc123"
        assert entry["file_count"] == 2
        assert entry["approx_size_bytes"] == 15

    def test_ignores_non_directory_entries(self, tmp_path):
        cache_root = tmp_path / "Service Worker" / "CacheStorage"
        cache_root.mkdir(parents=True)
        (cache_root / "stray_file.txt").write_text("not a folder")

        results = ra.inventory_service_worker_cache(tmp_path)

        assert results == []

    def test_counts_files_in_nested_subdirectories(self, tmp_path):
        cache_root = tmp_path / "Service Worker" / "CacheStorage"
        nested = cache_root / "origin" / "nested"
        nested.mkdir(parents=True)
        (nested / "blob").write_bytes(b"abc")

        results = ra.inventory_service_worker_cache(tmp_path)

        assert results[0]["file_count"] == 1
        assert results[0]["approx_size_bytes"] == 3


# ---------------------------------------------------------------------------
# clean_site_name
# ---------------------------------------------------------------------------

class TestCleanSiteName:
    def test_strips_https_port_and_trailing_wildcard(self):
        assert ra.clean_site_name("https://discord.com:443,*") == "discord.com"

    def test_strips_http_prefix(self):
        assert ra.clean_site_name("http://example.com,*") == "example.com"

    def test_strips_bracket_wildcard_subdomain(self):
        assert ra.clean_site_name("https://[*.]google.com,*") == "google.com"

    def test_leaves_chrome_internal_urls_recognizable(self):
        assert ra.clean_site_name("chrome://newtab/,*") == "chrome://newtab/"

    def test_already_clean_name_is_unchanged(self):
        assert ra.clean_site_name("example.com") == "example.com"


# ---------------------------------------------------------------------------
# format_permissions_section
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------

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
        assert "BROWSER ANTI-FORENSIC RESIDUE REPORT" in text
        assert "discord.com" in text
        assert "Location access: Allowed" in text
        assert "Field: email" in text
        assert "Cache folder: abc123" in text

    def test_writes_placeholder_messages_when_all_empty(self, tmp_path):
        output_path = tmp_path / "report.txt"

        ra.generate_report([], [], [], str(output_path))

        text = output_path.read_text(encoding="utf-8")
        assert "No permission grants found." in text
        assert "No autofill entries found." in text
        assert "No Service Worker cache data found." in text


# ---------------------------------------------------------------------------
# main (end-to-end integration test)
# ---------------------------------------------------------------------------

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
        assert "Field: username | Value: jdoe" in text
        assert "Cache folder: hash1" in text
        assert "Files: 1" in text

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
