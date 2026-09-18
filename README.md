# Browser Anti-Forensic Residue Analyzer

A Chrome-only forensic/privacy-auditing tool that inspects a browser profile
folder and reports what browsing-related evidence is still recoverable from
it. It's read-only: it never modifies, deletes, or hides anything in the
profile it examines.

It looks at three artifact sources:

1. **Site permission grants** — from `Secure Preferences` / `Preferences`
   (camera, microphone, location, notifications, etc.)
2. **Autofill form data** — from the `Web Data` SQLite database
3. **Service Worker Cache Storage** — a per-origin file/size inventory

The output is a single, plain-English text report — no coding knowledge
needed to read it.

## Usage

```bash
python residue_analyzer.py --profile-path "C:\path\to\Default" --output report.txt
```

- `--profile-path` — a Chrome profile folder (e.g. a copied evidence folder
  containing `Preferences`, `Web Data`, and `Service Worker`). If omitted,
  the tool tries to locate the live local Chrome `Default` profile
  (Windows only, via the `LOCALAPPDATA` environment variable).
- `--output` — where to save the report (default: `residue_report.txt`).

## Report format

The site permissions section groups results by site and separates real
allow/block decisions from Chrome's internal bookkeeping:

```
discord.com
    - Camera access: Allowed
    - Microphone access: Allowed
    Other browser bookkeeping (not a permission you granted):
      - Site engagement — Chrome's internal 'how often do you use this site' score.
```

## Requirements

- Python 3, standard library only (no third-party runtime dependencies)

## Running the tests

The test suite uses [pytest](https://docs.pytest.org/) with plain `assert`
statements, and covers each parsing module individually as well as the
full pipeline end-to-end (`main()` run against a synthetic Chrome profile).

```bash
pip install -r requirements-dev.txt
pytest
```

Test files live in `tests/test_residue_analyzer.py`. Most tests are plain
`test_*` functions grouped by the function they cover (`chrome_time_to_iso`,
`find_chrome_profile_path`, `parse_permissions`, `parse_autofill`,
`inventory_service_worker_cache`, and the readability layer
`friendly_permission_type`/`friendly_site_name`/`summarize_permissions_by_site`),
including regression tests for two `AttributeError` crashes previously found
in `parse_permissions` on malformed/non-dict JSON, and a deduplication test
for the same exception appearing in both `Secure Preferences` and
`Preferences`. An end-to-end test runs the full pipeline against a
synthetic profile.

A few remaining classes cover behavior not exercised above:

| Class | Covers |
|---|---|
| `TestFindChromeProfilePathLiveDetection` | `LOCALAPPDATA`-based live profile lookup |
| `TestParsePermissionsAdditional` | A non-dict per-site "details" value; merging distinct entries across both preference files |
| `TestParseAutofillAdditional` | WAL/SHM companion file copying; a locked/inaccessible `Web Data` file |
| `TestCleanSiteNameAdditional` | Site name display cleanup edge cases |
| `TestFormatPermissionsSection` | Plain-English permission report text rendering |
| `TestGenerateReport` | Full report generation, including the all-empty case |
| `TestMainEndToEnd` | Full CLI pipeline, including a nonexistent profile path |
