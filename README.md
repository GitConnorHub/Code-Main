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

## Sharing a captured dataset (e.g. for grading)

To let someone else (a marker, a colleague) run this tool against the
exact same data you did and get matching results, hand over the raw
profile files, not just your generated report — the report on its own
can't be re-analyzed.

1. **Close Chrome first.** `Web Data` in particular is locked while
   Chrome is running and may not copy cleanly otherwise.
2. **Copy these three items out of the seeded profile folder** (typically
   `%LOCALAPPDATA%\Google\Chrome\User Data\Default`) into a new, empty
   folder — keep the exact names:
   - `Preferences` and/or `Secure Preferences`
   - `Web Data`
   - the `Service Worker\CacheStorage` folder (with its contents)

   Don't copy the whole profile folder — it also contains history,
   cookies, and cached site content that isn't needed here and may be
   sensitive even in a seeded profile (e.g. real login sessions if you
   ever signed into anything other than test accounts while seeding it).
3. **Zip that folder** (e.g. `seed_profile.zip`) and send it alongside
   `residue_analyzer.py` (or a link to this repo).
4. **Tell them the exact command to run:**
   ```bash
   python residue_analyzer.py --profile-path "<path to extracted seed_profile>" --output marker_report.txt
   ```
5. Optionally, generate `residue_report.txt` yourself from that same
   seed data first and include it as a reference, so they can diff their
   output against yours. Everything should match except the `Generated:`
   line at the top, which is always the current date/time and isn't
   derived from the data.

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
