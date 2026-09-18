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

Test files live in `tests/test_residue_analyzer.py`, organized into one
class per function:

| Class | Covers |
|---|---|
| `TestFindChromeProfilePath` | Profile path resolution, `LOCALAPPDATA` lookup |
| `TestChromeTimeToIso` | Chrome/WebKit timestamp conversion |
| `TestParsePermissions` | Preferences JSON parsing, including a regression test for the `AttributeError` crash on malformed exception data |
| `TestParseAutofill` | `Web Data` SQLite parsing, WAL/SHM copying, copy failures |
| `TestInventoryServiceWorkerCache` | Cache Storage directory inventory |
| `TestCleanSiteName` | Site name display cleanup |
| `TestFormatPermissionsSection` | Plain-English permission report formatting |
| `TestGenerateReport` | Full report generation |
| `TestMainEndToEnd` | Full CLI pipeline against a fake profile directory |
