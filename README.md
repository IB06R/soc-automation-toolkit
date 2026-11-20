# SOC Automation Toolkit

A collection of lightweight, practical CLI tools built in **PowerShell** and **Python** to automate repetitive Tier-1 Security Operations Center (SOC) triage, threat-intelligence enrichment, and endpoint integrity monitoring workflows. Every tool outputs structured CSV reports ready for incident ticketing or SIEM ingestion.

---

## Repository Structure

    soc-automation-toolkit/
    ├── 1-windows-log-triage/
    │   └── Get-FailedLogons.ps1         # Event ID 4625 brute-force & password-spray triage
    ├── 2-threat-intel-enricher/
    │   ├── enrich_indicators.py         # Bulk IPv4 extraction & AbuseIPDB reputation enricher
    │   ├── requirements.txt
    │   └── sample_iocs.txt
    ├── 3-file-integrity-monitor/
    │   └── fim_monitor.py               # SHA-256 cryptographic File Integrity Monitor (FIM)
    ├── .env.example
    └── .gitignore

---

## 1. Windows Failed-Login Triage (`Get-FailedLogons.ps1`)

Queries the Windows `Security` event log (`Get-WinEvent -FilterHashtable`) for **Event ID 4625** (*An account failed to log on*), parses raw XML event payloads, translates Windows `LogonType` and `SubStatus` hex codes into plain English, and flags both **Brute-Force** (single user) and **Password-Spraying** (multiple distinct accounts from one IP) patterns.

### Usage

    # Run PowerShell as Administrator
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

    # Standard CLI triage (last 24 hours, threshold 5, exports CSV)
    .\Get-FailedLogons.ps1

    # Custom incident window with interactive Windows Out-GridView table
    .\Get-FailedLogons.ps1 -HoursBack 2 -Threshold 2 -Gui

### Sample Output

    [*] Querying Event ID 4625 on [ISAIAH-B-RAMONT] since 11/20/2026 13:53:41...

    --- Brute-Force Check (Grouped by Source IP & Target User) ---
    [HIGH - BRUTE FORCE] Attempts: 2 | ::1, SOC_TestUser
    [INFO] Attempts: 1 | ::1, fakeuser

    --- Password-Spray Check (Unique Users Targeted per Source IP) ---
    [HIGH - PASSWORD SPRAY] Source IP: ::1 targeted 2 distinct accounts!

    [+] Exported 3 total events to .\failed_logon_triage.csv

---

## 2. Threat Intelligence IP Enricher (`enrich_indicators.py`)

Eliminates manual browser lookups during alert triage. Extracts IPv4 addresses from plain text, CSV exports, or raw firewall log lines using regex, deduplicates indicators, filters out private/loopback RFC1918 addresses locally so internal topology never leaks externally, and enriches public IPs via the **AbuseIPDB v2 API**.

### Usage

    cd 2-threat-intel-enricher
    pip install -r requirements.txt

    # Configure API key via environment variable (never hardcoded)
    $env:ABUSEIPDB_API_KEY="your_api_key_here"

    # Run against an indicator list or raw log dump
    python enrich_indicators.py sample_iocs.txt

### Sample Output

    [*] Found 4 unique valid IP(s) in 'sample_iocs.txt'...

    [CLEAN     ] 8.8.8.8          | Score:   0% | Reports: 205  | ISP: Google LLC
    [CLEAN     ] 1.1.1.1          | Score:   0% | Reports: 281  | ISP: APNIC and Cloudflare DNS Resolver project
    [INTERNAL  ] 192.168.1.50     | Score:   0% | Reports: 0    | ISP: Private/Internal Network
    [MALICIOUS ] 185.220.101.1    | Score: 100% | Reports: 484  | ISP: Artikel10 e.V.

    [+] Saved full threat-intel report to enriched_iocs_20261120_164612.csv

---

## 3. File Integrity Monitor (`fim_monitor.py`)

A zero-dependency Python File Integrity Monitoring (FIM) utility using `hashlib.sha256`. Streams files in 64 KB binary chunks to establish a cryptographic baseline manifest (`fim_baseline.json`) with file sizes and UTC modification timestamps. On subsequent audits, it detects unauthorized file modifications, deletions, or dropped payloads, exports a forensic CSV alert report, and returns automation-friendly exit codes (`0` = clean, `1` = error, `2` = tampering detected).

### Usage

    cd 3-file-integrity-monitor

    # Initialize baseline manifest (fim_baseline.json)
    python fim_monitor.py init ./target_directory

    # Audit directory against baseline (exports fim_alerts_*.csv if changes occur)
    python fim_monitor.py check ./target_directory

### Sample Output

    [+] Baseline initialized with 2 file(s) -> fim_baseline.json
    [ALERT - MODIFIED] server.conf (Size: 38B -> 35B | Modified: 2026-11-20T15:24:11+00:00)
    [ALERT - DELETED]  users.db
    [ALERT - CREATED]  persistence.bat (Size: 31B | SHA256: 9f86d081884c7d65...)

    [!] Integrity check complete: 3 alert(s) triggered.
    [+] Exported forensic alert report to fim_alerts_20261120_172814.csv

---

## Engineering Notes & What Broke During Testing

* **CSV File-Lock Collisions (`IOException`):** During testing of `Get-FailedLogons.ps1`, keeping a previous CSV report open in Excel locked the file handle and crashed subsequent runs. Wrapped `Export-Csv` in a `try/catch` block that automatically falls back to a timestamped filename (`failed_logon_triage_yyyyMMdd_HHmmss.csv`).
* **Windows PowerShell UTF-8 BOM Parsing Bug:** Generating test IOC files via PowerShell `Out-File -Encoding utf8` prepended an invisible `\ufeff` Byte Order Mark (BOM) to line 1, causing comment lines (`# ...`) to bypass prefix checks and fail API queries. Resolved by reading files with `encoding="utf-8-sig"` and extracting valid IPv4 tokens via regex + Python's `ipaddress` module.
* **RFC1918 Privacy & API Rate Hygiene:** Added local checks (`is_private`, `is_loopback`) and `dict.fromkeys()` deduplication in `enrich_indicators.py` so duplicate entries or internal LAN addresses do not waste free-tier API quota or expose internal IP space.
* **Baseline Schema Migration (`TypeError`):** Upgrading `fim_monitor.py` from storing flat SHA-256 strings to structured metadata dictionaries initially triggered a `TypeError` when auditing against v1 baseline manifests. Added backward-compatible type checking (`isinstance(old_entry, str)`) and `target_directory` validation to prevent cross-folder baseline collisions.