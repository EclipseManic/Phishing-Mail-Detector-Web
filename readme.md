# Malware Analyzer

**Multi-format malware triage engine** — static analysis, YARA scanning, sandbox enrichment, and category-aware risk scoring in a self-hosted web dashboard.

Analyze PE (Windows), ELF (Linux), Mach-O (macOS), APK (Android), Office documents, PDFs, scripts, and archives through a unified pipeline. Offline heuristics and optional online threat intelligence feeds produce a normalized risk score with full evidence breakdown.

---

## Features

### Static Analysis (Offline)
| Feature | Details |
|---|---|
| **Hashing** | MD5, SHA-1, SHA-256 |
| **YARA** | 2,778 rules from 40 sources (Elastic, YARA-Rules, CAPE, APKiD, THOR) |
| **PE / EXE / DLL** | Sections, imports, entropy, packer hints, TLS callbacks, overlay, Authenticode, suspicious imports |
| **ELF (Linux)** | Sections, imports, RPATH/RUNPATH, NX/PIE/RELRO/Canary, interpreter, packer hints, suspicious sections |
| **Mach-O (macOS)** | Load commands, imports, encryption LC, code signing, CPU anomalies, packer hints |
| **APK (Android)** | Permissions, DEX analysis, exposed components, debuggable, backup flag, native code, packer hints |
| **Office documents** | VBA macros, auto-exec triggers, P-code, obfuscation, suspicious API calls, OLE objects, DDE, Equation Editor, encrypted macros |
| **PDF** | JavaScript, embedded files, launch actions, OpenAction, XFA forms, suspicious keys, URI count, embedded fonts, XREF anomalies |
| **Scripts** | PowerShell, VBS, BAT, Python, JS, AutoIT, CS, Lua, HTA — suspicion scoring per language |
| **Strings** | Printable strings extraction, base64 detection, embedded PE detection, suspicious keywords |
| **MITRE ATT&CK** | Technique mapping from static indicators and sandbox telemetry |
| **Similarity** | IMP hash, strings SimHash |

### Online Enrichment
| Provider | Data Retrieved |
|---|---|
| **VirusTotal** | Detection ratio, reputation, threat categories/labels, sandbox verdicts, Sigma/YARA/IDS crowdsourcing |
| **Hybrid-Analysis (CrowdStrike Falcon)** | Threat score, verdict, signatures, MITRE ATT&CK, processes, network, registry, filesystem, screenshots |
| **Tria.ge** | Sandbox score, verdict, signatures, MITRE TTPs, network IOCs, extracted configs, task reports |
| **FileScan.io** | Verdict, threat level, behavioral signals, MITRE, extracted IOCs, YARA matches |

All providers are toggleable and rate-limited. Unknown samples can optionally be submitted for analysis.

### Risk Scoring

**Category-aware scoring** that adjusts evidence budgets per file type:

| Category | Reputation | Sandbox | Static | Total |
|---|---|---|---|---|
| PE (Windows) | 25 | 35 | 40 | 100 |
| ELF (Linux) | 30 | 35 | 35 | 100 |
| Mach-O (macOS) | 30 | 30 | 40 | 100 |
| APK (Android) | 35 | 25 | 40 | 100 |
| Office | 40 | 20 | 40 | 100 |
| PDF | 35 | 20 | 45 | 100 |
| Script | 40 | 20 | 40 | 100 |
| Archive | 45 | 25 | 15 | 85 |
| Generic | 45 | 25 | 30 | 100 |

Risk tiers: **CRITICAL** (≥70), **HIGH** (≥45), **MEDIUM** (≥20), **LOW**.

Cross-source correlation is computed for display but does not affect the total score. An Authenticode floor (minimum score 70) applies when a revoked certificate is corroborated by multiple sandbox vendors.

### Web Dashboard
- Dark cybersecurity-themed UI with drag-drop file upload
- Real-time scan progress via WebSocket (Socket.IO)
- Report tabs: Overview, Static Analysis, Threat Intel, Behavioral, IOCs
- Score Breakdown table with per-pillar details
- Indicator pills (VT detections, HA score, Triage score)
- Provider status monitoring
- Correlated IOC visualization
- Report history with JSON export
- ZIP password prompt for encrypted archives

### Architecture
- **Byte-backed analysis pipeline** — uploaded files are processed entirely in memory; no temporary files are written to disk
- **Thread-pooled** concurrent provider lookups with configurable rate limiting
- **SQLite persistence** for scan history across restarts
- **WebSocket streaming** for real-time progress without polling latency

---

## Quick Start

### Requirements
- Python 3.8+
- [YARA](https://yara.readthedocs.io/) compiler (`yara-python` installs it automatically)

### Install

```powershell
git clone https://github.com/yourusername/malware-analyzer.git
cd malware-analyzer
pip install -r requirements.txt
```

On Windows, `python-magic` may require a compatible `libmagic` build. If import errors occur, `pip install python-magic-bin` provides a pre-built binary.

### Run

```powershell
python run.py
```

Open **http://127.0.0.1:5001/** in your browser.

| Environment Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5001` | Server port |
| `FLASK_DEBUG` | — | Enable debug mode (`1`) |
| `DISABLE_AUTO_OPEN` | — | Prevent automatic browser launch (`1`) |

---

## Configuration

### `config.json`

All settings live in `config.json` at the project root (gitignored — never commit secrets).

#### Rate Limits
```json
{
  "rate_limits": {
    "virustotal": 15,
    "hybrid_analysis": 5,
    "triage": 1,
    "filescan": 2
  }
}
```

#### Timeouts
```json
{
  "timeouts": {
    "request_timeout": 30,
    "max_retries": 2,
    "backoff_factor": 1.5,
    "max_file_size": 152428800,
    "max_concurrent_scans": 1,
    "enable_ssl_verification": true,
    "vt_poll_max_seconds": 300,
    "ha_poll_max_seconds": 600,
    "submission_timeout_seconds": 900
  }
}
```

#### Analysis Toggles
```json
{
  "analysis": {
    "enable_virustotal": true,
    "enable_hybrid_analysis": true,
    "enable_triage": true,
    "enable_filescan": true,
    "submit_unknown_to_vt": false,
    "submit_unknown_to_ha": false,
    "submit_unknown_to_triage": false,
    "submit_unknown_to_filescan": false,
    "enrichment_depth": "deep",
    "api_cache_ttl_seconds": 3600,
    "enable_macho_analysis": true,
    "enable_apk_analysis": true,
    "enable_deep_pdf": true,
    "enable_deep_office": true
  }
}
```

#### Provider Settings
```json
{
  "virustotal": { "api_key": "" },
  "hybrid_analysis": { "api_key": "" },
  "triage": { "api_key": "", "base_url": "https://tria.ge/api/v0" },
  "filescan": { "api_key": "" }
}
```

### Environment Variables

API keys can also be supplied via environment variables which take precedence over `config.json`:

```text
VT_API_KEY=your_virustotal_api_key
HA_API_KEY=your_hybrid_analysis_api_key
TRIAGE_API_KEY=your_triage_api_key
FILESCAN_API_KEY=your_filescan_api_key
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web UI |
| `GET` | `/api/config` | Public configuration (no secrets) |
| `POST` | `/api/scan` | Upload and analyze a file |
| `GET` | `/api/scan/<id>` | Poll scan status or retrieve completed result |
| `DELETE` | `/api/scan/<id>` | Cancel a running scan |
| `GET` | `/api/scans` | List completed scan history |
| `DELETE` | `/api/scans/clear` | Clear all scan history |
| `GET` | `/api/docs` | API documentation |

### Upload Format

Files can be uploaded as `application/octet-stream` with headers:

```
Content-Type: application/octet-stream
X-File-Name: sample.exe
X-Offline-Scan: 1
X-Online-Scan: 1
X-Zip-Password: infected
```

Or as `multipart/form-data` with field `malware_file`.

---

## YARA Rules

The analyzer ships with **2,778 rules** from **40 curated sources** covering:

| Category | Sources | Rules |
|---|---|---|
| Windows / PE | Elastic Windows (Trojan, Infostealer, Ransomware), CAPE, packers | ~1,400 |
| Webshells | Elastic Linux Webshell, THOR Webshells | ~550 |
| Linux / ELF | Elastic Linux (Trojan, Rootkit, Cryptominer, Backdoor, Worm, Shellcode, Downloader) | ~85 |
| Android / APK | APKiD (Packers, Obfuscators, Protectors) | ~95 |
| macOS / Mach-O | Elastic macOS (Trojan, Cryptominer) | ~5 |
| Office / PDF | YARA-Rules maldoc (Dridex, DDE, CVE-2017-11882, VBA, RTF, OLE, etc.) | ~70 |
| Generic / Multi | Elastic Multi (Threat, Cryptominer), EICAR test | ~560 |

The combined ruleset lives at `data/rules.yar`. To update it:

```powershell
python -c "from modules.update_rules import update_rules; update_rules('data/rules.yar')"
```

This fetches the latest rules from all 40 upstream sources (Elastic, YARA-Rules, CAPE, APKiD, THOR) and compiles them into a single file.

---

## Project Structure

```
malware-analyzer/
├── run.py                  # Flask application entry point, API routes, WebSocket
├── config.json             # User configuration (gitignored)
├── requirements.txt        # Python dependencies
├── package.json            # Node.js frontend server (optional)
├── modules/
│   ├── Malware_Analyzer.py # Core analysis engine (6600+ lines)
│   ├── scoring_system.py   # Category-aware risk scoring
│   ├── scoring_adapter.py  # Report format adapter
│   └── update_rules.py     # YARA rule updater
├── ui/
│   ├── index.html          # Web application template
│   ├── app.js              # Dashboard JavaScript
│   ├── styles.css          # Dark theme stylesheet
│   └── Malware.png         # Favicon
├── data/
│   ├── rules.yar           # Combined YARA ruleset (auto-generated)
│   └── scans.db            # SQLite scan history (auto-generated)
├── frontend/
│   └── server.js           # Optional Node.js frontend proxy
└── tests/
    ├── test_api_request.py
    ├── test_category_scoring.py
    ├── test_config_bool.py
    ├── test_filescan.py
    ├── test_hybrid_analysis.py
    ├── test_memory_pipeline.py
    ├── test_phase5_validation.py
    ├── test_report_schema.py
    ├── test_scoring_semantics.py
    ├── test_static_analysis.py
    ├── test_triage.py
    ├── test_ui_contract.py
    ├── test_ui_history.py
    ├── test_virustotal.py
    └── test_web_only_surface.py
```

---

## Running Tests

```powershell
python -m pytest tests/
```

All 75 tests pass with no external dependencies — online providers are mocked. Tests cover scoring semantics, provider integration, report schema, UI contracts, memory pipeline, and configuration parsing.

---

## Development

### Adding a New YARA Source

Edit `modules/update_rules.py` and append a `Source` entry to the `SOURCES` list:

```python
Source(
    url="https://raw.githubusercontent.com/owner/repo/main/rules.yar",
    label="my_source",
    section="my_section",
)
```

Run the updater and verify compilation:

```powershell
python -c "from modules.update_rules import update_rules; update_rules('data/rules.yar')"
```

### Adding a New File Category

1. Add a policy tuple to `CATEGORY_POLICIES` in `modules/scoring_system.py`
2. Add static analysis logic in `_score_static()` in the same file
3. Add the detection branch in `detect_category()`
4. Handle extraction in `modules/Malware_Analyzer.py`

---

## Security Considerations

- The web app **does not** prevent antivirus products from detecting the original source file before the browser reads it
- Unknown samples **may** be submitted to external providers when online enrichment and submit flags are enabled
- The built-in Flask server is a development server — **not** suitable for hardened multi-user deployments
- API keys in `config.json` are gitignored but stored in plain text on disk
- Enable HTTPS behind a reverse proxy (nginx, Caddy) for production use
- Set `max_concurrent_scans` to limit resource usage

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [Elastic Security](https://github.com/elastic/protections-artifacts) — YARA rules
- [YARA-Rules](https://github.com/Yara-Rules/rules) — Maldoc and packer rules
- [APKiD](https://github.com/rednaga/APKiD) — Android packer detection
- [CAPE](https://github.com/kevoreilly/CAPEv2) — YARA rules
- [THOR](https://github.com/Neo23x0/thor) — Webshell rules
- [LIEF](https://lief-project.github.io/) — Binary parsing
- [oletools](https://github.com/decalage2/oletools) — Office document analysis
- [Androguard](https://github.com/androguard/androguard) — APK analysis
- [pdfminer.six](https://github.com/pdfminer/pdfminer.six) — PDF parsing
