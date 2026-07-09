# Phishing Mail Detector — Web

An enterprise-style phishing investigation tool with a Flask backend and browser UI. Drop in a raw `.eml` file and get back a full forensic breakdown: authentication verification, sender/domain spoofing checks, URL and attachment analysis, threat intel enrichment, a weighted 0–10 risk score, and MITRE ATT&CK mapping — all with live progress tracking and persistent scan history.

Built as a SOC-analyst-facing tool, not a toy classifier — the scoring model, brand/domain map, and keyword corpora are hand-tuned against real phishing patterns rather than a black-box ML score.

## Status

Actively developed, single-maintainer project. Core analysis pipeline is functional and in daily use for personal investigation work. Not yet covered by an automated test suite — treat as a research/analyst tool rather than a hardened, deployment-ready service. See [Known Limitations](#known-limitations) below.

## What it actually checks

**Header & authentication forensics**
- Parses raw `.eml` structure, decodes MIME/encoded headers, and walks the full `Received` chain
- Validates SPF, DKIM, DMARC, and ARC, including Microsoft's composite authentication (`compauth`) header and alignment between the `From`, `Return-Path`, and `Reply-To` addresses

**Sender & domain analysis**
- Display-name vs. domain mismatch and homograph/lookalike domain detection
- Domain age lookups via WHOIS, flagging newly registered domains (< 30 days by default)
- Brand impersonation: cross-references sender/body content against a curated map of ~50 commonly spoofed brands (Microsoft, PayPal, Amazon, major banks, shipping carriers, government agencies, etc.) and their legitimate domains, so "paypal-secure-login.xyz" gets flagged as impersonating PayPal rather than matching it

**URL & content analysis**
- Link extraction, normalization, defanging, and shortener unwrapping (bit.ly, tinyurl, etc.)
- Flags abused-but-legitimate hosting services (Google Docs, Firebase, Netlify, ngrok, SharePoint, and ~30 others) used as phishing delivery infrastructure
- Redirect-parameter detection (`?url=`, `?redirect=`, `?next=`, etc.), suspicious/high-abuse TLDs, and reference-URL filtering to cut XML-schema noise from real findings
- HTML body inspection for hidden elements, meta-refresh redirects, iframes, and inline JavaScript
- QR code extraction and decoding from embedded images (quishing detection)

**Attachment analysis**
- Static analysis for PDF (`pdfplumber`), OOXML/Office (`.docx`/`.xlsx`/`.pptx` zip structure), and legacy OLE files
- VBA/macro detection via `oletools`, double-extension detection, risky-extension flagging (`.exe`, `.hta`, `.lnk`, `.iso`, `.js`, etc.), and link/text extraction from inside attachments

**Threat intel enrichment (optional)**
- VirusTotal: domain/URL/file-hash/IP reputation lookups
- urlscan.io: submission, search, DOM/HAR retrieval, and detection-flag correlation

**Risk scoring**
- A weighted model (`core/config.py: WEIGHTS`) scores ~40 distinct signal types across auth failures, sender anomalies, domain/network reputation, content, keywords, URLs, attachments, and behavioral combinations (e.g. "young domain + attachment" or "auth failure + urgency language" score higher together than either alone)
- Critical findings (malicious attachment, macros present, homograph attack) set a score floor independent of everything else, so one severe signal can't get diluted by several benign ones
- Verdict tiers: **UNSAFE** (score ≥ 7), **CAUTIOUS** (score 4–6), **SAFE** (score < 4)

**MITRE ATT&CK mapping**
- Maps findings to relevant techniques (e.g. `T1566.001/.002/.003` — phishing via attachment/link/service, `T1204.002` — malicious file execution) with tailored remediation recommendations per verdict

## Tech Stack

- **Backend:** Flask (Python), background threading for async scan tasks, Flask's built-in dev server
- **Storage:** SQLite (`data/scans.db`) — scan history with list/view/delete
- **Frontend:** Single-page HTML/JS UI (`templates/index.html`) with live step-by-step progress polling
- **Optional integrations:** VirusTotal API, urlscan.io API, WHOIS, Tesseract OCR + pyzbar (QR), oletools (macros)

Each optional dependency degrades gracefully — if it's not installed, that analysis stage is simply skipped rather than crashing the pipeline (see `VT_AVAILABLE`, `WHOIS_AVAILABLE`, `IMAGE_SCANNING_AVAILABLE`, etc. in `core/config.py`).

## Getting Started

### Prerequisites
- Python 3.10+
- System packages for optional features:
  ```bash
  sudo apt install libzbar0 tesseract-ocr
  ```

### Installation
```bash
git clone https://github.com/EclipseManic/Phishing-Mail-Detector-Web.git
cd Phishing-Mail-Detector-Web
pip install -r requirements.py
```
> Note: dependencies are listed in `requirements.py` (plain pip-requirements format despite the `.py` extension) — `pip install -r` reads it the same as a `.txt` file.

### Configuration (optional)
```bash
export VT_API_KEY="your_virustotal_api_key"
export URL_SCAN_API_KEY="your_urlscan_api_key"
```
The app runs fully without these — VirusTotal and urlscan.io enrichment stages are skipped if the keys aren't set.

### Run
```bash
python run.py
```
Starts on `http://127.0.0.1:5000/` and opens automatically in your browser.

| Env var | Purpose |
|---|---|
| `PORT` | Override the default port (`5000`) |
| `FLASK_DEBUG=1` | Enable Flask debug mode |
| `DISABLE_AUTO_OPEN=1` | Don't auto-open the browser on start |

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web UI |
| `POST` | `/api/analyze` | Upload an `.eml` file, kicks off an async scan (25 MB max) |
| `GET` | `/api/analyze/<task_id>/progress` | Poll live progress through the 11-stage pipeline |
| `GET` | `/api/scans` | List saved scans |
| `GET` | `/api/scans/<scan_id>` | Retrieve a full past report |
| `DELETE` | `/api/scans/<scan_id>` | Delete a scan |
| `DELETE` | `/api/scans` | Clear all scan history |

Analysis pipeline stages (visible via the progress endpoint): `upload → parse → auth → sender → urls → attachments → vt → urlscan → score → mitre → complete`.

## Project Structure

```
Phishing-Mail-Detector-Web/
├── run.py               # Flask app, routes, async task orchestration, verdict thresholds
├── requirements.py      # Python dependencies
├── core/
│   ├── config.py         # Feature flags, scoring weights, brand/domain map, keyword corpora
│   ├── utils.py           # Normalization, defanging, domain/URL helpers
│   ├── analyzers.py       # Header forensics, URL/HTML/QR/attachment analysis (~55 KB)
│   ├── apis.py             # VirusTotal & urlscan.io integrations
│   ├── pipeline.py         # Risk scoring, MITRE mapping, report/recommendation building (~48 KB)
│   └── database.py         # SQLite persistence layer
├── data/                 # SQLite scan history (scans.db)
├── templates/            # Web UI
├── static/               # Assets
└── test_files/           # Sample/test .eml files
```

## Known Limitations

- **No automated test suite yet.** The analysis modules are functionally verified through manual/real-world scans, not unit tests. A pytest suite covering the pure functions in `analyzers.py` and `utils.py` is planned.
- **Single-user, local-first design.** Built to run on one machine for one analyst via Flask's development server — not load-tested or hardened for multi-tenant/public-facing deployment.
- **Git history starts from a single upload commit** — earlier iteration history isn't preserved in this repo.


## Notes

- WHOIS, attachment parsing, image/QR scanning, TLD extraction, and OLE macro analysis are optional — each activates automatically only if its Python package is installed, checked at import time in `core/config.py`.
- Everything runs locally. No data leaves the machine except enrichment calls to VirusTotal/urlscan.io when those keys are configured.
- `analysis_version` is currently `2.0.0` (tracked in `SETTINGS`), matching the `core` package `__version__`.
