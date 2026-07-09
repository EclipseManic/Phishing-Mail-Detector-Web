# Phishing Mail Detector — Web

Flask-based web app for analyzing `.eml` files and generating a full phishing risk report — header forensics, URL/domain analysis, attachment scanning, threat intel enrichment, and MITRE ATT&CK mapping — with async progress tracking and persistent scan history.

## Features

- **Email parsing & header forensics** — parses `.eml` files, decodes headers, walks `Received` chains, and validates authentication (SPF, DKIM, DMARC, ARC, Microsoft security headers)
- **Sender & domain analysis** — spoofing detection, domain age lookups (WHOIS), brand impersonation checks
- **URL analysis** — link extraction, normalization, unshortening, and reference-link filtering
- **HTML & QR analysis** — inspects HTML body content and scans embedded images for QR codes
- **Attachment analysis** — static analysis for PDF, OOXML (Office), and OLE files, double-extension detection, and text/link extraction from attachments
- **Threat intel enrichment** — optional integration with VirusTotal and urlscan.io
- **Risk scoring** — weighted score and feedback generation from all observables
- **MITRE ATT&CK mapping** — maps findings to relevant ATT&CK techniques with recommendations
- **Async scans with live progress** — background task processing with a step-by-step progress API
- **Scan history** — results persisted to a local SQLite database, with list/view/delete endpoints

## Tech Stack

- **Backend:** Flask (Python)
- **Storage:** SQLite (`data/scans.db`)
- **Frontend:** Single-page HTML/JS (`templates/index.html`)
- **Optional integrations:** VirusTotal API, urlscan.io API, WHOIS, Tesseract OCR, pyzbar (QR), oletools

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

### Configuration (optional)

Set API keys as environment variables to enable enrichment:

```bash
export VT_API_KEY="your_virustotal_api_key"
export URL_SCAN_API_KEY="your_urlscan_api_key"
```

Without these, the app still runs — VirusTotal and urlscan.io enrichment steps are simply skipped.

### Run

```bash
python run.py
```

The app starts on `http://127.0.0.1:5000/` and opens automatically in your browser. Override the port with `PORT=8080`, or disable the browser auto-open with `DISABLE_AUTO_OPEN=1`.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web UI |
| `POST` | `/api/analyze` | Upload and analyze an `.eml` file |
| `GET` | `/api/analyze/<task_id>/progress` | Poll analysis progress |
| `GET` | `/api/scans` | List saved scans |
| `GET` | `/api/scans/<scan_id>` | Get a specific scan report |
| `DELETE` | `/api/scans/<scan_id>` | Delete a scan |
| `DELETE` | `/api/scans` | Delete all scans |

Max upload size is 25 MB.

## Project Structure

```
Phishing-Mail-Detector-Web/
├── run.py              # Flask app, routes, async task orchestration
├── requirements.py     # Python dependencies
├── core/
│   ├── config.py        # Feature flags & threat intel config
│   ├── utils.py          # Normalization & shared utilities
│   ├── analyzers.py      # Header, URL, HTML, attachment analysis
│   ├── apis.py            # VirusTotal & urlscan.io integrations
│   └── database.py        # SQLite persistence layer
├── data/                # SQLite scan history
├── templates/           # Web UI
├── static/              # Assets
└── test_files/          # Sample/test .eml files
```

## Notes

- WHOIS, attachment parsing, image/QR scanning, TLD extraction, and OLE macro analysis are all optional and only activate if the relevant Python packages are installed.
- Scan history is stored locally in `data/scans.db`; no data leaves your machine except for enrichment calls to VirusTotal/urlscan.io when configured.
