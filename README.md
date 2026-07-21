<br>

<h1 align="center">
  🕵️ Phishing Mail Detector
</h1>
<div align="center">
  <img src="https://github.com/user-attachments/assets/d22b07c6-fb4f-4542-a3f0-dd85a0417ebe" alt="Phishing Mail Detector Dashboard" width="900" style="border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);"/>
</div>

<p align="center">
  <b>Enterprise-Grade Forensic Email Investigation Platform</b><br>
  <i>Upload a raw <code>.eml</code> → Receive a Full Threat Intelligence Report</i>
</p>

<br>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="#"><img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"></a>
  <a href="#"><img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"></a>
  <a href="#"><img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Red?style=for-the-badge&logo=mitre&logoColor=white" alt="MITRE ATT&CK"></a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Status-Active%20Development-yellow?style=flat-square" alt="Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-2.0.0-blue?style=flat-square" alt="Version"></a>
  <a href="#"><img src="https://img.shields.io/badge/Maintainer-Solo-ff69b4?style=flat-square" alt="Maintainer"></a>
</p>

<br>

---

## 🌟 Overview

**Phishing Mail Detector** is a professional-grade investigation tool built for **SOC analysts**, **incident responders**, and **security researchers**. Unlike simple phishing classifiers that output a basic "phishing or not" verdict, this tool performs a deep forensic analysis of email artifacts, correlating ~40 distinct signal types across authentication, sender identity, URLs, attachments, and threat intelligence feeds.

<p align="center">
  <table>
    <tr>
      <td align="center" width="33%"><b>🔐 Authentication</b><br><sub>SPF · DKIM · DMARC · ARC</sub></td>
      <td align="center" width="33%"><b>🕵️ Spoofing</b><br><sub>Homographs · Brand Impersonation</sub></td>
      <td align="center" width="33%"><b>📊 Scoring</b><br><sub>Weighted 0–10 Risk Model</sub></td>
    </tr>
    <tr>
      <td align="center"><b>🔗 URL Intel</b><br><sub>Shorteners · Redirects · Quishing</sub></td>
      <td align="center"><b>📎 Attachments</b><br><sub>Macros · OLE · PDF Analysis</sub></td>
      <td align="center"><b>🌐 Threat Intel</b><br><sub>VT · urlscan.io Enrichment</sub></td>
    </tr>
    <tr>
      <td align="center"><b>⚔️ MITRE Mapping</b><br><sub>T1566 · T1204 · Remediation</sub></td>
      <td align="center"><b>⏱️ Live Progress</b><br><sub>11-Stage Pipeline Visibility</sub></td>
      <td align="center"><b>💾 History</b><br><sub>Persistent SQLite Storage</sub></td>
    </tr>
  </table>
</p>

> Built as a **SOC-analyst-facing tool**, not a toy classifier. The scoring model, brand/domain map, and keyword corpora are hand-tuned against real-world phishing patterns rather than a black-box ML score.

---

## 🎯 Table of Contents

<p align="center">
  <a href="#-features">📋 Features</a> • 
  <a href="#-tech-stack">🛠 Tech Stack</a> • 
  <a href="#-getting-started">🚀 Getting Started</a> • 
  <a href="#-api-reference">📖 API Reference</a> • 
  <a href="#-project-structure">📁 Structure</a> • 
  <a href="#-known-limitations">⚠️ Limitations</a> • 
  <a href="#-notes">📝 Notes</a>
</p>

---

## 📋 Features

### 1️⃣ Header & Authentication Forensics

| Component | Capability |
|-----------|------------|
| **📧 MIME Parsing** | Decodes raw `.eml` structure, encoded headers, and full `Received` chain |
| **🔐 SPF / DKIM / DMARC** | Full validation with alignment analysis |
| **🏢 Microsoft CompAuth** | Composite authentication header parsing |
| **🔄 Address Alignment** | Cross-checks `From`, `Return-Path`, and `Reply-To` addresses |

### 2️⃣ Sender & Domain Analysis

| Component | Capability |
|-----------|------------|
| **👤 Display-Name Spoofing** | Detects mismatch between display name and actual domain |
| **🔤 Homograph Detection** | Identifies lookalike characters (e.g., `rnicrosoft.com`) |
| **🌐 Domain Age** | WHOIS lookups flag domains registered < 30 days |
| **🏷️ Brand Impersonation** | Cross-references against 50+ commonly spoofed brands (Microsoft, PayPal, Amazon, major banks, shipping carriers, government agencies) |
| **🚩 Smart Matching** | `paypal-secure-login.xyz` → flagged as **impersonating** PayPal, not matching it |

### 3️⃣ URL & Content Analysis

| Component | Capability |
|-----------|------------|
| **🔗 Link Extraction** | Normalization, defanging, and shortener unwrapping (bit.ly, tinyurl, etc.) |
| **🏢 Hosting Abuse Detection** | Flags Google Docs, Firebase, Netlify, ngrok, SharePoint, and ~30 other services used as phishing delivery infrastructure |
| **🔄 Redirect Detection** | Identifies `?url=`, `?redirect=`, `?next=` parameters |
| **🌍 TLD Analysis** | Flags suspicious and high-abuse top-level domains |
| **📄 HTML Inspection** | Hidden elements, meta-refresh redirects, iframes, inline JavaScript |
| **📷 QR Extraction** | Detects and decodes QR codes from embedded images (quishing) |

### 4️⃣ Attachment Analysis

| Component | Capability |
|-----------|------------|
| **📑 PDF Analysis** | Static analysis via `pdfplumber` |
| **📊 Office Documents** | OOXML (`.docx`/`.xlsx`/`.pptx`) zip structure analysis |
| **🗄️ Legacy OLE** | Old-format Office file inspection |
| **🦠 Macro Detection** | VBA/macro detection via `oletools` |
| **📁 Extension Checks** | Double-extension detection, risky extensions (`.exe`, `.hta`, `.lnk`, `.iso`, `.js`) |
| **🔗 Content Extraction** | Extracts links and text from inside attachments |

### 5️⃣ Threat Intelligence Enrichment

<p align="center">
  <table>
    <tr>
      <th align="center">Service</th>
      <th align="center">Capabilities</th>
      <th align="center">Requires API Key?</th>
    </tr>
    <tr>
      <td align="center"><b>🛡️ VirusTotal</b></td>
      <td>Domain, URL, file hash, IP reputation lookups</td>
      <td align="center">✅ Optional</td>
    </tr>
    <tr>
      <td align="center"><b>🔍 urlscan.io</b></td>
      <td>Submission, search, DOM/HAR retrieval, detection correlation</td>
      <td align="center">✅ Optional</td>
    </tr>
  </table>
</p>

> All enrichment stages **degrade gracefully** — if a key isn't set, the corresponding analysis is skipped without crashing.

### 6️⃣ Risk Scoring Model

The risk engine evaluates **~40 distinct signal types** across multiple categories:

```
🔐 Auth Failures    👤 Sender Anomalies    🌐 Domain Reputation
📝 Content Analysis  🔑 Keywords            🔗 URL Analysis
📎 Attachments       🔄 Behavioral Combinations
```

**Scoring Rules:**
- **Weighted model** defined in `core/config.py: WEIGHTS`
- **Critical findings** (malicious attachment, macros, homograph attack) set a **score floor** — one severe signal can't be diluted by benign findings
- **Composite scoring**: combinations like "young domain + attachment" or "auth failure + urgency language" score higher together than either alone

<p align="center">
  <table>
    <tr>
      <th align="center">Score Range</th>
      <th align="center">Verdict</th>
      <th align="center">Indicator</th>
    </tr>
    <tr>
      <td align="center"><b>≥ 7</b></td>
      <td align="center"><b>UNSAFE</b></td>
      <td align="center"><code>🛑 🔴</code></td>
    </tr>
    <tr>
      <td align="center"><b>4 – 6</b></td>
      <td align="center"><b>CAUTIOUS</b></td>
      <td align="center"><code>⚠️ 🟡</code></td>
    </tr>
    <tr>
      <td align="center"><b>&lt; 4</b></td>
      <td align="center"><b>SAFE</b></td>
      <td align="center"><code>✅ 🟢</code></td>
    </tr>
  </table>
</p>

### 7️⃣ MITRE ATT&CK Mapping

| Technique ID | Description | Context |
|-------------|-------------|---------|
| `T1566.001` | Spearphishing Attachment | Malicious file attached to email |
| `T1566.002` | Spearphishing Link | Malicious URL in email body |
| `T1566.003` | Spearphishing via Service | Abuse of legitimate cloud services |
| `T1204.002` | Malicious File Execution | User tricked into running malware |

Each verdict includes **tailored remediation recommendations** based on the specific findings.

---

## 🛠 Tech Stack

<div align="center">
  <table>
    <tr>
      <th align="center">Layer</th>
      <th align="center">Technology</th>
      <th align="center">Purpose</th>
    </tr>
    <tr>
      <td align="center"><b>🧠 Backend</b></td>
      <td>Flask (Python)</td>
      <td>Async scan orchestration with background threading</td>
    </tr>
    <tr>
      <td align="center"><b>💾 Storage</b></td>
      <td>SQLite</td>
      <td>Persistent scan history (list / view / delete)</td>
    </tr>
    <tr>
      <td align="center"><b>🎨 Frontend</b></td>
      <td>Single-page HTML/JS</td>
      <td>Live step-by-step progress polling</td>
    </tr>
    <tr>
      <td align="center"><b>🔌 Integrations</b></td>
      <td>VirusTotal · urlscan.io · WHOIS · Tesseract OCR · pyzbar · oletools</td>
      <td>Optional — graceful degradation when unavailable</td>
    </tr>
  </table>
</div>

---

## 🚀 Getting Started

### 📋 Prerequisites

<table>
  <tr>
    <td><b>🐍 Python</b></td>
    <td>Version 3.10 or higher</td>
  </tr>
  <tr>
    <td><b>📦 System Packages</b></td>
    <td><i>(Optional, for advanced features)</i></td>
  </tr>
</table>

```bash
# Install system dependencies for QR scanning & OCR
sudo apt install libzbar0 tesseract-ocr
```

### 📥 Installation

```bash
# Clone the repository
git clone https://github.com/EclipseManic/Phishing-Mail-Detector-Web.git

# Navigate to project directory
cd Phishing-Mail-Detector-Web

# Install Python dependencies
pip install -r requirements.py
```

> **💡 Note:** Dependencies are listed in `requirements.py` (plain pip-requirements format despite the `.py` extension). `pip install -r` reads it the same as a `.txt` file.

### 🔑 Configuration (Optional)

```bash
export VT_API_KEY="your_virustotal_api_key"
export URL_SCAN_API_KEY="your_urlscan_api_key"
```

The application runs **fully functional** without these keys — VirusTotal and urlscan.io enrichment stages are simply skipped.

### ▶️ Running the Application

```bash
python run.py
```

The server starts on `http://127.0.0.1:5000/` and opens automatically in your browser.

### ⚙️ Environment Variables

<p align="center">
  <table>
    <tr>
      <th>Variable</th>
      <th>Purpose</th>
      <th>Example</th>
    </tr>
    <tr>
      <td><code>PORT</code></td>
      <td>Override default port</td>
      <td><code>PORT=8080</code></td>
    </tr>
    <tr>
      <td><code>FLASK_DEBUG</code></td>
      <td>Enable Flask debug mode</td>
      <td><code>FLASK_DEBUG=1</code></td>
    </tr>
    <tr>
      <td><code>DISABLE_AUTO_OPEN</code></td>
      <td>Prevent auto-launching browser</td>
      <td><code>DISABLE_AUTO_OPEN=1</code></td>
    </tr>
  </table>
</p>

---

## 📖 API Reference

<div align="center">
  <table>
    <tr>
      <th>Method</th>
      <th>Endpoint</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>GET</code></td>
      <td><code>/</code></td>
      <td>Web UI</td>
    </tr>
    <tr>
      <td><code>POST</code></td>
      <td><code>/api/analyze</code></td>
      <td>Upload an <code>.eml</code> file (max 25 MB) — initiates async analysis</td>
    </tr>
    <tr>
      <td><code>GET</code></td>
      <td><code>/api/analyze/&lt;task_id&gt;/progress</code></td>
      <td>Poll live progress through the 11-stage pipeline</td>
    </tr>
    <tr>
      <td><code>GET</code></td>
      <td><code>/api/scans</code></td>
      <td>List all saved scans</td>
    </tr>
    <tr>
      <td><code>GET</code></td>
      <td><code>/api/scans/&lt;scan_id&gt;</code></td>
      <td>Retrieve a specific past report</td>
    </tr>
    <tr>
      <td><code>DELETE</code></td>
      <td><code>/api/scans/&lt;scan_id&gt;</code></td>
      <td>Delete a single scan</td>
    </tr>
    <tr>
      <td><code>DELETE</code></td>
      <td><code>/api/scans</code></td>
      <td>Clear all scan history</td>
    </tr>
  </table>
</div>

### 🔄 Analysis Pipeline

The following stages are executed sequentially and are visible via the progress endpoint:

<div align="center">
  <p>
    <code>📤 upload</code> → <code>📋 parse</code> → <code>🔐 auth</code> → <code>👤 sender</code> → <code>🔗 urls</code> → <code>📎 attachments</code> → <code>🛡️ vt</code> → <code>🔍 urlscan</code> → <code>📊 score</code> → <code>⚔️ mitre</code> → <code>✅ complete</code>
  </p>
</div>

---

## 📁 Project Structure

```
📦 Phishing-Mail-Detector-Web/
├── 🚀 run.py                  # Flask app, routes, async task orchestration, verdict thresholds
├── 📦 requirements.py         # Python dependencies
├── ⚙️ core/
│   ├── ⚙️ config.py           # Feature flags, scoring weights, brand/domain map, keyword corpora
│   ├── 🛠️ utils.py            # Normalization, defanging, domain/URL helpers
│   ├── 🧠 analyzers.py        # Header forensics, URL/HTML/QR/attachment analysis (~55 KB)
│   ├── 🌐 apis.py             # VirusTotal & urlscan.io integrations
│   ├── 📊 pipeline.py         # Risk scoring, MITRE mapping, report/recommendation building (~48 KB)
│   └── 🗄️ database.py         # SQLite persistence layer
├── 💾 data/                   # SQLite scan history (scans.db)
├── 🎨 templates/              # Web UI
├── 🖼️ static/                 # Assets (CSS, JS, images)
└── 🧪 test_files/             # Sample/test .eml files
```

---

## ⚠️ Known Limitations

<div align="center">
  <table>
    <tr>
      <td align="center" width="33%">
        <br>
        <b>🧪 No Automated Tests</b><br><br>
        <sub>Functionally verified through real-world scans. A pytest suite covering pure functions in <code>analyzers.py</code> and <code>utils.py</code> is planned.</sub><br><br>
      </td>
      <td align="center" width="33%">
        <br>
        <b>👤 Single-User Design</b><br><br>
        <sub>Built for one analyst via Flask's dev server — not load-tested or hardened for multi-tenant or public-facing deployment.</sub><br><br>
      </td>
      <td align="center" width="33%">
        <br>
        <b>📜 Single-Commit History</b><br><br>
        <sub>Git history starts from a single upload commit — earlier iteration history isn't preserved in this repo.</sub><br><br>
      </td>
    </tr>
  </table>
</div>

---

## 📝 Notes

- **🧩 Graceful Degradation:** WHOIS, attachment parsing, image/QR scanning, TLD extraction, and OLE macro analysis each activate automatically only when their Python package is installed — checked at import time in `core/config.py`. No crashes, just skipped stages.
- **🔒 Privacy-First:** Everything runs **locally**. No data leaves your machine except enrichment calls to VirusTotal/urlscan.io (and only when you've configured those API keys).
- **🏷️ Version:** `analysis_version` is currently **`2.0.0`** (tracked in `SETTINGS`), matching the `core` package `__version__`.

---

<div align="center">
  <br>
  <p>
    <b>🕵️ Phishing Mail Detector</b> — <i>Know what's in your inbox.</i>
  </p>
  <br>
  <p>
    <sub>Built with ❤️ by a solo maintainer · <a href="https://github.com/EclipseManic/Phishing-Mail-Detector-Web">GitHub</a></sub>
  </p>
  <br>
  <a href="#-table-of-contents">⬆ Back to Top</a>
</div>
