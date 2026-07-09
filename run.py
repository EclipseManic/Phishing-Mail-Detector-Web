"""
Advanced Phishing Mail Detector — Web Application
Flask-based GUI for email phishing analysis with async progress tracking
and persistent scan history.
"""

import contextlib
import io
import logging
import os
import tempfile
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from threading import Timer

from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from core import (
    analyze_attachment,
    analyze_domain_for_spoofing,
    analyze_header,
    analyze_html_content,
    analyze_url,
    build_observables,
    build_report,
    check_domain_age,
    enrich_with_virustotal,
    extract_links,
    generate_score_and_feedback,
    normalize_url,
    parse_eml_file,
    scan_images_for_qrcodes,
    unshorten_url,
    unique_list,
    url_host,
    clean_url,
    defang,
    registered_domain,
    vt_detection_count,
    urlscan_submit,
    urlscan_search,
    urlscan_search_or_submit,
    urlscan_get_dom,
    urlscan_get_har,
    urlscan_detection_flagged,
    build_mitre_mapping,
    build_recommendations,
    VT_AVAILABLE,
    WHOIS_AVAILABLE,
    URLSCAN_AVAILABLE,
)
from core.config import SETTINGS
from core.database import init_db, save_scan, get_scan, list_scans, delete_scan, scan_count

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# ── Background task management ────────────────────────────────────
_tasks = {}
_tasks_lock = threading.Lock()

PROGRESS_STEPS = [
    ("upload", "Uploading email file"),
    ("parse", "Parsing email headers & structure"),
    ("auth", "Verifying authentication (SPF/DKIM/DMARC/ARC)"),
    ("sender", "Analyzing sender identity & spoofing"),
    ("urls", "Extracting & analyzing URLs"),
    ("attachments", "Scanning attachments"),
    ("vt", "Enriching with VirusTotal"),
    ("urlscan", "Enriching with urlscan.io"),
    ("score", "Calculating risk score"),
    ("mitre", "Mapping to MITRE ATT&CK"),
    ("complete", "Finalizing report"),
]


def _init_progress():
    return {
        "status": "pending",
        "error": None,
        "progress_pct": 0,
        "current_step": None,
        "steps": {sid: {"label": label, "status": "pending"} for sid, label in PROGRESS_STEPS},
        "result": None,
    }


def _update_step(task_id, step_id, status):
    with _tasks_lock:
        task = _tasks.get(task_id)
        if task and step_id in task["steps"]:
            task["steps"][step_id]["status"] = status
            _update_progress_pct(task)


def _update_progress_pct(task):
    steps = list(PROGRESS_STEPS)
    total = len(steps)
    done = sum(1 for sid, _ in steps if task["steps"].get(sid, {}).get("status") == "done")
    running = sum(1 for sid, _ in steps if task["steps"].get(sid, {}).get("status") == "in_progress")
    pct = int((done / total) * 100)
    task["progress_pct"] = min(pct, 99)
    for sid, _ in steps:
        if task["steps"].get(sid, {}).get("status") == "in_progress":
            task["current_step"] = task["steps"][sid]["label"]
            break


def _set_error(task_id, message):
    with _tasks_lock:
        task = _tasks.get(task_id)
        if task:
            task["status"] = "error"
            task["error"] = message


def _set_result(task_id, result):
    with _tasks_lock:
        task = _tasks.get(task_id)
        if task:
            task["status"] = "complete"
            task["progress_pct"] = 100
            task["current_step"] = "Complete"
            task["result"] = result
            for sid in task["steps"]:
                if task["steps"][sid]["status"] != "done":
                    task["steps"][sid]["status"] = "done"


def _run_analysis(task_id, file_path, original_name, use_external, resolve_redirects):
    try:
        _update_step(task_id, "upload", "done")
        _update_step(task_id, "parse", "in_progress")

        msg, header_text, body, html_body, attachments, images = parse_eml_file(file_path)
        _update_step(task_id, "parse", "done")

        _update_step(task_id, "auth", "in_progress")
        header_findings = analyze_header(msg)
        _update_step(task_id, "auth", "done")

        _update_step(task_id, "sender", "in_progress")
        from_addr = header_findings.get("From Address")
        sender_domain = from_addr.split("@")[1] if from_addr and "@" in from_addr else None
        spoof_findings = analyze_domain_for_spoofing(sender_domain) if sender_domain else {}
        domain_age = check_domain_age(sender_domain) if use_external and sender_domain else None
        _update_step(task_id, "sender", "done")

        _update_step(task_id, "urls", "in_progress")
        url_records = extract_links(body, html_body)
        url_records.extend(scan_images_for_qrcodes(images))
        attachment_results = []
        for att in attachments:
            result = analyze_attachment(att)
            attachment_results.append(result)
            for embedded_url in result.get("embedded_urls", []):
                url_records.append(
                    analyze_url(embedded_url, f"attachment.{result['filename']}.embedded_url")
                )
        url_records = _dedupe_url_records(url_records)
        _normalize_attachment_urls(attachment_results)
        _update_step(task_id, "urls", "done")

        _update_step(task_id, "attachments", "in_progress")
        if resolve_redirects:
            for record in url_records:
                final_url, redirect_chain = unshorten_url(record["normalized_url"])
                record["final_url"] = final_url
                record["redirect_chain"] = redirect_chain
                if final_url and final_url != record["normalized_url"]:
                    final_record = analyze_url(final_url, f"{record['source']}.redirect_final")
                    record["features"] = unique_list(record["features"] + final_record["features"])
        content_findings = analyze_html_content(html_body)
        observables = build_observables(header_findings, url_records, attachment_results)
        _update_step(task_id, "attachments", "done")

        _update_step(task_id, "vt", "in_progress")
        vt_summary = enrich_with_virustotal(
            observables, url_records, attachment_results,
            delay_seconds=SETTINGS["default_vt_delay_seconds"] if use_external else 0,
            max_items=SETTINGS["default_max_vt_items"],
            no_vt=not use_external,
        )
        _update_step(task_id, "vt", "done")

        # Fallback: derive domain age from VT creation_date when WHOIS unavailable
        if domain_age is None and sender_domain:
            for obs in observables:
                if obs.get("type") == "domain" and obs.get("value") == sender_domain:
                    vt = obs.get("vt")
                    if vt and vt.get("status") == "ok" and vt.get("creation_date"):
                        try:
                            cd = datetime.fromisoformat(vt["creation_date"])
                            domain_age = (datetime.now(timezone.utc) - cd).days
                        except Exception:
                            pass
                    break

        _update_step(task_id, "urlscan", "in_progress")
        urlscan_results = {}
        urlscan_doms = {}
        urlscan_hars = {}
        if use_external and URLSCAN_AVAILABLE:
            scanned_url_hosts = set()
            for url_record in url_records[:5]:
                url_val = url_record.get("normalized_url") or url_record.get("url")
                if url_val and url_val not in urlscan_results:
                    result = urlscan_search_or_submit(url_val, tags=["phishing-detector", original_name[:50]])
                    urlscan_results[url_val] = result
                    url_record["urlscan"] = result
                    scan_id = result.get("scan_id")
                    if scan_id and result.get("status") == "ok":
                        dom_result = urlscan_get_dom(scan_id)
                        if dom_result.get("status") == "ok":
                            urlscan_doms[url_val] = {
                                "size_bytes": dom_result.get("size_bytes", 0),
                                "content_type": dom_result.get("content_type", ""),
                                "dom_preview": dom_result.get("dom", "")[:2000],
                            }
                        har_result = urlscan_get_har(scan_id)
                        if har_result.get("status") == "ok":
                            urlscan_hars[url_val] = {
                                "total_entries": har_result.get("total_entries", 0),
                                "domains_contacted": har_result.get("domains_contacted", []),
                                "requests": har_result.get("requests", [])[:20],
                            }
                    host = url_record.get("host")
                    if host:
                        scanned_url_hosts.add(host)
            # urlscan.io domain-level search for all URL host domains
            for host in scanned_url_hosts:
                if host not in urlscan_results:
                    domain_search = urlscan_search(f"domain:{host}", size=3)
                    if domain_search.get("status") == "ok" and domain_search.get("results"):
                        urlscan_results[f"_search_domain:{host}"] = domain_search
            # urlscan.io domain-level search for email header domains
            for domain_source in ("From", "Reply-To", "Return-Path", "Sender"):
                box = header_findings.get(domain_source)
                if box and box.get("domain"):
                    d = box["domain"]
                    if d not in urlscan_results and d not in scanned_url_hosts:
                        domain_search = urlscan_search(f"domain:{d}", size=3)
                        if domain_search.get("status") == "ok" and domain_search.get("results"):
                            urlscan_results[f"_search_domain:{d}"] = domain_search
        _update_step(task_id, "urlscan", "done")

        _update_step(task_id, "score", "in_progress")
        analysis_data = {
            "header_text": header_text,
            "header_findings": header_findings,
            "spoof_findings": spoof_findings,
            "url_results": url_records,
            "attachment_results": attachment_results,
            "observables": observables,
            "full_body": body + "\n" + html_body,
            "body": body,
            "html_body": html_body,
            "domain_age": domain_age,
            "content_findings": content_findings,
            "virustotal": vt_summary,
            "urlscan": urlscan_results,
            "urlscan_doms": urlscan_doms,
            "urlscan_hars": urlscan_hars,
        }
        score, feedback_items = generate_score_and_feedback(analysis_data)
        signal_counts = {"critical": 0, "warning": 0, "positive": 0}
        for item in feedback_items:
            level = item.get("level", "warning") if isinstance(item, dict) else "warning"
            if level in signal_counts:
                signal_counts[level] += 1
        analysis_data["signal_counts"] = signal_counts
        _update_step(task_id, "score", "done")

        _update_step(task_id, "mitre", "in_progress")
        if score >= 7:
            verdict, severity = "UNSAFE", "high"
        elif score >= 4:
            verdict, severity = "CAUTIOUS", "medium"
        else:
            verdict, severity = "SAFE", "low"
        report = build_report(analysis_data, score, feedback_items, eml_file=original_name, verdict=verdict)
        _update_step(task_id, "mitre", "done")

        _update_step(task_id, "complete", "in_progress")
        result = {
            "file": {"name": original_name, "size_bytes": os.path.getsize(file_path)},
            "verdict": verdict,
            "severity": severity,
            "score": score,
            "feedback": feedback_items,
            "signal_counts": signal_counts,
            "summary": report["summary"],
            "details": report["details"],
            "options": {
                "external_enrichment": use_external,
                "resolve_redirects": resolve_redirects,
                "virustotal_available": VT_AVAILABLE,
                "whois_available": WHOIS_AVAILABLE,
                "urlscan_available": URLSCAN_AVAILABLE,
            },
            "mitre_attack": report.get("mitre_attack", {}),
            "recommendations": report.get("recommendations", []),
            "body": body,
            "html_body": html_body,
            "report": report,
        }

        # Save to persistent database
        save_scan(original_name, verdict, severity, score, result)

        _update_step(task_id, "complete", "done")
        _set_result(task_id, result)

    except Exception as exc:
        logger.exception("Background analysis failed")
        _set_error(task_id, str(exc))
    finally:
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass


def _dedupe_url_records(url_records):
    deduped = {}
    for record in url_records:
        r = _normalize_url_record(record)
        if not r:
            continue
        key = r["normalized_url"]
        if key not in deduped:
            deduped[key] = r
            continue
        deduped[key]["source"] = ",".join(
            unique_list(deduped[key]["source"].split(",") + [r["source"]])
        )
        deduped[key]["features"] = unique_list(deduped[key]["features"] + r["features"])
        deduped[key]["vt"] = _better_vt_result(deduped[key].get("vt"), r.get("vt"))
    return list(deduped.values())


def _normalize_url_record(record):
    cleaned = normalize_url(record.get("normalized_url") or record.get("url") or "")
    if not cleaned:
        return None
    normalized = dict(record)
    normalized["url"] = clean_url(normalized.get("url") or cleaned) or cleaned
    normalized["normalized_url"] = cleaned
    normalized["defanged"] = defang(cleaned)
    normalized["host"] = url_host(cleaned)
    normalized["registered_domain"] = registered_domain(normalized["host"])
    return normalized


def _better_vt_result(current, candidate):
    if not current:
        return candidate
    if not candidate:
        return current
    if not isinstance(current, dict) or not isinstance(candidate, dict):
        return candidate or current
    if vt_detection_count(candidate) > vt_detection_count(current):
        return candidate
    if current.get("status") in {"not_found", "skipped", "error"} and candidate.get("status") == "ok":
        return candidate
    return current


def _normalize_attachment_urls(attachment_results):
    for attachment in attachment_results:
        embedded_urls = []
        for url in attachment.get("embedded_urls", []):
            cleaned = normalize_url(url)
            if cleaned:
                embedded_urls.append(cleaned)
        attachment["embedded_urls"] = unique_list(embedded_urls)


# ── Routes ────────────────────────────────────────────────────────
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "logo.png")


@app.post("/api/analyze")
def analyze_upload():
    """Start an async analysis task. Returns a task_id for progress polling."""
    if not _is_same_origin_request(request):
        return jsonify({"error": "Missing X-Requested-With header."}), 403

    uploaded = request.files.get("email_file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Upload an .eml file before running analysis."}), 400

    original_name = secure_filename(uploaded.filename) or "uploaded_email.eml"
    suffix = Path(original_name).suffix or ".eml"
    use_external = str(request.form.get("external_enrichment", "")).lower() in {"1", "true", "yes", "on"}
    resolve_redirects = str(request.form.get("resolve_redirects", "")).lower() in {"1", "true", "yes", "on"}

    # Save uploaded file to temp location
    tmp_path = None
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)
        os.close(tmp_fd)
        uploaded.save(tmp_path)

        task_id = _create_task()
        thread = threading.Thread(
            target=_run_analysis,
            args=(task_id, tmp_path, original_name, use_external, resolve_redirects),
            daemon=True,
        )
        thread.start()

        return jsonify({"task_id": task_id, "status": "started"}), 202
    except Exception as exc:
        logger.exception("Failed to start analysis")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return jsonify({"error": f"Failed to start analysis: {exc}"}), 500


def _create_task():
    import uuid
    task_id = uuid.uuid4().hex[:12]
    with _tasks_lock:
        _tasks[task_id] = _init_progress()
        _tasks[task_id]["status"] = "running"
    return task_id


@app.get("/api/analyze/<task_id>/progress")
def get_progress(task_id):
    """Poll the progress of an async analysis task."""
    with _tasks_lock:
        task = _tasks.get(task_id)

    if task is None:
        return jsonify({"error": "Task not found"}), 404

    resp = {
        "status": task["status"],
        "progress_pct": task["progress_pct"],
        "current_step": task["current_step"],
        "steps": task["steps"],
    }

    if task["status"] == "error":
        resp["error"] = task.get("error")
    elif task["status"] == "complete" and task["result"]:
        resp["result"] = task["result"]

    return jsonify(resp)


@app.get("/api/scans")
def list_all_scans():
    """List all persisted scans (latest first)."""
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    scans = list_scans(limit=min(limit, 200), offset=max(offset, 0))
    # Remove payload from list response to keep it light
    for s in scans:
        s.pop("payload", None)
    return jsonify({"scans": scans, "total": scan_count()})


@app.get("/api/scans/<scan_id>")
def get_scan_by_id(scan_id):
    """Get full scan result by ID."""
    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.delete("/api/scans/<scan_id>")
def delete_scan_by_id(scan_id):
    """Delete a scan."""
    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    delete_scan(scan_id)
    return jsonify({"status": "deleted"})


@app.delete("/api/scans")
def delete_all_scans_endpoint():
    """Delete all scans."""
    from core.database import delete_all_scans as _delete_all
    _delete_all()
    return jsonify({"status": "all_deleted"})


def _is_same_origin_request(req):
    origin = req.headers.get("Origin")
    referer = req.headers.get("Referer")
    expected = req.host_url.rstrip("/")
    if origin and origin.rstrip("/") != expected:
        return False
    if referer and not referer.startswith(expected):
        return False
    return req.headers.get("X-Requested-With") == "XMLHttpRequest"


@app.errorhandler(413)
def upload_too_large(_exc):
    return jsonify({"error": "Upload too large. Maximum is 25 MB."}), 413


# ── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()

    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG") == "1"
    url = f"http://127.0.0.1:{port}/"

    if os.getenv("DISABLE_AUTO_OPEN") != "1":
        if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
            Timer(0.8, lambda: webbrowser.open(url)).start()

    logger.info("Starting Phishing Mail Detector on %s", url)
    logger.info("VT API key: %s, urlscan API key: %s, whois: %s",
                "configured" if VT_AVAILABLE else "not set",
                "configured" if URLSCAN_AVAILABLE else "not set",
                "available" if WHOIS_AVAILABLE else "not installed")
    app.run(host="127.0.0.1", port=port, debug=debug, threaded=True)
