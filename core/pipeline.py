"""
IOC extraction, risk scoring, MITRE ATT&CK mapping, recommendations, and report building.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .config import (
    ABUSED_LEGIT_SERVICES,
    CREDENTIAL_KEYWORDS,
    FINANCIAL_KEYWORDS,
    FREE_MAIL_PROVIDERS,
    IMPERSONATED_BRANDS,
    PHISHING_THEMES,
    SETTINGS,
    SOCIAL_KEYWORDS,
    SUSPICIOUS_TLDS,
    URGENCY_KEYWORDS,
    WEIGHTS,
    EXECUTIVE_NAMES,
    TXID_INDICATORS,
)
from .utils import (
    defang,
    brand_mentions,
    is_free_mail_provider,
    is_public_ip,
    normalize_domain,
    normalize_email_address,
    normalize_ip,
    normalize_url,
    registered_domain,
    unique_list,
)
from .apis import vt_detection_count, vt_summary_text, urlscan_detection_flagged, urlscan_summary_text


__all__ = ['build_observables', 'generate_score_and_feedback', 'build_report', 'build_mitre_mapping', 'build_recommendations']



# ═══════════════════════════════════════════════════════════════════
# IOC (OBSERVABLE) EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def _add_observable(observables, index, observable_type, value, source, role=None, metadata=None):
    if not value:
        return None

    if observable_type == "email":
        normalized = normalize_email_address(value)
    elif observable_type == "domain":
        normalized = normalize_domain(value)
    elif observable_type == "ip":
        normalized = normalize_ip(value)
    elif observable_type == "url":
        normalized = normalize_url(value)
    elif observable_type in {"md5", "sha1", "sha256"}:
        normalized = str(value).lower()
    else:
        normalized = str(value).strip()

    if not normalized:
        return None

    key = (observable_type, normalized)
    if key not in index:
        observable = {
            "type": observable_type,
            "value": normalized,
            "defanged": defang(normalized) if observable_type in {"domain", "url", "email", "ip"} else normalized,
            "sources": [],
            "roles": [],
            "metadata": {},
            "vt": None,
        }
        if observable_type == "domain":
            observable["registered_domain"] = registered_domain(normalized)
        if observable_type == "ip":
            observable["is_public"] = is_public_ip(normalized)
        index[key] = observable
        observables.append(observable)
    else:
        observable = index[key]

    if source and source not in observable["sources"]:
        observable["sources"].append(source)
    if role and role not in observable["roles"]:
        observable["roles"].append(role)
    if metadata:
        for key_name, meta_value in metadata.items():
            if key_name not in observable["metadata"]:
                observable["metadata"][key_name] = meta_value
            elif observable["metadata"][key_name] != meta_value:
                existing = observable["metadata"][key_name]
                if not isinstance(existing, list):
                    existing = [existing]
                if not isinstance(meta_value, list):
                    meta_value = [meta_value]
                observable["metadata"][key_name] = unique_list(existing + meta_value)
    return observable


def build_observables(header_findings, url_records, attachment_results):
    """Extract all IOCs from headers, URLs, and attachments."""
    from .analyzers import analyze_url

    observables = []
    index = {}

    for header_name in ("From", "Return-Path", "Reply-To"):
        box = header_findings.get(header_name)
        if box:
            _add_observable(observables, index, "email", box.get("address"), f"header.{header_name}", header_name.lower())
            _add_observable(observables, index, "domain", box.get("domain"), f"header.{header_name}", f"{header_name.lower()}_domain")

    for header_name in ("To", "Cc"):
        for box in header_findings.get(header_name, []):
            _add_observable(observables, index, "email", box.get("address"), f"header.{header_name}", header_name.lower())
            _add_observable(observables, index, "domain", box.get("domain"), f"header.{header_name}", f"{header_name.lower()}_domain")

    for domain in header_findings.get("SPF MailFrom Domains", []):
        _add_observable(observables, index, "domain", domain, "auth.smtp.mailfrom", "spf_mailfrom")
    for domain in header_findings.get("Header From Domains", []):
        _add_observable(observables, index, "domain", domain, "auth.header.from", "header_from")
    for domain in header_findings.get("DKIM Domains", []):
        _add_observable(observables, index, "domain", domain, "auth.header.d", "dkim_domain")
    for email_address in header_findings.get("Display Name Claimed Emails", []):
        _add_observable(observables, index, "email", email_address, "header.From.display_name", "display_name_claim")
    for domain in header_findings.get("Display Name Claimed Domains", []):
        _add_observable(observables, index, "domain", domain, "header.From.display_name", "display_name_claim_domain")
    for ip in header_findings.get("Sender IPs", []):
        _add_observable(observables, index, "ip", ip, "auth_or_received.sender_ip", "sender_ip")

    for hop in header_findings.get("Received Path", []):
        for ip in hop.get("public_ips", []):
            _add_observable(
                observables, index, "ip", ip,
                f"received.hop_{hop.get('hop')}", "received_public_ip",
                {"from": hop.get("from"), "by": hop.get("by")},
            )

    for record in url_records:
        _add_observable(
            observables, index, "url", record["normalized_url"],
            record["source"], "embedded_url",
            {"host": record.get("host"), "features": record.get("features")},
        )
        if record.get("host"):
            _add_observable(observables, index, "domain", record["host"], record["source"], "url_host")

    for attachment in attachment_results:
        hashes = attachment.get("hashes", {})
        for hash_type in ("md5", "sha1", "sha256"):
            _add_observable(
                observables, index, hash_type, hashes.get(hash_type),
                f"attachment.{attachment.get('filename')}", "attachment_hash",
            )
        for embedded_url in attachment.get("embedded_urls", []):
            record = analyze_url(embedded_url, f"attachment.{attachment.get('filename')}.embedded_url")
            _add_observable(observables, index, "url", record["normalized_url"], record["source"], "attachment_url")
            if record.get("host"):
                _add_observable(observables, index, "domain", record["host"], record["source"], "attachment_url_host")

    return observables


# ═══════════════════════════════════════════════════════════════════
# RISK SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════

def _f(level, title, message, detail=""):
    return {"level": level, "title": title, "message": message, "detail": detail}


def _match_keywords(text, keyword_list):
    return [kw for kw in keyword_list if kw in text]


def _vt_scored_observables(data, observable_type):
    """Return observables of a given type that have a VT result attached."""
    for observable in data.get("observables", []):
        if observable.get("type") == observable_type and observable.get("vt"):
            yield observable


def generate_score_and_feedback(data):
    """Score analysis with prioritized tiers. Returns (score, feedback_items)."""
    w = WEIGHTS
    header = data["header_findings"]
    full_text = (data.get("full_body") or data.get("body", "") + data.get("html_body", "")).lower()
    plain_text = (data.get("body") or "").lower()

    from_addr = header.get("From Address") or ""
    from_box = header.get("From") or {}
    from_domain = from_box.get("domain") or ""
    rp_addr = header.get("Return-Path Address") or ""
    rt_addr = header.get("Reply-To Address") or ""

    critical_floor = 0
    warning_score = 0
    positive_offset = 0
    items = []

    critical_floor, warning_score, positive_offset, items = _score_auth(
        header, critical_floor, warning_score, positive_offset, items, w,
        from_addr, rp_addr, rt_addr, from_domain,
    )

    critical_floor, warning_score, positive_offset, items = _score_sender(
        data, header, critical_floor, warning_score, positive_offset, items, w, from_domain,
    )

    critical_floor, warning_score, positive_offset, items = _score_content(
        data, critical_floor, warning_score, positive_offset, items, w, full_text, plain_text,
    )

    critical_floor, warning_score, positive_offset, items = _score_urls(
        data, critical_floor, warning_score, positive_offset, items, w,
    )

    critical_floor, warning_score, positive_offset, items = _score_attachments(
        data, critical_floor, warning_score, positive_offset, items, w,
    )

    critical_floor, warning_score, positive_offset, items = _score_behavioral(
        data, header, full_text, critical_floor, warning_score, positive_offset, items, w,
    )

    net_warning = max(0, warning_score - positive_offset)
    final_score = max(critical_floor, net_warning)

    spf = header.get("SPF Result")
    dkim = header.get("DKIM Result")
    dmarc = header.get("DMARC Result")
    arc = header.get("ARC Result")
    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        items.append(_f("positive", "Sender Identity Verified",
                        "SPF, DKIM, and DMARC all passed. Sender identity is strongly verified.",
                        f"SPF={spf} DKIM={dkim} DMARC={dmarc}"))

    sender_ips = header.get("Sender IPs") or []
    if sender_ips:
        items.append(_f("positive", "Sender IPs Identified",
                        f"Found {len(sender_ips)} sender/relay IP(s).",
                        f"IPs: {', '.join(sender_ips[:5])}"))

    if not items:
        items.append(_f("positive", "No Risk Factors Detected",
                        "No major risk factors were identified. The email appears legitimate.",
                        "All checks passed"))

    return min(final_score, 10), unique_list(items)


def _score_auth(header, cf, ws, po, items, w, from_addr, rp_addr, rt_addr, from_domain):
    if header.get("Return-Path Mismatch"):
        ws += w["return_path_mismatch"]
        items.append(_f("critical", "Return-Path Mismatch",
                        f"The Return-Path ({rp_addr}) differs from the From address ({from_addr}).",
                        "This mismatch is suspicious because delivery bounces or replies could be redirected "
                        "to an attacker-controlled address while the recipient sees a trusted sender."))

    if header.get("Reply-To Mismatch"):
        ws += w["reply_to_mismatch"]
        items.append(_f("critical", "Reply-To Domain Mismatch",
                        f"Replies go to {rt_addr.split('@')[-1]} instead of {from_addr.split('@')[-1]}.",
                        "The Reply-To domain differs from the From domain. This is a common phishing technique "
                        "to intercept replies while the recipient believes they are responding to the legitimate sender."))

    dmarc = header.get("DMARC Result", "not found")
    if dmarc == "fail":
        cf = max(cf, w["dmarc_fail"])
        items.append(_f("critical", "DMARC Authentication Failed",
                        f"The Header From domain ({from_domain}) failed DMARC authentication.",
                        "DMARC failure indicates the email may not be authorized by the domain owner. "
                        "This is a strong indicator of spoofing or phishing."))
    elif dmarc in {"none", "not found", "neutral"}:
        ws += w["dmarc_weak_or_missing"]
        items.append(_f("warning", "DMARC Policy Not Enforced",
                        f"DMARC result is '{dmarc}' — no enforcement policy is configured for {from_domain}.",
                        "Without DMARC enforcement, attackers can spoof this domain more easily. "
                        "However, this alone is not evidence of an attack."))

    spf = header.get("SPF Result", "not found")
    if spf not in {"pass", "not found", "neutral", "none", "softfail"}:
        ws += w["spf_fail"]
        items.append(_f("critical", "SPF Authentication Failed",
                        f"SPF result is '{spf}' for the sending server.",
                        "SPF failure means the sending IP is not authorized to send mail for the claimed domain. "
                        "This is a strong indicator of unauthorized sending."))
    elif spf == "softfail":
        ws += w["spf_fail"]
        items.append(_f("warning", "SPF SoftFail",
                        "The SPF result is 'softfail' — the sending server is not fully authorized.",
                        "SoftFail is a weaker form of SPF failure and may indicate misconfiguration, "
                        "but it can also indicate unauthorized sending."))
    elif spf == "not found":
        ws += w["spf_not_found"]
        items.append(_f("warning", "SPF Record Not Found",
                        f"No SPF result found for the sender domain ({from_domain}).",
                        "Without SPF records, the domain has no mechanism to prevent sender forgery."))

    dkim = header.get("DKIM Result", "not found")
    if dkim not in {"pass", "not found", "neutral", "none", "present"}:
        ws += w["dkim_fail"]
        items.append(_f("critical", "DKIM Authentication Failed",
                        f"DKIM result is '{dkim}' for the email.",
                        "DKIM failure means the email's cryptographic signature could not be verified. "
                        "This may indicate tampering with the email content or headers."))
    elif dkim == "not found":
        ws += w["dkim_not_found"]
        items.append(_f("warning", "DKIM Signature Not Found",
                        "No DKIM signature was found for this email.",
                        "Without DKIM, the email content could have been modified in transit without detection."))

    spf_domains = header.get("SPF MailFrom Domains") or []
    header_domains = header.get("Header From Domains") or []

    if header.get("SPF Aligned") is False and spf == "pass":
        ws += w["auth_alignment_mismatch"]
        items.append(_f("critical", "SPF Alignment Mismatch",
                        f"SPF passed for {spf_domains} but Header From is {header_domains or from_domain}.",
                        "The SPF-authorized domain differs from the domain in the From header. "
                        "While SPF technically passed, the email may be using a different sending infrastructure."))

    if header.get("DKIM Aligned") is False and dkim == "pass":
        ws += w["auth_alignment_mismatch"]
        items.append(_f("critical", "DKIM Alignment Mismatch",
                        f"DKIM-signed by {header.get('DKIM Domains')} but Header From is {from_domain}.",
                        "The DKIM signing domain does not match the From domain. This can happen in "
                        "legitimate mailing list setups but is also abused by attackers."))

    compauth = header.get("CompAuth Result")
    if compauth and compauth not in {"pass", "softpass"}:
        ws += w["compauth_fail"]
        items.append(_f("critical", "Microsoft Composite Authentication",
                        f"Microsoft's composite auth (compauth={compauth}) indicates the email failed "
                        f"Microsoft's overall authentication evaluation.",
                        f"Reason: {header.get('CompAuth Reason') or 'unknown'}"))

    claimed_domains = header.get("Display Name Claimed Domains") or []
    brand_mentions_list = header.get("Display Name Brand Mentions") or []

    if header.get("Display Name Domain Mismatch"):
        cf = max(cf, w["display_name_domain_mismatch"])
        items.append(_f("critical", "Display Name Domain Mismatch",
                        f"The display name references {', '.join(claimed_domains[:3])} but the From address uses {from_domain}.",
                        "The sender's display name claims to represent one domain while "
                        "the actual sending address belongs to a different domain. "
                        "This is a classic display name spoofing technique."))

    if header.get("Display Name Brand Mismatch"):
        cf = max(cf, w["brand_impersonation"])
        items.append(_f("critical", "Brand Impersonation in Display Name",
                        f"The display name mentions {', '.join(brand_mentions_list[:3])} "
                        f"but the From address belongs to {from_domain}.",
                        "The sender is claiming to represent a well-known brand in the display name "
                        f"while the actual sending domain ({from_domain}) is not an official brand domain. "
                        "This is a strong indicator of brand impersonation phishing."))

    return cf, ws, po, items


def _score_sender(data, header, cf, ws, po, items, w, from_domain):
    spoof = data.get("spoof_findings", {})
    domain_age = data.get("domain_age")
    threshold = SETTINGS["domain_age_threshold_days"]
    warning_threshold = SETTINGS["domain_age_warning_days"]

    if spoof.get("is_homograph_attack"):
        cf = max(cf, w["homograph_attack"])
        punycode = spoof.get("punycode_version") or ""
        decoded = spoof.get("domain_without_idn") or ""
        items.append(_f("critical", "Homograph/Punycode Attack Detected",
                        f"The sender domain uses look-alike/unicode characters to mimic a legitimate domain.",
                        f"Domain: {spoof.get('unicode_normalized')} | "
                        f"{'Punycode: ' + punycode if punycode else ''}"
                        f"{' | Decoded: ' + decoded if decoded else ''}"))

    if domain_age is not None:
        if domain_age < threshold:
            cf = max(cf, w["recent_domain"])
            items.append(_f("critical", "Recently Registered Domain",
                            f"The sender domain ({from_domain}) is only {domain_age} days old.",
                            "Domains registered within the last 30 days are disproportionately "
                            "used in phishing campaigns before being detected."))
        elif domain_age < warning_threshold:
            ws += w.get("young_domain", 2)
            items.append(_f("warning", "Moderately New Domain",
                            f"The sender domain ({from_domain}) is {domain_age} days old.",
                            "Domains under 180 days should be treated with additional scrutiny."))
        elif domain_age > 365 * 3 and not is_free_mail_provider(from_domain):
            po += 1

    if from_domain:
        tld = "." + from_domain.rsplit(".", 1)[-1] if "." in from_domain else ""
        if tld in SUSPICIOUS_TLDS:
            ws += w["suspicious_tld"]
            items.append(_f("warning", "Suspicious Top-Level Domain",
                            f"The sender domain uses '{tld}' — a TLD commonly abused in phishing.",
                            "These TLDs offer cheap or free domain registration with minimal "
                            "verification, making them attractive to attackers."))

    if header.get("Free Email From") and header.get("Display Name Brand Mentions"):
        cf = max(cf, w["brand_impersonation"])
        items.append(_f("critical", "Brand Impersonation via Free Email",
                        f"The sender uses a free email provider ({from_domain}) while claiming "
                        f"to represent {', '.join(header['Display Name Brand Mentions'][:3])}.",
                        "Legitimate organizations do not send official communications from "
                        "free email addresses. This is a strong indicator of impersonation."))

    dkim_domains = header.get("DKIM Domains") or []
    if dkim_domains and from_domain:
        dkim_lower = [d.lower() for d in dkim_domains if d]
        from_lower = from_domain.lower()
        if from_lower not in dkim_lower and not any(from_lower.endswith("." + d) for d in dkim_lower):
            ws += w["third_party_dkim"]
            items.append(_f("warning", "DKIM Signed by Third Party",
                            f"The email was DKIM-signed by {', '.join(dkim_domains)} but the From address is {from_domain}.",
                            "Third-party DKIM signing can be legitimate (e.g., mailing lists, "
                            "email marketing platforms) but is also abused for phishing."))

    for observable in _vt_scored_observables(data, "domain"):
        observable_value = observable.get("value") or ""
        obs_reg_domain = observable.get("registered_domain") or ""
        if from_domain and observable_value != from_domain and obs_reg_domain != from_domain:
            continue
        detections = vt_detection_count(observable.get("vt"))
        if detections > 0:
            vt_text = vt_summary_text(observable.get("vt"))
            cf = max(cf, w["malicious_domain"])
            items.append(_f("critical", "Malicious Sender Domain Detected by VirusTotal",
                            f"{from_domain or observable_value} was flagged by {vt_text}.",
                            "The sender's domain has been identified as malicious by multiple "
                            "security vendors. This is a definitive indicator of malicious intent."))
            break

    for observable in _vt_scored_observables(data, "ip"):
        if not observable.get("is_public"):
            continue
        if "sender_ip" not in (observable.get("roles") or []) and "received_public_ip" not in (observable.get("roles") or []):
            continue
        detections = vt_detection_count(observable.get("vt"))
        if detections > 0:
            vt_text = vt_summary_text(observable.get("vt"))
            cf = max(cf, w["malicious_ip"])
            items.append(_f("critical", "Malicious Sender IP Detected by VirusTotal",
                            f"{observable.get('value')} was flagged by {vt_text}.",
                            "The sending server's IP address is associated with malicious activity."))
            break

    return cf, ws, po, items


def _score_content(data, cf, ws, po, items, w, full_text, plain_text):
    content = data.get("content_findings", {})

    script_count = content.get("script_count", 0)
    form_count = content.get("form_count", 0)
    password_inputs = content.get("password_inputs", 0)
    iframe_count = len(content.get("iframe_sources") or [])
    hidden_count = content.get("hidden_element_count", 0)
    meta_count = len(content.get("meta_refresh_urls") or [])

    if content.get("javascript_present"):
        ws += w["javascript_present"]
        items.append(_f("warning", "JavaScript Content Detected",
                        f"Email contains {script_count} script tag(s).",
                        "JavaScript in email can be used for tracking, evasion, or exploitation. "
                        "Most legitimate transactional emails do not include JavaScript."))

    if password_inputs or form_count:
        cf = max(cf, w["credential_form"])
        items.append(_f("critical", "Credential Harvesting Form Detected",
                        f"HTML contains {form_count} form(s) and {password_inputs} password input(s).",
                        "Password input fields in email are almost exclusively used for phishing. "
                        "Legitimate organizations never ask you to enter credentials inside an email."))

    if hidden_count > 0:
        ws += w["hidden_elements"]
        samples = content.get("hidden_element_samples") or []
        items.append(_f("warning", "Hidden HTML Elements Detected",
                        f"Email contains {hidden_count} visually hidden element(s).",
                        f"Hidden: {hidden_count} | Samples: {', '.join(samples[:3])}" if samples else f"Hidden: {hidden_count}"))

    if iframe_count > 0:
        sources = content.get("iframe_sources") or []
        ws += w["iframe_present"]
        items.append(_f("warning", "Inline Frame (Iframe) Elements",
                        f"Email contains {iframe_count} iframe(s).",
                        f"Iframes can load external content and are frequently used in phishing "
                        f"to display legitimate login pages within malicious emails."
                        f"{' Sources: ' + ', '.join(defang(s) for s in sources[:3]) if sources else ''}"))

    if meta_count > 0:
        urls = content.get("meta_refresh_urls") or []
        ws += w["meta_refresh"]
        items.append(_f("warning", "Meta Refresh Redirect Detected",
                        f"HTML contains {meta_count} meta-refresh redirect(s).",
                        "Meta-refresh redirects can automatically forward the user to a "
                        "malicious page without any visible indication."))

    for theme_name, keywords in PHISHING_THEMES.items():
        matched = _match_keywords(full_text, keywords)
        if not matched:
            continue
        count = len(matched)
        if theme_name == "financial":
            pts = min(count, 4) + 1
            if count >= 3:
                cf = max(cf, w["financial_keywords"])
            ws += pts
            items.append(_f("critical" if count >= 3 else "warning", "Financial/Payment Language Detected",
                            f"Found {count} financial or payment-related term(s) in the email body.",
                            f"Terms: {', '.join(matched[:8])}"))
        elif theme_name == "credential_theft":
            pts = min(count, 4) + 1
            if count >= 3:
                cf = max(cf, w["credential_keywords"])
            ws += pts
            items.append(_f("critical" if count >= 3 else "warning", "Credential Harvesting Language Detected",
                            f"Found {count} credential-phishing term(s) in the email body.",
                            f"Terms: {', '.join(matched[:8])}"))
        elif theme_name == "urgency_pressure":
            if count >= 2:
                ws += w["urgency_keywords"]
                items.append(_f("warning", "Urgency/Pressure Language Detected",
                                f"Found {count} urgency or pressure term(s) in the email body.",
                                "Urgency is a common social engineering tactic used to bypass "
                                f"rational decision-making. Terms: {', '.join(matched[:8])}"))
        elif theme_name == "social_engineering":
            if count >= 3:
                ws += w["social_engineering"]
                items.append(_f("warning", "Social Engineering Language Detected",
                                f"Found {count} social engineering term(s) in the email body.",
                                f"Terms: {', '.join(matched[:8])}"))

    body_brands = brand_mentions(full_text)
    if body_brands:
        all_matched = _match_keywords(full_text, CREDENTIAL_KEYWORDS + URGENCY_KEYWORDS + FINANCIAL_KEYWORDS)
        if all_matched:
            cf = max(cf, w["brand_impersonation_body"])
            items.append(_f("critical", "Brand Impersonation with Phishing Keywords",
                            f"The email body mentions {', '.join(body_brands[:5])} alongside "
                            f"phishing-associated language.",
                            "Attackers frequently impersonate well-known brands in the email body "
                            "to create a false sense of legitimacy. Combined with urgency or "
                            "credential-theft language, this strongly indicates a phishing attempt."))

    return cf, ws, po, items


def _score_urls(data, cf, ws, po, items, w):
    for url_record in data.get("url_results", []):
        url_defanged = defang(url_record.get("normalized_url") or "")
        host = url_record.get("host") or ""
        features = url_record.get("features") or []

        if url_record.get("deceptive_display"):
            cf = max(cf, w["deceptive_link"])
            displayed = defang(url_record.get("displayed_url") or "")
            items.append(_f("critical", "Deceptive Link Display",
                            f"The link text displays {displayed} but the actual href points to {url_defanged}.",
                            "This mismatch between visible text and actual destination is a common "
                            "phishing technique to trick users into clicking malicious links."))

        if features:
            feature_count = len(features)
            has_encoded = any(kw in " ".join(features).lower()
                              for kw in ["jwt", "encoded", "base64", "email address"])
            has_tracking = any("tracking" in f.lower() for f in features)
            has_pii = any("email" in f.lower() or "pii" in f.lower() for f in features)

            base = w["suspicious_url_feature"]
            url_score = base + max(0, (feature_count - 1))

            if has_encoded or (has_tracking and has_pii):
                cf = max(cf, url_score)
            else:
                ws += url_score

            level = "critical" if has_encoded or (has_tracking and has_pii) else "warning"
            items.append(_f(level, "Suspicious URL Features",
                            f"{url_defanged}: {', '.join(features)}.",
                            f"Host: {host} | Flags: {feature_count}"))

        if url_record.get("is_tracking_pixel"):
            ws += w["tracking_pixel"]
            items.append(_f("warning", "Tracking Pixel Detected",
                            f"URL at {host} appears to be a tracking pixel or web beacon.",
                            "Tracking pixels collect analytics data such as when the email was opened, "
                            "the recipient's IP address, and device information."))

        if any(service in host for service in ABUSED_LEGIT_SERVICES):
            ws += w["abused_service_link"]
            items.append(_f("warning", "Link Uses Abused Legitimate Service",
                            f"URL uses {host}, a legitimate service frequently abused for phishing.",
                            "Attackers often use legitimate services like file sharing, URL shorteners, "
                            "or cloud hosting to bypass initial URL reputation checks."))

        detections = vt_detection_count(url_record.get("vt"))
        if detections > 0:
            vt_text = vt_summary_text(url_record.get("vt"))
            cf = max(cf, w["malicious_link"])
            items.append(_f("critical", "Malicious URL Detected by VirusTotal",
                            f"{url_defanged} was flagged by {vt_text}.",
                            "Multiple security vendors have identified this URL as malicious. "
                            "Do not access this link."))

    urlscan_results = data.get("urlscan", {})
    for url_val, us_result in urlscan_results.items():
        if urlscan_detection_flagged(us_result):
            us_text = urlscan_summary_text(us_result)
            brands = us_result.get("brands", [])
            categories = us_result.get("categories", [])
            detail_parts = [f"urlscan.io: {us_text}"]
            if brands:
                detail_parts.append(f"Targeted brands: {', '.join(brands[:3])}")
            if categories:
                detail_parts.append(f"Categories: {', '.join(categories[:3])}")
            cf = max(cf, 6)
            items.append(_f("critical", "urlscan.io Flagged URL as Malicious",
                            f"urlscan.io analysis found {defang(url_val)} to be malicious/suspicious.",
                            " | ".join(detail_parts)))

    return cf, ws, po, items


def _score_attachments(data, cf, ws, po, items, w):
    for attachment in data.get("attachment_results", []):
        detections = vt_detection_count(attachment.get("vt"))
        sha256 = attachment.get("hashes", {}).get("sha256", "")
        filename = attachment.get("filename", "unknown")
        detected_type = attachment.get("detected_type", "")
        size = attachment.get("size_bytes", 0)
        size_str = f"{size / 1024:.1f}KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f}MB"
        indicators = attachment.get("indicators") or []

        if detections > 0:
            vt_text = vt_summary_text(attachment.get("vt"))
            cf = max(cf, w["malicious_attachment"])
            items.append(_f("critical", "Malicious Attachment Detected by VirusTotal",
                            f"{filename} ({sha256[:16]}...) was flagged by {vt_text}.",
                            "Security vendors have identified this attachment as malicious. "
                            "It should be isolated and analyzed in a sandbox environment."))
        elif indicators:
            cf = max(cf, w["suspicious_attachment"])
            items.append(_f("critical", "Suspicious Attachment Indicators",
                            f"{filename}: {', '.join(indicators)}.",
                            f"The attachment exhibits {len(indicators)} suspicious characteristic(s). "
                            "While VirusTotal results may be clean, the file's behavior "
                            "and structure warrant further investigation."))

        ooxml = attachment.get("ooxml") or {}
        ole = attachment.get("ole") or {}
        if ooxml.get("macros_present") or ole.get("macros_present"):
            cf = max(cf, w["macros_present"])
            items.append(_f("critical", "Macro-Enabled Document Detected",
                            f"{filename} contains VBA macros.",
                            "Macro-enabled documents are the most common initial access vector "
                            "in email-based attacks. Macros can execute arbitrary code when "
                            "the document is opened."))

        embedded_urls = attachment.get("embedded_urls") or []
        if embedded_urls:
            ws += w["embedded_urls_in_attachment"]
            items.append(_f("warning", "Embedded URLs in Attachment",
                            f"{filename} contains {len(embedded_urls)} embedded URL(s).",
                            "URLs inside attachments are often used to bypass email link scanning. "
                            "The attachments should be analyzed for phishing-related content."))

    return cf, ws, po, items


def _score_behavioral(data, header, full_text, cf, ws, po, items, w):
    has_attachments = bool(data.get("attachment_results", []))

    all_phishing_kw = _match_keywords(full_text, CREDENTIAL_KEYWORDS + URGENCY_KEYWORDS + FINANCIAL_KEYWORDS)
    if has_attachments and all_phishing_kw:
        ws += 2
        items.append(_f("warning", "Attachment with Phishing Language",
                        "Email contains attachments combined with phishing-associated wording.",
                        "The combination of attachments and phishing language increases "
                        "the likelihood of a targeted attack."))

    auth_failures = 0
    for auth_type in ["SPF", "DKIM", "DMARC"]:
        result = header.get(f"{auth_type} Result", "not found")
        if auth_type == "DMARC":
            if result == "fail":
                auth_failures += 1
        else:
            if result not in {"pass", "not found", "neutral", "none", "present"}:
                auth_failures += 1

    if auth_failures >= 2:
        cf = max(cf, w["multiple_auth_failures"])
        items.append(_f("critical", "Multiple Authentication Failures",
                        f"Email failed {auth_failures} of 3 authentication checks (SPF/DKIM/DMARC).",
                        "Multiple authentication failures strongly indicate the email "
                        "is not legitimate. Authenticated emails from legitimate senders "
                        "typically pass all three checks."))

    has_mismatch = header.get("Return-Path Mismatch") or header.get("Reply-To Mismatch")
    has_urgency = _match_keywords(full_text, URGENCY_KEYWORDS)
    if has_mismatch and has_urgency:
        cf = max(cf, w["auth_with_urgency"])
        items.append(_f("critical", "Header Mismatch with Urgency Language",
                        "Header mismatches combined with urgency language — a classic phishing pattern.",
                        "Attackers combine technical deception (header mismatches) with "
                        "psychological manipulation (urgency) to create convincing phishing emails."))

    url_count = len(data.get("url_results", []))
    if url_count > 10:
        ws += w["url_heavy_email"]
        items.append(_f("warning", "URL-Heavy Email Content",
                        f"Email contains {url_count} distinct embedded URLs.",
                        "A high number of embedded URLs is unusual for legitimate "
                        "personal communication and may indicate tracking or phishing content."))

    domain_age = data.get("domain_age")
    if domain_age is not None and domain_age < SETTINGS["domain_age_threshold_days"] * 2 and has_attachments:
        ws += w["young_domain_with_attachment"]
        items.append(_f("warning", "Young Domain Sending Attachments",
                        f"A relatively new domain ({domain_age}d old) is sending email with attachments.",
                        "New domains that immediately send attachments are often "
                        "compromised or attacker-controlled accounts."))

    return cf, ws, po, items


# ═══════════════════════════════════════════════════════════════════
# REPORT BUILDING
# ═══════════════════════════════════════════════════════════════════

def build_mitre_mapping(header, feedback_items, url_records, attachment_results):
    """Map findings to MITRE ATT&CK techniques."""
    techniques = []

    if header.get("Display Name Brand Mismatch") or header.get("Display Name Domain Mismatch"):
        techniques.append({
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "details": "Sender impersonation detected via display name or brand mismatch",
        })

    if header.get("Reply-To Mismatch") or header.get("Return-Path Mismatch"):
        techniques.append({
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "details": "Reply-To or Return-Path mismatch indicates email address manipulation",
        })

    dmarc = header.get("DMARC Result", "")
    spf = header.get("SPF Result", "")
    dkim = header.get("DKIM Result", "")
    spf_fail = spf not in {"pass", "not found", "neutral", "none", "softfail"}
    dkim_fail = dkim not in {"pass", "not found", "neutral", "none", "present"}
    dmarc_fail = dmarc == "fail"
    if dmarc_fail or spf_fail or dkim_fail:
        techniques.append({
            "id": "T1566.003",
            "name": "Spearphishing via Service",
            "tactic": "Initial Access",
            "details": f"Email authentication failed: SPF={spf}, DKIM={dkim}, DMARC={dmarc}",
        })

    for url_record in url_records:
        host = url_record.get("host", "")
        features = url_record.get("features", [])
        if url_record.get("deceptive_display"):
            techniques.append({
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "details": f"Deceptive link: {host}",
            })
        if any("shortener" in f.lower() for f in features):
            techniques.append({
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "details": f"URL shortener used: {host}",
            })

    for att in attachment_results:
        detected_type = att.get("detected_type", "")
        indicators = att.get("indicators", [])
        ooxml = att.get("ooxml") or {}
        ole = att.get("ole") or {}
        if ooxml.get("macros_present") or ole.get("macros_present"):
            techniques.append({
                "id": "T1204.002",
                "name": "User Execution: Malicious File",
                "tactic": "Execution",
                "details": f"Document with macros: {att.get('filename')}",
            })
        if any("executable" in i.lower() for i in indicators):
            techniques.append({
                "id": "T1204.002",
                "name": "User Execution: Malicious File",
                "tactic": "Execution",
                "details": f"Executable attachment: {att.get('filename')} ({detected_type})",
            })
        if att.get("embedded_urls"):
            techniques.append({
                "id": "T1566.001",
                "name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "details": f"Attachment contains embedded URLs: {att.get('filename')}",
            })

    if header.get("spoof_findings", {}).get("is_homograph_attack"):
        techniques.append({
            "id": "T1566.002",
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "details": "Homograph attack detected in sender domain",
        })

    for item in feedback_items:
        title = item.get("title", "").lower()
        if "credential" in title or "password" in title:
            techniques.append({
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "details": "Credential harvesting language detected in email body",
            })
            break

    # Deduplicate by ID
    seen_ids = set()
    unique_techniques = []
    for t in techniques:
        if t["id"] not in seen_ids:
            seen_ids.add(t["id"])
            unique_techniques.append(t)

    return unique_techniques


def build_recommendations(verdict, score, feedback_items, url_records, attachment_results):
    """Generate actionable recommendations based on findings."""
    recommendations = []

    if verdict in ("UNSAFE",):
        recommendations.append({
            "priority": "high",
            "action": "Do not open, forward, or reply to this email.",
            "reason": "The email has been classified as malicious with high confidence.",
        })
        recommendations.append({
            "priority": "high",
            "action": "Report the email to your security team or SOC immediately.",
            "reason": "Timely reporting enables containment and broader threat hunting.",
        })
        recommendations.append({
            "priority": "high",
            "action": "Delete the email from your inbox and trash folder.",
            "reason": "Prevents accidental interaction and potential compromise.",
        })

    if any((att.get("ooxml") or {}).get("macros_present") or (att.get("ole") or {}).get("macros_present")
           for att in attachment_results):
        recommendations.append({
            "priority": "high",
            "action": "Do not enable macros in any attachments from this email.",
            "reason": "Macro-enabled documents are the primary initial access vector for ransomware and malware.",
        })

    if url_records:
        recommendations.append({
            "priority": "medium",
            "action": "Do not click any links in this email. Hover over links to verify destinations.",
            "reason": "Links in phishing emails often lead to credential harvesting sites or malware downloads.",
        })

    if verdict == "UNSAFE":
        recommendations.append({
            "priority": "high",
            "action": "If you have already clicked a link or opened an attachment, contact your security team immediately.",
            "reason": "Post-exploitation activities may already be in progress.",
        })

    if score >= 4:
        recommendations.append({
            "priority": "medium",
            "action": "Check if similar emails have been received by other team members.",
            "reason": "Phishing campaigns often target multiple individuals within an organization.",
        })
        recommendations.append({
            "priority": "medium",
            "action": "Review email filtering rules to block similar messages in the future.",
            "reason": "Updating detection rules helps prevent future attacks from the same campaign.",
        })

    if attachment_results:
        recommendations.append({
            "priority": "medium",
            "action": "Submit suspicious attachments to a sandbox for dynamic analysis.",
            "reason": "Static analysis may not detect all malicious behaviors. Sandbox analysis provides deeper insight.",
        })

    if url_records:
        recommendations.append({
            "priority": "info",
            "action": f"Review IOCs section for all extracted domains, IPs, URLs, and file hashes.",
            "reason": "Retain these IOCs for threat hunting and detection engineering.",
        })

    return recommendations


def build_report(analysis_data, score, feedback_items, eml_file=None, verdict=None):
    header = analysis_data["header_findings"]
    url_records = analysis_data.get("url_results", [])
    attachment_results = analysis_data.get("attachment_results", [])

    mitre_techniques = build_mitre_mapping(header, feedback_items, url_records, attachment_results)
    recommendations = build_recommendations(verdict, score, feedback_items, url_records, attachment_results)

    report = {
        "file": eml_file,
        "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_version": SETTINGS.get("analysis_version", "2.0.0"),
        "verdict": verdict,
        "score": score,
        "feedback": feedback_items,
        "summary": {
            "observable_count": len(analysis_data["observables"]),
            "url_count": len(url_records),
            "attachment_count": len(attachment_results),
            "sender_ips": header.get("Sender IPs", []),
            "signal_counts": analysis_data.get("signal_counts", {
                "critical": sum(1 for f in feedback_items if isinstance(f, dict) and f.get("level") == "critical"),
                "warning": sum(1 for f in feedback_items if isinstance(f, dict) and f.get("level") == "warning"),
                "positive": sum(1 for f in feedback_items if isinstance(f, dict) and f.get("level") == "positive"),
            }),
        },
        "mitre_attack": {
            "techniques": mitre_techniques,
            "total": len(mitre_techniques),
        },
        "recommendations": recommendations,
        "details": {
            "header_text": analysis_data.get("header_text", ""),
            "header_findings": header,
            "spoof_findings": analysis_data["spoof_findings"],
            "domain_age_days": analysis_data["domain_age"],
            "content_findings": analysis_data["content_findings"],
            "observables": analysis_data["observables"],
            "url_results": url_records,
            "attachment_results": attachment_results,
            "virustotal": analysis_data["virustotal"],
            "urlscan": analysis_data.get("urlscan", {}),
            "urlscan_doms": analysis_data.get("urlscan_doms", {}),
            "urlscan_hars": analysis_data.get("urlscan_hars", {}),
        },
    }

    return report