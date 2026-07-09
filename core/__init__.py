"""
Advanced Phishing Mail Detector — modular analysis library.

Modules:
    config      — Configuration, feature flags, threat intel lists
    utils       — Core normalization and utility functions
    analyzers   — Email parsing, header forensics, URL/content/attachment analysis
    apis        — VirusTotal and urlscan.io API integrations
    pipeline    — IOC extraction, risk scoring, report building
"""

__version__ = "2.0.0"

from .config import * # noqa: F401,F403
from .utils import * # noqa: F401,F403
from .analyzers import (  # noqa: F401
    parse_eml_file, decode_part_text,
    analyze_header, check_domain_age,
    parse_authentication_results, choose_primary_auth,
    parse_microsoft_security_headers, parse_received_headers,
    parse_dkim_signatures, parse_received_spf, parse_tag_value_header,
    analyze_url, extract_links, extract_urls_from_bytes, extract_urls_from_text,
    unshorten_url,
    analyze_html_content, scan_images_for_qrcodes,
    analyze_attachment, analyze_ole_static, analyze_ooxml_zip,
    analyze_pdf_static, detect_file_type,
    extract_links_from_attachment_text, has_double_extension,
)
from .apis import (  # noqa: F401
    enrich_with_virustotal,
    scan_domain, scan_file_hash, scan_ip, scan_url,
    summarize_vt_response, vt_detection_count, vt_fetch,
    vt_summary_text, vt_url_id,
    urlscan_submit, urlscan_search, urlscan_search_or_submit,
    urlscan_get_dom, urlscan_get_har,
    urlscan_summary_text, urlscan_detection_flagged,
)
from .pipeline import (  # noqa: F401
    build_observables,
    generate_score_and_feedback,
    build_report,
    build_mitre_mapping,
    build_recommendations,
)

__all__ = [
    "API_KEY", "VT_AVAILABLE", "URL_SCAN_API_KEY", "URLSCAN_AVAILABLE",
    "WHOIS_AVAILABLE", "ATTACHMENT_PARSING_AVAILABLE",
    "IMAGE_SCANNING_AVAILABLE", "TLDEXTRACT_AVAILABLE", "OLETOOLS_AVAILABLE",
    # utils
    "decode_header_value", "unfold_header", "unique_list", "get_header_values", "get_first_header",
    "normalize_domain", "normalize_email_address", "parse_mailbox_headers", "get_primary_mailbox",
    "registered_domain", "domains_align", "clean_url", "normalize_url", "url_host", "defang",
    "is_reference_url", "filter_actionable_urls", "brand_mentions", "brand_domain_mismatches",
    "normalize_ip", "is_public_ip", "extract_ips", "hashes_for_bytes", "timestamp_to_iso",
    "analyze_domain_for_spoofing",
    # analyzers
    "parse_eml_file", "decode_part_text",
    "parse_tag_value_header", "parse_authentication_results", "choose_primary_auth",
    "parse_microsoft_security_headers", "parse_received_headers", "parse_dkim_signatures",
    "parse_received_spf", "analyze_header", "check_domain_age",
    "extract_urls_from_text", "extract_urls_from_bytes", "analyze_url", "extract_links", "unshorten_url",
    "analyze_html_content", "scan_images_for_qrcodes",
    "detect_file_type", "has_double_extension", "analyze_pdf_static", "analyze_ooxml_zip",
    "analyze_ole_static", "extract_links_from_attachment_text", "analyze_attachment",
    # apis
    "vt_fetch", "vt_url_id", "summarize_vt_response", "scan_domain", "scan_ip", "scan_url",
    "scan_file_hash", "vt_detection_count", "vt_summary_text", "enrich_with_virustotal",
    "urlscan_submit", "urlscan_summary_text", "urlscan_detection_flagged",
    # pipeline
    "build_observables", "generate_score_and_feedback", "build_report",
    "build_mitre_mapping", "build_recommendations",
]