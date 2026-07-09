"""
Configuration constants, feature flags, and threat intelligence lists for enterprise-grade
phishing investigation. Designed for SOC analysts, DFIR investigators, and threat hunters.
"""

import os
import logging

logger = logging.getLogger(__name__)

# ── Feature flags ────────────────────────────────────────────────
API_KEY = os.getenv("VT_API_KEY", "")
VT_AVAILABLE = bool(API_KEY)

URL_SCAN_API_KEY = os.getenv("URL_SCAN_API_KEY", "")
URLSCAN_AVAILABLE = bool(URL_SCAN_API_KEY)

WHOIS_AVAILABLE = False
ATTACHMENT_PARSING_AVAILABLE = False
IMAGE_SCANNING_AVAILABLE = False
TLDEXTRACT_AVAILABLE = False
OLETOOLS_AVAILABLE = False

try:
    import whois  # noqa: F401
    WHOIS_AVAILABLE = True
except ImportError:
    logger.debug("whois module not available")

try:
    import pdfplumber  # noqa: F401
    import docx  # noqa: F401
    ATTACHMENT_PARSING_AVAILABLE = True
except ImportError:
    logger.debug("pdfplumber/docx not available")

try:
    from PIL import Image  # noqa: F401
    from pyzbar.pyzbar import decode as qr_decode  # noqa: F401
    import pytesseract  # noqa: F401
    IMAGE_SCANNING_AVAILABLE = True
except ImportError:
    logger.debug("Image/QR scanning not available")

try:
    import tldextract  # noqa: F401
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    logger.debug("tldextract not available")

try:
    from oletools.olevba import VBA_Parser  # noqa: F401
    OLETOOLS_AVAILABLE = True
except ImportError:
    logger.debug("oletools not available")

# ── Scoring weights (calibrated for enterprise threat landscape) ──
# Each weight value represents the contribution to the 0-10 risk score.
# Weights >= 6 represent critical findings that independently elevate risk.
# Weights 3-5 represent significant concerns in combination.
# Weights 1-2 represent contributing indicators.

WEIGHTS = {
    # Authentication failures (critical)
    "dmarc_fail": 7,
    "spf_fail": 5,
    "dkim_fail": 5,
    "arc_fail": 4,
    "dmarc_weak_or_missing": 2,
    "spf_not_found": 1,
    "dkim_not_found": 1,
    "auth_alignment_mismatch": 4,
    "compauth_fail": 4,
    # Sender anomalies
    "display_name_domain_mismatch": 5,
    "brand_impersonation": 6,
    "homograph_attack": 7,
    "reply_to_mismatch": 4,
    "return_path_mismatch": 4,
    "free_email_abuse": 3,
    # Domain/network reputation
    "malicious_domain": 8,
    "malicious_ip": 7,
    "malicious_link": 6,
    "recent_domain": 6,
    "suspicious_tld": 2,
    "third_party_dkim": 1,
    # Content analysis
    "credential_form": 6,
    "deceptive_link": 5,
    "javascript_present": 2,
    "iframe_present": 2,
    "hidden_elements": 2,
    "meta_refresh": 3,
    # Keyword signals
    "financial_keywords": 4,
    "credential_keywords": 5,
    "urgency_keywords": 2,
    "social_engineering": 2,
    "brand_impersonation_body": 4,
    # URL analysis
    "suspicious_url_feature": 2,
    "url_shortener": 2,
    "abused_service_link": 2,
    "tracking_pixel": 1,
    # Attachments
    "malicious_attachment": 10,
    "suspicious_attachment": 6,
    "macros_present": 8,
    "embedded_urls_in_attachment": 2,
    # Behavioral combinations
    "auth_with_urgency": 6,
    "multiple_auth_failures": 7,
    "young_domain_with_attachment": 3,
    "url_heavy_email": 1,
}

SETTINGS = {
    "domain_age_threshold_days": 30,
    "domain_age_warning_days": 180,
    "default_vt_delay_seconds": 16,
    "default_max_vt_items": 40,
    "vt_request_timeout_seconds": 20,
    "urlscan_request_timeout_seconds": 15,
    "urlscan_poll_timeout_seconds": 10,
    "unshorten_timeout_seconds": 10,
    "max_urls_for_urlscan": 10,
    "analysis_version": "2.0.0",
}

# ── Threat intelligence lists ────────────────────────────────────
ABUSED_LEGIT_SERVICES = [
    "docs.google.com", "drive.google.com", "onedrive.live.com",
    "dropbox.com", "forms.gle", "1drv.ms", "sharepoint.com",
    "storage.googleapis.com", "github.io", "pages.dev", "workers.dev",
    "firebaseapp.com", "web.app", "surge.sh", "netlify.app",
    "vercel.app", "herokuapp.com", "glitch.me", "notion.site",
    "canva.com", "mailchi.mp", "sendgrid.net", "mailgun.org",
    "awsapps.com", "azurewebsites.net", "azureedge.net",
    "cloudfront.net", "ngrok.io", "ngrok-free.app",
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com",
    "squarespace.com", "typeform.com", "jotform.com",
    "evernote.com", "trello.com", "asana.com", "basecamp.com",
]

FREE_MAIL_PROVIDERS = [
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.com.au",
    "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me",
    "aol.com", "aol.co.uk",
    "gmx.com", "gmx.net", "gmx.de",
    "mail.com", "fastmail.com", "fastmail.fm",
    "zoho.com", "zohomail.com",
    "yandex.com", "yandex.ru",
    "tutanota.com", "tutamail.com", "tuta.io",
    "outlook.fr", "outlook.de", "outlook.it", "outlook.es",
    "rediffmail.com", "mail.ru", "bk.ru", "inbox.ru",
    "seznam.cz", "post.cz",
    "libero.it", "virgilio.it", "tin.it",
    "naver.com", "daum.net", "hanmail.net",
    "qq.com", "163.com", "126.com", "sina.com", "sohu.com",
]

# ── Keywords: financial & payment ────────────────────────────────
FINANCIAL_KEYWORDS = [
    "wire transfer", "wire funds", "bank transfer", "bank account",
    "routing number", "account number", "swift code", "iban",
    "gift card", "gift cards", "itunes card", "google play card",
    "crypto", "bitcoin", "ethereum", "cryptocurrency", "wallet address",
    "urgent payment", "immediate payment", "payment overdue",
    "payroll", "direct deposit", "ach transfer", "zelle", "venmo",
    "invoice", "invoice attached", "payment due", "outstanding balance",
    "refund", "tax refund", "stimulus", "compensation",
    "inheritance", "lottery", "prize", "reward", "compensation fund",
]

# ── Keywords: credential theft ───────────────────────────────────
CREDENTIAL_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "validate your account", "re-verify", "account suspended",
    "account locked", "account will be closed", "unusual activity",
    "suspicious sign-in", "unauthorized access", "security alert",
    "password expired", "password reset", "change your password",
    "login here", "sign in here", "click to verify", "click here to confirm",
    "update your payment", "update your billing", "expired card",
    "confirm your email", "verify your email", "validate your email",
]

# ── Keywords: urgency & pressure ─────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "act fast", "right away",
    "within 24 hours", "within 48 hours", "expires today", "expires soon",
    "limited time", "time sensitive", "deadline", "final notice",
    "last warning", "final reminder", "do not ignore", "failure to",
    "you must", "you are required", "mandatory", "compulsory",
    "dear customer", "dear user", "dear valued", "dear account holder",
    "attention required", "action required", "immediate action",
]

# ── Keywords: social engineering ─────────────────────────────────
SOCIAL_KEYWORDS = [
    "congratulations", "you have been selected", "you have won",
    "exclusive offer", "special offer", "limited offer",
    "confidential", "do not share", "keep this private",
    "trusted partner", "verified sender", "secure message",
    "encrypted message", "protected document", "secure document",
    "shared a document", "shared a file", "has shared",
    "review the attached", "see attached", "please find attached",
    "download here", "view document", "access document",
    "candidate", "application", "resume", "cv", "job offer",
    "employment", "hiring", "onboarding", "interview",
    "shipment", "delivery", "tracking", "package", "fedex", "ups", "dhl",
    "receipt", "order confirmation", "purchase", "transaction",
]

# ── Phishing theme categories for pattern detection ──────────────
PHISHING_THEMES = {
    "financial": FINANCIAL_KEYWORDS,
    "credential_theft": CREDENTIAL_KEYWORDS,
    "urgency_pressure": URGENCY_KEYWORDS,
    "social_engineering": SOCIAL_KEYWORDS,
}

EXECUTIVE_NAMES = [
    "ceo", "chief executive", "cfo", "chief financial", "coo", "chief operating",
    "cto", "chief technology", "cio", "chief information", "cso", "chief security",
    "president", "vp", "vice president", "director", "manager",
    "founder", "chairman", "chairperson", "board member",
    "owner", "proprietor", "partner",
]

TXID_INDICATORS = [
    r'\b0x[a-fA-F0-9]{40}\b', r'\b0x[a-fA-F0-9]{64}\b',
    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    r'\bbc1[a-z0-9]{38,59}\b',
]

# ── Impersonated brands ─────────────────────────────────────────
IMPERSONATED_BRANDS = [
    "microsoft", "office 365", "office365", "outlook", "teams", "azure",
    "sharepoint", "onedrive", "microsoft 365",
    "paypal", "venmo", "zelle", "cashapp", "square",
    "amazon", "aws", "prime", "amazon pay",
    "apple", "icloud", "itunes", "app store",
    "google", "gmail", "google drive", "google docs", "google workspace",
    "facebook", "instagram", "whatsapp", "meta", "messenger",
    "docusign", "adobe", "adobe sign", "dropbox", "box",
    "netflix", "spotify", "hulu", "disney", "disney+",
    "coinbase", "binance", "kraken", "coinbase pro",
    "github", "gitlab", "bitbucket",
    "linkedin", "twitter", "x",
    "chase", "jpmorgan", "wells fargo", "bank of america", "bofa",
    "citibank", "hsbc", "barclays", "natwest", "lloyds",
    "capital one", "american express", "amex", "discover",
    "fedex", "ups", "dhl", "usps", "royal mail", "australia post",
    "zoom", "slack", "shopify", "stripe", "square",
    "irs", "hmrc", "cra", "ato", "social security", "ssa",
    "world health organization", "who", "unicef", "red cross",
    "shure", "samsung", "xiaomi", "huawei",
]

BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"],
    "office 365": ["microsoft.com", "office.com", "microsoftonline.com"],
    "office365": ["microsoft.com", "office.com", "microsoftonline.com"],
    "outlook": ["outlook.com", "hotmail.com", "live.com", "microsoft.com"],
    "teams": ["teams.microsoft.com", "microsoft.com"],
    "azure": ["azure.com", "azure.microsoft.com", "microsoft.com", "windowsazure.com"],
    "sharepoint": ["sharepoint.com", "microsoft.com"],
    "onedrive": ["onedrive.live.com", "microsoft.com"],
    "microsoft 365": ["microsoft.com", "office.com", "microsoftonline.com"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com"],
    "venmo": ["venmo.com"],
    "zelle": ["zellepay.com"],
    "cashapp": ["cash.app", "square.com"],
    "square": ["squareup.com", "square.com", "cash.app"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "amazon.in", "amazon.com.au", "amazonaws.com"],
    "aws": ["aws.amazon.com", "amazonaws.com", "amazon.com"],
    "prime": ["amazon.com", "primevideo.com"],
    "amazon pay": ["amazon.com", "pay.amazon.com"],
    "apple": ["apple.com", "icloud.com", "itunes.com", "appleid.apple.com"],
    "icloud": ["icloud.com", "apple.com"],
    "itunes": ["itunes.com", "apple.com"],
    "app store": ["apple.com", "apps.apple.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "gmail": ["gmail.com", "googlemail.com", "google.com"],
    "google drive": ["drive.google.com", "google.com"],
    "google docs": ["docs.google.com", "google.com"],
    "google workspace": ["google.com", "workspace.google.com"],
    "facebook": ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com", "messenger.com"],
    "instagram": ["instagram.com", "facebook.com"],
    "whatsapp": ["whatsapp.com", "facebook.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "messenger": ["messenger.com", "facebook.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com", "adobe.io"],
    "adobe sign": ["adobe.com", "adobesign.com"],
    "dropbox": ["dropbox.com", "dropboxapi.com"],
    "box": ["box.com"],
    "netflix": ["netflix.com", "nflx.com"],
    "spotify": ["spotify.com"],
    "hulu": ["hulu.com"],
    "disney": ["disneyplus.com", "disney.com", "go.com"],
    "disney+": ["disneyplus.com", "disney.com"],
    "coinbase": ["coinbase.com", "coinbasepro.com"],
    "coinbase pro": ["coinbase.com", "coinbasepro.com"],
    "binance": ["binance.com", "binance.us"],
    "kraken": ["kraken.com"],
    "github": ["github.com", "github.io"],
    "gitlab": ["gitlab.com"],
    "bitbucket": ["bitbucket.org"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "x": ["x.com", "twitter.com"],
    "chase": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "jpmorgan": ["jpmorgan.com", "jpmorganchase.com", "chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "bofa": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com", "citigroup.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk"],
    "barclays": ["barclays.co.uk", "barclays.com"],
    "natwest": ["natwest.com", "natwestgroup.com"],
    "lloyds": ["lloydsbank.co.uk", "lloyds.com"],
    "capital one": ["capitalone.com"],
    "american express": ["americanexpress.com", "amex.com"],
    "amex": ["americanexpress.com", "amex.com"],
    "discover": ["discover.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com", "upsers.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "usps": ["usps.com"],
    "royal mail": ["royalmail.com"],
    "australia post": ["auspost.com.au"],
    "zoom": ["zoom.us", "zoom.com"],
    "slack": ["slack.com"],
    "shopify": ["shopify.com", "myshopify.com"],
    "stripe": ["stripe.com"],
    "irs": ["irs.gov"],
    "hmrc": ["gov.uk", "hmrc.gov.uk"],
    "cra": ["canada.ca", "cra-arc.gc.ca"],
    "ato": ["ato.gov.au"],
    "social security": ["ssa.gov"],
    "ssa": ["ssa.gov"],
    "world health organization": ["who.int"],
    "who": ["who.int"],
    "unicef": ["unicef.org"],
    "red cross": ["redcross.org", "icrc.org"],
    "shure": ["shure.com"],
    "samsung": ["samsung.com"],
    "xiaomi": ["mi.com", "xiaomi.com"],
    "huawei": ["huawei.com"],
}

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".lnk", ".iso", ".img", ".jar",
    ".msi", ".dll", ".chm", ".one", ".docm", ".xlsm", ".pptm",
    ".xlam", ".xll", ".html", ".htm", ".svg", ".shtml", ".xhtml",
    ".cpl", ".msc", ".reg", ".rgs", ".inf", ".application",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "lnkd.in",
    "rb.gy", "bl.ink", "clck.ru", "v.gd", "qr.ae", "t.ly",
    "short.io", "tiny.cc", "dwz.cn", "suo.im", "url.cn",
    "shor.by",
]

REDIRECT_PARAM_NAMES = [
    "url", "u", "uri", "redirect", "redirect_uri", "target", "to",
    "next", "continue", "return", "returnurl", "r", "goto", "link",
    "dest", "destination", "forward", "ref", "out", "view",
]

REFERENCE_URL_HOSTS = [
    "schemas.openxmlformats.org", "schemas.microsoft.com",
    "purl.org", "www.w3.org", "www.wps.cn", "schemas.google.com",
    "ns.adobe.com", "www.openxmlformats.org",
]

SUSPICIOUS_TLDS = [
    # Free/abused TLDs (anyone can register cheaply)
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".space",
    ".site", ".online", ".store", ".icu", ".buzz", ".lol",
    ".quest", ".guru", ".review", ".download",
    ".racing", ".win", ".bid", ".accountant", ".science", ".date",
    ".stream", ".men", ".party", ".trade", ".webcam", ".cam",
    ".loan", ".mom", ".xin", ".cricket", ".faith",
    ".website", ".press", ".host", ".tech",
    # Country TLDs abused for phishing
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".cc", ".pw", ".ws",
    ".su", ".co", ".tk",
]

RISKY_EXTENSIONS_SET = set(RISKY_EXTENSIONS)