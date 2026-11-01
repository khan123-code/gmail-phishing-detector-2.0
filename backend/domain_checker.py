import re
import socket
import tldextract
from difflib import SequenceMatcher

TRUSTED_DOMAINS = {
    "sbi.co.in", "onlinesbi.com", "sbionline.com",
    "hdfcbank.com", "netbanking.hdfc.com",
    "icicibank.com", "infinityicici.com",
    "axisbank.com", "kotakbank.com", "kotak.com",
    "yesbank.in", "indusind.com", "federalbank.co.in",
    "pnbindia.in", "bankofbaroda.in", "canarabank.in",
    "unionbankofindia.co.in", "idbibank.in",
    "chase.com", "wellsfargo.com", "bankofamerica.com",
    "citibank.com", "hsbc.com", "barclays.co.uk",
    "paypal.com", "razorpay.com", "paytm.com",
    "phonepe.com", "gpay.com", "google.com",
    "amazonpay.in", "mobikwik.com", "freecharge.in",
    "payu.in", "ccavenue.com", "billdesk.com",
    "gov.in", "nic.in", "india.gov.in",
    "incometax.gov.in", "gst.gov.in", "epfindia.gov.in",
    "uidai.gov.in", "irctc.co.in", "nsdl.com",
    "sebi.gov.in", "rbi.org.in", "mca.gov.in",
    "amazon.in", "amazon.com", "flipkart.com",
    "myntra.com", "snapdeal.com", "meesho.com",
    "nykaa.com", "ajio.com", "tatacliq.com",
    "microsoft.com", "apple.com", "linkedin.com",
    "twitter.com", "facebook.com", "instagram.com",
    "zoom.us", "slack.com", "atlassian.com",
    "licindia.in", "hdfclife.com", "iciciprulife.com",
    "policybazaar.com", "groww.in", "zerodha.com",
    "upstox.com", "angelbroking.com", "5paisa.com",
    "airtel.in", "jio.com", "vodafoneidea.com",
    "bsnl.co.in", "tatasky.com",
    "nta.ac.in", "cbse.gov.in", "ugc.ac.in",
    "aicte-india.org", "coursera.org", "udemy.com",
}

GENERIC_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "protonmail.com", "icloud.com", "aol.com", "mail.com",
    "rediffmail.com", "live.com", "yandex.com",
}

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'}

SUSPICIOUS_KEYWORDS_IN_DOMAIN = [
    'secure', 'verify', 'update', 'login', 'signin', 'account',
    'banking', 'support', 'helpdesk', 'alert', 'confirm',
    'authenticate', 'validation', 'suspended', 'unusual',
]

def extract_sender_domain(sender_email):
    sender_email = sender_email.lower().strip()
    match = re.search(r'@([\w\.-]+)', sender_email)
    if match:
        return match.group(1)
    return sender_email

def is_trusted_domain(domain):
    domain = domain.lower()
    if domain in TRUSTED_DOMAINS:
        return True, "Domain is in trusted list"
    parts = domain.split('.')
    for i in range(len(parts)-1):
        parent = '.'.join(parts[i:])
        if parent in TRUSTED_DOMAINS:
            return True, f"Subdomain of trusted domain: {parent}"
    return False, "Domain not in trusted list"

def is_generic_email_provider(domain):
    domain = domain.lower()
    return domain in GENERIC_EMAIL_PROVIDERS

def normalize_domain(domain):
    normalized = domain.lower()
    normalized = normalized.replace('rn', 'm')
    normalized = normalized.replace('vv', 'w')
    normalized = normalized.replace('0', 'o')
    normalized = normalized.replace('1', 'l')
    normalized = normalized.replace('5', 's')
    normalized = normalized.replace('3', 'e')
    return normalized

def check_lookalike(domain, threshold=0.85):
    """
    IMPORTANT: Yeh function sirf un domains ke liye call hona chahiye jo
    khud already trusted list mein NAHI hain. Agar domain khud trusted hai,
    lookalike check ki zaroorat nahi (verify_domain mein yeh guard lagaya gaya hai).
    Threshold 0.85 rakha hai (0.80 se badhaya) taaki "amazon" vs "amazonpay"
    jaise legitimate-but-different brand names false-match na karein.
    """
    ext = tldextract.extract(domain)
    domain_name = ext.domain
    normalized_name = normalize_domain(domain_name)

    best_match = None
    best_ratio = 0

    for trusted in TRUSTED_DOMAINS:
        trusted_ext = tldextract.extract(trusted)
        trusted_name = trusted_ext.domain

        if domain_name == trusted_name:
            continue

        # Skip if one name is fully contained in other AND lengths differ a lot —
        # that's usually a different (legit) brand, e.g. amazon vs amazonpay,
        # not a typosquat. Typosquats are near-identical length.
        len_diff = abs(len(domain_name) - len(trusted_name))
        if (domain_name in trusted_name or trusted_name in domain_name) and len_diff > 2:
            continue

        ratio = SequenceMatcher(None, domain_name, trusted_name).ratio()
        norm_ratio = SequenceMatcher(None, normalized_name, trusted_name).ratio()
        max_ratio = max(ratio, norm_ratio)

        if max_ratio > best_ratio:
            best_ratio = max_ratio
            best_match = trusted

    if best_ratio >= threshold and best_match:
        return True, f"Lookalike of '{best_match}' (similarity: {best_ratio:.0%})"

    return False, "No lookalike detected"

def check_suspicious_domain_patterns(domain):
    flags = []
    ext = tldextract.extract(domain)

    if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
        flags.append(f"Suspicious TLD detected")

    try:
        socket.inet_aton(domain)
        flags.append("IP address used as domain")
    except:
        pass

    domain_lower = domain.lower()
    for kw in SUSPICIOUS_KEYWORDS_IN_DOMAIN:
        if kw in domain_lower:
            flags.append(f"Suspicious keyword in domain: '{kw}'")
            break

    if domain.count('-') > 2:
        flags.append("Too many hyphens in domain")
    if domain.count('.') > 4:
        flags.append("Too many subdomains")
    if len(ext.domain) > 30:
        flags.append("Unusually long domain name")

    return flags

def verify_domain(sender_email):
    if not sender_email:
        return {
            "domain": "unknown",
            "is_trusted": False,
            "is_generic_provider": False,
            "trust_score": 0,
            "flags": ["No sender email found"],
            "trusted_signals": [],
        }

    domain = extract_sender_domain(sender_email)
    flags = []
    trusted_signals = []

    trusted, reason = is_trusted_domain(domain)
    is_generic = is_generic_email_provider(domain)

    if trusted:
        trust_score = 90
        trusted_signals.append(reason)
    elif is_generic:
        trust_score = 45
        flags.append(f"Sender uses generic email provider ({domain}) — identity not verified by organization")
    else:
        trust_score = 25

    # IMPORTANT FIX: Agar domain already trusted hai, lookalike check skip karo.
    # Trusted domain khud kisi aur trusted domain se "similar" lag sakta hai
    # (e.g. amazon.in vs amazonpay.in) — yeh false positive hai, attack nahi.
    is_lookalike, lookalike_reason = (False, "Domain is already trusted — skipped")
    if not trusted:
        is_lookalike, lookalike_reason = check_lookalike(domain)
        if is_lookalike:
            flags.append(f"LOOKALIKE ATTACK DETECTED: {lookalike_reason}")
            trust_score = max(0, trust_score - 60)

    pattern_flags = check_suspicious_domain_patterns(domain)
    flags.extend(pattern_flags)
    trust_score = max(0, trust_score - (len(pattern_flags) * 12))

    try:
        socket.gethostbyname(domain)
        trusted_signals.append("Domain resolves to valid IP")
    except:
        flags.append("Domain does not resolve — possibly fake")
        trust_score = max(0, trust_score - 25)

    return {
        "domain": domain,
        "is_trusted": trusted,
        "is_generic_provider": is_generic,
        "trust_score": min(100, max(0, trust_score)),
        "flags": flags,
        "trusted_signals": trusted_signals,
    }
