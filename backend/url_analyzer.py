import re
import socket
from urllib.parse import urlparse, unquote

# URL shortening services — suspicious hote hain
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'short.link', 'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 'urlzs.com', 'clck.ru',
}

# Suspicious URL keywords
SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'password', 'credential', 'authenticate',
    'validate', 'suspended', 'unlock', 'recover', 'restore',
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'hdfc', 'sbi', 'icici', 'axis', 'rbi', 'gov', 'uidai',
]

# Trusted domains — inke URLs safe hain
TRUSTED_URL_DOMAINS = {
    'google.com', 'gmail.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'amazon.in', 'flipkart.com', 'paypal.com',
    'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'axisbank.com',
    'kotakbank.com', 'paytm.com', 'phonepe.com', 'razorpay.com',
    'gov.in', 'nic.in', 'irctc.co.in', 'uidai.gov.in',
    'linkedin.com', 'twitter.com', 'facebook.com', 'instagram.com',
    'zoom.us', 'youtube.com', 'github.com', 'stackoverflow.com',
}

def extract_urls(text):
    """Text se saare URLs nikalo"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    # HTML href se bhi URLs nikalo
    href_pattern = r'href=["\']([^"\']+)["\']'
    href_urls = re.findall(href_pattern, text, re.IGNORECASE)
    all_urls = list(set(urls + href_urls))
    return [u for u in all_urls if u.startswith('http')]

def is_ip_based_url(url):
    """Kya URL mein IP address hai domain ki jagah?"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        socket.inet_aton(hostname)
        return True
    except:
        return False

def check_url_shortener(url):
    """Kya URL kisi shortener service se hai?"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        return domain in URL_SHORTENERS
    except:
        return False

def check_trusted_url(url):
    """Kya URL trusted domain se hai?"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        # Exact match
        if domain in TRUSTED_URL_DOMAINS:
            return True
        # Subdomain match
        parts = domain.split('.')
        for i in range(len(parts)-1):
            parent = '.'.join(parts[i:])
            if parent in TRUSTED_URL_DOMAINS:
                return True
        return False
    except:
        return False

def analyze_single_url(url):
    """Ek URL ko analyze karo"""
    flags = []
    risk_score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url_lower = url.lower()

        # Check if trusted
        if check_trusted_url(url):
            return {"url": url[:60], "risk_score": 0, "flags": ["Trusted domain URL"], "is_trusted": True}

        # IP based URL — very suspicious
        if is_ip_based_url(url):
            flags.append("IP address used instead of domain name")
            risk_score += 40

        # URL shortener
        if check_url_shortener(url):
            flags.append("URL shortener used — real destination hidden")
            risk_score += 25

        # Suspicious keywords in URL
        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in domain or kw in path:
                flags.append(f"Suspicious keyword in URL: '{kw}'")
                risk_score += 10
                break

        # HTTP instead of HTTPS
        if url.startswith('http://') and not url.startswith('https://'):
            flags.append("Insecure HTTP connection — no encryption")
            risk_score += 15

        # Too many subdomains — e.g. login.secure.bank.verify.com
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            flags.append(f"Too many subdomains: {subdomain_count}")
            risk_score += 15

        # Encoded characters — hiding real URL
        if '%' in url and unquote(url) != url:
            flags.append("URL contains encoded/hidden characters")
            risk_score += 10

        # Suspicious parameters
        suspicious_params = ['redirect', 'url=', 'goto=', 'return=', 'next=', 'continue=']
        for param in suspicious_params:
            if param in query:
                flags.append(f"Suspicious redirect parameter: '{param}'")
                risk_score += 10

        # Very long URL — often used to hide real destination
        if len(url) > 200:
            flags.append("Unusually long URL")
            risk_score += 10

        # Domain mismatch — URL text aur actual link alag
        if '@' in parsed.netloc:
            flags.append("@ symbol in URL — real domain hidden after @")
            risk_score += 30

    except Exception as e:
        flags.append(f"URL parsing error: {str(e)}")
        risk_score += 5

    return {
        "url": url[:80],
        "risk_score": min(100, risk_score),
        "flags": flags,
        "is_trusted": False,
    }

def analyze_urls(text):
    """Email text ke saare URLs analyze karo"""
    urls = extract_urls(text)

    if not urls:
        return {
            "url_count": 0,
            "url_risk_score": 0,
            "suspicious_urls": [],
            "trusted_urls": [],
            "all_flags": [],
        }

    results = [analyze_single_url(url) for url in urls[:10]]

    suspicious = [r for r in results if r["risk_score"] > 20 and not r.get("is_trusted")]
    trusted = [r for r in results if r.get("is_trusted")]
    all_flags = []
    for r in suspicious:
        all_flags.extend(r["flags"])

    # Overall URL risk score
    if suspicious:
        avg_risk = sum(r["risk_score"] for r in suspicious) / len(suspicious)
    else:
        avg_risk = 0

    # Bonus: agar sab URLs trusted hain
    if trusted and not suspicious:
        avg_risk = 0

    return {
        "url_count": len(urls),
        "url_risk_score": round(avg_risk),
        "suspicious_urls": [r["url"] for r in suspicious],
        "trusted_urls": [r["url"] for r in trusted],
        "all_flags": list(set(all_flags)),
    }
