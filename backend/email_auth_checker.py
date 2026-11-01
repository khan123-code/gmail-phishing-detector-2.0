import dns.resolver
import re

def get_root_domain(domain):
    """Subdomain se root domain nikalo, e.g. mail.company.com -> company.com"""
    parts = domain.split('.')
    if len(parts) > 2:
        # Simple heuristic — proper TLD parsing ke liye tldextract use kar sakte hain,
        # lekin yeh most common cases ke liye kaafi hai.
        return '.'.join(parts[-2:])
    return domain

def check_spf_record(domain):
    """
    SPF record check karo — yeh batata hai domain ne authorize kiya hai
    kaunse mail servers uske naam se email bhej sakte hain.
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=3)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                return True, txt
        return False, None
    except Exception:
        return False, None

def check_dmarc_record(domain):
    """
    DMARC record check karo — yeh batata hai domain ne email spoofing
    se protect karne ke liye policy set ki hai ya nahi.
    """
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=3)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                policy = 'none'
                match = re.search(r'p=(\w+)', txt)
                if match:
                    policy = match.group(1)
                return True, policy
        return False, None
    except Exception:
        return False, None

def check_email_authentication(sender_domain):
    """
    Domain ke email authentication setup ko check karo.
    Yeh PROOF nahi hai ki yeh specific email genuine hai —
    yeh batata hai ki domain ne security properly configure ki hai ya nahi.

    Legitimate businesses (banks, big companies) almost hamesha
    SPF + DMARC setup karte hain. Fresh phishing domains aksar
    yeh setup nahi karte kyunki unhe jaldi disposable domain chahiye hota hai.
    """
    root_domain = get_root_domain(sender_domain)

    has_spf, spf_record = check_spf_record(root_domain)
    has_dmarc, dmarc_policy = check_dmarc_record(root_domain)

    auth_score = 50  # neutral baseline
    flags = []
    signals = []

    if has_spf:
        signals.append("Domain has SPF record configured (anti-spoofing)")
        auth_score += 20
    else:
        flags.append("No SPF record found — domain may not protect against email spoofing")
        auth_score -= 15

    if has_dmarc:
        signals.append(f"Domain has DMARC policy configured (policy: {dmarc_policy})")
        auth_score += 20
        if dmarc_policy in ('reject', 'quarantine'):
            signals.append(f"DMARC policy is strict ('{dmarc_policy}') — spoofed emails are actively blocked/flagged")
            auth_score += 10
    else:
        flags.append("No DMARC record found — domain has no policy against email spoofing")
        auth_score -= 15

    # Both missing — significant red flag for an org claiming to be a business
    if not has_spf and not has_dmarc:
        flags.append("Domain has NO email authentication setup at all — common in throwaway/phishing domains")
        auth_score -= 20

    auth_score = max(0, min(100, auth_score))

    return {
        "root_domain": root_domain,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "dmarc_policy": dmarc_policy,
        "auth_score": auth_score,
        "flags": flags,
        "signals": signals,
    }
