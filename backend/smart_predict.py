from backend.domain_checker import verify_domain
from backend.credential_detector import detect_credentials
from backend.url_analyzer import analyze_urls
from backend.semantic_analyzer import semantic_analyze
from backend.email_auth_checker import check_email_authentication

def calculate_final_score(domain_result, credential_result, url_result, semantic_result, auth_result):
    domain_trust = domain_result["trust_score"]
    domain_phishing_score = 100 - domain_trust


    has_lookalike = any("LOOKALIKE" in f for f in domain_result["flags"])
    if has_lookalike:
        domain_phishing_score = min(100, domain_phishing_score + 40)

    credential_score = credential_result["credential_risk_score"]
    if credential_result["legitimate_signals"]:
        credential_score = max(0, credential_score - 25)

    url_score = url_result["url_risk_score"]

    behavioral_score = 0
    if credential_result["urgency_detected"]:
        behavioral_score += 40
    if credential_result["scam_detected"]:
        behavioral_score += 60
    if credential_result.get("bec_detected"):
        behavioral_score += 50
    behavioral_score = min(100, behavioral_score)

    semantic_score = semantic_result["semantic_score"]
    auth_phishing_score = 100 - auth_result["auth_score"]

    # Updated weight distribution — auth check added as its own factor
    weighted_breakdown = {
        "domain_check":     {"raw_score": round(domain_phishing_score), "weight": 25, "weighted": round(domain_phishing_score * 0.25, 1)},
        "credential_check": {"raw_score": round(credential_score), "weight": 20, "weighted": round(credential_score * 0.20, 1)},
        "semantic_check":   {"raw_score": round(semantic_score), "weight": 20, "weighted": round(semantic_score * 0.20, 1)},
        "auth_check":       {"raw_score": round(auth_phishing_score), "weight": 15, "weighted": round(auth_phishing_score * 0.15, 1)},
        "url_check":        {"raw_score": round(url_score), "weight": 10, "weighted": round(url_score * 0.10, 1)},
        "behavior_check":   {"raw_score": round(behavioral_score), "weight": 10, "weighted": round(behavioral_score * 0.10, 1)},
    }

    

    final_score = sum(v["weighted"] for v in weighted_breakdown.values())

    is_org_trusted  = domain_result["is_trusted"]
    is_generic_mail = domain_result.get("is_generic_provider", False)

    rule_applied = None

    # Rule: Strong email authentication (SPF+DMARC with reject/quarantine policy)
    # is a strong trust signal even for domains NOT in our hardcoded list.
    # This is the key fix for "unknown but legitimate" senders.
    has_strong_auth = (
        auth_result["has_spf"]
        and auth_result["has_dmarc"]
        and auth_result["dmarc_policy"] in ("reject", "quarantine")
    )

    if is_org_trusted and url_result["url_risk_score"] < 30 and semantic_result["intent"] == "informational":
        if final_score > 25:
            rule_applied = "Trusted org domain + informational content -> score capped at 25"
        final_score = min(final_score, 25)
    elif is_org_trusted and url_result["url_risk_score"] < 30:
        if final_score > 35:
            rule_applied = "Trusted org domain + safe URLs -> score capped at 35"
        final_score = min(final_score, 35)

    if is_org_trusted and credential_result["legitimate_signals"]:
        if final_score > 15:
            rule_applied = "Trusted org domain + legitimate notification language -> score capped at 15"
        final_score = min(final_score, 15)

    if (semantic_result["intent"] == "informational"
            and not credential_result["is_requesting_credentials"]
            and url_result["url_risk_score"] < 20):
        if final_score > 20:
            rule_applied = "Semantically informational + no credential request + no suspicious URLs -> score capped at 20"
        final_score = min(final_score, 20)

    # NEW RULE: Unknown domain (not in our list) but has STRONG email authentication
    # + no credential request + no suspicious URLs = treat cautiously safe.
    # This is what lets a legitimate but unlisted sender (like a real company
    # we've never added) avoid being falsely flagged.
    if (not is_org_trusted
            and not is_generic_mail
            and has_strong_auth
            and not credential_result["is_requesting_credentials"]
            and url_result["url_risk_score"] < 30):
        if final_score > 30:
            rule_applied = "Unknown domain but has strong SPF+DMARC authentication + no credential request -> score capped at 30"
        final_score = min(final_score, 30)

    if not is_org_trusted and credential_result["is_requesting_credentials"]:
        if final_score < 65:
            rule_applied = "Unverified domain + actively requesting credentials -> score raised to minimum 65"
        final_score = max(final_score, 65)

    if has_lookalike:
        if final_score < 80:
            rule_applied = "Lookalike/typosquat domain detected -> score raised to minimum 80"
        final_score = max(final_score, 80)

    if any("IP address" in f for f in url_result["all_flags"]):
        if final_score < 65:
            rule_applied = "IP address used as URL -> score raised to minimum 65"
        final_score = max(final_score, 65)

    has_suspicious_tld = any("Suspicious TLD" in f for f in domain_result["flags"])
    if has_suspicious_tld and credential_result["is_requesting_credentials"]:
        if final_score < 70:
            rule_applied = "Suspicious domain extension + credential request -> score raised to minimum 70"
        final_score = max(final_score, 70)

    if (not is_org_trusted
            and credential_result["urgency_detected"]
            and credential_result["is_requesting_credentials"]):
        if final_score < 75:
            rule_applied = "Unverified sender + urgency tactics + credential request -> score raised to minimum 75"
        final_score = max(final_score, 75)

    if is_generic_mail and (
        "corporate_credentials" in credential_result["categories_detected"]
        or credential_result.get("bec_detected")
    ):
        if final_score < 70:
            rule_applied = "Personal email account requesting corporate/server credentials -> score raised to minimum 70"
        final_score = max(final_score, 70)

    if is_generic_mail and credential_result["is_requesting_credentials"]:
        if final_score < 55:
            rule_applied = "Personal email account requesting sensitive info -> score raised to minimum 55"
        final_score = max(final_score, 55)

    if semantic_result["intent"] == "requesting_action" and credential_result["is_requesting_credentials"]:
        if final_score < 70:
            rule_applied = "AI detected action-request intent + credential keywords matched -> score raised to minimum 70"
        final_score = max(final_score, 70)

    # NEW RULE: No email authentication at all (no SPF, no DMARC) + credentials requested
    # = strong phishing signal, regardless of domain trust status.
    if (not auth_result["has_spf"]
            and not auth_result["has_dmarc"]
            and credential_result["is_requesting_credentials"]):
        if final_score < 75:
            rule_applied = "No email authentication (SPF/DMARC) configured + credential request -> score raised to minimum 75"
        final_score = max(final_score, 75)

    # NEW RULE - Context-Aware Override for transaction notifications
    # We do NOT check semantic intent here because BERT sometimes misclassifies
    # debit/credit notifications as requesting_action due to action words
    # Instead we rely on the combination of ALL other signals being zero
    domain_resolves = any(
        "resolves to valid IP" in s
        for s in domain_result.get("trusted_signals", [])
    )
    has_dmarc = auth_result.get("has_dmarc", False)
    zero_risk_content = (
        not credential_result["is_requesting_credentials"]
        and url_result["url_risk_score"] < 10
        and not credential_result["urgency_detected"]
        and not credential_result["scam_detected"]
        and not credential_result.get("bec_detected")
        and credential_result["credential_risk_score"] == 0
    )
    if (zero_risk_content
            and domain_resolves
            and has_dmarc
            and final_score < 45):
        final_score = min(final_score, 25)
        rule_applied = "Zero content risk with valid domain resolution and DMARC - capped at Safe"

    return round(min(100, max(0, final_score))), weighted_breakdown, rule_applied

def classify_score(score):
    if score <= 30:
        return "Safe", "green"
    elif score <= 60:
        return "Suspicious", "yellow"
    else:
        return "Phishing", "red"

def build_explanation(score, label, domain_result, credential_result, url_result, semantic_result, auth_result):
    reasons = []
    suspicious_indicators = []
    trusted_indicators = []

    if domain_result["is_trusted"]:
        trusted_indicators.append(f"Sender domain '{domain_result['domain']}' is verified and trusted")
    elif domain_result.get("is_generic_provider"):
        suspicious_indicators.append(f"Sender uses generic email provider '{domain_result['domain']}' — identity not verified by any organization")
    else:
        suspicious_indicators.append(f"Sender domain '{domain_result['domain']}' is unknown or unverified")

    for flag in domain_result["flags"]:
        suspicious_indicators.append(flag)
    for signal in domain_result["trusted_signals"]:
        trusted_indicators.append(signal)

    # Email authentication signals
    for signal in auth_result["signals"]:
        trusted_indicators.append(signal)
    for flag in auth_result["flags"]:
        suspicious_indicators.append(flag)

    if credential_result["categories_detected"]:
        cats = [c for c in credential_result["categories_detected"]
                if c not in ["urgency_tactics", "scam_tactics", "bec_attempt"]]
        if cats:
            suspicious_indicators.append(f"Requests sensitive info: {', '.join(cats)}")

    if credential_result.get("bec_detected"):
        suspicious_indicators.append("Business Email Compromise pattern — requesting credentials/access via email")
    if credential_result["legitimate_signals"]:
        trusted_indicators.append("Email uses legitimate notification language")
    if credential_result["urgency_detected"]:
        suspicious_indicators.append("Urgency tactics — pressuring you to act fast")
    if credential_result["scam_detected"]:
        suspicious_indicators.append("Scam patterns — fake reward or threat detected")

    if semantic_result["intent"] == "requesting_action":
        suspicious_indicators.append("AI semantic analysis: email is requesting an action from you")
    elif semantic_result["intent"] == "informational":
        trusted_indicators.append("AI semantic analysis: email is purely informational, not a request")

    if url_result["suspicious_urls"]:
        suspicious_indicators.append(f"Suspicious URLs detected: {len(url_result['suspicious_urls'])}")
    if url_result["trusted_urls"]:
        trusted_indicators.append(f"Contains trusted URLs: {len(url_result['trusted_urls'])}")
    for flag in url_result["all_flags"]:
        suspicious_indicators.append(f"URL: {flag}")

    if label == "Safe":
        reasons.append("Email is from a verified sender with legitimate, informational content")
    elif label == "Suspicious":
        reasons.append("Email has unusual patterns — be careful before clicking any links or sharing information")
    else:
        reasons.append("HIGH RISK — Multiple phishing indicators detected. Do not click links or share any information.")

    return {
        "reasons": reasons,
        "suspicious_indicators": suspicious_indicators[:7],
        "trusted_indicators": trusted_indicators[:5],
    }

def smart_predict(subject, sender, body):
    full_text = f"{subject} {sender} {body}"

    domain_result     = verify_domain(sender)
    credential_result = detect_credentials(full_text)
    url_result        = analyze_urls(full_text)
    semantic_result   = semantic_analyze(f"{subject}. {body}")
    auth_result       = check_email_authentication(domain_result["domain"])

    score, breakdown, rule_applied = calculate_final_score(
        domain_result, credential_result, url_result, semantic_result, auth_result
    )
    label, color = classify_score(score)
    explanation = build_explanation(
        score, label, domain_result, credential_result, url_result, semantic_result, auth_result
    )

    return {
        "prediction": label,
        "color": color,
        "confidence": round(score / 100, 2),
        "phishing_score": score,
        "classification": f"{score}/100",
        "reasons": explanation["reasons"],
        "suspicious_indicators": explanation["suspicious_indicators"],
        "trusted_indicators": explanation["trusted_indicators"],
        "domain_verified": domain_result["is_trusted"],
        "sender_domain": domain_result["domain"],
        "credentials_requested": credential_result["is_requesting_credentials"],
        "urgency_detected": credential_result["urgency_detected"],
        "semantic_intent": semantic_result["intent"],
        "has_spf": auth_result["has_spf"],
        "has_dmarc": auth_result["has_dmarc"],
        "layer_breakdown": breakdown,
        "deciding_rule": rule_applied,
    }


