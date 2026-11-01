import re

CREDENTIAL_PATTERNS = {
    "password": [
        r'\bpassword\b', r'\bpasswd\b', r'\bpin\b',
        r'\benter your password\b', r'\breset password\b',
        r'\bchange password\b', r'\bcreate password\b',
    ],
    "otp": [
        r'\botp\b', r'\bone.time.password\b', r'\bverification code\b',
        r'\bauthentication code\b', r'\bsecurity code\b',
        r'\benter the code\b', r'\b6.digit code\b', r'\b4.digit code\b',
    ],
    "banking": [
        r'\baccount number\b', r'\bifsc\b',
        r'\bnet banking\b.*\b(password|login|credential)\b',
        r'\btransaction password\b', r'\bbank details\b',
    ],
    "card_details": [
        r'\bcard number\b', r'\bcvv\b', r'\bcvc\b', r'\bexpiry date\b',
        r'\bcard details\b', r'\bcard information\b',
    ],
    "upi": [
        r'\bupi pin\b', r'\bupi id\b.*\b(share|send|provide)\b', r'\bvpa\b.*\bpin\b',
    ],
    "crypto": [
        r'\bwallet\b.*\baddress\b', r'\bprivate key\b',
        r'\bseed phrase\b', r'\brecovery phrase\b', r'\bmnemonic\b',
        r'\bcrypto\b.*\bsend\b', r'\bwallet phrase\b',
    ],
    "government_id": [
        r'\baadhar\b', r'\baadhaar\b', r'\buid\b.*\bnumber\b',
        r'\bpan card\b', r'\bpan number\b', r'\bpassport number\b',
        r'\bvoter id\b', r'\bdriving license\b', r'\bgovernment id\b',
        r'\bnational id\b', r'\bsocial security\b', r'\bssn\b',
    ],
    "investment": [
        r'\bdemat\b.*\b(password|pin|credential)\b', r'\btrading account\b.*\bpassword\b',
        r'\bdp id\b',
    ],
    "personal_docs": [
        r'\bkyc\b.*\bupload\b', r'\bkyc\b.*\bsubmit\b',
        r'\bkyc\b.*\bcomplete\b', r'\bkyc\b.*\bverif\b',
        r'\bupload\b.*\bdocuments\b', r'\bsend\b.*\bdocuments\b',
        r'\bshare\b.*\bdocuments\b',
    ],
    "financial_info": [
        r'\bsalary\b.*\bdetails\b.*\b(share|send)\b', r'\bincome\b.*\bproof\b',
        r'\bbank statement\b.*\bsend\b', r'\bloan\b.*\baccount\b.*\bdetails\b',
        r'\btax\b.*\binformation\b.*\b(share|send)\b', r'\bform 16\b',
    ],
    "corporate_credentials": [
        r'\baccess credentials\b', r'\blogin credentials\b',
        r'\badmin (access|credentials|password)\b',
        r'\bserver (access|credentials)\b', r'\baws\b.*\b(access|credentials|key)\b',
        r'\bapi key\b', r'\bsecret key\b', r'\baccess key\b',
        r'\bvpn (access|credentials)\b', r'\bssh key\b',
        r'\bshare credentials\b', r'\bprovide.{0,3}credentials\b',
        r'\bsend credentials\b', r'\bcredentials (reply|via email)\b',
        r'\bsystem access\b', r'\bdatabase (access|credentials)\b',
        r'\broot (access|password)\b', r'\bremote access\b',
    ],
}

# IMPORTANT: Yeh "action verbs" hain jo batate hain ki email REQUEST kar rahi hai,
# sirf MENTION nahi kar rahi. "Your account" likhna safe hai, lekin
# "share your account details" likhna request hai.
ACTION_REQUEST_VERBS = [
    r'\bshare\b', r'\bsend\b', r'\benter\b', r'\bprovide\b',
    r'\bsubmit\b', r'\bconfirm\b', r'\bverify\b', r'\bclick\b',
    r'\bupdate\b', r'\bgive\b', r'\breply with\b', r'\bfill\b',
    r'\bupload\b', r'\bdisclose\b', r'\breveal\b', r'\btype\b',
]

URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\bwithin 24 hours\b',
    r'\bwithin 48 hours\b', r'\bexpires today\b', r'\blast chance\b',
    r'\bact now\b', r'\bfinal notice\b', r'\bwarning\b',
    r'\byour account (will be|has been) (suspended|blocked|disabled|terminated)\b',
    r'\bunusual activity\b', r'\bsuspicious login\b',
    r'\bimmediate action required\b', r'\bdo not ignore\b',
    r'\bfailure to (respond|comply|verify)\b',
]

SCAM_PATTERNS = [
    r'\byou have won\b', r'\bcongratulations\b.*\bwon\b',
    r'\blottery\b', r'\bprize\b.*\bclaim\b', r'\bfree gift\b',
    r'\bunclaimed\b.*\bmoney\b', r'\binheritance\b',
    r'\binvestment\b.*\b(guarantee|guaranteed)\b',
    r'\b(double|triple)\b.*\b(money|investment|returns)\b',
    r'\brisk.free\b.*\binvest\b', r'\bget rich\b',
    r'\bjob offer\b.*\bwork from home\b', r'\bearning\b.*\bper day\b',
    r'\bcustomer (care|support|service)\b.*\b(call|contact)\b.*\b(now|immediately)\b',
    r'\brefund\b.*\b(pending|processing|claim)\b',
    r'\bceo\b.*\btransfer\b', r'\binvoice\b.*\burgent\b.*\bpay\b',
]

BEC_PATTERNS = [
    r'\bplease share\b.*\bcredentials\b',
    r'\breply (on this email|with).*\bcredentials\b',
    r'\bprovide.*\baccess credentials\b',
    r'\brequest access\b.*\bserver\b',
    r'\bneed.*\baccess.*\bcredentials\b.*\basap\b',
    r'\bkindly\b.*\bcredentials\b',
]

LEGITIMATE_CONTEXT = [
    r'\byou have received\b', r'\byour (recent|latest|last) transaction\b',
    r'\bstatement (is|has been) (ready|generated|attached)\b',
    r'\byour (order|booking|reservation) (has been|is) (confirmed|placed|received)\b',
    r'\bthank you for (your payment|shopping|banking with us)\b',
    r'\bmonthly statement\b', r'\bquarterly statement\b',
    r'\byour otp is\b', r'\byour otp for\b',
    r'\bdo not share (this|your) otp\b',
    r'\bnever share your otp\b',
    r'\bwe will never ask for your password\b',
    r'\bwe never ask for your (pin|otp|password)\b',
    r'\bavailable balance\b', r'\btransaction (date|id|successful)\b',
    r'\bno action is required\b', r'\bautomated notification\b',
]

def detect_credentials(text):
    text_lower = text.lower()
    found = {}
    total_matches = 0

    for category, patterns in CREDENTIAL_PATTERNS.items():
        matches = []
        for pattern in patterns:
            if re.search(pattern, text_lower):
                matches.append(pattern.replace(r'\b', '').replace('\\', ''))
        if matches:
            found[category] = matches
            total_matches += len(matches)

    urgency_found = []
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            urgency_found.append(pattern.replace(r'\b', '').replace('\\', ''))
    if urgency_found:
        found["urgency_tactics"] = urgency_found[:3]

    scam_found = []
    for pattern in SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            scam_found.append(pattern.replace(r'\b', '').replace('\\', ''))
    if scam_found:
        found["scam_tactics"] = scam_found[:3]

    bec_found = []
    for pattern in BEC_PATTERNS:
        if re.search(pattern, text_lower):
            bec_found.append(pattern.replace(r'\b', '').replace('\\', ''))
    if bec_found:
        found["bec_attempt"] = bec_found[:3]

    legitimate_signals = []
    for pattern in LEGITIMATE_CONTEXT:
        if re.search(pattern, text_lower):
            legitimate_signals.append(pattern.replace(r'\b', '').replace('\\', ''))

    # NEW: Check if there's an actual ACTION REQUEST verb near credential mention
    has_action_verb = any(re.search(p, text_lower) for p in ACTION_REQUEST_VERBS)

    credential_score = min(100, total_matches * 15)
    urgency_score = min(100, len(urgency_found) * 20)
    scam_score = min(100, len(scam_found) * 25)
    bec_score = min(100, len(bec_found) * 35)
    legitimate_reduction = len(legitimate_signals) * 20

    raw_score = (credential_score * 0.4) + (urgency_score * 0.2) + (scam_score * 0.2) + (bec_score * 0.2)
    final_score = max(0, raw_score - legitimate_reduction)

    # KEY FIX: "is_requesting_credentials" sirf TRUE hoga agar:
    # 1. Koi credential-category match mila HO, AND
    # 2. Email mein actual action-request verb bhi HO (share/send/enter/provide etc), AND
    # 3. Koi legitimate/notification signal NA mila ho
    real_categories = [c for c in found if c not in ("urgency_tactics", "scam_tactics", "bec_attempt")]
    is_requesting = (
        len(real_categories) > 0
        and has_action_verb
        and len(legitimate_signals) == 0
    ) or bool(bec_found)  # BEC pattern khud hi proof hai request ka

    return {
        "credential_risk_score": round(final_score),
        "is_requesting_credentials": is_requesting,
        "categories_detected": list(found.keys()),
        "patterns_found": found,
        "legitimate_signals": legitimate_signals,
        "urgency_detected": len(urgency_found) > 0,
        "scam_detected": len(scam_found) > 0,
        "bec_detected": len(bec_found) > 0,
        "has_action_verb": has_action_verb,
    }
