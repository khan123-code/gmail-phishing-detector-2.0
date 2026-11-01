from sentence_transformers import SentenceTransformer, util
import re

print("Loading semantic model... (one-time, takes a few seconds)")
model = SentenceTransformer("all-MiniLM-L6-v2")
print("Semantic model loaded.")

# ── Reference sentences ──────────────────────────────────
# Yeh "anchor" sentences hain jinke against hum email ko compare karte hain.
# Model dekh ta hai ki email kis group ke "meaning" ke zyada paas hai.

PHISHING_INTENT_EXAMPLES = [
    "Please click this link and enter your password to verify your account.",
    "Reply with your login credentials to confirm your identity.",
    "Provide your OTP, card number and CVV to avoid account suspension.",
    "Share your bank account details and PIN immediately or your account will be blocked.",
    "Send your Aadhaar number, PAN card and date of birth to claim your reward.",
    "Click here and enter your credit card information to receive your refund.",
    "Provide remote access and your system password so we can fix the issue.",
    "Share your private key or recovery phrase to recover your crypto wallet.",
    "We need your KYC documents and bank statement sent immediately to this email.",
    "Kindly share your access credentials and server password as requested.",
]

NOTIFICATION_INTENT_EXAMPLES = [
    "You have received a payment in your account. Your available balance is shown below.",
    "This is to inform you that your transaction has been completed successfully.",
    "Your order has been shipped and will arrive in 3 business days.",
    "Your monthly account statement is now available to view.",
    "Thank you for your payment. Here is your receipt for the transaction.",
    "Your OTP for login is 123456. Do not share this code with anyone.",
    "This is an automated notification. No action is required from you.",
    "Your subscription has been renewed successfully.",
    "Here is a summary of your recent account activity.",
    "Your appointment has been confirmed for tomorrow at 10 AM.",
]

# Pre-compute embeddings once at startup (fast lookup later)
phishing_embeddings = model.encode(PHISHING_INTENT_EXAMPLES, convert_to_tensor=True)
notification_embeddings = model.encode(NOTIFICATION_INTENT_EXAMPLES, convert_to_tensor=True)


def clean_for_semantic(text):
    """Halka cleanup — semantic model raw sentences pe better kaam karta hai"""
    text = re.sub(r'http\S+', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:1000]  # model ke liye limit rakho


def semantic_analyze(text):
    """
    Email body ka actual MEANING samjho — sirf keywords nahi.
    Compare karta hai ki email "asking for something" jaisa hai
    ya "just informing you" jaisa hai.
    """
    text = clean_for_semantic(text)
    if not text or len(text) < 10:
        return {
            "semantic_score": 0,
            "intent": "unknown",
            "phishing_similarity": 0,
            "notification_similarity": 0,
        }

    email_embedding = model.encode(text, convert_to_tensor=True)

    # Compare against both example sets
    phishing_scores = util.cos_sim(email_embedding, phishing_embeddings)[0]
    notification_scores = util.cos_sim(email_embedding, notification_embeddings)[0]

    max_phishing_sim = float(phishing_scores.max())
    max_notification_sim = float(notification_scores.max())

    avg_phishing_sim = float(phishing_scores.mean())
    avg_notification_sim = float(notification_scores.mean())

    # Decide intent based on which group it's semantically closer to
    if max_phishing_sim > max_notification_sim + 0.05:
        intent = "requesting_action"
    elif max_notification_sim > max_phishing_sim + 0.05:
        intent = "informational"
    else:
        intent = "ambiguous"

    # Semantic risk score (0-100)
    # Higher phishing similarity + lower notification similarity = higher risk
    diff = max_phishing_sim - max_notification_sim
    semantic_score = max(0, min(100, round((diff + 0.3) * 150)))

    return {
        "semantic_score": semantic_score,
        "intent": intent,
        "phishing_similarity": round(max_phishing_sim, 3),
        "notification_similarity": round(max_notification_sim, 3),
    }
