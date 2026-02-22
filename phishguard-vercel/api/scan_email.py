"""
PhishGuard AI — Email Scan Serverless Function
Vercel Python Runtime (WSGI handler)
"""
from http.server import BaseHTTPRequestHandler
import json, re, hashlib, time, math
from urllib.parse import urlparse

# ── DETECTION DATA ────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "account suspended",
    "urgent", "click here immediately", "account will be closed",
    "limited time", "act now", "security alert", "login immediately",
    "unauthorized access", "update your payment", "prize winner",
    "claim your reward", "password expired", "verify now",
    "unusual activity", "billing problem", "delivery failed",
    "account locked", "reset password", "bank details", "wire transfer",
    "inheritance", "lottery", "free gift", "congratulations",
    "investment opportunity", "100% guaranteed", "risk free",
    "click here", "confirm now", "verify immediately",
]

SUSPICIOUS_TLD = {".xyz", ".top", ".club", ".work", ".gq", ".tk", ".ml", ".cf", ".ga"}

URGENCY_PHRASES = [
    "immediately", "urgent", "asap", "right now",
    "expires in", "within 24 hours", "act now", "last chance",
]

SENSITIVE_TERMS = [
    "password", "ssn", "social security", "credit card",
    "cvv", "bank account", "pin number", "account number",
]

BRAND_TYPOS = {
    "paypal": ["paypa1", "paypai", "paypa1"],
    "amazon": ["amaz0n", "amzon", "amazn"],
    "google": ["g00gle", "gogle", "googl"],
    "netflix": ["netfli", "netfix"],
    "microsoft": ["micros0ft", "microsft"],
}

# ── FEATURE EXTRACTION ────────────────────────────────────────────────
def extract_email_features(subject: str, sender: str, body: str):
    text = f"{subject} {body}".lower()
    indicators = []
    score = 0.0

    # 1. Keyword analysis
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in text]
    score += min(len(matched_kw) * 0.12, 0.55)
    if matched_kw:
        indicators.append(f"Phishing keywords detected: \"{matched_kw[0]}\", \"{matched_kw[1]}\"" if len(matched_kw) > 1 else f"Phishing keyword: \"{matched_kw[0]}\"")

    # 2. URLs in body
    urls_in_body = re.findall(r'https?://\S+', body)
    if len(urls_in_body) > 3:
        score += 0.1
        indicators.append(f"Excessive links in email body ({len(urls_in_body)} found)")

    # 3. Sender domain analysis
    sender_match = re.search(r'@([\w.\-]+)', sender)
    if sender_match:
        domain = sender_match.group(1).lower()
        tld = "." + domain.split(".")[-1]
        if tld in SUSPICIOUS_TLD:
            score += 0.25
            indicators.append(f"High-risk sender TLD: {tld}")
        lookalikes = ["paypa1", "g00gle", "amaz0n", "micros0ft", "app1e", "paypai"]
        if any(la in domain for la in lookalikes):
            score += 0.35
            indicators.append("Homograph/lookalike domain in sender address")
        if re.search(r'\d{2,}', domain.split(".")[0]):
            score += 0.08
            indicators.append("Numeric sequence in sender domain")

    # 4. Urgency language
    if any(p in text for p in URGENCY_PHRASES):
        score += 0.12
        indicators.append("High-urgency language patterns detected")

    # 5. Sensitive info requests
    matched_sensitive = [s for s in SENSITIVE_TERMS if s in text]
    if matched_sensitive:
        score += 0.20
        indicators.append(f"Request for sensitive information: {matched_sensitive[0]}")

    # 6. Deceptive links
    if re.search(r'<a\s+href=', body, re.IGNORECASE) and ("click here" in text or "verify" in text):
        score += 0.08
        indicators.append("Deceptive hyperlink pattern found")

    # 7. Brand misspellings
    for brand, typos in BRAND_TYPOS.items():
        if any(t in text for t in typos) and brand not in text:
            score += 0.15
            indicators.append(f"Brand name misspelling detected (impersonating {brand})")
            break

    if not indicators:
        indicators.append("No suspicious indicators found")

    score = min(score, 1.0)
    return score, indicators


def classify_risk(score: float):
    if score < 0.20: return "SAFE", False
    if score < 0.40: return "LOW", False
    if score < 0.60: return "MEDIUM", True
    if score < 0.80: return "HIGH", True
    return "CRITICAL", True


def get_threat_type(indicators, score):
    combined = " ".join(indicators).lower()
    if "homograph" in combined or "lookalike" in combined:
        return "Brand Impersonation"
    if "sensitive" in combined or "password" in combined:
        return "Credential Harvesting"
    if "keyword" in combined and score > 0.5:
        return "Social Engineering"
    if score > 0.3:
        return "Suspicious Activity"
    return None


def get_recommendation(risk):
    return {
        "SAFE":     "No threats detected. This appears to be legitimate.",
        "LOW":      "Minor concerns detected. Exercise normal caution.",
        "MEDIUM":   "Potential phishing attempt. Do not click links or provide information.",
        "HIGH":     "High-confidence phishing detected. Delete immediately and report.",
        "CRITICAL": "⚠ CRITICAL THREAT. Do not interact. Report to IT security immediately.",
    }[risk]


# ── VERCEL HANDLER ────────────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body_raw = self.rfile.read(length)
            data = json.loads(body_raw)

            sender  = data.get("sender", "")
            subject = data.get("subject", "")
            body    = data.get("body", "")

            start = time.time()
            score, indicators = extract_email_features(subject, sender, body)
            elapsed = (time.time() - start) * 1000

            risk, is_phishing = classify_risk(score)
            result = {
                "is_phishing":    is_phishing,
                "confidence":     round(score, 4),
                "risk_level":     risk,
                "threat_type":    get_threat_type(indicators, score),
                "indicators":     indicators,
                "recommendation": get_recommendation(risk),
                "scan_id":        hashlib.md5(f"{sender}{subject}{time.time()}".encode()).hexdigest()[:12].upper(),
                "scan_time_ms":   round(elapsed, 2),
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format, *args):
        pass
