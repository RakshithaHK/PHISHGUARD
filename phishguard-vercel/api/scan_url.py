"""
PhishGuard AI — URL Scan Serverless Function
Vercel Python Runtime (WSGI handler)
"""
from http.server import BaseHTTPRequestHandler
import json, re, hashlib, time, math
from urllib.parse import urlparse

SUSPICIOUS_TLD  = {"xyz","top","club","work","gq","tk","ml","cf","ga","icu","buzz","live"}
BRAND_NAMES     = ["paypal","amazon","google","apple","microsoft","netflix",
                   "facebook","instagram","bank","irs","fedex","dhl","ebay","dropbox"]
SUSPICIOUS_PATHS = ["login","signin","verify","account","secure","update",
                    "confirm","banking","password","credential","recover","validate"]


def calculate_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())


def extract_url_features(url: str):
    indicators = []
    score = 0.0

    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    except Exception:
        return 0.9, ["Malformed URL structure"]

    hostname = (parsed.hostname or "").lower()
    path     = parsed.path or ""
    lower    = url.lower()
    parts    = hostname.split(".")

    # 1. IP as hostname
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 0.45
        indicators.append("IP address used instead of domain name")

    # 2. URL length
    if len(url) > 75:
        score += 0.10
        indicators.append(f"Abnormally long URL ({len(url)} characters)")
    if len(url) > 120:
        score += 0.08

    # 3. Excessive subdomains
    subdomain_count = max(len(parts) - 2, 0)
    if subdomain_count > 2:
        score += 0.15
        indicators.append(f"Excessive subdomains detected ({subdomain_count})")

    # 4. Suspicious TLD
    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLD:
        score += 0.20
        indicators.append(f"High-risk top-level domain: .{tld}")

    # 5. Brand impersonation
    for brand in BRAND_NAMES:
        if brand in hostname and not hostname.endswith(f"{brand}.com"):
            score += 0.30
            indicators.append(f"Brand impersonation: \"{brand}\" in non-official domain")
            break

    # 6. Domain entropy
    root_domain = parts[0] if parts else ""
    entropy = calculate_entropy(root_domain)
    if entropy > 3.8:
        score += 0.15
        indicators.append(f"High domain entropy ({entropy:.2f}) — likely auto-generated")

    # 7. Suspicious path keywords
    matched_paths = [p for p in SUSPICIOUS_PATHS if p in path.lower()]
    if matched_paths:
        score += 0.10
        indicators.append(f"Suspicious path keywords: /{matched_paths[0]}")

    # 8. @ redirect trick
    if "@" in url:
        score += 0.30
        indicators.append("@ symbol in URL — classic redirect trick")

    # 9. Double slash redirect
    clean_path = url.replace("://", "~~")
    if "//" in clean_path:
        score += 0.15
        indicators.append("Double-slash redirect pattern detected")

    # 10. Hex / URL encoding
    if re.search(r'%[0-9a-fA-F]{2}', url):
        score += 0.10
        indicators.append("URL-encoded characters detected (possible obfuscation)")

    # 11. HTTP not HTTPS
    if parsed.scheme == "http":
        score += 0.12
        indicators.append("Unencrypted HTTP connection (no SSL/TLS)")

    # 12. Numeric domain
    if re.match(r'^\d[\d.]+$', hostname):
        score += 0.20
        indicators.append("Numeric-only domain structure")

    if not indicators:
        indicators.append("No suspicious indicators found")

    return min(score, 1.0), indicators


def classify_risk(score):
    if score < 0.20: return "SAFE", False
    if score < 0.40: return "LOW", False
    if score < 0.60: return "MEDIUM", True
    if score < 0.80: return "HIGH", True
    return "CRITICAL", True


def get_threat_type(indicators, score):
    combined = " ".join(indicators).lower()
    if "brand impersonation" in combined: return "Brand Impersonation"
    if "redirect" in combined or "ip address" in combined: return "Malicious Redirect"
    if "entropy" in combined: return "Malware Distribution Domain"
    if score > 0.3: return "Suspicious URL"
    return None


def get_recommendation(risk):
    return {
        "SAFE":     "No threats detected. This URL appears legitimate.",
        "LOW":      "Minor concerns. Exercise normal caution before clicking.",
        "MEDIUM":   "Potential phishing URL. Do not enter any personal information.",
        "HIGH":     "High-confidence malicious URL. Do not visit this link.",
        "CRITICAL": "⚠ CRITICAL. This URL is almost certainly malicious. Block immediately.",
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
            data   = json.loads(self.rfile.read(length))
            url    = data.get("url", "").strip()

            if not url:
                raise ValueError("URL is required")

            start = time.time()
            score, indicators = extract_url_features(url)
            elapsed = (time.time() - start) * 1000

            risk, is_phishing = classify_risk(score)
            result = {
                "is_phishing":    is_phishing,
                "confidence":     round(score, 4),
                "risk_level":     risk,
                "threat_type":    get_threat_type(indicators, score),
                "indicators":     indicators,
                "recommendation": get_recommendation(risk),
                "scan_id":        hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12].upper(),
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
