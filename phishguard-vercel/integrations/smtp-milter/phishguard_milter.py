"""
PhishGuard AI — SMTP Milter (Mail Filter)
==========================================
Sits between the internet and your mail server (Postfix/Exchange).
Intercepts every incoming email BEFORE delivery, scans it with
PhishGuard AI, and either:
  - Delivers with a threat warning header
  - Quarantines to a spam folder
  - Rejects the message entirely (CRITICAL threats)

Installation:
  pip install pymilter requests

Postfix integration (main.cf):
  smtpd_milters = inet:127.0.0.1:8894
  milter_default_action = accept

Run:
  python phishguard_milter.py
"""

import Milter
import email
import requests
import logging
import threading
from email.policy import default as email_policy
from io import BytesIO
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────────────────
PHISHGUARD_API  = "http://localhost:8000"
MILTER_PORT     = 8894
MILTER_TIMEOUT  = 10  # seconds
LOG_FILE        = "/var/log/phishguard-milter.log"

# Action thresholds
REJECT_ON    = ["CRITICAL"]          # Reject these entirely
QUARANTINE_ON = ["HIGH"]             # Add X-Spam header, move to spam
WARN_ON      = ["MEDIUM"]            # Add warning header, deliver
ALLOW_ON     = ["SAFE", "LOW"]       # Pass through silently

# Quarantine email address (for HIGH threats)
QUARANTINE_ADDRESS = "quarantine@yourdomain.com"

# ── LOGGING ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PhishGuard Milter] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE) if LOG_FILE else logging.StreamHandler(),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


# ── MILTER CLASS ──────────────────────────────────────────────────────
class PhishGuardMilter(Milter.Base):
    """
    Email milter that scans all incoming mail for phishing.
    """

    def __init__(self):
        self.id = Milter.uniqueID()
        self._body_chunks = []
        self._headers = {}

    # ── Header collection ──
    @Milter.noreply
    def header(self, name, value):
        key = name.lower()
        if key not in self._headers:
            self._headers[key] = []
        self._headers[key].append(value)
        return Milter.CONTINUE

    # ── Body collection ──
    @Milter.noreply
    def body(self, chunk):
        self._body_chunks.append(chunk)
        return Milter.CONTINUE

    # ── End of message — scan here ──
    def eom(self):
        try:
            return self._process_message()
        except Exception as e:
            log.error(f"Milter error: {e}")
            return Milter.ACCEPT  # Fail open — always deliver on error

    def _process_message(self):
        raw_body = b"".join(self._body_chunks)

        # Parse email
        sender  = self._headers.get("from", [""])[0]
        subject = self._headers.get("subject", ["(no subject)"])[0]
        body_text = self._extract_text(raw_body)

        log.info(f"Scanning: From='{sender}' Subject='{subject[:60]}'")

        # Call PhishGuard API
        result = self._scan_email(sender, subject, body_text)
        if not result:
            log.warning("PhishGuard API unreachable — allowing message")
            return Milter.ACCEPT

        risk     = result.get("risk_level", "SAFE")
        pct      = round(result.get("confidence", 0) * 100)
        scan_id  = result.get("scan_id", "unknown")
        threat   = result.get("threat_type") or "N/A"
        rec      = result.get("recommendation", "")
        indicators = result.get("indicators", [])

        log.info(f"Result: risk={risk} confidence={pct}% threat_type={threat} scan_id={scan_id}")

        # ── CRITICAL: reject ──
        if risk in REJECT_ON:
            log.warning(f"REJECTING message — {risk} risk (scan_id={scan_id})")
            self.setreply(
                "550", "5.7.1",
                f"Message rejected: PhishGuard AI detected CRITICAL phishing threat "
                f"(scan_id={scan_id}, confidence={pct}%)"
            )
            return Milter.REJECT

        # ── HIGH: quarantine ──
        if risk in QUARANTINE_ON:
            log.warning(f"QUARANTINING message — {risk} risk (scan_id={scan_id})")
            self._add_phishguard_headers(risk, pct, scan_id, threat, indicators)
            self.addheader("X-PhishGuard-Action", "QUARANTINED")
            self.addheader("X-Spam-Flag", "YES")
            self.addheader("X-Spam-Score", str(round(result.get("confidence", 0) * 20, 1)))
            return Milter.ACCEPT

        # ── MEDIUM: warn but deliver ──
        if risk in WARN_ON:
            log.info(f"WARNING headers added — {risk} risk (scan_id={scan_id})")
            self._add_phishguard_headers(risk, pct, scan_id, threat, indicators)
            self.addheader("X-PhishGuard-Action", "WARNED")
            # Prepend [SUSPECTED PHISHING] to subject
            self.chgheader("Subject", 1, f"[⚠ SUSPECTED PHISHING] {subject}")
            return Milter.ACCEPT

        # ── SAFE/LOW: pass through ──
        self.addheader("X-PhishGuard-Scanned", f"CLEAN scan_id={scan_id}")
        return Milter.ACCEPT

    def _add_phishguard_headers(self, risk, pct, scan_id, threat, indicators):
        """Add diagnostic headers visible to mail clients and admins."""
        self.addheader("X-PhishGuard-Risk",        risk)
        self.addheader("X-PhishGuard-Confidence",  f"{pct}%")
        self.addheader("X-PhishGuard-ScanID",      scan_id)
        self.addheader("X-PhishGuard-ThreatType",  threat or "Unknown")
        self.addheader("X-PhishGuard-Scanned",     datetime.utcnow().isoformat() + "Z")
        if indicators:
            self.addheader("X-PhishGuard-Indicators", "; ".join(indicators[:3]))

    def _scan_email(self, sender, subject, body):
        """POST to PhishGuard REST API."""
        try:
            resp = requests.post(
                f"{PHISHGUARD_API}/api/scan/email",
                json={"sender": sender, "subject": subject, "body": body},
                timeout=MILTER_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            log.error(f"PhishGuard API call failed: {e}")
            return None

    def _extract_text(self, raw: bytes) -> str:
        """Extract plain text from MIME email."""
        try:
            msg = email.message_from_bytes(raw, policy=email_policy)
            parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        parts.append(part.get_content())
            else:
                parts.append(msg.get_content())
            return "\n".join(parts)[:4000]
        except Exception:
            return raw.decode("utf-8", errors="replace")[:4000]


# ── RUNNER ────────────────────────────────────────────────────────────
def run_milter():
    """Start the milter server."""
    socketname = f"inet:{MILTER_PORT}@localhost"
    timeout = 600

    Milter.factory = PhishGuardMilter
    Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)

    log.info(f"PhishGuard Milter starting on {socketname}")
    log.info(f"Connected to PhishGuard API at {PHISHGUARD_API}")
    log.info(f"Reject on: {REJECT_ON} | Quarantine on: {QUARANTINE_ON} | Warn on: {WARN_ON}")

    Milter.runmilter("phishguard", socketname, timeout)


if __name__ == "__main__":
    run_milter()
