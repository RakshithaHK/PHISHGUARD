"""
PhishGuard AI — Gmail Webhook Integration
==========================================
Uses Gmail API + Google Cloud Pub/Sub to receive real-time push
notifications when new emails arrive, then auto-scans them and
labels/flags them in Gmail.

Prerequisites:
  1. Google Cloud project with Gmail API + Pub/Sub enabled
  2. OAuth2 credentials (credentials.json)
  3. Service account with Pub/Sub subscriber role

Install:
  pip install google-auth google-auth-oauthlib google-api-python-client
              google-cloud-pubsub flask requests

Setup:
  1. Create Pub/Sub topic: phishguard-gmail-notifications
  2. Create push subscription pointing to: https://yourdomain.com/webhook/gmail
  3. Run: python setup_gmail_watch.py   (creates the Gmail watch)
  4. Run: python phishguard_webhook.py  (starts webhook server)
"""

import os
import json
import base64
import logging
import requests
from flask import Flask, request, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from google.cloud import pubsub_v1

# ── CONFIG ────────────────────────────────────────────────────────────
PHISHGUARD_API   = os.getenv("PHISHGUARD_API", "http://localhost:8000")
GOOGLE_PROJECT   = os.getenv("GOOGLE_PROJECT_ID", "your-gcp-project-id")
PUBSUB_TOPIC     = f"projects/{GOOGLE_PROJECT}/topics/phishguard-gmail-notifications"
WEBHOOK_PORT     = 5050
CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE       = "token.json"

# Gmail label IDs (will be created if they don't exist)
LABEL_PHISHING  = "PhishGuard/Phishing"
LABEL_SUSPECTED = "PhishGuard/Suspected"
LABEL_SAFE      = "PhishGuard/Scanned-Safe"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Webhook] %(message)s")
log = logging.getLogger(__name__)
app = Flask(__name__)


# ── GMAIL AUTH ────────────────────────────────────────────────────────
def get_gmail_service():
    """Authenticate and return Gmail API service."""
    creds = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


# ── GMAIL LABEL MANAGEMENT ────────────────────────────────────────────
def ensure_labels(service) -> dict:
    """Create PhishGuard labels if they don't exist. Returns label_id map."""
    existing = {l["name"]: l["id"] for l in service.users().labels().list(userId="me").execute().get("labels", [])}
    label_map = {}

    for label_name in [LABEL_PHISHING, LABEL_SUSPECTED, LABEL_SAFE]:
        if label_name not in existing:
            body = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
                "color": {
                    LABEL_PHISHING:  {"backgroundColor": "#fb4c2f", "textColor": "#ffffff"},
                    LABEL_SUSPECTED: {"backgroundColor": "#ffad47", "textColor": "#000000"},
                    LABEL_SAFE:      {"backgroundColor": "#16a766", "textColor": "#ffffff"},
                }.get(label_name, {}),
            }
            created = service.users().labels().create(userId="me", body=body).execute()
            label_map[label_name] = created["id"]
            log.info(f"Created Gmail label: {label_name}")
        else:
            label_map[label_name] = existing[label_name]

    return label_map


# ── EMAIL FETCHING ────────────────────────────────────────────────────
def fetch_email(service, message_id: str) -> dict:
    """Fetch full email content by message ID."""
    msg = service.users().messages().get(
        userId="me", id=message_id, format="full"
    ).execute()

    headers = {h["name"].lower(): h["value"] for h in msg["payload"].get("headers", [])}
    body_text = extract_body(msg["payload"])

    return {
        "id": message_id,
        "sender": headers.get("from", ""),
        "subject": headers.get("subject", "(no subject)"),
        "body": body_text[:4000],
        "thread_id": msg.get("threadId"),
    }


def extract_body(payload: dict) -> str:
    """Recursively extract plain text from MIME payload."""
    parts = payload.get("parts", [])
    text = ""

    if not parts:
        data = payload.get("body", {}).get("data", "")
        if data:
            text = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    else:
        for part in parts:
            mime = part.get("mimeType", "")
            if mime == "text/plain":
                data = part.get("body", {}).get("data", "")
                if data:
                    text += base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            elif mime.startswith("multipart/"):
                text += extract_body(part)

    return text


# ── PHISHGUARD SCAN ───────────────────────────────────────────────────
def scan_with_phishguard(email_data: dict) -> dict | None:
    """Send email to PhishGuard API for scanning."""
    try:
        r = requests.post(
            f"{PHISHGUARD_API}/api/scan/email",
            json={
                "sender": email_data["sender"],
                "subject": email_data["subject"],
                "body": email_data["body"],
            },
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.error(f"PhishGuard scan failed: {e}")
        return None


# ── GMAIL ACTIONS ─────────────────────────────────────────────────────
def apply_gmail_actions(service, message_id: str, result: dict, label_map: dict):
    """Apply labels and actions to email based on scan result."""
    risk = result.get("risk_level", "SAFE")
    pct  = round(result.get("confidence", 0) * 100)

    add_labels    = []
    remove_labels = ["INBOX"]  # Remove from inbox for phishing

    if risk in ("CRITICAL", "HIGH"):
        add_labels.append(label_map[LABEL_PHISHING])
        add_labels.append("SPAM")
        log.warning(f"Message {message_id}: LABELED PHISHING ({risk}, {pct}%)")

    elif risk == "MEDIUM":
        add_labels.append(label_map[LABEL_SUSPECTED])
        remove_labels = []  # Keep in inbox but label it
        log.info(f"Message {message_id}: LABELED SUSPECTED ({risk}, {pct}%)")

    else:
        add_labels.append(label_map[LABEL_SAFE])
        remove_labels = []  # Keep in inbox
        log.info(f"Message {message_id}: CLEAN ({risk})")

    # Apply label changes
    if add_labels or remove_labels:
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={
                "addLabelIds": add_labels,
                "removeLabelIds": remove_labels,
            }
        ).execute()


# ── WEBHOOK ENDPOINT ──────────────────────────────────────────────────
gmail_service = None
label_map = {}

@app.route("/webhook/gmail", methods=["POST"])
def gmail_webhook():
    """
    Receives Pub/Sub push notifications from Gmail.
    Google sends a base64-encoded message containing the historyId.
    """
    global gmail_service, label_map

    try:
        envelope = request.get_json()
        if not envelope:
            return jsonify({"error": "No data"}), 400

        # Decode Pub/Sub message
        pubsub_data = envelope.get("message", {}).get("data", "")
        if not pubsub_data:
            return jsonify({"status": "no data"}), 200

        notification = json.loads(base64.urlsafe_b64decode(pubsub_data + "=="))
        email_address = notification.get("emailAddress")
        history_id    = notification.get("historyId")

        log.info(f"Notification received: user={email_address} historyId={history_id}")

        # Lazy init
        if not gmail_service:
            gmail_service = get_gmail_service()
            label_map = ensure_labels(gmail_service)

        # Fetch new messages since last historyId
        process_new_messages(gmail_service, history_id, label_map)

        return jsonify({"status": "processed"}), 200

    except Exception as e:
        log.error(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500


def process_new_messages(service, history_id: str, label_map: dict):
    """Fetch message history and scan new arrivals."""
    try:
        history = service.users().history().list(
            userId="me",
            startHistoryId=history_id,
            historyTypes=["messageAdded"],
            labelId="INBOX",
        ).execute()

        for record in history.get("history", []):
            for added in record.get("messagesAdded", []):
                msg_id = added["message"]["id"]
                log.info(f"New message detected: {msg_id}")

                email_data = fetch_email(service, msg_id)
                result = scan_with_phishguard(email_data)

                if result:
                    apply_gmail_actions(service, msg_id, result, label_map)
                    log_scan(email_data, result)

    except Exception as e:
        log.error(f"History processing error: {e}")


def log_scan(email_data: dict, result: dict):
    """Log scan results for auditing."""
    log.info(
        f"SCAN | from='{email_data['sender'][:40]}' "
        f"subject='{email_data['subject'][:50]}' "
        f"risk={result['risk_level']} "
        f"confidence={round(result['confidence']*100)}% "
        f"scan_id={result['scan_id']}"
    )


# ── HEALTH CHECK ─────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "phishguard-gmail-webhook"})


# ── STARTUP ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("PhishGuard Gmail Webhook starting...")
    log.info(f"PhishGuard API: {PHISHGUARD_API}")
    log.info(f"Listening on port {WEBHOOK_PORT}")
    app.run(host="0.0.0.0", port=WEBHOOK_PORT, debug=False)
