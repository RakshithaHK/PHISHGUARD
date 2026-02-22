"""
PhishGuard AI — Gmail Watch Setup
Run this ONCE to register Gmail push notifications via Pub/Sub.

Usage:
  python setup_gmail_watch.py
"""
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.labels"]
PROJECT_ID  = os.getenv("GOOGLE_PROJECT_ID", "your-gcp-project-id")
TOPIC_NAME  = f"projects/{PROJECT_ID}/topics/phishguard-gmail-notifications"
TOKEN_FILE  = "token.json"
CREDS_FILE  = "credentials.json"

def authenticate():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    return creds

def setup_watch():
    creds = authenticate()
    service = build("gmail", "v1", credentials=creds)

    body = {
        "labelIds": ["INBOX"],
        "topicName": TOPIC_NAME,
        "labelFilterBehavior": "INCLUDE",
    }

    result = service.users().watch(userId="me", body=body).execute()
    print(f"✅ Gmail watch registered!")
    print(f"   historyId  : {result['historyId']}")
    print(f"   expiration : {result['expiration']} (renew every 7 days)")
    print(f"\nNext: deploy phishguard_webhook.py and point your Pub/Sub")
    print(f"push subscription to: https://yourdomain.com/webhook/gmail")

if __name__ == "__main__":
    setup_watch()
