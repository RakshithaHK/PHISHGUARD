# 🛡 PHISHGUARD

**Real-time AI-powered phishing detection for emails and URLs — with 4 Gmail integration modes.**

Built with Python (serverless functions) + vanilla HTML/CSS/JS. Deploys to Vercel in under 60 seconds with zero configuration.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Vercel](https://img.shields.io/badge/Deployed%20on-Vercel-000000?style=flat-square&logo=vercel&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![No Dependencies](https://img.shields.io/badge/Frontend-Zero%20Dependencies-f59e0b?style=flat-square)

---

## ✨ What It Does

PhishGuard AI scans emails and URLs in real time using a multi-signal heuristic engine and returns a structured threat report including risk level, confidence score, detected indicators, and a recommended action.

**Scan an email** → detects phishing keywords, suspicious sender domains, urgency language, credential harvesting attempts, and more.

**Scan a URL** → detects brand impersonation, IP-based hostnames, high-risk TLDs, Shannon entropy anomalies, redirect tricks, URL obfuscation, and more.

**4 Gmail integrations** → plug PhishGuard directly into Gmail as a Chrome Extension, SMTP Milter, Pub/Sub Webhook, or official Gmail Add-in.

**Works offline** → the frontend includes a full client-side simulation engine, so the app is fully usable even without a running backend.

---

## 📁 Project Structure

```
phishguard-ai/
│
├── index.html                          ← Unified frontend app (served at /)
├── vercel.json                         ← Vercel routing configuration
├── requirements.txt                    ← Python dependencies
├── .gitignore
├── README.md
│
├── api/                                ← Serverless Python functions
│   ├── health.py                       ← GET  /api/health
│   ├── scan_email.py                   ← POST /api/scan/email
│   ├── scan_url.py                     ← POST /api/scan/url
│   └── stats.py                        ← GET  /api/stats
│
├── integrations/
│   ├── chrome-extension/               ← Gmail Chrome Extension (5 files)
│   │   ├── manifest.json
│   │   ├── content.js
│   │   ├── content.css
│   │   ├── background.js
│   │   └── popup.html
│   │
│   ├── smtp-milter/                    ← SMTP server-level filter
│   │   └── phishguard_milter.py
│   │
│   ├── webhook/                        ← Gmail Pub/Sub webhook listener
│   │   ├── phishguard_webhook.py
│   │   └── setup_gmail_watch.py
│   │
│   └── gmail-addon/                    ← Google Workspace Add-in
│       ├── Code.gs
│       └── appsscript.json
│
└── docs/
    └── integration-guide.html          ← Visual setup guide
```

---

## ✅ Prerequisites

### For the frontend only (no backend needed)
- Any modern web browser (Chrome, Firefox, Safari, Edge)
- Nothing else — the app runs entirely in the browser

### For running the API locally
- Python **3.10 or higher**
- pip

### For Gmail integrations (optional)
| Integration | Extra Requirements |
|---|---|
| Chrome Extension | Google Chrome browser |
| SMTP Milter | Linux server running Postfix |
| Pub/Sub Webhook | Google Cloud project with Gmail API + Pub/Sub enabled |
| Gmail Add-in | Google account or Google Workspace org |

---

## 💻 Run Locally

### Option 1 — Frontend only (no setup needed)

Just open `index.html` directly in your browser:

```bash
# macOS
open index.html

# Linux
xdg-open index.html

# Windows
start index.html
```

The app auto-detects that no backend is running and switches to its built-in client-side simulation engine. All scanning features work fully.

---

### Option 2 — With Python API backend

**Step 1 — Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/phishguard-ai.git
cd phishguard-ai
```

**Step 2 — Create and activate a virtual environment** *(recommended)*

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

**Step 3 — Install dependencies**

```bash
pip install -r requirements.txt
```

**Step 4 — Serve the app**

```bash
# Serve everything with Python's built-in server (prevents CORS issues)
python -m http.server 3000
```

Then open `http://localhost:3000` in your browser.

---

### Risk Levels

| Level | Confidence Score | `is_phishing` | Recommended Action |
|---|---|---|---|
| `SAFE` | 0 – 20% | `false` | Deliver normally |
| `LOW` | 20 – 40% | `false` | Minor caution |
| `MEDIUM` | 40 – 60% | `true` | Warn user, do not click links |
| `HIGH` | 60 – 80% | `true` | Delete and report |
| `CRITICAL` | 80 – 100% | `true` | Block immediately, alert IT |

---

## 🔗 Gmail Integrations

### 1. 🔌 Chrome Extension

Automatically scans every Gmail email you open. Injects a real-time threat banner above the email body and highlights dangerous links in red.

**Setup**

```
1. Open Chrome → chrome://extensions
2. Enable "Developer mode" toggle (top-right corner)
3. Click "Load unpacked"
4. Select the integrations/chrome-extension/ folder
5. Open Gmail — PhishGuard is now active
```

**Configure your API URL** — edit line 1 of `content.js`:
```js
const API_BASE = 'https://your-app.vercel.app';
```

---

### 2. 📬 SMTP Milter

Intercepts every inbound email at the mail server level — before it reaches any inbox.

**Setup**

```bash
# Install dependency
pip install pymilter requests

# Set your API URL in the file
nano integrations/smtp-milter/phishguard_milter.py
# → PHISHGUARD_API = "https://your-app.vercel.app"

# Run the milter
python integrations/smtp-milter/phishguard_milter.py &

# Add to Postfix (/etc/postfix/main.cf)
echo "smtpd_milters = inet:127.0.0.1:8894" >> /etc/postfix/main.cf
echo "milter_default_action = accept"       >> /etc/postfix/main.cf
postfix reload
```

| Risk Level | Default Action |
|---|---|
| `CRITICAL` | Reject with SMTP 550 error |
| `HIGH` | Move to spam + add X-PhishGuard headers |
| `MEDIUM` | Prepend `[⚠ SUSPECTED PHISHING]` to subject |
| `SAFE` / `LOW` | Deliver with `X-PhishGuard-Scanned` header |

---

### 3. 🔗 Gmail Pub/Sub Webhook

Receives a push notification the instant a new email arrives, then scans and labels it automatically in Gmail.

**Setup**

```bash
# Install dependencies
pip install flask google-auth google-auth-oauthlib \
            google-api-python-client google-cloud-pubsub requests

# Set environment variables
export GOOGLE_PROJECT_ID=your-gcp-project-id
export PHISHGUARD_API=https://your-app.vercel.app

# Create Pub/Sub topic (once)
gcloud pubsub topics create phishguard-gmail-notifications \
  --project=$GOOGLE_PROJECT_ID

# Create push subscription pointing to your server
gcloud pubsub subscriptions create phishguard-sub \
  --topic=phishguard-gmail-notifications \
  --push-endpoint=https://your-server.com/webhook/gmail \
  --project=$GOOGLE_PROJECT_ID

# Register Gmail inbox watch (once — renew every 7 days)
python integrations/webhook/setup_gmail_watch.py

# Start the webhook listener
python integrations/webhook/phishguard_webhook.py
```

Labels created automatically in Gmail: `PhishGuard/Phishing`, `PhishGuard/Suspected`, `PhishGuard/Scanned-Safe`

---

### 4. 📱 Gmail Add-in

An official Google Workspace sidebar panel showing threat analysis for every email you open. Deployable org-wide via Admin Console.

**Setup**

```
1. Go to script.google.com → New project
2. Open Project Settings → check "Show appsscript.json manifest"
3. Paste integrations/gmail-addon/appsscript.json into the manifest editor
4. Paste integrations/gmail-addon/Code.gs into Code.gs
5. Set your API URL on line 1 of Code.gs:
   const PHISHGUARD_API_URL = "https://your-app.vercel.app";
6. Deploy → New deployment → Type: Gmail Add-on → Deploy
7. Authorize permissions → refresh Gmail
```
## ⚡ Quick Reference — All Commands

```bash
# ── Setup ─────────────────────────────────────────────────────────────
git clone https://github.com/YOUR_USERNAME/phishguard-ai.git && cd phishguard-ai
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# ── Run locally ───────────────────────────────────────────────────────
python -m http.server 3000                         # open http://localhost:3000
vercel dev                                         # with live API (needs Vercel CLI)

# ── Test API ──────────────────────────────────────────────────────────
curl https://your-app.vercel.app/api/health

curl -X POST https://your-app.vercel.app/api/scan/email \
  -H "Content-Type: application/json" \
  -d '{"sender":"test@paypa1.xyz","subject":"Urgent","body":"Verify now"}'

curl -X POST https://your-app.vercel.app/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://paypal-fake.login.xyz/verify"}'

# ── SMTP Milter ───────────────────────────────────────────────────────
pip install pymilter && python integrations/smtp-milter/phishguard_milter.py

# ── Gmail Webhook ─────────────────────────────────────────────────────
pip install flask google-auth google-api-python-client google-cloud-pubsub
export GOOGLE_PROJECT_ID=your-project
python integrations/webhook/setup_gmail_watch.py
python integrations/webhook/phishguard_webhook.py
---
---

<p align="center">Built with ❤️ by TEAM BUFFERED PhishGuard2.0</p>
