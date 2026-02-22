# 🛡 PhishGuard AI — Vercel Deployment

> Real-time phishing detection for emails and URLs with 4 Gmail integration modes.  
> Fully serverless — deploys to Vercel in under 60 seconds.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/YOUR_USERNAME/phishguard-ai)

---

## 📁 Project Structure

```
phishguard-ai/
├── index.html                         ← Frontend app (served at /)
├── vercel.json                        ← Vercel routing config (critical!)
├── requirements.txt                   ← Python runtime deps
│
├── api/                               ← Serverless functions (auto-routed)
│   ├── health.py                      → GET  /api/health
│   ├── scan_email.py                  → POST /api/scan/email
│   ├── scan_url.py                    → POST /api/scan/url
│   └── stats.py                       → GET  /api/stats
│
├── integrations/
│   ├── chrome-extension/              ← Load in chrome://extensions
│   ├── smtp-milter/                   ← Postfix server filter
│   ├── webhook/                       ← Gmail Pub/Sub listener
│   └── gmail-addon/                   ← Google Apps Script add-in
│
└── docs/
    └── integration-guide.html
```

---

## 🚀 Deploy to Vercel (60 seconds)

### Method 1 — Vercel CLI (Recommended)

```bash
# Install Vercel CLI
npm i -g vercel

# Clone and deploy
git clone https://github.com/YOUR_USERNAME/phishguard-ai.git
cd phishguard-ai
vercel

# Follow prompts — done! Your app is live.
```

### Method 2 — GitHub + Vercel Dashboard

1. Push this repo to GitHub
2. Go to [vercel.com](https://vercel.com) → **Add New Project**
3. Import your GitHub repository
4. Click **Deploy** — no configuration needed
5. ✅ Live at `https://phishguard-ai.vercel.app`

### Method 3 — One-click Button
Click the **Deploy** badge at the top of this README.

---

## ✅ How It Works on Vercel

| Request | Goes To |
|---------|---------|
| `GET /` | `index.html` (static frontend) |
| `POST /api/scan/email` | `api/scan_email.py` (serverless) |
| `POST /api/scan/url` | `api/scan_url.py` (serverless) |
| `GET /api/stats` | `api/stats.py` (serverless) |
| `GET /api/health` | `api/health.py` (serverless) |
| `GET /anything-else` | `index.html` (SPA fallback) |

The frontend automatically calls `/api/*` relative paths — no environment variables needed.

---

## 🔧 Local Development

```bash
# Install Vercel CLI
npm i -g vercel

# Run locally (mirrors Vercel environment exactly)
vercel dev

# Or run the Python API directly
pip install fastapi uvicorn
# Then open index.html in browser
```

---

## 🔌 Gmail Integrations

All integration source files are in `/integrations/`. See the [Integration Guide](docs/integration-guide.html) for setup instructions for:
- **Chrome Extension** — load `integrations/chrome-extension/` as unpacked extension
- **SMTP Milter** — run `integrations/smtp-milter/phishguard_milter.py`
- **Gmail Webhook** — run `integrations/webhook/phishguard_webhook.py`
- **Gmail Add-in** — deploy `integrations/gmail-addon/Code.gs` to Apps Script

For integrations, point `API_BASE` to your live Vercel URL:  
`https://phishguard-ai.vercel.app`
