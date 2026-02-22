# 🛡 PhishGuard

> Real-time phishing detection for emails and URLs with 4 Gmail integration modes.  

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

## 🔌 Gmail Integrations

All integration source files are in `/integrations/`. See the [Integration Guide](docs/integration-guide.html) for setup instructions for:
- **Chrome Extension** — load `integrations/chrome-extension/` as unpacked extension
- **SMTP Milter** — run `integrations/smtp-milter/phishguard_milter.py`
- **Gmail Webhook** — run `integrations/webhook/phishguard_webhook.py`
- **Gmail Add-in** — deploy `integrations/gmail-addon/Code.gs` to Apps Script

For integrations, point `API_BASE` to your live Vercel URL:  
`https://phishguard-ai.vercel.app`
