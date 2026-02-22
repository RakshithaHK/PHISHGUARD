/**
 * PhishGuard AI — Gmail Content Script
 * Injects scan button + threat overlay into Gmail's reading pane
 */

const API_BASE = 'http://localhost:8000'; // Change to your deployed API

// ── RISK COLORS & ICONS ──────────────────────────────────────────────
const RISK_CONFIG = {
  SAFE:     { color: '#00e096', bg: 'rgba(0,224,150,0.1)',  icon: '✅', border: 'rgba(0,224,150,0.3)' },
  LOW:      { color: '#5df5c0', bg: 'rgba(93,245,192,0.08)', icon: '🔵', border: 'rgba(93,245,192,0.2)' },
  MEDIUM:   { color: '#ffcc00', bg: 'rgba(255,204,0,0.1)',  icon: '⚠️', border: 'rgba(255,204,0,0.3)'  },
  HIGH:     { color: '#ff9500', bg: 'rgba(255,149,0,0.1)',  icon: '🔶', border: 'rgba(255,149,0,0.3)'  },
  CRITICAL: { color: '#ff3b5c', bg: 'rgba(255,59,92,0.12)', icon: '🚨', border: 'rgba(255,59,92,0.4)'  },
};

// ── OBSERVE GMAIL FOR EMAIL OPEN EVENTS ─────────────────────────────
const observer = new MutationObserver(debounce(onDomChange, 600));
observer.observe(document.body, { childList: true, subtree: true });

function onDomChange() {
  injectScanButtons();
  autoScanOpenEmail();
}

// ── INJECT "SCAN" BUTTON INTO EMAIL TOOLBAR ──────────────────────────
function injectScanButtons() {
  // Gmail's email toolbar selector (subject area action buttons)
  const toolbars = document.querySelectorAll('.ade:not([data-phishguard])');
  toolbars.forEach(toolbar => {
    toolbar.setAttribute('data-phishguard', 'true');
    const btn = createScanButton();
    toolbar.appendChild(btn);
  });
}

function createScanButton() {
  const btn = document.createElement('div');
  btn.className = 'phishguard-btn';
  btn.title = 'Scan with PhishGuard AI';
  btn.innerHTML = `🛡 <span>PhishGuard Scan</span>`;
  btn.addEventListener('click', handleManualScan);
  return btn;
}

// ── AUTO-SCAN WHEN EMAIL OPENS ────────────────────────────────────────
let lastScannedHash = '';

function autoScanOpenEmail() {
  const emailBody = getEmailBody();
  const sender = getSender();
  const subject = getSubject();
  if (!emailBody && !sender) return;

  const hash = btoa(unescape(encodeURIComponent((sender + subject).slice(0, 100)))).slice(0, 20);
  if (hash === lastScannedHash) return;
  lastScannedHash = hash;

  // Remove old banner
  document.querySelectorAll('.phishguard-banner').forEach(el => el.remove());

  // Show loading banner
  showBanner({ loading: true });

  scanEmail(sender, subject, emailBody).then(result => {
    showBanner({ loading: false, result });
    if (result.is_phishing) {
      chrome.runtime.sendMessage({
        type: 'PHISHING_DETECTED',
        risk: result.risk_level,
        subject: subject,
        confidence: Math.round(result.confidence * 100),
      });
    }
  }).catch(() => {
    document.querySelectorAll('.phishguard-banner').forEach(el => el.remove());
  });
}

// ── MANUAL SCAN HANDLER ───────────────────────────────────────────────
async function handleManualScan(e) {
  e.stopPropagation();
  const btn = e.currentTarget;
  btn.innerHTML = `⏳ <span>Scanning...</span>`;
  btn.style.opacity = '0.7';

  const emailBody = getEmailBody();
  const sender = getSender();
  const subject = getSubject();

  try {
    const result = await scanEmail(sender, subject, emailBody);
    showBanner({ loading: false, result });
  } catch (err) {
    showBanner({ error: true });
  } finally {
    btn.innerHTML = `🛡 <span>PhishGuard Scan</span>`;
    btn.style.opacity = '1';
  }
}

// ── DOM HELPERS ───────────────────────────────────────────────────────
function getSender() {
  const el = document.querySelector('.gD') || document.querySelector('[email]');
  return el ? (el.getAttribute('email') || el.textContent.trim()) : '';
}

function getSubject() {
  const el = document.querySelector('h2.hP') || document.querySelector('[data-legacy-thread-id] h2');
  return el ? el.textContent.trim() : '';
}

function getEmailBody() {
  const el = document.querySelector('.a3s.aiL') || document.querySelector('.ii.gt .a3s');
  return el ? el.innerText.slice(0, 4000) : '';
}

// ── API CALL ──────────────────────────────────────────────────────────
async function scanEmail(sender, subject, body) {
  const response = await fetch(`${API_BASE}/api/scan/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sender, subject, body }),
  });
  if (!response.ok) throw new Error('API error');
  return response.json();
}

async function scanUrl(url) {
  const response = await fetch(`${API_BASE}/api/scan/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) throw new Error('API error');
  return response.json();
}

// ── BANNER UI ─────────────────────────────────────────────────────────
function showBanner({ loading, result, error }) {
  document.querySelectorAll('.phishguard-banner').forEach(el => el.remove());

  const banner = document.createElement('div');
  banner.className = 'phishguard-banner';

  if (loading) {
    banner.innerHTML = `
      <div class="pg-loading">
        <div class="pg-spinner"></div>
        <span>PhishGuard AI is analyzing this email...</span>
      </div>`;
    banner.style.background = 'rgba(13,17,23,0.95)';
    banner.style.borderColor = 'rgba(0,229,255,0.3)';
  } else if (error) {
    banner.innerHTML = `<div style="color:#ff9500">⚠ PhishGuard: Could not connect to scan API. Check that the server is running.</div>`;
    banner.style.background = 'rgba(255,149,0,0.08)';
    banner.style.borderColor = 'rgba(255,149,0,0.3)';
  } else if (result) {
    const cfg = RISK_CONFIG[result.risk_level];
    const pct = Math.round(result.confidence * 100);
    const indicators = result.indicators.slice(0, 3).map(i =>
      `<li class="pg-indicator">${i}</li>`).join('');

    banner.style.background = cfg.bg;
    banner.style.borderColor = cfg.border;
    banner.innerHTML = `
      <div class="pg-header">
        <span class="pg-icon">${cfg.icon}</span>
        <div class="pg-title-group">
          <span class="pg-title" style="color:${cfg.color}">
            ${result.risk_level} RISK
            ${result.threat_type ? `<span class="pg-threat-type">· ${result.threat_type}</span>` : ''}
          </span>
          <span class="pg-sub">${result.recommendation}</span>
        </div>
        <div class="pg-confidence" style="color:${cfg.color}">${pct}%</div>
        <button class="pg-dismiss" title="Dismiss">✕</button>
      </div>
      ${result.indicators.length && result.is_phishing ? `
      <div class="pg-indicators">
        <ul>${indicators}</ul>
      </div>` : ''}
      <div class="pg-meta">
        🛡 PhishGuard AI &nbsp;·&nbsp; Scan ID: ${result.scan_id} &nbsp;·&nbsp; ${result.scan_time_ms}ms
      </div>`;
  }

  // Insert above email body
  const emailContainer = document.querySelector('.aeJ') || document.querySelector('.nH .if');
  if (emailContainer) {
    emailContainer.insertBefore(banner, emailContainer.firstChild);
  } else {
    document.body.appendChild(banner);
  }

  // Dismiss button
  const dismissBtn = banner.querySelector('.pg-dismiss');
  if (dismissBtn) dismissBtn.addEventListener('click', () => banner.remove());

  // Auto-scan links inside email
  if (result && result.is_phishing) {
    scanLinksInEmail();
  }
}

// ── LINK SCANNING ─────────────────────────────────────────────────────
function scanLinksInEmail() {
  const emailBody = document.querySelector('.a3s.aiL');
  if (!emailBody) return;

  const links = emailBody.querySelectorAll('a[href]:not([data-phishguard-scanned])');
  links.forEach(async link => {
    link.setAttribute('data-phishguard-scanned', 'true');
    const href = link.getAttribute('href');
    if (!href || href.startsWith('mailto:')) return;

    try {
      const result = await scanUrl(href);
      if (result.risk_level === 'HIGH' || result.risk_level === 'CRITICAL') {
        link.style.cssText += `
          outline: 2px solid #ff3b5c !important;
          background: rgba(255,59,92,0.1) !important;
          border-radius: 3px;
          padding: 1px 3px;
        `;
        link.title = `⚠ PhishGuard: ${result.risk_level} RISK — ${result.threat_type || 'Suspicious URL'}`;
      }
    } catch {}
  });
}

// ── UTILITY ───────────────────────────────────────────────────────────
function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}
