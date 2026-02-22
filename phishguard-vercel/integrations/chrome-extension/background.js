/**
 * PhishGuard AI — Background Service Worker
 * Handles desktop notifications for detected threats
 */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'PHISHING_DETECTED') {
    showThreatNotification(msg);
  }
  if (msg.type === 'SCAN_URL') {
    scanUrlBackground(msg.url).then(sendResponse);
    return true; // async
  }
});

function showThreatNotification({ risk, subject, confidence }) {
  const urgency = risk === 'CRITICAL' ? '🚨 CRITICAL THREAT' : '⚠️ Phishing Detected';
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: `PhishGuard AI — ${urgency}`,
    message: `"${subject?.slice(0, 60) || 'Unknown Subject'}" — ${confidence}% threat confidence (${risk} risk)`,
    priority: risk === 'CRITICAL' ? 2 : 1,
    buttons: [{ title: 'View Details' }],
  });
}

async function scanUrlBackground(url) {
  try {
    const r = await fetch('http://localhost:8000/api/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return r.json();
  } catch {
    return { error: true };
  }
}
