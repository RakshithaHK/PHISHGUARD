/**
 * PhishGuard AI — Gmail Add-in (Google Apps Script)
 * ===================================================
 * Shows a PhishGuard threat analysis panel in the Gmail reading pane.
 * Deploy via: script.google.com → Deploy → New deployment → Gmail Add-on
 *
 * IMPORTANT: Replace PHISHGUARD_API_URL with your deployed API endpoint.
 */

const PHISHGUARD_API_URL = "https://your-phishguard-api.com";  // ← change this

// ── RISK CONFIG ───────────────────────────────────────────────────────
const RISK_CONFIG = {
  SAFE:     { icon: "✅", color: "#00e096", label: "Safe",           header: "No Threats Detected" },
  LOW:      { icon: "🔵", color: "#5df5c0", label: "Low Risk",       header: "Minor Concerns Detected" },
  MEDIUM:   { icon: "⚠️", color: "#ffcc00", label: "Suspected",      header: "Potential Phishing Attempt" },
  HIGH:     { icon: "🔶", color: "#ff9500", label: "High Risk",      header: "High-Confidence Phishing" },
  CRITICAL: { icon: "🚨", color: "#ff3b5c", label: "CRITICAL THREAT",header: "⚠ DO NOT INTERACT" },
};

// ── MAIN ADD-ON ENTRY POINT ───────────────────────────────────────────
function buildAddOn(e) {
  const message = getCurrentMessage(e);

  if (!message) {
    return buildErrorCard("Could not read email content.");
  }

  // Auto-scan the open email
  const result = scanEmail(message.sender, message.subject, message.body);

  if (!result) {
    return buildErrorCard("PhishGuard API unavailable. Check server connection.");
  }

  return buildResultCard(result, message);
}


// ── FETCH EMAIL DATA ──────────────────────────────────────────────────
function getCurrentMessage(e) {
  try {
    const messageId = e.gmail.messageId;
    const message   = GmailApp.getMessageById(messageId);

    return {
      id:      messageId,
      sender:  message.getFrom(),
      subject: message.getSubject(),
      body:    message.getPlainBody().slice(0, 4000),
      date:    message.getDate().toLocaleString(),
    };
  } catch (err) {
    console.error("Error reading message:", err);
    return null;
  }
}


// ── SCAN EMAIL VIA API ────────────────────────────────────────────────
function scanEmail(sender, subject, body) {
  try {
    const response = UrlFetchApp.fetch(`${PHISHGUARD_API_URL}/api/scan/email`, {
      method:      "post",
      contentType: "application/json",
      payload:     JSON.stringify({ sender, subject, body }),
      muteHttpExceptions: true,
    });

    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    }
    console.error("API returned:", response.getResponseCode());
    return null;
  } catch (err) {
    console.error("API error:", err);
    return null;
  }
}


// ── BUILD RESULT CARD ─────────────────────────────────────────────────
function buildResultCard(result, message) {
  const cfg  = RISK_CONFIG[result.risk_level] || RISK_CONFIG.SAFE;
  const pct  = Math.round(result.confidence * 100);
  const card = CardService.newCardBuilder();

  card.setName("PhishGuard AI Analysis");
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("🛡 PhishGuard AI")
      .setSubtitle(cfg.header)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png")
  );

  // ── Risk Badge Section ──
  const riskSection = CardService.newCardSection()
    .setHeader("Threat Assessment");

  riskSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Risk Level")
      .setText(`${cfg.icon} ${cfg.label}`)
      .setBottomLabel(`${pct}% confidence · Scan ID: ${result.scan_id}`)
  );

  if (result.threat_type) {
    riskSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Threat Category")
        .setText(result.threat_type)
    );
  }

  riskSection.addWidget(
    CardService.newTextParagraph()
      .setText(`<font color="${cfg.color}"><b>${result.recommendation}</b></font>`)
  );

  card.addSection(riskSection);

  // ── Detection Signals Section ──
  if (result.indicators && result.indicators.length > 0) {
    const sigSection = CardService.newCardSection()
      .setHeader(`Detection Signals (${result.indicators.length})`);

    result.indicators.slice(0, 5).forEach(indicator => {
      sigSection.addWidget(
        CardService.newDecoratedText()
          .setText(`› ${indicator}`)
      );
    });

    card.addSection(sigSection);
  }

  // ── Action Buttons ──
  const actionSection = CardService.newCardSection().setHeader("Actions");

  if (result.is_phishing) {
    // Mark as spam button
    actionSection.addWidget(
      CardService.newTextButton()
        .setText("🗑 Move to Spam")
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("moveToSpam")
            .setParameters({ messageId: message.id })
        )
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setBackgroundColor("#ff3b5c")
    );

    // Report button
    actionSection.addWidget(
      CardService.newTextButton()
        .setText("🚩 Report Phishing")
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("reportPhishing")
            .setParameters({ messageId: message.id, scanId: result.scan_id })
        )
    );
  }

  // Re-scan button
  actionSection.addWidget(
    CardService.newTextButton()
      .setText("🔄 Re-Scan")
      .setOnClickAction(
        CardService.newAction().setFunctionName("rescanMessage")
      )
  );

  card.addSection(actionSection);

  // ── Footer Meta ──
  const metaSection = CardService.newCardSection();
  metaSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        `<font color="#445566">Scan time: ${result.scan_time_ms}ms ` +
        `· Engine: PhishGuard AI v1.0 ` +
        `· ${new Date().toLocaleTimeString()}</font>`
      )
  );
  card.addSection(metaSection);

  return card.build();
}


// ── BUILD ERROR CARD ──────────────────────────────────────────────────
function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setName("PhishGuard AI")
    .setHeader(
      CardService.newCardHeader()
        .setTitle("🛡 PhishGuard AI")
        .setSubtitle("Connection Error")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(`⚠️ ${message}`)
      )
    )
    .build();
}


// ── ACTION HANDLERS ───────────────────────────────────────────────────
function moveToSpam(e) {
  try {
    const msg = GmailApp.getMessageById(e.parameters.messageId);
    GmailApp.moveMessageToSpam(msg);
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("✅ Moved to spam"))
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Error: " + err.message))
      .build();
  }
}

function reportPhishing(e) {
  // Log to your security team's system
  console.log(`Phishing reported: messageId=${e.parameters.messageId} scanId=${e.parameters.scanId}`);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("🚩 Reported to security team"))
    .build();
}

function rescanMessage(e) {
  return buildAddOn(e);
}

function onAuthorizationRequired(e) {
  return CardService.newAuthorizationException()
    .setAuthorizationUrl("https://accounts.google.com")
    .setResourceDisplayName("PhishGuard AI")
    .throwException();
}
