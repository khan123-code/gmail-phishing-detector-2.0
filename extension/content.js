const API_URL = "http://127.0.0.1:8000/predict";
const SUMMARY_URL = "http://127.0.0.1:8000/summarize";
let lastEmailId = null;

function getEmailData() {
  const subject = document.querySelector("h2.hP")?.innerText || "";
  const sender  = document.querySelector(".gD")?.getAttribute("email") || "";
  const body = (
    document.querySelector(".a3s.aiL")?.innerText ||
    document.querySelector(".a3s")?.innerText ||
    document.querySelector(".ii.gt div")?.innerText ||
    ""
  );
  return { subject, sender, body };
}

function removeBanner() {
  document.getElementById("phishing-banner")?.remove();
  document.getElementById("summary-panel")?.remove();
}

function removeSummary() {
  document.getElementById("summary-panel")?.remove();
}

function layerBar(label, raw, weight, weighted) {
  const pct = Math.min(100, raw);
  const barColor = raw > 60 ? "#ea4335" : raw > 30 ? "#fbbc04" : "#34a853";
  return (
    "<div style='margin:6px 0'>" +
    "<div style='display:flex;justify-content:space-between;font-size:11px;color:#444;margin-bottom:2px'>" +
    "<span>" + label + " (" + weight + "% weight)</span>" +
    "<span>" + raw + "/100 contributes " + weighted + "</span></div>" +
    "<div style='background:#e0e0e0;border-radius:4px;height:6px;overflow:hidden'>" +
    "<div style='background:" + barColor + ";height:100%;width:" + pct + "%'></div></div></div>"
  );
}

function getEmailTypeIcon(type) {
  const icons = {
    transaction:"💳", newsletter:"📰", job:"💼",
    promotion:"🏷️", personal:"👤", alert:"🔔",
    spam:"🚫", unknown:"📧"
  };
  return icons[type] || "📧";
}

function showSummaryPanel(summary) {
  removeSummary();
  const s = summary;
  const panel = document.createElement("div");
  panel.id = "summary-panel";
  panel.style.cssText = "position:sticky;top:0;z-index:9998;padding:14px 18px;background:#f8f9ff;border-left:4px solid #4285f4;font-family:Arial,sans-serif;font-size:13px;color:#1a1a2e;border-top:1px solid #e0e0e0;";

  const icon = getEmailTypeIcon(s.email_type);
  const actionHtml = s.action_required && s.action_required.needed
    ? "<div style='margin-top:10px;padding:8px 12px;background:#fff3cd;border-radius:6px;font-size:12px'><b>Action Required:</b> " + s.action_required.what_to_do + "</div>"
    : "<div style='margin-top:10px;padding:8px 12px;background:#e6f4ea;border-radius:6px;font-size:12px'><b>No Action Required</b></div>";

  const pointsHtml = (s.key_points || []).map(function(p) {
    return "<li style='margin:4px 0;color:#333'>" + p + "</li>";
  }).join("");

  panel.innerHTML =
    "<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:10px'>" +
    "<div style='display:flex;align-items:center;gap:8px'>" +
    "<span style='font-size:20px'>" + icon + "</span>" +
    "<strong style='font-size:14px;color:#4285f4'>AI Email Summary</strong>" +
    "<span style='font-size:11px;background:#e8f0fe;color:#4285f4;padding:2px 8px;border-radius:12px'>" + (s.email_type || "unknown") + "</span>" +
    "</div>" +
    "<span id='close-summary' style='cursor:pointer;color:#888;font-size:18px'>x</span>" +
    "</div>" +
    "<div style='background:white;border-radius:8px;padding:12px;margin-bottom:8px;border:0.5px solid #e0e0e0'>" +
    "<b style='color:#333'>What this email is about:</b>" +
    "<p style='margin:4px 0 0 0;color:#555;line-height:1.5'>" + (s.what_this_email_is_about || "") + "</p></div>" +
    "<div style='background:white;border-radius:8px;padding:12px;margin-bottom:8px;border:0.5px solid #e0e0e0'>" +
    "<b style='color:#333'>Sender Intent:</b>" +
    "<p style='margin:4px 0 0 0;color:#555;line-height:1.5'>" + (s.sender_intent || "") + "</p></div>" +
    "<div style='background:white;border-radius:8px;padding:12px;margin-bottom:8px;border:0.5px solid #e0e0e0'>" +
    "<b style='color:#333'>Key Points:</b>" +
    "<ul style='margin:6px 0 0 18px;padding:0;line-height:1.6'>" + pointsHtml + "</ul></div>" +
    actionHtml +
    "<div style='margin-top:8px;font-size:10px;color:#999;text-align:right'>Powered by Gemini AI</div>";

  const banner = document.getElementById("phishing-banner");
  if (banner && banner.parentNode) {
    banner.parentNode.insertBefore(panel, banner.nextSibling);
  } else {
    const emailView = document.querySelector(".nH") || document.body;
    emailView.prepend(panel);
  }

  const closeBtn = document.getElementById("close-summary");
  if (closeBtn) {
    closeBtn.addEventListener("click", function() {
      removeSummary();
    });
  }
}

function showErrorPanel(message) {
  removeSummary();
  const panel = document.createElement("div");
  panel.id = "summary-panel";
  panel.style.cssText = "position:sticky;top:0;z-index:9998;padding:12px 18px;background:#fce8e6;border-left:4px solid #ea4335;font-family:Arial,sans-serif;font-size:13px;color:#c5221f;";
  panel.innerHTML = "<b>Error:</b> " + message + " <span id='close-err' style='float:right;cursor:pointer;font-size:16px'>x</span>";
  const banner = document.getElementById("phishing-banner");
  if (banner && banner.parentNode) {
    banner.parentNode.insertBefore(panel, banner.nextSibling);
  }
  const closeErr = document.getElementById("close-err");
  if (closeErr) closeErr.addEventListener("click", function() { removeSummary(); });
}

function summarizeEmail() {
  const btn = document.getElementById("summarize-btn");
  if (btn) { btn.textContent = "Summarizing..."; btn.disabled = true; }

  const emailData = getEmailData();

  fetch(SUMMARY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      subject: emailData.subject,
      sender: emailData.sender,
      body: emailData.body
    })
  })
  .then(function(res) { return res.json(); })
  .then(function(data) {
    if (data.success) {
      showSummaryPanel(data.summary);
    } else {
      showErrorPanel("Gemini API error: " + (data.error || "Unknown error"));
    }
  })
  .catch(function(err) {
    console.error("Summarize fetch error:", err);
    showErrorPanel("Cannot connect to API server. Make sure server is running on port 8000.");
  })
  .finally(function() {
    if (btn) { btn.textContent = "Summarize"; btn.disabled = false; }
  });
}

function showBanner(data) {
  removeBanner();
  const colors = {
    "Safe":       { bg:"#e6f4ea", border:"#34a853", text:"#1e8e3e", icon:"OK" },
    "Suspicious": { bg:"#fef7e0", border:"#fbbc04", text:"#e37400", icon:"!" },
    "Phishing":   { bg:"#fce8e6", border:"#ea4335", text:"#c5221f", icon:"X" },
  };
  const c = colors[data.prediction] || colors["Suspicious"];

  const banner = document.createElement("div");
  banner.id = "phishing-banner";
  banner.style.cssText = "position:sticky;top:0;z-index:9999;padding:12px 16px;background:" + c.bg + ";border-left:4px solid " + c.border + ";font-family:Arial,sans-serif;font-size:14px;color:" + c.text + ";";

  const bd = data.layer_breakdown || {};
  let layersHtml = "";
  if (bd && bd.domain_check) {
    layersHtml =
      "<div style='margin-top:10px;padding-top:8px;border-top:1px solid #ddd'>" +
      "<b style='font-size:12px'>Score Breakdown (Total: " + data.classification + "):</b>" +
      layerBar("Sender/Domain Trust", bd.domain_check.raw_score, bd.domain_check.weight, bd.domain_check.weighted) +
      layerBar("Credential Request Detection", bd.credential_check.raw_score, bd.credential_check.weight, bd.credential_check.weighted) +
      layerBar("AI Semantic Understanding", bd.semantic_check.raw_score, bd.semantic_check.weight, bd.semantic_check.weighted) +
      layerBar("Email Authentication (SPF/DMARC)", bd.auth_check.raw_score, bd.auth_check.weight, bd.auth_check.weighted) +
      layerBar("URL Analysis", bd.url_check.raw_score, bd.url_check.weight, bd.url_check.weighted) +
      layerBar("Behavioral Signals", bd.behavior_check.raw_score, bd.behavior_check.weight, bd.behavior_check.weighted) +
      "</div>";
  }

  const reasonsHtml = (data.suspicious_indicators || []).map(function(r) {
    return "<li style='margin:2px 0'>" + r + "</li>";
  }).join("");

  const trustedHtml = (data.trusted_indicators || []).map(function(r) {
    return "<li style='margin:2px 0'>" + r + "</li>";
  }).join("");

  const ruleHtml = data.deciding_rule
    ? "<div style='margin-top:8px;padding:6px 8px;background:rgba(0,0,0,0.05);border-radius:4px;font-size:11px'><b>Rule applied:</b> " + data.deciding_rule + "</div>"
    : "";

  banner.innerHTML =
    "<div id='banner-top-row' style='display:flex;align-items:center;gap:8px;cursor:pointer'>" +
    "<span style='font-size:18px'>" + c.icon + "</span>" +
    "<strong>" + data.prediction + "</strong>" +
    "<span style='color:#666;font-size:12px'>Risk Score: " + data.classification + "</span>" +
    "<span style='color:#666;font-size:12px'>| Sender: " + data.sender_domain + "</span>" +
    "<span style='color:#666;font-size:12px'>SPF:" + (data.has_spf ? "OK" : "Missing") + " DMARC:" + (data.has_dmarc ? "OK" : "Missing") + "</span>" +
    "<button id='summarize-btn' style='margin-left:10px;padding:4px 14px;background:#4285f4;color:white;border:none;border-radius:12px;font-size:12px;cursor:pointer;font-family:Arial,sans-serif'>Summarize</button>" +
    "<span style='color:#888;font-size:11px;margin-left:4px'>(click row for details)</span>" +
    "<span id='banner-close' style='margin-left:auto;cursor:pointer;font-size:18px;color:#888'>x</span>" +
    "</div>" +
    "<div id='banner-details' style='display:none;margin-top:8px;font-size:12px;line-height:1.5'>" +
    (reasonsHtml ? "<div><b>Suspicious indicators:</b><ul style='margin:4px 0 8px 18px;padding:0'>" + reasonsHtml + "</ul></div>" : "") +
    (trustedHtml ? "<div><b>Trusted signals:</b><ul style='margin:4px 0 8px 18px;padding:0'>" + trustedHtml + "</ul></div>" : "") +
    layersHtml +
    ruleHtml +
    "</div>";

  const emailView = document.querySelector(".nH") || document.body;
  emailView.prepend(banner);

  document.getElementById("banner-close").addEventListener("click", function(e) {
    e.stopPropagation();
    removeBanner();
  });

  document.getElementById("summarize-btn").addEventListener("click", function(e) {
    e.stopPropagation();
    summarizeEmail();
  });

  document.getElementById("banner-top-row").addEventListener("click", function() {
    const details = document.getElementById("banner-details");
    if (details) details.style.display = details.style.display === "none" ? "block" : "none";
  });
}

async function analyzeEmail() {
  const emailData = getEmailData();
  const subject = emailData.subject;
  const sender = emailData.sender;
  const body = emailData.body;

  if (!subject && !sender) return;

  const emailId = subject + sender;
  if (emailId === lastEmailId) return;
  lastEmailId = emailId;

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject: subject, sender: sender, body: body })
    });
    const data = await res.json();
    console.log("Smart Phishing Detector result:", data);
    showBanner(data);
    chrome.storage.local.set({ lastResult: data });
  } catch (err) {
    console.error("Phishing detector error:", err);
  }
}

const observer = new MutationObserver(function() {
  if (document.querySelector("h2.hP")) analyzeEmail();
});
observer.observe(document.body, { childList: true, subtree: true });
