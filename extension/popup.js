chrome.storage.local.get(['lastResult'], (data) => {
  const el = document.getElementById('status');
  if (!data.lastResult) return;
  const r = data.lastResult;
  el.textContent = r.prediction + ' (' + (r.confidence*100).toFixed(1) + '%)';
  el.className = r.prediction === 'Phishing' ? 'phish' : 'safe';
});
