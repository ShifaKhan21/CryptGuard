// ═══════════════════════════════════════════════════════════════════════════
// CryptGuard Extension Popup — Logic
// ═══════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  // Tab switching
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
  });

  // Initial load + polling
  refreshData();
  setInterval(refreshData, 2000);
});

function refreshData() {
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
    if (chrome.runtime.lastError || !response) return;

    // API status (Standalone mode is always online)
    const pill = document.getElementById('api-status');
    const txt = document.getElementById('api-status-text');
    pill.className = 'status-pill online';
    txt.textContent = 'Active Sentinel';

    // Stats
    document.getElementById('stat-requests').textContent = fmtNum(response.totalRequests);
    document.getElementById('stat-domains').textContent = response.totalDomains;
    document.getElementById('stat-threats').textContent = response.totalBlocked;
    const mins = Math.floor(response.sessionDuration / 60000);
    document.getElementById('stat-session').textContent = mins < 60 ? `${mins}m` : `${Math.floor(mins / 60)}h${mins % 60}m`;

    // Render lists
    renderDomains(response.domains || []);
    renderDownloads(response.downloads || []);
    renderAlerts(response.alerts || []);
  });
}

function renderDomains(domains) {
  const el = document.getElementById('domains-list');
  if (!domains.length) {
    el.innerHTML = '<div class="empty-state">Monitoring network traffic...</div>';
    return;
  }
  el.innerHTML = domains.map(d => `
    <div class="list-item">
      <div class="list-item-left">
        <span class="list-domain">${esc(d.domain)}</span>
        <span class="list-meta">${d.count} req · ${(d.contentTypes || []).slice(0, 2).join(', ') || '—'}</span>
      </div>
      <span class="risk-badge ${riskClass(d.riskScore)}">${d.riskScore > 0 ? d.riskScore : '✓'}</span>
    </div>
  `).join('');
}

function renderDownloads(downloads) {
  const el = document.getElementById('downloads-list');
  if (!downloads.length) {
    el.innerHTML = '<div class="empty-state">No downloads scanned yet.</div>';
    return;
  }
  el.innerHTML = downloads.map(d => `
    <div class="list-item">
      <div class="list-item-left">
        <span class="list-domain">${esc(d.filename)}</span>
        <span class="list-meta">${d.mime} · ${d.signals.length ? d.signals.join(', ') : 'Clean'}</span>
      </div>
      <span class="risk-badge ${riskClass(d.riskScore)}">${d.verdict}</span>
    </div>
  `).join('');
}

function renderAlerts(alerts) {
  const el = document.getElementById('alerts-list');
  if (!alerts.length) {
    el.innerHTML = '<div class="empty-state">No threats detected. 🛡️</div>';
    return;
  }
  el.innerHTML = alerts.map(a => `
    <div class="list-item">
      <div class="list-item-left">
        <span class="list-domain" style="color:var(--red)">${esc(a.domain)}</span>
        <span class="list-meta">${a.signals.join(', ')} · ${new Date(a.timestamp).toLocaleTimeString()}</span>
      </div>
      <span class="risk-badge risk-danger">${a.risk}</span>
    </div>
  `).join('');
}

function riskClass(score) {
  if (score >= 60) return 'risk-danger';
  if (score >= 30) return 'risk-warning';
  return 'risk-safe';
}

function fmtNum(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n);
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
