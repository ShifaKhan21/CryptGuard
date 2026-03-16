import { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE_URL = 'http://localhost:8081/api';

function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);

  const [stats, setStats] = useState({
    domains: [],
    total_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0,
    rule_blocked_count: 0,
    beaconing_count: 0,
    encrypted_pct: 0,
  });

  const [selectedFlow, setSelectedFlow] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [error, setError] = useState(null);
  const pollInterval = useRef(null);

  useEffect(() => { fetchInterfaces(); }, []);

  useEffect(() => {
    if (isCapturing) {
      pollInterval.current = setInterval(fetchStats, 2000);
    } else {
      if (pollInterval.current) clearInterval(pollInterval.current);
    }
    return () => { if (pollInterval.current) clearInterval(pollInterval.current); };
  }, [isCapturing]);

  const fetchInterfaces = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/interfaces`);
      const data = await res.json();
      setInterfaces(data.interfaces || []);
      if (data.is_capturing) {
        setIsCapturing(true);
        setSelectedInterface(data.selected);
      } else if (data.interfaces && data.interfaces.length > 0) {
        setSelectedInterface('1');
      }
      setError(null);
    } catch (err) {
      setError("Failed to connect to DPI API Server. Is it running on port 8081?");
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/stats`);
      const data = await res.json();
      setStats(data);
      setError(null);
    } catch (err) {
      console.error("Error fetching stats:", err);
    }
  };

  const handleStartCapture = async () => {
    if (!selectedInterface) return;
    try {
      await fetch(`${API_BASE_URL}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface_idx: parseInt(selectedInterface) })
      });
      setIsCapturing(true);
      setError(null);
      fetchStats();
    } catch (err) {
      setError("Failed to start capture");
    }
  };

  const handleStopCapture = async () => {
    try {
      await fetch(`${API_BASE_URL}/stop`, { method: 'POST' });
      setIsCapturing(false);
      setError(null);
    } catch (err) {
      setError("Failed to stop capture");
    }
  };

  const handleBlockProcess = async (pid, processName) => {
    if (!window.confirm(`Terminate process "${processName}" (PID: ${pid})?`)) return;
    try {
      const res = await fetch(`${API_BASE_URL}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      const data = await res.json();
      if (data.status === "success") { alert(`Terminated ${processName}.`); fetchStats(); }
      else alert(`Failed: ${data.message || 'Unknown error'}`);
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const getProductivityColor = (score) => {
    if (score >= 75) return '#04d772';
    if (score >= 50) return '#ffcc00';
    if (score >= 25) return '#ff8800';
    return '#ff4c4c';
  };

  const visibleDomains = stats.domains.filter(item => !item.domain.includes('Local PC'));

  return (
    <div className="app-container">
      {/* ── Header ── */}
      <header>
        <div className="brand">
          <div className="logo-icon">CG</div>
          <div>
            <h1>CryptGuard DPI</h1>
            <span className="header-sub">AI-Powered Deep Packet Inspection</span>
          </div>
        </div>
        <div className="status-badge">
          <div className={`status-dot ${!isCapturing ? 'inactive' : ''}`}></div>
          {isCapturing ? 'Monitoring Live Traffic' : 'System Idle'}
        </div>
      </header>

      {error && (
        <div style={{ background: 'rgba(255,76,76,0.1)', color: '#ff4c4c', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', border: '1px solid rgba(255,76,76,0.3)' }}>
          {error}
        </div>
      )}

      {/* ── Control Panel ── */}
      <section className="glass-panel controls-section">
        <div className="control-group">
          <label htmlFor="interface-select">Network Interface</label>
          <select id="interface-select" value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)} disabled={isCapturing}>
            <option value="" disabled>Select an interface...</option>
            {interfaces.map((iface, idx) => (
              <option key={idx} value={idx + 1}>{iface}</option>
            ))}
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {!isCapturing ? (
            <button className="btn-primary" onClick={handleStartCapture} disabled={!selectedInterface}>
              ▶ Start Inspection
            </button>
          ) : (
            <button className="btn-danger" onClick={handleStopCapture}>■ Stop Capture</button>
          )}
        </div>
      </section>

      {/* ── Packet Stats Cards ── */}
      <div className="stats-grid">
        <div className="glass-panel stat-card">
          <div className="stat-value">{stats.total_packets.toLocaleString()}</div>
          <div className="stat-label">Total Packets Inspected</div>
        </div>
        <div className="glass-panel stat-card">
          <div className="stat-value" style={{ color: '#ff4c4c' }}>{stats.dropped_packets.toLocaleString()}</div>
          <div className="stat-label">Packets Blocked/Dropped</div>
        </div>
        <div className="glass-panel stat-card">
          <div className="stat-value" style={{ color: 'var(--secondary-color)' }}>{stats.forwarded_packets.toLocaleString()}</div>
          <div className="stat-label">Packets Forwarded</div>
        </div>
      </div>

      {/* ── Intelligence Summary Bar ── */}
      <div className="intel-bar">
        <div className="intel-card intel-card--red">
          <div className="intel-icon">🛡️</div>
          <div>
            <div className="intel-value">{stats.rule_blocked_count ?? 0}</div>
            <div className="intel-label">Rule Blocks Active</div>
          </div>
        </div>
        <div className="intel-card intel-card--orange">
          <div className="intel-icon">📡</div>
          <div>
            <div className="intel-value">{stats.beaconing_count ?? 0}</div>
            <div className="intel-label">Beaconing Alerts</div>
          </div>
        </div>
        <div className="intel-card intel-card--green">
          <div className="intel-icon">🔒</div>
          <div>
            <div className="intel-value">{stats.encrypted_pct ?? 0}%</div>
            <div className="intel-label">Traffic Encrypted</div>
          </div>
        </div>
        <div className="intel-card intel-card--blue">
          <div className="intel-icon">🧠</div>
          <div>
            <div className="intel-value">{visibleDomains.length}</div>
            <div className="intel-label">Flows Analyzed</div>
          </div>
        </div>
      </div>

      {/* ── Main Traffic Table ── */}
      <section className="glass-panel scoreboard-container">
        <div className="scoreboard-header">
          <h2>Real-Time Traffic Intelligence</h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            DPI ＋ ML ＋ Rule Engine ＋ Beaconing Detection
          </span>
        </div>

        {visibleDomains.length === 0 ? (
          <div className="empty-state">
            {isCapturing ? (
              <>
                <div className="status-dot" style={{ margin: '0 auto 1rem', width: '12px', height: '12px' }}></div>
                <p>Analyzing Live Traffic... Visit a website to begin extraction.</p>
              </>
            ) : (
              <p>No traffic data available. Select an interface and start inspection.</p>
            )}
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Destination</th>
                  <th>Service (PID)</th>
                  <th>Category</th>
                  <th>Security Flags</th>
                  <th>Risk Score</th>
                  <th>AI Verdict</th>
                  <th>Productivity</th>
                  <th style={{ textAlign: 'right' }}>Hits</th>
                  <th style={{ textAlign: 'center' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleDomains.map((item, index) => {
                  const rowClass = item.is_rule_blocked
                    ? 'row-rule-blocked'
                    : item.is_beaconing
                    ? 'row-beaconing'
                    : '';
                  return (
                    <tr key={index} className={rowClass}>
                      {/* Domain */}
                      <td className="domain-cell">
                        <div className="domain-icon">{item.domain.charAt(0).toUpperCase()}</div>
                        <span>{item.domain}</span>
                        <span className="enc-badge" title={item.is_encrypted ? 'Encrypted' : 'Unencrypted'}>
                          {item.is_encrypted ? '🔒' : '🔓'}
                        </span>
                      </td>

                      {/* Process */}
                      <td className="process-cell">
                        <div className="process-info">
                          <span className="process-name">{item.process?.name || 'Searching...'}</span>
                          <span className="process-pid">PID: {item.process?.pid || '-'}</span>
                        </div>
                      </td>

                      {/* Category */}
                      <td>
                        <span className="category-badge" style={{
                          backgroundColor: item.category?.includes('RULE BLOCK') ? 'rgba(255,70,70,0.2)' :
                                          item.category === 'Unacademy' ? 'rgba(4,215,114,0.2)' :
                                          item.category === 'Netflix' ? 'rgba(229,9,20,0.2)' :
                                          item.category === 'SUSPICIOUS' ? 'rgba(255,140,0,0.2)' :
                                          'rgba(255,255,255,0.1)'
                        }}>
                          {item.category}
                        </span>
                      </td>

                      {/* Security Flags */}
                      <td>
                        <div className="flags-cell">
                          {item.is_rule_blocked && (
                            <span
                              className={`flag-badge flag-rule ${item.rule_severity === 'HIGH' ? 'flag-high' : 'flag-medium'}`}
                              title={item.rule_reason}
                            >
                              🚫 RULE BLOCK
                            </span>
                          )}
                          {item.is_beaconing && (
                            <span className="flag-badge flag-beacon" title="Regular interval hits detected — possible C2 beaconing">
                              📡 BEACONING
                            </span>
                          )}
                          {!item.is_rule_blocked && !item.is_beaconing && (
                            <span className="flag-badge flag-clean">✓ CLEAN</span>
                          )}
                        </div>
                      </td>

                      {/* Risk Score */}
                      <td>
                        <div className="risk-meter-container">
                          <div className="risk-meter-fill" style={{
                            width: `${item.risk_score}%`,
                            background: item.risk_score > 70 ? '#ff4c4c' : item.risk_score > 30 ? '#ffcc00' : '#04d772'
                          }} />
                          <span className="risk-value">{item.risk_score}%</span>
                        </div>
                      </td>

                      {/* AI Verdict */}
                      <td>
                        <span className={`verdict-badge ${item.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>
                          {item.prediction}
                        </span>
                      </td>

                      {/* Productivity */}
                      <td>
                        <div className="productivity-col">
                          <div className="productivity-bar-bg">
                            <div className="productivity-bar-fill" style={{
                              width: `${item.productivity_score ?? 50}%`,
                              background: getProductivityColor(item.productivity_score ?? 50)
                            }} />
                          </div>
                          <span className="productivity-label" style={{ color: getProductivityColor(item.productivity_score ?? 50) }}>
                            {item.productivity_score ?? 50}
                          </span>
                        </div>
                      </td>

                      {/* Hits */}
                      <td className="hits-cell" style={{ textAlign: 'right', fontWeight: 'bold' }}>
                        {item.hits.toLocaleString()}
                      </td>

                      {/* Actions */}
                      <td style={{ textAlign: 'center' }}>
                        <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'center' }}>
                          <button
                            className="btn-primary"
                            style={{ padding: '5px 9px', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: '700' }}
                            onClick={() => { setSelectedFlow(item); setShowModal(true); }}
                            disabled={Object.keys(item.ml_features || {}).length === 0}
                          >
                            {Object.keys(item.ml_features || {}).length > 0 ? "Inspect" : "Scanning"}
                          </button>

                          {item.prediction === 'Malicious' && item.process?.pid > 0 && (
                            <button
                              className="btn-danger"
                              style={{ padding: '5px 9px', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: '700' }}
                              onClick={() => handleBlockProcess(item.process.pid, item.process.name)}
                            >
                              Block
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ── Flow Inspect Modal ── */}
      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content glass-panel" style={{ maxWidth: '960px', width: '92%' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                <div className="domain-icon" style={{ width: '48px', height: '48px', fontSize: '1.4rem' }}>
                  {selectedFlow.domain.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.4rem' }}>{selectedFlow.domain}</h2>
                  <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginTop: '6px', flexWrap: 'wrap' }}>
                    <span className={`verdict-badge ${selectedFlow.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>
                      {selectedFlow.prediction}
                    </span>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      Risk: <strong style={{ color: selectedFlow.risk_score > 50 ? '#ff4c4c' : '#04d772' }}>{selectedFlow.risk_score}%</strong>
                    </span>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      {selectedFlow.is_encrypted ? '🔒 Encrypted' : '🔓 Unencrypted'}
                    </span>
                    <span style={{ fontSize: '0.85rem', color: getProductivityColor(selectedFlow.productivity_score ?? 50) }}>
                      📊 Productivity: {selectedFlow.productivity_score ?? 50}
                    </span>
                    {selectedFlow.is_rule_blocked && (
                      <span className={`flag-badge flag-rule ${selectedFlow.rule_severity === 'HIGH' ? 'flag-high' : 'flag-medium'}`}>
                        🚫 {selectedFlow.rule_reason}
                      </span>
                    )}
                    {selectedFlow.is_beaconing && (
                      <span className="flag-badge flag-beacon">📡 Beaconing Detected</span>
                    )}
                  </div>
                </div>
              </div>
              <button className="close-btn" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            <div className="modal-body" style={{ maxHeight: '68vh', padding: '20px' }}>
              <div className="features-grid">
                {Object.entries(selectedFlow.ml_features || {}).map(([key, value]) => (
                  <div key={key} className="feature-item" style={{
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.05)',
                    padding: '12px', borderRadius: '8px'
                  }}>
                    <div className="feature-key" style={{
                      fontSize: '0.63rem', textTransform: 'uppercase', letterSpacing: '0.5px',
                      color: 'var(--secondary-color)', marginBottom: '4px'
                    }}>{key}</div>
                    <div className="feature-value" style={{
                      fontSize: '1.05rem', fontWeight: '700',
                      fontFamily: '"JetBrains Mono", monospace'
                    }}>
                      {typeof value === 'number'
                        ? (key.toLowerCase().includes('iat') || key.toLowerCase().includes('duration') || key.toLowerCase().includes('std') || key.toLowerCase().includes('mean')
                          ? value.toLocaleString(undefined, { minimumFractionDigits: 4, maximumFractionDigits: 6 })
                          : value.toLocaleString())
                        : value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-footer" style={{ padding: '14px', borderTop: '1px solid rgba(255,255,255,0.1)', textAlign: 'center' }}>
              <span style={{ fontSize: '0.73rem', opacity: 0.5 }}>
                Features extracted in real-time via CryptGuard Multi-Threaded DPI Engine ＋ Intelligence Layer
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
