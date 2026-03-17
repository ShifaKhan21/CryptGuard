import { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE_URL = 'http://localhost:8081/api';

function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const [activeTab, setActiveTab] = useState('traffic'); // 'traffic' | 'beacons'
  
  const [stats, setStats] = useState({
    domains: [],
    total_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0,
  });

  const [beaconAlerts, setBeaconAlerts] = useState([]);
  const [beaconStats, setBeaconStats] = useState({ total_alerts: 0, beacon_count: 0, suspicious_count: 0 });
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [error, setError] = useState(null);
  const pollInterval = useRef(null);
  const beaconPollInterval = useRef(null);

  useEffect(() => {
    document.body.className = theme === 'light' ? 'light-theme' : '';
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => { fetchInterfaces(); }, []);

  useEffect(() => {
    if (isCapturing) {
      pollInterval.current = setInterval(fetchStats, 1500);
      beaconPollInterval.current = setInterval(fetchBeacons, 4000);
    } else {
      if (pollInterval.current) clearInterval(pollInterval.current);
      if (beaconPollInterval.current) clearInterval(beaconPollInterval.current);
    }
    return () => {
      if (pollInterval.current) clearInterval(pollInterval.current);
      if (beaconPollInterval.current) clearInterval(beaconPollInterval.current);
    };
  }, [isCapturing]);

  // Always poll beacons even when not capturing (to show simulation results)
  useEffect(() => {
    fetchBeacons();
    const t = setInterval(fetchBeacons, 5000);
    return () => clearInterval(t);
  }, []);

  const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark');

  const fetchInterfaces = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/interfaces`);
      const data = await res.json();
      setInterfaces(data.interfaces || []);
      if (data.is_capturing) {
        setIsCapturing(true);
        setSelectedInterface(data.selected);
      } else if (data.interfaces?.length > 0) {
        setSelectedInterface('1');
      }
    } catch (err) { setError("CryptGuard Core Offline."); }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/stats`);
      const data = await res.json();
      setStats(data);
    } catch (err) { console.error(err); }
  };

  const fetchBeacons = async () => {
    try {
      const [histRes, cacheRes] = await Promise.all([
        fetch(`${API_BASE_URL}/beacon-history`),
        fetch(`${API_BASE_URL}/threat-cache`)
      ]);
      const histData = await histRes.json();
      const cacheData = await cacheRes.json();
      setBeaconAlerts(histData.alerts || []);
      setBeaconStats({
        total_alerts: cacheData.total_alerts || 0,
        beacon_count: cacheData.beacon_count || 0,
        suspicious_count: cacheData.suspicious_count || 0,
        total_records: cacheData.total_records || 0,
      });
    } catch (err) { console.error('Beacon fetch failed:', err); }
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
      fetchStats();
    } catch (err) { setError("Startup failed."); }
  };

  const handleStopCapture = async () => {
    try {
      await fetch(`${API_BASE_URL}/stop`, { method: 'POST' });
      setIsCapturing(false);
    } catch (err) { setError("Stopped."); }
  };

  const handleBlockProcess = async (pid, processName) => {
    if (!window.confirm(`Shut down ${processName}?`)) return;
    try {
      await fetch(`${API_BASE_URL}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      fetchStats();
    } catch (err) { alert(err.message); }
  };

  const handleClearCache = async () => {
    if (!window.confirm('Clear all beacon history records?')) return;
    try {
      await fetch(`${API_BASE_URL}/clear-cache`, { method: 'POST' });
      fetchBeacons();
    } catch (err) { console.error(err); }
  };

  const beaconCount = beaconAlerts.filter(a => a.verdict === 'BEACON').length;
  const suspiciousCount = beaconAlerts.filter(a => a.verdict === 'SUSPICIOUS').length;

  return (
    <div className="app-container">
      <header>
        <div className="brand">
          <div className="logo-icon">CG</div>
          <h1>CryptGuard <span style={{ opacity: 0.5, fontWeight: 400, marginLeft: '4px' }}>| Real-Time Traffic</span></h1>
        </div>
        
        <div className="header-actions">
           <div className="status-badge">
             <div className={`status-dot ${!isCapturing ? 'inactive' : ''}`}></div>
             {isCapturing ? 'Scanning' : 'Stopped'}
           </div>
           <button className="theme-toggle" onClick={toggleTheme} title="Switch Theme">
             {theme === 'dark' ? '☀️' : '🌙'}
           </button>
        </div>
      </header>

      <div className="top-controls">
        <section className="glass-panel control-item">
          <label>Network</label>
          <select value={selectedInterface} onChange={(e) => setSelectedInterface(e.target.value)} disabled={isCapturing}>
            {interfaces.map((iface, idx) => <option key={idx} value={idx + 1}>{iface}</option>)}
          </select>
          <button className={isCapturing ? "btn-danger btn-action" : "btn-primary btn-action"} onClick={isCapturing ? handleStopCapture : handleStartCapture}>
            {isCapturing ? 'Stop' : 'Start'}
          </button>
        </section>

        <div className="glass-panel stat-mini">
           <div className="lab">Inspected</div>
           <div className="val">{stats.total_packets.toLocaleString()}</div>
        </div>
        <div className="glass-panel stat-mini">
           <div className="lab">Blocked</div>
           <div className="val" style={{ color: 'var(--danger)' }}>{stats.dropped_packets.toLocaleString()}</div>
        </div>
        {/* C2 Beacon Summary Stats */}
        <div className="glass-panel stat-mini beacon-stat-card" onClick={() => setActiveTab('beacons')} style={{ cursor: 'pointer', borderColor: beaconCount > 0 ? 'var(--danger)' : suspiciousCount > 0 ? 'var(--warning)' : 'var(--panel-border)' }}>
          <div>
            <div className="lab">C2 Beacons</div>
            <div className="val" style={{ color: beaconCount > 0 ? 'var(--danger)' : suspiciousCount > 0 ? 'var(--warning)' : 'var(--text-muted)' }}>
              {beaconCount > 0 ? `🔴 ${beaconCount}` : suspiciousCount > 0 ? `🟡 ${suspiciousCount}` : '—'}
            </div>
          </div>
          {(beaconCount > 0 || suspiciousCount > 0) && <div className="beacon-pulse"></div>}
        </div>
      </div>

      {error && <div className="glass-panel" style={{ color: 'var(--danger)', marginBottom: '0.75rem', padding: '0.5rem', fontSize: '0.75rem' }}>⚠️ {error}</div>}

      {/* TAB BAR */}
      <div className="tab-bar">
        <button className={`tab-btn ${activeTab === 'traffic' ? 'active' : ''}`} onClick={() => setActiveTab('traffic')}>
          📡 Live Traffic
          <span className="tab-count">{stats.domains.length}</span>
        </button>
        <button className={`tab-btn ${activeTab === 'beacons' ? 'active' : ''} ${beaconCount > 0 ? 'tab-danger' : suspiciousCount > 0 ? 'tab-warning' : ''}`} onClick={() => setActiveTab('beacons')}>
          🎯 C2 Beacon Alerts
          {(beaconCount + suspiciousCount) > 0 && (
            <span className={`tab-count ${beaconCount > 0 ? 'danger' : 'warning'}`}>
              {beaconCount + suspiciousCount}
            </span>
          )}
        </button>
      </div>

      {/* ═══ TAB 1: LIVE TRAFFIC ═══ */}
      {activeTab === 'traffic' && (
        <section className="table-section">
          <div className="table-header">
            <h2>Live Stream</h2>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              {stats.domains.length} Flows Active
            </div>
          </div>

          <div className="table-container">
            {stats.domains.length === 0 ? (
               <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                 {isCapturing ? 'Waiting for packets...' : 'Start scanning to see live traffic.'}
               </div>
            ) : (
               <table>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>App / Process</th>
                    <th>Label</th>
                    <th style={{ width: '50px' }}>Risk</th>
                    <th>Logic</th>
                    <th>C2 Score</th>
                    <th style={{ textAlign: 'right' }}>Hits</th>
                    <th style={{ textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.domains.map((item, index) => {
                    const ba = item.beacon_analysis || {};
                    const bScore = ba.beacon_score || 0;
                    const bVerdict = ba.verdict || 'NORMAL';
                    return (
                      <tr key={index} className={bVerdict === 'BEACON' ? 'row-beacon' : bVerdict === 'SUSPICIOUS' ? 'row-suspicious' : ''}>
                        <td className="domain-cell">
                          <div className="domain-info">
                            <div className="domain-icon" style={{ opacity: 0.7 }}>{item.domain.charAt(0).toUpperCase()}</div>
                            <strong>{item.domain}</strong>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <span style={{ fontWeight: 600 }}>{item.process?.name || 'System / Network'}</span>
                            <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>PID: {item.process?.pid || '-'}</span>
                          </div>
                        </td>
                        <td><span className="category-tag">{item.category}</span></td>
                        <td>
                          <div className="risk-bar">
                            <div className="risk-fill" style={{ width: `${item.risk_score}%`, background: item.risk_score > 70 ? 'var(--danger)' : 'var(--warning)' }} />
                          </div>
                        </td>
                        <td>
                          <span className={`verdict-chip ${item.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>
                            {item.prediction === 'Malicious' ? 'Unsafe' : 'Safe'}
                          </span>
                        </td>
                        <td>
                          {bScore > 0 ? (
                            <span className={`beacon-mini-chip ${bVerdict === 'BEACON' ? 'b-danger' : bVerdict === 'SUSPICIOUS' ? 'b-warning' : 'b-normal'}`}>
                              {bVerdict === 'BEACON' ? '🔴' : '🟡'} {bScore}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>—</span>
                          )}
                        </td>
                        <td className="hits-cell" style={{ textAlign: 'right' }}>{item.hits}</td>
                        <td>
                          <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'center' }}>
                            <button className="btn-primary btn-action btn-outline" onClick={() => { setSelectedFlow(item); setShowModal(true); }}>Details</button>
                            {item.prediction === 'Malicious' && item.process?.pid > 0 && (
                              <button className="btn-danger btn-action" onClick={() => handleBlockProcess(item.process.pid, item.process.name)}>Stop</button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>
      )}

      {/* ═══ TAB 2: C2 BEACON ALERTS ═══ */}
      {activeTab === 'beacons' && (
        <section className="table-section">
          <div className="table-header">
            <h2>🎯 C2 Beacon Alerts</h2>
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              {/* Summary pills */}
              <span className="beacon-pill danger">🔴 BEACON: {beaconCount}</span>
              <span className="beacon-pill warning">🟡 SUSPICIOUS: {suspiciousCount}</span>
              <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>{beaconStats.total_records?.toLocaleString()} records in DB</span>
              <button className="btn-outline btn-action" onClick={handleClearCache}>Clear DB</button>
            </div>
          </div>

          {/* Detection Signals Legend */}
          <div className="signals-legend">
            <div className="signal-badge s1">📡 FFT Periodicity <span>Regular timing intervals</span></div>
            <div className="signal-badge s2">🎯 Destination Consistency <span>Single IP target</span></div>
            <div className="signal-badge s3">📦 Packet Size Uniformity <span>Same-size payloads</span></div>
            <div className="signal-badge s4">🌙 Night Activity <span>00:00–06:00 local</span></div>
          </div>

          <div className="table-container">
            {beaconAlerts.length === 0 ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🛡️</div>
                <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>No Beacon Alerts</div>
                <div style={{ fontSize: '0.7rem' }}>Run <code>python run_sim.py</code> to simulate C2 beaconing</div>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Process</th>
                    <th>Destination IP</th>
                    <th style={{ textAlign: 'center' }}>Score</th>
                    <th style={{ textAlign: 'center' }}>Verdict</th>
                    <th>Signals Triggered</th>
                    <th style={{ textAlign: 'center' }}>Block?</th>
                  </tr>
                </thead>
                <tbody>
                  {beaconAlerts.map((alert, idx) => (
                    <tr key={idx} className={alert.verdict === 'BEACON' ? 'row-beacon' : 'row-suspicious'}>
                      <td style={{ fontSize: '0.65rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <div style={{ fontWeight: 700, fontSize: '0.8rem' }}>{alert.process_name}</div>
                      </td>
                      <td>
                        <code style={{ fontSize: '0.75rem' }}>{alert.destination_ip}</code>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <div className="score-ring" style={{ '--score-color': alert.beacon_score >= 75 ? 'var(--danger)' : 'var(--warning)' }}>
                          <strong>{alert.beacon_score}</strong>
                          <span>/100</span>
                        </div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <span className={`verdict-chip ${alert.verdict === 'BEACON' ? 'malicious' : 'suspicious-chip'}`}>
                          {alert.verdict === 'BEACON' ? '🔴 BEACON' : '🟡 SUSPICIOUS'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                          {(alert.signals || []).map((sig, si) => (
                            <span key={si} className="signal-tag">{sig.replace(/_/g, ' ')}</span>
                          ))}
                        </div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        {alert.should_block
                          ? <span className="verdict-chip malicious">🚫 BLOCK</span>
                          : <span className="verdict-chip benign">✓ ALERT</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      )}

      {/* FLOW DETAILS MODAL */}
      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div className="domain-icon" style={{ width: '32px', height: '32px', fontSize: '1rem' }}>{selectedFlow.domain.charAt(0).toUpperCase()}</div>
                <div>
                  <h2 style={{ fontSize: '1.2rem' }}>{selectedFlow.domain}</h2>
                  <span className={`verdict-chip ${selectedFlow.prediction === 'Malicious' ? 'malicious' : 'benign'}`} style={{ marginTop: '2px', display: 'inline-block' }}>
                    {selectedFlow.prediction === 'Malicious' ? 'High Risk' : 'Verified Safe'}
                  </span>
                </div>
              </div>
              <button className="theme-toggle" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            
            {/* Beacon Analysis in Modal */}
            {selectedFlow.beacon_analysis && selectedFlow.beacon_analysis.beacon_score > 0 && (
              <div className="beacon-modal-banner" style={{ background: selectedFlow.beacon_analysis.verdict === 'BEACON' ? 'rgba(244,63,94,0.1)' : 'rgba(245,158,11,0.1)', border: `1px solid ${selectedFlow.beacon_analysis.verdict === 'BEACON' ? 'var(--danger)' : 'var(--warning)'}`, borderRadius: '6px', padding: '0.75rem', marginBottom: '1rem' }}>
                <div style={{ fontWeight: 700, marginBottom: '0.3rem', color: selectedFlow.beacon_analysis.verdict === 'BEACON' ? 'var(--danger)' : 'var(--warning)' }}>
                  🎯 C2 Beacon Score: {selectedFlow.beacon_analysis.beacon_score}/100 — {selectedFlow.beacon_analysis.verdict}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                  {(selectedFlow.beacon_analysis.signals_triggered || []).map((s, i) => (
                    <span key={i} className="signal-tag">{s.replace(/_/g, ' ')}</span>
                  ))}
                </div>
              </div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', marginBottom: '0.3rem' }}>Traffic Signature (JA3/TLS)</label>
              <div style={{ padding: '0.5rem', background: 'var(--input-bg)', borderRadius: '4px', fontSize: '0.75rem' }}>
                <code className="mono">{selectedFlow.ja3 || 'No signature captured'}</code>
              </div>
            </div>

            <label style={{ display: 'block', marginBottom: '0.3rem' }}>Internal Analysis Factors</label>
            <div className="features-mini">
              {Object.entries(selectedFlow.ml_features || {}).map(([key, value]) => (
                <div key={key} className="feature-box">
                  <div className="f-key">{key}</div>
                  <div className="f-val">{typeof value === 'number' ? value.toFixed(3) : value}</div>
                </div>
              ))}
            </div>
            
            <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              Verified via Smart Logic & Multi-Layer Behavioral Checks
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
