import { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE_URL = 'http://localhost:8081/api';

function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  
  const [stats, setStats] = useState({
    domains: [],
    total_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0,
  });

  const [selectedFlow, setSelectedFlow] = useState(null);
  const [showModal, setShowModal] = useState(false);

  const [error, setError] = useState(null);
  const pollInterval = useRef(null);

  useEffect(() => {
    document.body.className = theme === 'light' ? 'light-theme' : '';
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    fetchInterfaces();
  }, []);

  useEffect(() => {
    if (isCapturing) {
      pollInterval.current = setInterval(fetchStats, 2000);
    } else {
      if (pollInterval.current) clearInterval(pollInterval.current);
    }
    return () => { if (pollInterval.current) clearInterval(pollInterval.current); };
  }, [isCapturing]);

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
    } catch (err) {
      setError("DPI API Offline. Connect to explorer.");
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/stats`);
      const data = await res.json();
      setStats(data);
    } catch (err) { console.error(err); }
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
    } catch (err) { setError("Capture failed."); }
  };

  const handleStopCapture = async () => {
    try {
      await fetch(`${API_BASE_URL}/stop`, { method: 'POST' });
      setIsCapturing(false);
    } catch (err) { setError("Shutdown failed."); }
  };

  const handleBlockProcess = async (pid, processName) => {
    if (!window.confirm(`Terminate ${processName} (PID: ${pid})?`)) return;
    try {
      const res = await fetch(`${API_BASE_URL}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      const data = await res.json();
      if (data.status === "success") fetchStats();
      else alert(data.message);
    } catch (err) { alert(err.message); }
  };

  return (
    <div className="app-container">
      <header>
        <div className="brand">
          <div className="logo-icon">CG</div>
          <h1>CryptGuard</h1>
        </div>
        
        <div className="header-actions">
           <button className="theme-toggle" onClick={toggleTheme}>
             {theme === 'dark' ? '☀️' : '🌙'}
           </button>
           <div className="status-badge">
             <div className={`status-dot ${!isCapturing ? 'inactive' : ''}`}></div>
             {isCapturing ? 'Monitoring' : 'Idle'}
           </div>
        </div>
      </header>

      {error && <div className="glass-panel" style={{ color: 'var(--danger)', marginBottom: '1rem', padding: '0.75rem' }}>⚠️ {error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
        <section className="glass-panel" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <div className="control-group" style={{ flex: 1 }}>
            <label>Interface</label>
            <select value={selectedInterface} onChange={(e) => setSelectedInterface(e.target.value)} disabled={isCapturing} style={{ width: '100%' }}>
              <option value="" disabled>Select adapter...</option>
              {interfaces.map((iface, idx) => <option key={idx} value={idx + 1}>{iface}</option>)}
            </select>
          </div>
          <button className={isCapturing ? "btn-danger" : "btn-primary"} onClick={isCapturing ? handleStopCapture : handleStartCapture} disabled={!selectedInterface}>
            {isCapturing ? 'Stop' : 'Start'}
          </button>
        </section>

        <div className="stats-grid" style={{ gridTemplateColumns: '1fr 1fr', marginBottom: 0 }}>
          <div className="glass-panel stat-card">
            <span className="stat-label">Packets</span>
            <span className="stat-value">{stats.total_packets.toLocaleString()}</span>
          </div>
          <div className="glass-panel stat-card">
             <span className="stat-label">Blocks</span>
             <span className="stat-value" style={{ color: 'var(--danger)' }}>{stats.dropped_packets.toLocaleString()}</span>
          </div>
        </div>
      </div>

      <section className="glass-panel scoreboard-container">
        <div className="scoreboard-header">
          <h2>Network Traffic Monitor</h2>
        </div>

        <div className="table-wrapper">
          {stats.domains.length === 0 ? (
             <div className="empty-state" style={{ padding: '2rem' }}>
               <p>{isCapturing ? 'Scanning flows...' : 'Select interface to begin.'}</p>
             </div>
          ) : (
             <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Service</th>
                  <th>Cat.</th>
                  <th>Risk</th>
                  <th>JA3</th>
                  <th>AI Verdict</th>
                  <th style={{ textAlign: 'right' }}>Hits</th>
                  <th style={{ textAlign: 'center' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {stats.domains.filter(item => !item.domain.includes('Local PC')).map((item, index) => (
                  <tr key={index}>
                    <td className="domain-cell">
                      <div className="domain-icon">{item.domain.charAt(0).toUpperCase()}</div>
                      <strong>{item.domain}</strong>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: 600 }}>{item.process?.name || 'Unknown'}</span>
                        <span style={{ fontSize: '0.65rem', opacity: 0.6 }}>PID: {item.process?.pid || '-'}</span>
                      </div>
                    </td>
                    <td><span className="category-badge">{item.category}</span></td>
                    <td>
                      <div className="risk-meter-container">
                        <div className="risk-meter-fill" style={{ width: `${item.risk_score}%`, background: item.risk_score > 70 ? 'var(--danger)' : '#f59e0b' }} />
                      </div>
                    </td>
                    <td><code style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{item.ja3?.substring(0, 8) || 'N/A'}</code></td>
                    <td>
                      <span className={`verdict-badge ${item.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>{item.prediction}</span>
                    </td>
                    <td className="hits-cell" style={{ textAlign: 'right' }}>{item.hits}</td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'center' }}>
                        <button className="btn-primary-table" onClick={() => { setSelectedFlow(item); setShowModal(true); }}>Inspect</button>
                        {item.prediction === 'Malicious' && item.process?.pid > 0 && (
                          <button className="btn-danger-table" onClick={() => handleBlockProcess(item.process.pid, item.process.name)}>Block</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <div className="domain-icon" style={{ width: '40px', height: '40px', fontSize: '1.2rem' }}>{selectedFlow.domain.charAt(0).toUpperCase()}</div>
                <div>
                  <h2 style={{ margin: 0 }}>{selectedFlow.domain}</h2>
                  <span className={`verdict-badge ${selectedFlow.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>{selectedFlow.prediction}</span>
                </div>
              </div>
              <button className="theme-toggle" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            
            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', marginBottom: '0.5rem' }}>TLS Fingerprint</label>
              <div style={{ padding: '0.75rem', background: 'var(--input-bg)', borderRadius: '6px', fontSize: '0.9rem' }}>
                <code>{selectedFlow.ja3 || 'No TLS captured'}</code>
              </div>
            </div>

            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Extracted Features</label>
            <div className="features-grid" style={{ maxHeight: '400px', overflowY: 'auto' }}>
              {Object.entries(selectedFlow.ml_features || {}).map(([key, value]) => (
                <div key={key} className="feature-item">
                  <div className="feature-key">{key}</div>
                  <div className="feature-value">{typeof value === 'number' ? value.toFixed(4) : value}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
