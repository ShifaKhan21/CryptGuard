import { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE_URL = 'http://localhost:8081/api';

function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  
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
      pollInterval.current = setInterval(fetchStats, 1500); // Faster polling for real-time feel
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
    } catch (err) { setError("CryptGuard Core Offline."); }
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
      </div>

      {error && <div className="glass-panel" style={{ color: 'var(--danger)', marginBottom: '0.75rem', padding: '0.5rem', fontSize: '0.75rem' }}>⚠️ {error}</div>}

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
                  <th style={{ textAlign: 'right' }}>Hits</th>
                  <th style={{ textAlign: 'center' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {stats.domains.map((item, index) => (
                  <tr key={index}>
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
