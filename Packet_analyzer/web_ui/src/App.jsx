import { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE_URL = 'http://localhost:8081/api';

// Sparkline removed per user request

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
      pollInterval.current = setInterval(() => {
        fetchStats();
      }, 1000);
    } else {
      if (pollInterval.current) clearInterval(pollInterval.current);
    }
    return () => { if (pollInterval.current) clearInterval(pollInterval.current); };
  }, [isCapturing]);

  const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark');

  const fetchInterfaces = async () => {
    try {
      console.log(`[DEBUG] Requesting interfaces from: ${API_BASE_URL}/interfaces`);
      const res = await fetch(`${API_BASE_URL}/interfaces`);
      if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
      const data = await res.json();
      console.log(`[DEBUG] Received interfaces:`, data.interfaces);
      setInterfaces(data.interfaces || []);
      if (data.is_capturing) {
        setIsCapturing(true);
        setSelectedInterface(data.selected);
      }
    } catch (err) { 
      console.error("CryptGuard Backend Connectivity Error:", err); 
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
    } catch (err) { console.error("Startup failed."); }
  };

  const handleStopCapture = async () => {
    try {
      await fetch(`${API_BASE_URL}/stop`, { method: 'POST' });
      setIsCapturing(false);
    } catch (err) { console.error("Stopped."); }
  };


  return (
    <div className="app-container">
      <header className="glass-panel">
        <div className="brand">
          <div className="logo-icon">CG</div>
          <div style={{display:'flex', flexDirection:'column'}}>
            <h1 style={{fontSize:'1.2rem'}}>CryptGuard <span style={{color:'var(--text-secondary)', fontWeight:400, fontSize:'1rem'}}>| Real-Time Traffic</span></h1>
          </div>
        </div>
        
        <div className="header-actions">
           <div className={`status-badge ${isCapturing ? 'scanning' : ''}`}>
             <span className="dot"></span> {isCapturing ? 'Scanning' : 'Standby'}
           </div>
           <button className="theme-toggle" onClick={toggleTheme}>
             {theme === 'dark' ? '☀️' : '🌙'}
           </button>
        </div>
      </header>

      <main className="dashboard-content">
        <div className="top-dashboard-grid">
          <section className="glass-panel adapter-card">
            <div className="section-header">
              <span className="label">NETWORK ADAPTER</span>
              <button className="refresh-btn" onClick={fetchInterfaces} title="Refresh Interfaces">
                🔄
              </button>
            </div>
            {!isCapturing ? (
              <select 
                className="interface-select"
                value={selectedInterface || ""} 
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={isCapturing}
              >
                <option value="" disabled>Select Interface...</option>
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.description}
                  </option>
                ))}
              </select>
            ) : (
              <div className="active-interface-display">
                <div className="interface-name">{selectedInterface} (Active)</div>
              </div>
            )}
            <div className="control-group">
              <button 
                className={isCapturing ? "btn-danger" : "btn-primary"}
                onClick={isCapturing ? handleStopCapture : handleStartCapture}
              >
                {isCapturing ? "Terminate Capture" : "Initialize Stream"}
              </button>
            </div>
          </section>

          <section className="glass-panel stat-card">
            <label>Packets Inspected</label>
            <div className="stat-val">{stats.total_packets.toLocaleString()}</div>
          </section>

          <section className="glass-panel stat-card alert">
            <label>Security Blocks</label>
            <div className="stat-val danger">{stats.dropped_packets.toLocaleString()}</div>
          </section>
        </div>

        <section className="table-section glass-panel">
          <div className="table-header">
            <div>
              <h2 style={{fontSize:'1.4rem', color:'var(--text-primary)'}}>Real-Time Traffic Stream</h2>
              <p style={{fontSize:'0.75rem', color:'var(--text-secondary)', marginTop:'4px'}}>Deep Packet Inspection (DPI) powered by Random Forest Classifier</p>
            </div>
            <div className="flow-count">
              <span style={{color:'var(--accent-color)', fontWeight:800}}>{stats.domains.length}</span> ACTIVE FLOWS
            </div>
          </div>
          
          <div className="table-container">
            <table>
              <thead>
                <tr>
                   <th>Target Destination</th>
                   <th>Service / Process</th>
                   <th>Category</th>
                   <th style={{textAlign:'center'}}>Prod. Score</th>
                   <th>TLS JA3</th>
                   <th>AI Verdict</th>
                   <th>Hits</th>
                   <th style={{textAlign:'right'}}>Mitigation</th>
                </tr>
              </thead>
              <tbody>
                {stats.domains.map((item, index) => (
                  <tr key={item.domain} className={item.prediction === 'Malicious' ? 'blink-danger' : ''}>
                    <td>
                      <div className="domain-info">
                        <div className={`logo-icon ${item.domain.charAt(0).toUpperCase()}`} style={{background:'rgba(47, 129, 247, 0.1)', color:'var(--accent-color)', border:'1px solid var(--panel-border)'}}>{item.domain.charAt(0).toUpperCase()}</div>
                        <strong>{item.domain}</strong>
                      </div>
                    </td>
                    <td>
                      <div style={{display:'flex', flexDirection:'column'}}>
                        <span style={{fontWeight:600}}>{item.process.name}</span>
                        <span style={{fontSize:'0.65rem', color:'var(--text-muted)'}}>PID: {item.process.pid || '-'}</span>
                      </div>
                    </td>
                    <td><span className="category-tag">{item.domain.includes('.') ? 'HTTPS' : 'DNS'}</span></td>
                    <td style={{textAlign:'center'}}>
                       <div className="risk-bar-mini">
                          <div className="risk-fill-mini" style={{width: `${item.risk_score}%`, background: item.risk_score > 70 ? 'var(--danger)' : 'var(--warning)'}}></div>
                       </div>
                    </td>
                    <td><span style={{fontSize:'0.65rem', color:'var(--text-muted)'}}>{item.ja3 ? 'SIGNED' : 'N/A'}</span></td>
                    <td>
                      <span className={`verdict-chip ${item.prediction.toLowerCase()}`}>
                        {item.prediction}
                      </span>
                    </td>
                    <td style={{fontWeight:800}}>{item.hits}</td>
                    <td style={{textAlign:'right'}}>
                      <button className="btn-inspect" onClick={() => { setSelectedFlow(item); setShowModal(true); }}>Inspect</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content glass-panel" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 style={{fontSize:'1.5rem', fontWeight:800}}>Forensic Inquiry: {selectedFlow.domain}</h3>
                <span style={{fontSize:'0.7rem', color:'var(--text-muted)', fontWeight:800}}>FLOW UID: {selectedFlow.id || 'N/A'}</span>
              </div>
              <button className="theme-toggle" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            
             <div className="glass-panel" style={{display:'flex', flexDirection:'column', justifyContent:'center'}}>
               <label>Risk Aggregation</label>
               <div style={{display:'flex', alignItems:'baseline', gap:'0.5rem', marginTop:'0.5rem'}}>
                  <div style={{fontSize:'3rem', fontWeight:900, color: selectedFlow.risk_score >= 70 ? 'var(--danger)' : 'var(--success)', lineHeight:1}}>
                    {selectedFlow.risk_score}%
                  </div>
                  <div style={{fontSize:'0.8rem', fontWeight:800, color:'var(--text-muted)', textTransform:'uppercase'}}>Composite Score</div>
               </div>
             </div>

            <div style={{display:'grid', gridTemplateColumns:'repeat(3, 1fr)', gap:'1rem', marginBottom:'1.5rem'}}>
               <div className="glass-panel">
                  <label>External Threat Intel</label>
                  <div style={{fontWeight:800, marginTop:'0.5rem'}}>{selectedFlow.threat_intel?.verdict || 'CLEAN'}</div>
               </div>
               <div className="glass-panel">
                  <label>Heuristic Logic</label>
                  <div style={{fontSize:'0.75rem', fontWeight:700, marginTop:'0.5rem', color:'var(--text-secondary)'}}>{selectedFlow.reason}</div>
               </div>
            </div>

            <div className="glass-panel" style={{background:'rgba(0,0,0,0.3)', border:'1px dashed var(--panel-border)', marginBottom:'1.5rem'}}>
               <label style={{color:'var(--accent-color)'}}>Forensic Flow Features (Live Capture)</label>
               <div className="features-mini">
                 {selectedFlow.ml_features && Object.entries(selectedFlow.ml_features).map(([k, v]) => (
                   <div key={k} className="feature-box">
                     <div className="f-key">{k}</div>
                     <div className="f-val">{typeof v === 'number' ? v.toFixed(4) : v}</div>
                   </div>
                 ))}
                 {/* Explicitly show model labels if they aren't in ml_features */}
                 {!selectedFlow.ml_features?.Label && (
                    <div className="feature-box" style={{borderLeft:'2px solid var(--accent-color)'}}>
                      <div className="f-key">Label</div>
                      <div className="f-val">{selectedFlow.prediction}</div>
                    </div>
                 )}
                 {!selectedFlow.ml_features?.ClassLabel && (
                    <div className="feature-box" style={{borderLeft:'2px solid var(--accent-color)'}}>
                      <div className="f-key">ClassLabel</div>
                      <div className="f-val">{selectedFlow.category}</div>
                    </div>
                 )}
               </div>
            </div>

            <div className="glass-panel" style={{background:'rgba(0,0,0,0.3)', border:'1px dashed var(--panel-border)'}}>
               <label style={{color:'var(--accent-color)'}}>JA3 TLS Fingerprint</label>
               <div className="mono" style={{fontSize:'0.85rem', marginTop:'0.5rem', wordBreak:'break-all'}}>{selectedFlow.ja3 || 'PLAINTEXT / NO SIGNATURE'}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
