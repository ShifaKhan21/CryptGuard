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
  });

  const [selectedFlow, setSelectedFlow] = useState(null);
  const [showModal, setShowModal] = useState(false);

  const [error, setError] = useState(null);
  const pollInterval = useRef(null);

  // Fetch interfaces on mount
  useEffect(() => {
    fetchInterfaces();
  }, []);

  // Poll for stats when capturing
  useEffect(() => {
    if (isCapturing) {
      pollInterval.current = setInterval(fetchStats, 2000);
    } else {
      if (pollInterval.current) clearInterval(pollInterval.current);
    }
    
    return () => {
      if (pollInterval.current) clearInterval(pollInterval.current);
    };
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
        // Auto-select first interface implicitly
        setSelectedInterface('1'); 
      }
      setError(null);
    } catch (err) {
      setError("Failed to connect to DPI API Server. Is it running on port 8081?");
      console.error(err);
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
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ interface_idx: parseInt(selectedInterface) })
      });
      setIsCapturing(true);
      setError(null);
      // Immediately fetch stats
      fetchStats();
    } catch (err) {
      setError("Failed to start capture");
      console.error(err);
    }
  };

  const handleStopCapture = async () => {
    try {
      await fetch(`${API_BASE_URL}/stop`, {
        method: 'POST'
      });
      setIsCapturing(false);
      setError(null);
    } catch (err) {
      setError("Failed to stop capture");
      console.error(err);
    }
  };

  return (
    <div className="app-container">
      <header>
        <div className="brand">
          <div className="logo-icon">CG</div>
          <h1>CryptGuard DPI</h1>
        </div>
        
        <div className="status-badge">
          <div className={`status-dot ${!isCapturing ? 'inactive' : ''}`}></div>
          {isCapturing ? 'Monitoring Live Traffic' : 'System Idle'}
        </div>
      </header>

      {error && (
        <div style={{ background: 'rgba(255, 76, 76, 0.1)', color: '#ff4c4c', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', border: '1px solid rgba(255, 76, 76, 0.3)' }}>
          {error}
        </div>
      )}

      <section className="glass-panel controls-section">
        <div className="control-group">
          <label htmlFor="interface-select">Network Interface</label>
          <select 
            id="interface-select" 
            value={selectedInterface} 
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isCapturing}
          >
            <option value="" disabled>Select an interface...</option>
            {interfaces.map((iface, idx) => (
               <option key={idx} value={idx + 1}>{iface}</option>
            ))}
          </select>
        </div>
        
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {!isCapturing ? (
            <button 
              className="btn-primary" 
              onClick={handleStartCapture}
              disabled={!selectedInterface}
            >
              Start Inspection
            </button>
          ) : (
            <button 
              className="btn-danger" 
              onClick={handleStopCapture}
            >
              Stop Capture
            </button>
          )}
        </div>
      </section>

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

      <section className="glass-panel scoreboard-container">
        <div className="scoreboard-header">
          <h2>Top Network Destinations</h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Detected via SNI/DNS Inspection
          </span>
        </div>

        {stats.domains.length === 0 ? (
           <div className="empty-state">
             {isCapturing ? (
               <>
                 <div className="status-dot" style={{ margin: '0 auto 1rem', width: '12px', height: '12px' }}></div>
                 <p>Listening for traffic... Open a browser and visit some websites.</p>
               </>
             ) : (
               <p>No traffic data available. Select an interface and start the inspection.</p>
             )}
           </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Destination Domain</th>
                <th>Application Category</th>
                <th>ML Features</th>
                <th style={{ textAlign: 'right' }}>Connection Hits</th>
              </tr>
            </thead>
            <tbody>
              {stats.domains.map((item, index) => (
                <tr key={index}>
                  <td className="domain-cell">
                    <div className="domain-icon">{item.domain.charAt(0).toUpperCase()}</div>
                    {item.domain}
                  </td>
                  <td>
                    <span className="category-badge">{item.category}</span>
                  </td>
                  <td>
                    <button 
                      className="btn-primary" 
                      style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                      onClick={() => {
                        setSelectedFlow(item);
                        setShowModal(true);
                      }}
                      disabled={Object.keys(item.ml_features || {}).length === 0}
                    >
                      {Object.keys(item.ml_features || {}).length > 0 ? "View ML Stats" : "Extracting..."}
                    </button>
                  </td>
                  <td className="hits-cell" style={{ textAlign: 'right' }}>
                    {item.hits.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content glass-panel" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>ML Features: {selectedFlow.domain}</h2>
              <button className="close-btn" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <div className="features-grid">
                {Object.entries(selectedFlow.ml_features || {}).map(([key, value]) => (
                  <div key={key} className="feature-item">
                    <span className="feature-key">{key}</span>
                    <span className="feature-value">
                      {typeof value === 'number' ? 
                        (key.toLowerCase().includes('iat') || key.toLowerCase().includes('duration') ? value.toFixed(6) : value.toLocaleString()) 
                        : value}
                    </span>
                  </div>
                ))}
              </div>
              {Object.keys(selectedFlow.ml_features || {}).length === 0 && (
                <p style={{ textAlign: 'center', opacity: 0.7 }}>No ML features extracted for this flow yet.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
