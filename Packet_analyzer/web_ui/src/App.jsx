import React, { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE_URL = 'http://127.0.0.1:8081/api';

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
  const [expandedRows, setExpandedRows] = useState({});

  const [error, setError] = useState(null);
  const ws = useRef(null);

  // Fetch interfaces on mount
  useEffect(() => {
    fetchInterfaces();
    return () => {
      if (ws.current) ws.current.close();
    };
  }, []);

  // WebSocket connection when capturing
  useEffect(() => {
    if (isCapturing) {
      connectWebSocket();
    } else {
      if (ws.current) ws.current.close();
    }
    
    return () => {
      if (ws.current) ws.current.close();
    };
  }, [isCapturing]);

  const connectWebSocket = () => {
    if (ws.current) ws.current.close();
    
    const wsUrl = API_BASE_URL.replace('http', 'ws').replace('/api', '/ws/stats');
    ws.current = new WebSocket(wsUrl);
    
    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setStats(prev => ({
        ...prev,
        total_packets: data.total_packets,
        forwarded_packets: data.forwarded,
        dropped_packets: data.dropped,
        domains: data.top_destinations
      }));
    };
    
    ws.current.onerror = (err) => {
      console.error("WebSocket error:", err);
    };
    
    ws.current.onclose = () => {
      console.log("WebSocket connection closed");
    };
  };

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

  const toggleRow = (domain) => {
    setExpandedRows(prev => ({
      ...prev,
      [domain]: !prev[domain]
    }));
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
                <th>ML Classification</th>
                <th>Confidence</th>
                <th>Last Seen</th>
                <th style={{ textAlign: 'right' }}>Connection Hits</th>
              </tr>
            </thead>
            <tbody>
              {stats.domains.map((item, index) => (
                <React.Fragment key={index}>
                  <tr onClick={() => toggleRow(item.domain)} style={{ cursor: 'pointer' }} title="Click to view raw ML Features">
                    <td className="domain-cell">
                      <div className="domain-icon">{item.domain.charAt(0).toUpperCase()}</div>
                      {item.domain}
                    </td>
                    <td>
                      <span className="category-badge">{item.category}</span>
                    </td>
                    <td>
                      <span className={`status-badge ${item.ml_prediction === 'MALWARE' ? 'danger' : 'safe'}`} style={{ 
                        padding: '4px 8px', borderRadius: '4px', fontSize: '0.85rem', fontWeight: 'bold',
                        backgroundColor: item.ml_prediction === 'MALWARE' ? 'rgba(255, 76, 76, 0.15)' : 'rgba(76, 255, 120, 0.15)',
                        color: item.ml_prediction === 'MALWARE' ? '#ff4c4c' : '#4cff78'
                      }}>
                        {item.ml_prediction || 'BENIGN'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                      {item.ml_confidence !== "--" ? `${item.ml_confidence}%` : '--%'}
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                      {item.last_seen_time || '--:--:--'}
                    </td>
                    <td className="hits-cell" style={{ textAlign: 'right' }}>
                      {item.hits.toLocaleString()}
                    </td>
                  </tr>
                  {expandedRows[item.domain] && item.extended_features && Object.keys(item.extended_features).length > 0 && (
                    <tr className="expanded-features-row">
                      <td colSpan="6" style={{ padding: '0', backgroundColor: 'var(--bg-elevated)', borderBottom: '1px solid var(--border-color)' }}>
                        <div style={{ padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          <div style={{ gridColumn: '1 / -1', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px', marginBottom: '8px', color: 'var(--text-primary)', fontWeight: 'bold' }}>
                            ML Flow Features (CICFlowMeter)
                          </div>
                          {Object.entries(item.extended_features).filter(([_, v]) => v && v !== '0' && v !== '0.0').slice(0, 16).map(([key, value]) => (
                             <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', backgroundColor: 'rgba(255,255,255,0.02)', borderRadius: '4px' }}>
                               <span style={{ opacity: 0.8 }}>{key}:</span>
                               <span style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{value}</span>
                             </div>
                          ))}
                          {Object.keys(item.extended_features).length > 20 && (
                             <div style={{ gridColumn: '1 / -1', textAlign: 'center', paddingTop: '8px', fontSize: '0.75rem', opacity: 0.6 }}>
                               ... and {Object.keys(item.extended_features).length - 16} more feature dimensions (filtered empty values)
                             </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

export default App;
