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

  const handleBlockProcess = async (pid, processName) => {
    if (!window.confirm(`Are you sure you want to terminate process "${processName}" (PID: ${pid})? This will stop the network threat.`)) {
      return;
    }
    
    try {
      const res = await fetch(`${API_BASE_URL}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      const data = await res.json();
      if (data.status === "success") {
        alert(`Successfully terminated ${processName}.`);
        fetchStats();
      } else {
        alert(`Failed to block process: ${data.message || 'Unknown error'}`);
      }
    } catch (err) {
      alert(`Error blocking process: ${err.message}`);
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
          <h2>Top Real-Time Destinations</h2>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Inspected via ML DPI Engine
          </span>
        </div>

        {stats.domains.length === 0 ? (
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
           <table>
            <thead>
              <tr>
                <th>Official Destination</th>
                <th>Service (PID)</th>
                <th>Category</th>
                <th>Productivity Score</th>
                <th>AI Verdict</th>
                <th style={{ textAlign: 'right' }}>Hits</th>
                <th style={{ textAlign: 'center' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {stats.domains
                .filter(item => !item.domain.includes('Local PC'))
                .map((item, index) => (
                <tr key={index}>
                  <td className="domain-cell">
                    <div className="domain-icon">{item.domain.charAt(0).toUpperCase()}</div>
                    {item.domain}
                  </td>
                  <td className="process-cell">
                    <div className="process-info">
                      <span className="process-name">{item.process?.name || 'Searching...'}</span>
                      <span className="process-pid">PID: {item.process?.pid || '-'}</span>
                    </div>
                  </td>
                  <td>
                    <span className="category-badge" style={{
                      backgroundColor: item.category === 'Unacademy' ? 'rgba(4, 215, 114, 0.2)' : 
                                      item.category === 'Netflix' ? 'rgba(229, 9, 20, 0.2)' :
                                      item.category === 'Twitter/X' ? 'rgba(29, 161, 242, 0.2)' : 'rgba(255,255,255,0.1)'
                    }}>
                      {item.category}
                    </span>
                  </td>
                  <td>
                    <div className="risk-meter-container">
                      <div 
                        className="risk-meter-fill" 
                        style={{ 
                          width: `${item.risk_score}%`,
                          background: item.risk_score > 70 ? '#ff4c4c' : item.risk_score > 30 ? '#ffcc00' : '#04d772'
                        }}
                      />
                      <span className="risk-value">{item.risk_score}%</span>
                    </div>
                  </td>
                  <td>
                    <span className={`verdict-badge ${item.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>
                      {item.prediction}
                    </span>
                    {item.beacon_detected && (
                      <span className="verdict-badge malicious" style={{ display: 'block', marginTop: '4px', fontSize: '0.6rem' }}>
                        BEACON DETECTED
                      </span>
                    )}
                  </td>
                  <td className="hits-cell" style={{ textAlign: 'right', fontWeight: 'bold' }}>
                    {item.hits.toLocaleString()}
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
                      <button 
                        className="btn-primary" 
                        style={{ padding: '6px 10px', fontSize: '0.65rem', textTransform: 'uppercase', fontWeight: '700' }}
                        onClick={() => {
                          setSelectedFlow(item);
                          setShowModal(true);
                        }}
                        disabled={Object.keys(item.ml_features || {}).length === 0}
                      >
                        {Object.keys(item.ml_features || {}).length > 0 ? "Inspect" : "Scanning"}
                      </button>
                      
                      {item.prediction === 'Malicious' && item.process?.pid > 0 && (
                        <button 
                          className="btn-danger" 
                          style={{ padding: '6px 10px', fontSize: '0.65rem', textTransform: 'uppercase', fontWeight: '700' }}
                          onClick={() => handleBlockProcess(item.process.pid, item.process.name)}
                        >
                          Block
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content glass-panel" style={{ maxWidth: '900px', width: '90%' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                <div className="domain-icon" style={{ width: '48px', height: '48px', fontSize: '1.4rem' }}>
                  {selectedFlow.domain.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.4rem' }}>{selectedFlow.domain}</h2>
                  <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginTop: '4px' }}>
                    <span className={`verdict-badge ${selectedFlow.prediction === 'Malicious' ? 'malicious' : 'benign'}`}>
                      {selectedFlow.prediction}
                    </span>
                    <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                      Productivity Score: <strong style={{ color: selectedFlow.risk_score > 50 ? '#ff4c4c' : '#04d772' }}>{selectedFlow.risk_score}%</strong>
                    </span>
                  </div>
                </div>
              </div>
              <button className="close-btn" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            <div className="modal-body" style={{ maxHeight: '70vh', padding: '20px' }}>
              <div className="features-grid">
                {Object.entries(selectedFlow.ml_features || {}).map(([key, value]) => (
                  <div key={key} className="feature-item" style={{ 
                    background: 'rgba(255,255,255,0.03)', 
                    border: '1px solid rgba(255,255,255,0.05)',
                    padding: '12px',
                    borderRadius: '8px'
                  }}>
                    <div className="feature-key" style={{ 
                      fontSize: '0.65rem', 
                      textTransform: 'uppercase', 
                      letterSpacing: '0.5px',
                      color: 'var(--secondary-color)',
                      marginBottom: '4px'
                    }}>
                      {key}
                    </div>
                    <div className="feature-value" style={{ 
                      fontSize: '1.1rem', 
                      fontWeight: '700',
                      fontFamily: '"JetBrains Mono", monospace'
                    }}>
                      {typeof value === 'number' ? 
                        (key.toLowerCase().includes('iat') || key.toLowerCase().includes('duration') || key.toLowerCase().includes('std') || key.toLowerCase().includes('mean') ? 
                          value.toLocaleString(undefined, { minimumFractionDigits: 4, maximumFractionDigits: 6 }) : 
                          value.toLocaleString()) 
                        : value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-footer" style={{ padding: '15px', borderTop: '1px solid rgba(255,255,255,0.1)', textAlign: 'center' }}>
                <span style={{ fontSize: '0.75rem', opacity: 0.5 }}>All features extracted in real-time via CryptGuard DPI Multi-Threaded Engine</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
