import { useState, useEffect, useRef, useCallback } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, Legend
} from 'recharts';
import {
  Shield, ShieldAlert, Wifi, WifiOff, Sun, Moon, Eye, Activity, Radio,
  Globe, Search, Crosshair, AlertTriangle, Ban, ChevronRight, X,
  Zap, Lock, Server, MonitorSmartphone
} from 'lucide-react';
import './index.css';

const API = 'http://localhost:8081/api';

const PIE_COLORS = ['#34d399', '#f43f5e', '#fbbf24', '#3b82f6'];

/* ────────────────────────── Custom Chart Tooltip ───────────────────────── */
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color, fontSize: '12px' }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   APP
   ══════════════════════════════════════════════════════════════════════════ */
export default function App() {
  /* ── State ─────────────────────────────────────────────────────────────── */
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('cg-theme') || 'dark');
  const [activeTab, setActiveTab] = useState('traffic');
  const [intelHistory, setIntelHistory] = useState([]);
  const [dnsHistory, setDnsHistory] = useState([]);
  const [stats, setStats] = useState({ domains: [], total_packets: 0, forwarded_packets: 0, dropped_packets: 0 });
  const [beaconAlerts, setBeaconAlerts] = useState([]);
  const [beaconStats, setBeaconStats] = useState({ total_alerts: 0, beacon_count: 0, suspicious_count: 0 });
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [error, setError] = useState(null);

  // Chart history data
  const [packetHistory, setPacketHistory] = useState([]);
  const lastPacketCount = useRef(0);

  const pollRef = useRef(null);
  const beaconPollRef = useRef(null);

  /* ── Theme ──────────────────────────────────────────────────────────────── */
  useEffect(() => {
    document.body.className = theme === 'light' ? 'light-mode' : '';
    localStorage.setItem('cg-theme', theme);
  }, [theme]);

  /* ── Fetch Helpers ─────────────────────────────────────────────────────── */
  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch(`${API}/interfaces`);
      const data = await res.json();
      setInterfaces(data.interfaces || []);
      if (data.is_capturing) {
        setIsCapturing(true);
        setSelectedInterface(data.selected);
      } else if (data.interfaces?.length > 0) {
        setSelectedInterface('1');
      }
      setError(null);
    } catch { setError('CryptGuard Core is offline. Start the API server.'); }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API}/stats`);
      const data = await res.json();
      setStats(data);

      // Build packet-rate history for chart
      const currentTotal = data.total_packets || 0;
      const delta = currentTotal - lastPacketCount.current;
      lastPacketCount.current = currentTotal;

      setPacketHistory(prev => {
        const now = new Date();
        const entry = {
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          packets: Math.max(0, delta),
          threats: (data.domains || []).filter(d => d.prediction === 'Malicious').length,
        };
        const updated = [...prev, entry];
        return updated.slice(-30); // Keep last 30 data points
      });
    } catch (err) { console.error(err); }
  }, []);

  const fetchBeacons = useCallback(async () => {
    try {
      const [histRes, cacheRes] = await Promise.all([
        fetch(`${API}/beacon-history`),
        fetch(`${API}/threat-cache`)
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
    } catch (err) { console.error('Beacon fetch:', err); }
  }, []);

  const fetchIntelHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API}/intel-history`);
      const data = await res.json();
      setIntelHistory(data.history || []);
    } catch (err) { console.error('Intel fetch:', err); }
  }, []);

  const fetchDNSHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API}/dns-history`);
      const data = await res.json();
      setDnsHistory(data.history || []);
    } catch (err) { console.error('DNS fetch:', err); }
  }, []);

  /* ── Polling ───────────────────────────────────────────────────────────── */
  useEffect(() => { fetchInterfaces(); }, [fetchInterfaces]);

  useEffect(() => {
    if (isCapturing) {
      pollRef.current = setInterval(fetchStats, 1500);
      beaconPollRef.current = setInterval(() => {
        fetchBeacons();
        fetchIntelHistory();
        fetchDNSHistory();
      }, 4000);
    } else {
      if (pollRef.current) clearInterval(pollRef.current);
      if (beaconPollRef.current) clearInterval(beaconPollRef.current);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      if (beaconPollRef.current) clearInterval(beaconPollRef.current);
    };
  }, [isCapturing, fetchStats, fetchBeacons, fetchIntelHistory, fetchDNSHistory]);

  // Always poll beacons (to show simulation results even when not capturing)
  useEffect(() => {
    fetchBeacons();
    fetchIntelHistory();
    const t = setInterval(() => {
      fetchBeacons();
      fetchIntelHistory();
      fetchDNSHistory();
    }, 5000);
    return () => clearInterval(t);
  }, [fetchBeacons, fetchIntelHistory, fetchDNSHistory]);

  /* ── Actions ───────────────────────────────────────────────────────────── */
  const handleStart = async () => {
    if (!selectedInterface) return;
    try {
      await fetch(`${API}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface_idx: parseInt(selectedInterface) })
      });
      setIsCapturing(true);
      setPacketHistory([]);
      lastPacketCount.current = 0;
      fetchStats();
    } catch { setError('Failed to start capture.'); }
  };

  const handleStop = async () => {
    try {
      await fetch(`${API}/stop`, { method: 'POST' });
      setIsCapturing(false);
    } catch { setError('Failed to stop capture.'); }
  };

  const handleBlock = async (pid, processName) => {
    if (!window.confirm(`Terminate process "${processName}" (PID ${pid})?`)) return;
    try {
      await fetch(`${API}/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      fetchStats();
    } catch (err) { alert(err.message); }
  };

  const handleClearCache = async () => {
    if (!window.confirm('Clear all beacon history?')) return;
    try {
      await fetch(`${API}/clear-cache`, { method: 'POST' });
      fetchBeacons();
    } catch (err) { console.error(err); }
  };

  /* ── Derived ───────────────────────────────────────────────────────────── */
  const beaconCount = beaconAlerts.filter(a => a.verdict === 'BEACON').length;
  const suspiciousCount = beaconAlerts.filter(a => a.verdict === 'SUSPICIOUS').length;
  const maliciousFlows = stats.domains.filter(d => d.prediction === 'Malicious').length;
  const safeFlows = stats.domains.filter(d => d.prediction !== 'Malicious').length;

  // Pie chart data
  const pieData = [
    { name: 'Safe', value: safeFlows || 0 },
    { name: 'Malicious', value: maliciousFlows || 0 },
    { name: 'Suspicious', value: suspiciousCount || 0 },
  ].filter(d => d.value > 0);

  /* ══════════════════════════════════════════════════════════════════════════
     RENDER
     ══════════════════════════════════════════════════════════════════════════ */
  return (
    <div className="app-shell">
      {/* ─── HEADER ──────────────────────────────────────────────────────── */}
      <header className="header">
        <div className="header-brand">
          <div className="brand-logo">
            <Shield size={18} />
          </div>
          <div className="brand-text">
            <h1>CryptGuard</h1>
            <span>Encrypted Traffic Intelligence</span>
          </div>
        </div>

        <div className="header-actions">
          <div className="privacy-badge">
            <Lock size={10} /> Zero Decryption
          </div>
          <div className={`status-indicator ${isCapturing ? 'active' : 'inactive'}`}>
            <div className={`status-dot ${isCapturing ? '' : 'off'}`} />
            {isCapturing ? 'Live Scanning' : 'Standby'}
          </div>
          <button className="btn-icon" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} title="Toggle Theme">
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>
      </header>

      {/* ─── CONTROLS BAR ────────────────────────────────────────────────── */}
      <div className="controls-bar">
        <Wifi size={14} style={{ color: 'var(--accent-cyan)' }} />
        <label>Interface</label>
        <select value={selectedInterface} onChange={e => setSelectedInterface(e.target.value)} disabled={isCapturing}>
          {interfaces.map((iface, i) => <option key={i} value={i + 1}>{iface}</option>)}
        </select>
        <button className={`btn ${isCapturing ? 'btn-danger' : 'btn-primary'}`} onClick={isCapturing ? handleStop : handleStart}>
          {isCapturing ? <><WifiOff size={14} /> Stop Capture</> : <><Zap size={14} /> Start Capture</>}
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* ─── STATS GRID ──────────────────────────────────────────────────── */}
      <div className="stats-grid">
        <div className={`stat-card ${isCapturing ? 'capturing' : ''}`} style={{ '--stat-accent': 'var(--accent-cyan)' }}>
          <div className="stat-header">
            <span className="stat-label">Packets Inspected</span>
            <div className="stat-icon"><Activity size={15} /></div>
          </div>
          <div className="stat-value">{stats.total_packets.toLocaleString()}</div>
          <div className="stat-sub">Total through DPI engine</div>
        </div>

        <div className="stat-card" style={{ '--stat-accent': 'var(--accent-green)' }}>
          <div className="stat-header">
            <span className="stat-label">Active Flows</span>
            <div className="stat-icon" style={{ background: 'rgba(52,211,153,0.08)', color: 'var(--accent-green)' }}>
              <Server size={15} />
            </div>
          </div>
          <div className="stat-value">{stats.domains.length}</div>
          <div className="stat-sub">{safeFlows} safe · {maliciousFlows} flagged</div>
        </div>

        <div className="stat-card" style={{ '--stat-accent': 'var(--accent-red)' }}>
          <div className="stat-header">
            <span className="stat-label">Blocked</span>
            <div className="stat-icon" style={{ background: 'rgba(244,63,94,0.08)', color: 'var(--accent-red)' }}>
              <Ban size={15} />
            </div>
          </div>
          <div className="stat-value" style={{ color: stats.dropped_packets > 0 ? 'var(--accent-red)' : undefined }}>
            {stats.dropped_packets.toLocaleString()}
          </div>
          <div className="stat-sub">Packets dropped</div>
        </div>

        <div
          className="stat-card clickable"
          style={{ '--stat-accent': beaconCount > 0 ? 'var(--accent-red)' : suspiciousCount > 0 ? 'var(--accent-amber)' : 'var(--accent-purple)' }}
          onClick={() => setActiveTab('beacons')}
        >
          <div className="stat-header">
            <span className="stat-label">C2 Beacons</span>
            <div className="stat-icon" style={{
              background: beaconCount > 0 ? 'rgba(244,63,94,0.08)' : 'rgba(167,139,250,0.08)',
              color: beaconCount > 0 ? 'var(--accent-red)' : 'var(--accent-purple)',
            }}>
              <Radio size={15} />
            </div>
          </div>
          <div className="stat-value" style={{
            color: beaconCount > 0 ? 'var(--accent-red)' : suspiciousCount > 0 ? 'var(--accent-amber)' : undefined
          }}>
            {beaconCount > 0 ? beaconCount : suspiciousCount > 0 ? suspiciousCount : '—'}
          </div>
          <div className="stat-sub">
            {beaconCount > 0 ? `${beaconCount} confirmed · ${suspiciousCount} suspicious` : suspiciousCount > 0 ? `${suspiciousCount} suspicious patterns` : 'No beacons detected'}
          </div>
        </div>
      </div>

      {/* ─── CHARTS ROW ──────────────────────────────────────────────────── */}
      <div className="charts-row">
        <div className="chart-card">
          <div className="chart-title">📈 Packet Rate (Live)</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={packetHistory}>
              <defs>
                <linearGradient id="gradCyan" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradRed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="packets" stroke="#22d3ee" fill="url(#gradCyan)" strokeWidth={2} name="Packets/s" dot={false} />
              <Area type="monotone" dataKey="threats" stroke="#f43f5e" fill="url(#gradRed)" strokeWidth={2} name="Threats" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <div className="chart-title">🛡️ Traffic Classification</div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={4}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  height={30}
                  formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '11px', fontWeight: 600 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 180, color: 'var(--text-muted)', fontSize: '12px' }}>
              No traffic data yet
            </div>
          )}
        </div>
      </div>

      {/* ─── TAB BAR ─────────────────────────────────────────────────────── */}
      <div className="tab-bar">
        <button className={`tab-btn ${activeTab === 'traffic' ? 'active' : ''}`} onClick={() => setActiveTab('traffic')}>
          <MonitorSmartphone size={14} /> Live Traffic
          <span className="tab-badge">{stats.domains.length}</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'beacons' ? 'active' : ''} ${beaconCount > 0 ? 'tab-danger' : suspiciousCount > 0 ? 'tab-warning' : ''}`}
          onClick={() => setActiveTab('beacons')}
        >
          <Crosshair size={14} /> C2 Beacon Alerts
          {(beaconCount + suspiciousCount) > 0 && (
            <span className={`tab-badge ${beaconCount > 0 ? 'danger' : 'warning'}`}>{beaconCount + suspiciousCount}</span>
          )}
        </button>
        <button className={`tab-btn ${activeTab === 'intel' ? 'active' : ''}`} onClick={() => setActiveTab('intel')}>
          <Globe size={14} /> Threat Intel
          {intelHistory.length > 0 && <span className="tab-badge info">{intelHistory.length}</span>}
        </button>
        <button className={`tab-btn ${activeTab === 'dns' ? 'active' : ''}`} onClick={() => setActiveTab('dns')}>
          <Search size={14} /> DNS Intelligence
          {dnsHistory.length > 0 && (
            <span className={`tab-badge ${dnsHistory.some(e => e.flags?.length > 0) ? 'warning' : 'info'}`}>{dnsHistory.length}</span>
          )}
        </button>
      </div>

      {/* ═══ TAB: LIVE TRAFFIC ═══════════════════════════════════════════ */}
      {activeTab === 'traffic' && (
        <div className="table-panel">
          <div className="table-panel-header">
            <h2><Activity size={15} /> Live Stream</h2>
            <div className="table-panel-actions">
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>
                {stats.domains.length} flows · {stats.total_packets.toLocaleString()} packets
              </span>
            </div>
          </div>

          <div className="table-scroll">
            {stats.domains.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">{isCapturing ? <Activity size={40} /> : <Shield size={40} />}</div>
                <div className="empty-title">{isCapturing ? 'Scanning Network...' : 'Ready to Scan'}</div>
                <div className="empty-desc">{isCapturing ? 'Waiting for packets to arrive...' : 'Select an interface and press Start Capture to begin analysis.'}</div>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Process</th>
                    <th>Category</th>
                    <th>Risk</th>
                    <th>Verdict</th>
                    <th>C2 Score</th>
                    <th style={{ textAlign: 'right' }}>Hits</th>
                    <th style={{ textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.domains.map((item, i) => {
                    const ba = item.beacon_analysis || {};
                    const bScore = ba.beacon_score || 0;
                    const bVerdict = ba.verdict || 'NORMAL';
                    const riskColor = item.risk_score > 70 ? 'var(--accent-red)' : item.risk_score > 30 ? 'var(--accent-amber)' : 'var(--accent-green)';

                    return (
                      <tr key={i} className={bVerdict === 'BEACON' ? 'row-beacon' : bVerdict === 'SUSPICIOUS' ? 'row-suspicious' : ''}>
                        <td>
                          <div className="domain-cell-content">
                            <div className="domain-avatar">{item.domain.charAt(0).toUpperCase()}</div>
                            <span className="domain-name">{item.domain}</span>
                          </div>
                        </td>
                        <td>
                          <div className="process-cell">
                            <span className="process-name">{item.process?.name || 'System'}</span>
                            <span className="process-pid">PID {item.process?.pid || '—'}</span>
                          </div>
                        </td>
                        <td><span className="chip chip-category">{item.category}</span></td>
                        <td>
                          <div className="risk-bar-wrap">
                            <div className="risk-bar">
                              <div className="risk-bar-fill" style={{ width: `${item.risk_score}%`, background: riskColor }} />
                            </div>
                            <span className="risk-value" style={{ color: riskColor }}>{Math.round(item.risk_score)}</span>
                          </div>
                        </td>
                        <td>
                          <span className={`chip ${item.prediction === 'Malicious' ? 'chip-unsafe' : 'chip-safe'}`}>
                            {item.prediction === 'Malicious' ? <><ShieldAlert size={11} /> Unsafe</> : <><Shield size={11} /> Safe</>}
                          </span>
                        </td>
                        <td>
                          {bScore > 0 ? (
                            <span className={`beacon-mini ${bVerdict === 'BEACON' ? 'b-danger' : 'b-warning'}`}>
                              {bVerdict === 'BEACON' ? '🔴' : '🟡'} {bScore}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>—</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '13px' }}>{item.hits}</td>
                        <td>
                          <div style={{ display: 'flex', gap: '6px', justifyContent: 'center' }}>
                            <button className="btn btn-ghost btn-sm" onClick={() => { setSelectedFlow(item); setShowModal(true); }}>
                              <Eye size={12} /> Details
                            </button>
                            {item.prediction === 'Malicious' && item.process?.pid > 0 && (
                              <button className="btn btn-danger btn-sm" onClick={() => handleBlock(item.process.pid, item.process.name)}>
                                <Ban size={12} /> Kill
                              </button>
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
        </div>
      )}

      {/* ═══ TAB: C2 BEACONS ═════════════════════════════════════════════ */}
      {activeTab === 'beacons' && (
        <div className="table-panel">
          <div className="table-panel-header">
            <h2><Crosshair size={15} /> C2 Beacon Alerts</h2>
            <div className="table-panel-actions">
              <span className="pill pill-danger">🔴 BEACON: {beaconCount}</span>
              <span className="pill pill-warning">🟡 SUSPICIOUS: {suspiciousCount}</span>
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', fontWeight: 600 }}>
                {beaconStats.total_records?.toLocaleString()} records
              </span>
              <button className="btn btn-ghost btn-sm" onClick={handleClearCache}>Clear</button>
            </div>
          </div>

          <div className="signals-legend">
            <div className="signal-legend-item">📡 FFT Periodicity <span className="signal-desc">— Regular timing intervals</span></div>
            <div className="signal-legend-item">🎯 Destination Lock <span className="signal-desc">— Single IP target</span></div>
            <div className="signal-legend-item">📦 Size Uniformity <span className="signal-desc">— Same-size payloads</span></div>
            <div className="signal-legend-item">🌙 Night Activity <span className="signal-desc">— 00:00–06:00 local</span></div>
          </div>

          <div className="table-scroll">
            {beaconAlerts.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon"><Shield size={40} /></div>
                <div className="empty-title">No Beacon Alerts</div>
                <div className="empty-desc">Run <code>python run_sim.py</code> to simulate C2 beaconing and test detection.</div>
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
                    <th style={{ textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {beaconAlerts.map((alert, i) => (
                    <tr key={i} className={alert.verdict === 'BEACON' ? 'row-beacon' : 'row-suspicious'}>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td><span style={{ fontWeight: 700 }}>{alert.process_name}</span></td>
                      <td><code style={{ fontSize: '12.5px', fontWeight: 600 }}>{alert.destination_ip}</code></td>
                      <td style={{ textAlign: 'center' }}>
                        <div className="score-ring" style={{ '--ring-color': alert.beacon_score >= 75 ? 'var(--accent-red)' : 'var(--accent-amber)', margin: '0 auto' }}>
                          <strong>{alert.beacon_score}</strong>
                          <span>/100</span>
                        </div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <span className={`chip ${alert.verdict === 'BEACON' ? 'chip-unsafe' : 'chip-suspicious'}`}>
                          {alert.verdict === 'BEACON' ? '🔴 BEACON' : '🟡 SUSPICIOUS'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                          {(alert.signals || []).map((sig, si) => (
                            <span key={si} className="signal-tag">{sig.replace(/_/g, ' ')}</span>
                          ))}
                        </div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        {alert.should_block
                          ? <span className="chip chip-unsafe"><Ban size={10} /> BLOCK</span>
                          : <span className="chip chip-info">ALERT</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ═══ TAB: THREAT INTEL ════════════════════════════════════════════ */}
      {activeTab === 'intel' && (
        <div className="table-panel">
          <div className="table-panel-header">
            <h2><Globe size={15} /> Threat Intelligence Cache</h2>
            <div className="table-panel-actions">
              <span className="pill pill-info">Verified IPs: {intelHistory.length}</span>
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Powered by AbuseIPDB</span>
            </div>
          </div>

          <div className="table-scroll">
            {intelHistory.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon"><Globe size={40} /></div>
                <div className="empty-title">No Intelligence Data</div>
                <div className="empty-desc">IP reputation checks will appear once external traffic is detected and verified.</div>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Provider</th>
                    <th style={{ textAlign: 'center' }}>Abuse Score</th>
                    <th>Risk Level</th>
                    <th>Last Verified</th>
                  </tr>
                </thead>
                <tbody>
                  {intelHistory.map((item, i) => (
                    <tr key={i}>
                      <td><code style={{ fontSize: '13px', fontWeight: 700 }}>{item.ip}</code></td>
                      <td><span className="chip chip-info">{item.provider}</span></td>
                      <td style={{ textAlign: 'center' }}>
                        <div className="score-ring" style={{
                          '--ring-color': item.score > 50 ? 'var(--accent-red)' : item.score > 0 ? 'var(--accent-amber)' : 'var(--accent-green)',
                          margin: '0 auto'
                        }}>
                          <strong>{item.score}</strong>
                          <span>/100</span>
                        </div>
                      </td>
                      <td>
                        <span className={`chip ${item.score > 50 ? 'chip-unsafe' : item.score > 0 ? 'chip-suspicious' : 'chip-safe'}`}>
                          {item.score > 50 ? 'BLACKLISTED' : item.score > 0 ? 'SUSPICIOUS' : 'CLEAN'}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {new Date(item.last_updated * 1000).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ═══ TAB: DNS INTELLIGENCE ════════════════════════════════════════ */}
      {activeTab === 'dns' && (
        <div className="table-panel">
          <div className="table-panel-header">
            <h2><Search size={15} /> DNS Traffic Analysis</h2>
            <div className="table-panel-actions">
              <span className="pill pill-info">Lookups: {dnsHistory.length}</span>
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Entropy & Length Heuristics</span>
            </div>
          </div>

          <div className="table-scroll">
            {dnsHistory.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon"><Search size={40} /></div>
                <div className="empty-title">No DNS Queries</div>
                <div className="empty-desc">DNS lookups will appear here in real-time during capture.</div>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Query Domain</th>
                    <th>Answer</th>
                    <th style={{ textAlign: 'center' }}>TTL</th>
                    <th>Security Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {dnsHistory.map((item, i) => (
                    <tr key={i} className={item.flags?.length > 0 ? 'row-suspicious' : ''}>
                      <td style={{ fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{item.timestamp}</td>
                      <td>
                        <span className={`chip ${item.type === 'QUERY' ? 'chip-info' : 'chip-safe'}`}>
                          {item.type}
                        </span>
                      </td>
                      <td><code style={{ fontSize: '12.5px', fontWeight: 600 }}>{item.domain}</code></td>
                      <td style={{ fontSize: '12.5px', color: item.answer === 'Pending...' ? 'var(--text-muted)' : 'var(--text-secondary)' }}>
                        {item.answer}
                      </td>
                      <td style={{ textAlign: 'center', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>{item.ttl}</td>
                      <td>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {item.flags?.map((f, fi) => (
                            <span key={fi} className="signal-tag warning">⚠️ {f}</span>
                          ))}
                          {(!item.flags || item.flags.length === 0) && (
                            <span style={{ color: 'var(--accent-green)', fontSize: '11px', fontWeight: 600 }}>✓ Clean</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ═══ FLOW DETAIL MODAL ═══════════════════════════════════════════ */}
      {showModal && selectedFlow && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-info">
                <div className="domain-avatar" style={{ width: 36, height: 36, fontSize: 14 }}>{selectedFlow.domain.charAt(0).toUpperCase()}</div>
                <div>
                  <h2>{selectedFlow.domain}</h2>
                  <span className={`chip ${selectedFlow.prediction === 'Malicious' ? 'chip-unsafe' : 'chip-safe'}`} style={{ marginTop: 4, display: 'inline-flex' }}>
                    {selectedFlow.prediction === 'Malicious' ? 'High Risk' : 'Verified Safe'}
                  </span>
                </div>
              </div>
              <button className="modal-close" onClick={() => setShowModal(false)}>
                <X size={16} />
              </button>
            </div>

            {/* Beacon banner inside modal */}
            {selectedFlow.beacon_analysis?.beacon_score > 0 && (
              <div className={`beacon-banner ${selectedFlow.beacon_analysis.verdict === 'BEACON' ? 'beacon-danger' : 'beacon-warning'}`}>
                <div className="beacon-banner-title" style={{ color: selectedFlow.beacon_analysis.verdict === 'BEACON' ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                  🎯 C2 Beacon Score: {selectedFlow.beacon_analysis.beacon_score}/100 — {selectedFlow.beacon_analysis.verdict}
                </div>
                <div className="beacon-banner-signals">
                  {(selectedFlow.beacon_analysis.signals_triggered || []).map((s, i) => (
                    <span key={i} className="signal-tag">{s.replace(/_/g, ' ')}</span>
                  ))}
                </div>
              </div>
            )}

            <div className="modal-section">
              <div className="modal-section-label">Traffic Signature (JA3/TLS)</div>
              <div className="ja3-box">{selectedFlow.ja3 || 'No signature captured'}</div>
            </div>

            <div className="modal-section">
              <div className="modal-section-label">ML Analysis Features</div>
              <div className="features-grid">
                {Object.entries(selectedFlow.ml_features || {}).map(([key, value]) => (
                  <div key={key} className="feature-tile">
                    <div className="f-key">{key}</div>
                    <div className="f-val">{typeof value === 'number' ? value.toFixed(3) : String(value)}</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ textAlign: 'center', fontSize: '10.5px', color: 'var(--text-muted)', fontWeight: 600, marginTop: 20 }}>
              Analyzed via CryptGuard DPI Engine + ML Pipeline · Zero Payload Decryption
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
