import { useState, useEffect, useRef } from 'react'
import {
  Activity,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Database,
  Globe,
  Filter,
  BarChart3,
  List,
  Plus,
  ChevronRight,
  Search,
  Wifi,
  Radio,
  Clock,
  TrendingUp,
  Lock,
  Unlock,
  Zap
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
  LineChart,
  Line,
  CartesianGrid,
  Legend
} from 'recharts'

interface AppStat   { name: string; count: number }
interface SniRecord { domain: string; app: string }
interface LiveData  {
  total_packets: number
  total_bytes: number
  forwarded: number
  dropped: number
  tcp_packets: number
  udp_packets: number
  applications: AppStat[]
  snis: SniRecord[]
}

const APP_COLORS: Record<string, string> = {
  Google: '#e74c3c', YouTube: '#ff0000', Facebook: '#3b5998',
  Twitter: '#1da1f2', Instagram: '#e1306c', Netflix: '#e50914',
  Amazon: '#ff9900', Microsoft: '#00a4ef', Apple: '#a2aaad',
  WhatsApp: '#25d366', Telegram: '#2ca5e0', TikTok: '#ff0050',
  Spotify: '#1db954', Zoom: '#2d8cff', Discord: '#5865f2',
  GitHub: '#6e5494', Cloudflare: '#f48120', HTTPS: '#60a5fa',
  HTTP: '#a78bfa', DNS: '#fbbf24', Other: '#64748b'
}
const getColor = (n: string) => APP_COLORS[n] ?? '#a855f7'

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [data,      setData]      = useState<LiveData | null>(null)
  const [isLive,    setIsLive]    = useState(false)
  const [error,     setError]     = useState<string | null>(null)
  const [history,   setHistory]   = useState<{t: string; packets: number; dropped: number}[]>([])
  const lastPackets = useRef(0)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch('http://localhost:5000/api/stats')
        if (!res.ok) throw new Error('not ok')
        const d: LiveData = await res.json()
        setData(d)
        setIsLive(true)
        setError(null)
        // update rolling history
        const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
        const delta = d.total_packets - lastPackets.current
        lastPackets.current = d.total_packets
        setHistory(prev => {
          const next = [...prev, { t: now, packets: d.total_packets, dropped: d.dropped }]
          return next.slice(-20)
        })
      } catch {
        setIsLive(false)
        setError('Waiting for DPI Bridge...')
      }
    }
    fetchData()
    const id = window.setInterval(fetchData, 2000)
    return () => clearInterval(id)
  }, [])

  /* ─── Loading screen ─────────────────────────────────── */
  if (!data) return (
    <div className="min-h-screen bg-[#0a0a0c] text-slate-200 flex items-center justify-center">
      <div className="text-center space-y-4">
        <div className="w-16 h-16 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin mx-auto"/>
        <h3 className="text-xl font-bold text-white">Initializing DPI Environment</h3>
        <p className="text-slate-500 italic">Connecting to Python Bridge...</p>
        {error && <p className="text-red-400/70 text-sm font-mono uppercase">{error}</p>}
      </div>
    </div>
  )

  /* ─── Main layout ─────────────────────────────────────── */
  return (
    <div className="min-h-screen bg-[#0a0a0c] text-slate-200 font-sans flex">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-[#0f0f12] border-r border-slate-800/50 flex flex-col z-50">
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-purple-600 to-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-purple-500/20">
            <Shield className="text-white" size={24}/>
          </div>
          <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
            CryptGuard
          </span>
        </div>

        <nav className="flex-1 px-4 py-4 space-y-2">
          <NavItem icon={BarChart3} label="Dashboard"     active={activeTab==='dashboard'} onClick={()=>setActiveTab('dashboard')}/>
          <NavItem icon={List}      label="Live Analysis" active={activeTab==='analysis'}  onClick={()=>setActiveTab('analysis')}/>
          <NavItem icon={Filter}    label="Blocking Rules" active={activeTab==='rules'}    onClick={()=>setActiveTab('rules')}/>
        </nav>

        <div className="p-4 border-t border-slate-800/50">
          <div className="bg-slate-900/50 rounded-xl p-3 flex items-center gap-3 border border-slate-800/50">
            <div className={`w-2 h-2 rounded-full ${isLive ? 'bg-green-500 animate-pulse shadow-[0_0_8px_#22c55e]' : 'bg-red-500'}`}/>
            <span className="text-sm text-slate-400 font-medium">
              {isLive ? 'Engine Link Active' : 'Connecting...'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="ml-64 flex-1 p-8">
        {/* Header */}
        <header className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
              {activeTab === 'dashboard' ? 'Security Overview' :
               activeTab === 'analysis' ? 'Live Traffic Analysis' : 'Blocking Rules'}
              {isLive && <Wifi className="text-purple-400 animate-pulse" size={20}/>}
            </h1>
            <p className="text-slate-400 mt-1">
              {error
                ? <span className="text-amber-400/80 italic">{error}</span>
                : <span>Deep Packet Inspection · <span className="text-green-400 font-semibold">SIMULATION MODE</span> · Updates every 3s</span>
              }
            </p>
          </div>
          <div className="flex gap-4 items-center">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18}/>
              <input type="text" placeholder="Search domains..."
                className="bg-slate-900/50 border border-slate-800/50 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500/40 w-64 transition-all"/>
            </div>
            <button className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
              <Plus size={18}/> New Capture
            </button>
          </div>
        </header>

        {/* ── DASHBOARD TAB ─────────────────────────────── */}
        {activeTab === 'dashboard' && (
          <div className="space-y-8 animate-in fade-in duration-500">
            {/* Stats */}
            <div className="grid grid-cols-4 gap-6">
              <StatCard label="Total Packets" value={data.total_packets.toLocaleString()} icon={Database}    color="text-blue-400"/>
              <StatCard label="Total Bytes"   value={(data.total_bytes/1024/1024).toFixed(2)+' MB'} icon={Activity} color="text-purple-400"/>
              <StatCard label="Forwarded"     value={data.forwarded.toLocaleString()} icon={ShieldCheck} color="text-green-400"/>
              <StatCard label="Dropped"       value={data.dropped.toLocaleString()}   icon={ShieldAlert} color="text-red-400"/>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-2 gap-8">
              <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-lg font-semibold text-white">Application Breakdown</h3>
                  <Globe size={18} className="text-slate-500"/>
                </div>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.applications.slice(0,8)} layout="vertical">
                      <XAxis type="number" hide/>
                      <YAxis dataKey="name" type="category" axisLine={false} tickLine={false}
                             tick={{ fill: '#94a3b8', fontSize: 11 }} width={80}/>
                      <Tooltip contentStyle={{ backgroundColor:'#0f0f12', border:'1px solid #334155', borderRadius:'8px' }}
                               itemStyle={{ color:'#fff' }}/>
                      <Bar dataKey="count" radius={[0,4,4,0]} barSize={16}>
                        {data.applications.slice(0,8).map((e,i)=>(
                          <Cell key={i} fill={getColor(e.name)}/>
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl flex flex-col">
                <div className="flex justify-between items-center mb-2">
                  <h3 className="text-lg font-semibold text-white">Traffic Integrity</h3>
                  <Shield size={18} className="text-slate-500"/>
                </div>
                <div className="flex-1 flex items-center justify-center relative h-64">
                  <div className="absolute inset-0 flex items-center justify-center flex-col z-10">
                    <span className="text-3xl font-bold text-white">
                      {data.total_packets>0 ? ((data.forwarded/data.total_packets)*100).toFixed(1) : '0'}%
                    </span>
                    <span className="text-xs text-slate-500 font-medium tracking-widest uppercase mt-1">Flow Safety</span>
                  </div>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={[{ value:data.forwarded },{ value:data.dropped }]}
                           cx="50%" cy="50%" innerRadius={75} outerRadius={95}
                           paddingAngle={8} dataKey="value" stroke="none">
                        <Cell fill="#10b981"/><Cell fill="#ef4444"/>
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* Packet history line chart */}
            {history.length > 2 && (
              <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-semibold text-white">Packet Count History</h3>
                  <TrendingUp size={18} className="text-slate-500"/>
                </div>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={history}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/>
                      <XAxis dataKey="t" tick={{ fill:'#64748b', fontSize:10 }} interval="preserveStartEnd"/>
                      <YAxis tick={{ fill:'#64748b', fontSize:10 }}/>
                      <Tooltip contentStyle={{ backgroundColor:'#0f0f12', border:'1px solid #334155', borderRadius:'8px' }}/>
                      <Legend/>
                      <Line type="monotone" dataKey="packets" stroke="#a855f7" strokeWidth={2} dot={false} name="Total Packets"/>
                      <Line type="monotone" dataKey="dropped"  stroke="#ef4444" strokeWidth={2} dot={false} name="Dropped"/>
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── LIVE ANALYSIS TAB ─────────────────────────── */}
        {activeTab === 'analysis' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            {/* Quick Stats */}
            <div className="grid grid-cols-3 gap-6">
              <div className="bg-[#121217] border border-slate-800/50 p-5 rounded-2xl flex items-center gap-4">
                <div className="w-12 h-12 bg-blue-500/10 rounded-xl flex items-center justify-center">
                  <Radio className="text-blue-400" size={22}/>
                </div>
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-widest font-bold">Live Packets</p>
                  <p className="text-2xl font-black text-white">{data.total_packets.toLocaleString()}</p>
                </div>
              </div>
              <div className="bg-[#121217] border border-slate-800/50 p-5 rounded-2xl flex items-center gap-4">
                <div className="w-12 h-12 bg-green-500/10 rounded-xl flex items-center justify-center">
                  <Zap className="text-green-400" size={22}/>
                </div>
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-widest font-bold">TCP / UDP</p>
                  <p className="text-2xl font-black text-white">{data.tcp_packets} / {data.udp_packets}</p>
                </div>
              </div>
              <div className="bg-[#121217] border border-slate-800/50 p-5 rounded-2xl flex items-center gap-4">
                <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center">
                  <Clock className="text-purple-400" size={22}/>
                </div>
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-widest font-bold">Last Updated</p>
                  <p className="text-lg font-black text-white">
                    {new Date().toLocaleTimeString('en-US',{hour12:false})}
                  </p>
                </div>
              </div>
            </div>

            {/* SNI table – full width */}
            <div className="bg-[#121217] border border-slate-800/50 rounded-2xl overflow-hidden">
              <div className="p-6 border-b border-slate-800/50 flex justify-between items-center">
                <h3 className="text-lg font-semibold text-white">Live Intelligence Log</h3>
                <span className="text-xs text-slate-500 font-mono">{data.snis.length} endpoints identified</span>
              </div>
              <div className="max-h-[480px] overflow-y-auto">
                <table className="w-full text-left">
                  <thead className="sticky top-0 z-20">
                    <tr className="bg-slate-900 text-slate-500 text-[10px] font-bold uppercase tracking-wider">
                      <th className="px-6 py-4">#</th>
                      <th className="px-6 py-4">Target Hostname</th>
                      <th className="px-6 py-4">Application</th>
                      <th className="px-6 py-4">Protocol</th>
                      <th className="px-6 py-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/30">
                    {data.snis.map((sni, i) => {
                      const blocked = sni.app === 'TikTok'
                      return (
                        <tr key={i} className="hover:bg-purple-500/5 transition-colors group">
                          <td className="px-6 py-4 text-slate-600 text-xs font-mono">{String(i+1).padStart(2,'0')}</td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 rounded-lg flex items-center justify-center ring-1 ring-slate-800"
                                   style={{ backgroundColor: getColor(sni.app)+'22' }}>
                                <Globe size={14} style={{ color: getColor(sni.app) }}/>
                              </div>
                              <span className="text-sm font-medium text-slate-300">{sni.domain}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-[11px] font-bold px-2.5 py-1 rounded-full uppercase tracking-wider"
                                  style={{ backgroundColor: getColor(sni.app)+'22', color: getColor(sni.app) }}>
                              {sni.app}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-[10px] font-bold text-slate-500 bg-slate-900 px-2 py-1 rounded">TLS 1.3</span>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-2">
                              {blocked
                                ? <><Lock size={13} className="text-red-400"/><span className="text-[11px] font-bold text-red-400">BLOCKED</span></>
                                : <><Unlock size={13} className="text-green-400"/><span className="text-[11px] font-bold text-green-400">PASS</span></>
                              }
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* App distribution in analysis tab */}
            <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-lg font-semibold text-white">App Traffic Distribution</h3>
                <BarChart3 size={18} className="text-slate-500"/>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {data.applications.map((app, i) => (
                  <div key={i} className="bg-slate-900/50 rounded-xl p-3 border border-slate-800/50 flex items-center gap-3">
                    <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: getColor(app.name) }}/>
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-slate-300 truncate">{app.name}</p>
                      <p className="text-slate-500 text-[10px]">{app.count} pkts</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── BLOCKING RULES TAB ────────────────────────── */}
        {activeTab === 'rules' && (
          <div className="animate-in fade-in duration-500 space-y-6">
            <div className="bg-[#121217] border border-slate-800/50 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Active Blocking Rules</h3>
              <div className="space-y-2">
                {['TikTok','Google','Facebook'].map((app, i) => (
                  <div key={i} className="flex items-center justify-between bg-slate-900/50 rounded-xl px-4 py-3 border border-slate-800/50">
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_#ef4444]"/>
                      <span className="text-sm font-semibold text-white">{app}</span>
                    </div>
                    <span className="text-[10px] font-bold text-red-400 bg-red-500/10 px-2 py-1 rounded-full uppercase">Blocked</span>
                  </div>
                ))}
              </div>
              <p className="text-slate-600 text-xs mt-4">Rule management coming soon...</p>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color }: any) {
  return (
    <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl relative overflow-hidden group hover:bg-[#16161c] transition-all">
      <div className="flex justify-between items-start relative z-10">
        <div>
          <p className="text-slate-500 text-xs font-bold uppercase tracking-widest mb-1.5">{label}</p>
          <h3 className="text-2xl font-black text-white tracking-tighter">{value}</h3>
        </div>
        <div className={`p-3 rounded-xl bg-slate-900/50 ${color} ring-1 ring-slate-800 group-hover:scale-110 transition-transform`}>
          <Icon size={18}/>
        </div>
      </div>
      <div className="absolute -right-6 -bottom-6 w-24 h-24 bg-gradient-to-br from-transparent to-white/[0.03] rounded-full blur-2xl"/>
    </div>
  )
}

function NavItem({ icon: Icon, label, active, onClick }: { icon: any; label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 group relative ${
        active ? 'bg-purple-600/10 text-purple-400' : 'text-slate-500 hover:bg-slate-800/50 hover:text-slate-300'
      }`}>
      <Icon size={18} className={active ? 'text-purple-400' : ''}/>
      <span className="font-bold text-xs uppercase tracking-widest">{label}</span>
      {active && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-purple-600 rounded-r-full shadow-[0_0_12px_#9333ea]"/>}
    </button>
  )
}
