import { useState, useEffect } from 'react'
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
  Trash2,
  ChevronRight,
  Search,
  Wifi
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
  Pie
} from 'recharts'

interface AppStat {
  name: string;
  count: number;
}

interface SniRecord {
  domain: string;
  app: string;
}

interface LiveData {
  total_packets: number;
  total_bytes: number;
  forwarded: number;
  dropped: number;
  tcp_packets: number;
  udp_packets: number;
  applications: AppStat[];
  snis: SniRecord[];
}

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [data, setData] = useState<LiveData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLive, setIsLive] = useState(false)

  useEffect(() => {
    let interval: number;
    
    const fetchData = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/stats')
        if (!response.ok) throw new Error('Bridge server not responding')
        const jsonData = await response.json()
        setData(jsonData)
        setIsLive(true)
        setError(null)
      } catch (err) {
        setIsLive(false)
        setError('Waiting for DPI Bridge...')
      }
    }

    fetchData()
    interval = window.setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  const appColors = {
    'HTTPS': '#60a5fa',
    'Unknown': '#94a3b8',
    'Google': '#f87171',
    'DNS': '#fbbf24',
    'HTTP': '#a78bfa',
    'WhatsApp': '#22c55e',
    'Spotify': '#1db954',
    'Zoom': '#34d399',
    'Facebook': '#3b82f6',
    'YouTube': '#ef4444',
  }

  const getAppColor = (name: string) => (appColors as any)[name] || '#a855f7'

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-slate-200 font-sans selection:bg-purple-500/30">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-[#0f0f12] border-r border-slate-800/50 flex flex-col z-50">
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-purple-600 to-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-purple-500/20">
            <Shield className="text-white" size={24} />
          </div>
          <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
            CryptGuard
          </span>
        </div>

        <nav className="flex-1 px-4 py-4 space-y-2">
          <NavItem 
            icon={BarChart3} 
            label="Dashboard" 
            active={activeTab === 'dashboard'} 
            onClick={() => setActiveTab('dashboard')} 
          />
          <NavItem 
            icon={List} 
            label="Live Analysis" 
            active={activeTab === 'analysis'} 
            onClick={() => setActiveTab('analysis')} 
          />
          <NavItem 
            icon={Filter} 
            label="Blocking Rules" 
            active={activeTab === 'rules'} 
            onClick={() => setActiveTab('rules')} 
          />
        </nav>

        <div className="p-4 border-t border-slate-800/50">
          <div className="bg-slate-900/50 rounded-xl p-3 flex items-center gap-3 border border-slate-800/50">
            <div className={`w-2 h-2 rounded-full ${isLive ? 'bg-green-500 animate-pulse shadow-[0_0_8px_#22c55e]' : 'bg-red-500'}`}></div>
            <span className="text-sm text-slate-400 font-medium">
              {isLive ? 'Engine Link Active' : 'Connecting to Engine...'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="ml-64 p-8">
        <header className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
              Security Overview {isLive && <Wifi className="text-purple-400 animate-pulse" size={20} />}
            </h1>
            <p className="text-slate-400 mt-1">
              {error ? <span className="text-amber-400/80 italic">{error}</span> : 'Deep Packet Inspection Monitoring & Control'}
            </p>
          </div>
          <div className="flex gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
              <input 
                type="text" 
                placeholder="Search domains..." 
                className="bg-slate-900/50 border border-slate-800/50 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500/40 w-64 transition-all"
              />
            </div>
            <button className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
              <Plus size={18} /> New Capture
            </button>
          </div>
        </header>

        {(activeTab === 'dashboard' && data) ? (
          <div className="space-y-8 animate-in fade-in duration-500">
            {/* Stats Grid */}
            <div className="grid grid-cols-4 gap-6">
              <StatCard label="Total Packets" value={data.total_packets.toLocaleString()} icon={Database} color="text-blue-400" />
              <StatCard label="Total Bytes" value={(data.total_bytes / 1024 / 1024).toFixed(2) + ' MB'} icon={Activity} color="text-purple-400" />
              <StatCard label="Forwarded" value={data.forwarded.toLocaleString()} icon={ShieldCheck} color="text-green-400" />
              <StatCard label="Dropped" value={data.dropped.toLocaleString()} icon={ShieldAlert} color="text-red-400" />
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-2 gap-8">
              <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-lg font-semibold text-white">Application Breakdown</h3>
                  <Globe size={18} className="text-slate-500" />
                </div>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.applications} layout="vertical">
                      <XAxis type="number" hide />
                      <YAxis 
                        dataKey="name" 
                        type="category" 
                        axisLine={false} 
                        tickLine={false} 
                        tick={{ fill: '#94a3b8', fontSize: 11 }}
                        width={80}
                      />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0f0f12', border: '1px solid #334155', borderRadius: '8px' }}
                        itemStyle={{ color: '#fff' }}
                      />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={16}>
                        {data.applications.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={getAppColor(entry.name)} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="bg-[#121217] border border-slate-800/50 p-6 rounded-2xl flex flex-col items-center">
                <div className="w-full flex justify-between items-center mb-2">
                  <h3 className="text-lg font-semibold text-white">Traffic Integrity</h3>
                  <Shield size={18} className="text-slate-500" />
                </div>
                <div className="flex-1 flex items-center justify-center relative w-full h-64">
                   <div className="absolute inset-0 flex items-center justify-center flex-col z-10">
                      <span className="text-3xl font-bold text-white">
                        {data.total_packets > 0 ? ((data.forwarded / data.total_packets) * 100).toFixed(1) : '0'}%
                      </span>
                      <span className="text-xs text-slate-500 font-medium tracking-widest uppercase mt-1">Flow Safety</span>
                   </div>
                   <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Forwarded', value: data.forwarded },
                          { name: 'Dropped', value: data.dropped },
                        ]}
                        cx="50%"
                        cy="50%"
                        innerRadius={75}
                        outerRadius={95}
                        paddingAngle={8}
                        dataKey="value"
                        stroke="none"
                      >
                        <Cell fill="#10b981" />
                        <Cell fill="#ef4444" />
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* SNI List */}
            <div className="bg-[#121217] border border-slate-800/50 rounded-2xl overflow-hidden shadow-2xl shadow-black/40">
              <div className="p-6 border-b border-slate-800/50 flex justify-between items-center">
                <h3 className="text-lg font-semibold text-white">Active Intelligence Log</h3>
                <span className="text-slate-500 text-xs font-mono">{data.snis.length} unique end-points identified</span>
              </div>
              <div className="overflow-x-auto max-h-[400px] overflow-y-auto custom-scrollbar">
                <table className="w-full text-left">
                  <thead className="sticky top-0 z-20">
                    <tr className="bg-slate-900 text-slate-500 text-[10px] font-bold uppercase tracking-wider">
                      <th className="px-6 py-4">Target Hostname</th>
                      <th className="px-6 py-4">Classification</th>
                      <th className="px-6 py-4">Edge Status</th>
                      <th className="px-6 py-4 text-right">Insights</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/30">
                    {data.snis.map((sni, i) => (
                      <tr key={i} className="hover:bg-purple-500/5 transition-colors group">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 bg-slate-900 rounded-lg flex items-center justify-center text-slate-500 ring-1 ring-slate-800 group-hover:ring-purple-500/50 transition-all">
                              <Globe size={14} />
                            </div>
                            <span className="text-sm font-medium text-slate-300">{sni.domain}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="bg-slate-900/80 text-slate-400 text-[10px] font-black px-2 py-1 rounded-md ring-1 ring-slate-800/50 uppercase tracking-tighter">
                            {sni.app}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-2">
                             <div className={`w-1.5 h-1.5 rounded-full ${sni.app !== 'Google' ? 'bg-green-500 shadow-[0_0_8px_#22c55e]' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`}></div>
                             <span className={`text-[11px] font-semibold ${sni.app !== 'Google' ? 'text-green-400' : 'text-red-400'}`}>
                                {sni.app !== 'Google' ? 'PASS' : 'BLOCKED'}
                             </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button className="text-slate-600 hover:text-white transition-colors">
                            <ChevronRight size={16} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ) : (
          <div className="h-[60vh] flex flex-col items-center justify-center text-center space-y-4">
             <div className="w-16 h-16 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin"></div>
             <div className="space-y-1">
               <h3 className="text-xl font-bold text-white">Initializing DPI Environment</h3>
               <p className="text-slate-500">Connecting to Python Bridge Bridge... {error && <span className="block text-red-500/50 text-sm mt-2 font-mono uppercase tracking-widest font-bold">{error}</span>}</p>
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
          <Icon size={18} />
        </div>
      </div>
      <div className="absolute -right-6 -bottom-6 w-24 h-24 bg-gradient-to-br from-transparent to-white/[0.03] rounded-full blur-2xl group-hover:scale-125 transition-all"></div>
    </div>
  )
}

function NavItem({ icon: Icon, label, active, onClick }: { icon: any, label: string, active: boolean, onClick: () => void }) {
  return (
    <button 
      onClick={onClick}
      className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 group relative ${
        active 
          ? 'bg-purple-600/10 text-purple-400' 
          : 'text-slate-500 hover:bg-slate-800/50 hover:text-slate-300'
      }`}
    >
      <Icon size={18} className={active ? 'text-purple-400' : 'group-hover:scale-110 transition-transform'} />
      <span className="font-bold text-xs uppercase tracking-widest">{label}</span>
      {active && (
        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-purple-600 rounded-r-full shadow-[0_0_12px_#9333ea]"></div>
      )}
    </button>
  )
}
