import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, PieChart, Pie, Cell } from 'recharts'
import { Shield, Bell, Server, AlertTriangle, Activity, TrendingUp, Globe, Zap } from 'lucide-react'
import { api } from '../services/api'
import type { DashboardStats } from '../types'

const SEVERITY_COLORS = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' }

function StatCard({ icon: Icon, label, value, color, sub }: {
  icon: React.ElementType; label: string; value: number | string; color: string; sub?: string
}) {
  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-cyber-muted uppercase tracking-wide">{label}</p>
          <p className="text-2xl font-bold mt-1" style={{ color }}>{typeof value === 'number' ? value.toLocaleString() : value}</p>
          {sub && <p className="text-xs text-cyber-muted mt-1">{sub}</p>}
        </div>
        <div className="p-2.5 rounded-lg" style={{ backgroundColor: `${color}15` }}>
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getDashboardStats().then(setStats).catch(console.error).finally(() => setLoading(false))
    const interval = setInterval(() => {
      api.getDashboardStats().then(setStats).catch(() => {})
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  if (loading) return <div className="flex items-center justify-center h-64"><Activity className="w-8 h-8 text-cyber-accent animate-spin" /></div>
  if (!stats) return <div className="text-center text-cyber-muted py-12">Unable to load dashboard</div>

  const severityData = [
    { name: 'Critical', value: stats.critical_alerts, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high_alerts, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium_alerts, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low_alerts, color: SEVERITY_COLORS.low },
  ].filter(d => d.value > 0)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Security Dashboard</h1>
        <div className="flex items-center gap-2 text-xs text-cyber-muted">
          <div className="w-2 h-2 rounded-full bg-cyber-success live-indicator" />
          Last 24 Hours
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Events (24h)" value={stats.total_events_24h} color="#3b82f6" sub={`${stats.events_per_second.toFixed(0)} EPS`} />
        <StatCard icon={Bell} label="Alerts (24h)" value={stats.total_alerts_24h} color="#f59e0b" sub={`${stats.critical_alerts} critical`} />
        <StatCard icon={Server} label="Agents" value={`${stats.active_agents}/${stats.total_agents}`} color="#10b981" sub="online / total" />
        <StatCard icon={AlertTriangle} label="Active Incidents" value={stats.active_incidents} color="#ef4444" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alert Trend */}
        <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyber-accent" /> Alert Trend (24h)
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={stats.alert_trend}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e293b', borderRadius: 8, color: '#e2e8f0' }} />
              <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="url(#alertGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Pie */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyber-accent" /> By Severity
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={4}>
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e293b', borderRadius: 8, color: '#e2e8f0' }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap justify-center gap-3 mt-2">
            {severityData.map(d => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                <span className="text-cyber-muted">{d.name}</span>
                <span className="font-semibold">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Attackers */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Globe className="w-4 h-4 text-red-400" /> Top Attackers
          </h3>
          <div className="space-y-2">
            {(stats.top_attackers.length > 0 ? stats.top_attackers : [{ ip: 'No data', count: 0 }]).slice(0, 8).map((a, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 px-3 rounded bg-cyber-bg/50">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-cyber-muted w-5">{i + 1}</span>
                  <code className="text-sm font-mono text-red-400">{a.ip}</code>
                </div>
                <span className="text-sm font-semibold">{a.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Rules */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-400" /> Top Detection Rules
          </h3>
          <div className="space-y-2">
            {(stats.top_rules.length > 0 ? stats.top_rules : [{ rule: 'No data', count: 0 }]).slice(0, 8).map((r, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 px-3 rounded bg-cyber-bg/50">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-cyber-muted w-5">{i + 1}</span>
                  <span className="text-sm truncate max-w-[250px]">{r.rule}</span>
                </div>
                <span className="text-sm font-semibold text-yellow-400">{r.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
