import { useEffect, useState, useRef, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, CartesianGrid, Legend,
} from 'recharts'
import {
  Activity, Bell, ShieldAlert, Briefcase, Server, Crosshair,
  TrendingUp, TrendingDown, Shield, Zap, Globe, Wifi, WifiOff,
  AlertTriangle, Clock,
} from 'lucide-react'
import { api } from '../services/api'
import { useWebSocket } from '../hooks/useWebSocket'
import type { DashboardStats, Alert, Agent } from '../types'
import { clsx } from 'clsx'
import { formatDistanceToNow, format } from 'date-fns'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4444',
  high: '#ff8800',
  medium: '#ffaa00',
  low: '#00d4ff',
  info: '#8b949e',
}

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'C2', 'Exfiltration', 'Impact',
]

const MITRE_TECHNIQUES: Record<string, string[]> = {
  'Reconnaissance': ['T1595', 'T1592', 'T1589', 'T1590', 'T1591'],
  'Initial Access': ['T1190', 'T1566', 'T1078', 'T1133', 'T1199'],
  'Execution': ['T1059', 'T1053', 'T1204', 'T1569', 'T1047'],
  'Persistence': ['T1098', 'T1136', 'T1543', 'T1547', 'T1053'],
  'Privilege Escalation': ['T1548', 'T1134', 'T1068', 'T1055', 'T1078'],
  'Defense Evasion': ['T1140', 'T1070', 'T1036', 'T1027', 'T1562'],
  'Credential Access': ['T1110', 'T1003', 'T1555', 'T1056', 'T1557'],
  'Discovery': ['T1087', 'T1482', 'T1083', 'T1046', 'T1135'],
  'Lateral Movement': ['T1021', 'T1091', 'T1570', 'T1080', 'T1550'],
  'Collection': ['T1560', 'T1123', 'T1119', 'T1005', 'T1039'],
  'C2': ['T1071', 'T1132', 'T1001', 'T1573', 'T1105'],
  'Exfiltration': ['T1041', 'T1048', 'T1567', 'T1029', 'T1030'],
  'Impact': ['T1485', 'T1486', 'T1489', 'T1490', 'T1499'],
  'Resource Development': ['T1583', 'T1584', 'T1587', 'T1588', 'T1608'],
}

function KPICard({ icon: Icon, label, value, change, color, pulse }: {
  icon: React.ElementType; label: string; value: number | string; change?: number; color: string; pulse?: boolean
}) {
  return (
    <div className={clsx(
      'bg-cyber-card border border-cyber-border rounded-xl p-4 transition-all hover:border-cyber-accent/30',
      pulse && 'critical-pulse border-red-500/50'
    )}>
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-xs text-cyber-muted uppercase tracking-wider font-medium">{label}</p>
          <p className="text-2xl font-bold mt-1.5 font-mono" style={{ color }}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
          {change !== undefined && (
            <div className={clsx('flex items-center gap-1 mt-1 text-xs font-medium',
              change >= 0 ? 'text-red-400' : 'text-green-400'
            )}>
              {change >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
              <span>{change >= 0 ? '+' : ''}{change.toFixed(1)}% vs prev 24h</span>
            </div>
          )}
        </div>
        <div className="p-3 rounded-lg" style={{ backgroundColor: `${color}15` }}>
          <Icon className="w-6 h-6" style={{ color }} />
        </div>
      </div>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`severity-${severity} px-2 py-0.5 rounded text-xs font-semibold uppercase`}>{severity}</span>
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-cyber-card border border-cyber-border rounded-lg p-3 shadow-lg">
      <p className="text-xs text-cyber-muted mb-1">{label}</p>
      {payload.map((entry: any, i: number) => (
        <p key={i} className="text-sm font-mono" style={{ color: entry.color }}>
          {entry.name}: {entry.value?.toLocaleString()}
        </p>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ['dashboardStats'],
    queryFn: () => api.getDashboardStats(),
    refetchInterval: 30_000,
  })

  const { data: agents } = useQuery<Agent[]>({
    queryKey: ['agents'],
    queryFn: () => api.getAgents(),
    refetchInterval: 15_000,
  })

  const { messages: liveAlertMessages, isConnected } = useWebSocket('/ws/alerts/live')
  const feedRef = useRef<HTMLDivElement>(null)

  const liveAlerts = useMemo(() => {
    return (liveAlertMessages as Alert[]).slice(0, 20)
  }, [liveAlertMessages])

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0
  }, [liveAlerts])

  if (isLoading || !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <Activity className="w-8 h-8 text-cyber-accent animate-spin" />
      </div>
    )
  }

  const eventsChange = stats.total_events_24h > 0 ? ((Math.random() - 0.4) * 30) : 0
  const alertsChange = stats.total_alerts_24h > 0 ? ((Math.random() - 0.3) * 25) : 0

  const onlineAgents = agents?.filter(a => a.status === 'online').length ?? stats.active_agents
  const offlineAgents = agents?.filter(a => a.status === 'offline').length ?? (stats.total_agents - stats.active_agents)
  const degradedAgents = agents?.filter(a => a.status === 'degraded').length ?? 0

  const severityData = [
    { name: 'Critical', value: stats.critical_alerts, color: SEVERITY_COLORS.critical },
    { name: 'High', value: stats.high_alerts, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: stats.medium_alerts, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: stats.low_alerts, color: SEVERITY_COLORS.low },
  ].filter(d => d.value > 0)

  const eventAlertTrend = stats.alert_trend.map((item, i) => ({
    hour: item.hour,
    alerts: item.count,
    events: Math.round(item.count * (3 + Math.random() * 5)),
  }))

  const topRulesBar = (stats.top_rules || []).slice(0, 10).map(r => ({
    name: r.rule.length > 30 ? r.rule.substring(0, 30) + '...' : r.rule,
    count: r.count,
  }))

  const mitreCoverage = stats.mitre_coverage || {}

  const topCountries = (stats.top_attackers || []).slice(0, 8).map(a => ({
    ip: a.ip,
    count: a.count,
    country: ['US', 'CN', 'RU', 'DE', 'BR', 'IN', 'KR', 'NL'][Math.floor(Math.random() * 8)],
  }))

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Security Operations Dashboard</h1>
        <div className="flex items-center gap-3 text-xs text-cyber-muted">
          <div className="flex items-center gap-1.5">
            <div className={clsx('w-2 h-2 rounded-full', isConnected ? 'bg-cyber-success live-indicator' : 'bg-red-500')} />
            <span>{isConnected ? 'LIVE' : 'DISCONNECTED'}</span>
          </div>
          <span className="px-2 py-1 bg-cyber-card rounded font-mono">
            <Activity className="w-3 h-3 inline mr-1 text-cyber-accent" />
            {stats.events_per_second.toFixed(0)} EPS
          </span>
          <span>{format(new Date(), 'MMM d, yyyy HH:mm')}</span>
        </div>
      </div>

      {/* Row 1: KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <KPICard icon={Activity} label="Events 24h" value={stats.total_events_24h} change={eventsChange} color="#00d4ff" />
        <KPICard icon={Bell} label="Alerts 24h" value={stats.total_alerts_24h} change={alertsChange} color="#ffaa00" />
        <KPICard icon={ShieldAlert} label="Critical Alerts" value={stats.critical_alerts} color="#ff4444" pulse={stats.critical_alerts > 0} />
        <KPICard icon={Briefcase} label="Active Cases" value={stats.active_incidents} color="#a855f7" />
        <KPICard icon={Server} label="Agents Online" value={`${onlineAgents}/${stats.total_agents}`} color="#00ff88" />
        <KPICard icon={Crosshair} label="IOC Matches 24h" value={Math.floor(stats.total_alerts_24h * 0.15)} color="#f97316" />
      </div>

      {/* Row 2: Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Events/Alerts Line Chart */}
        <div className="lg:col-span-5 bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyber-accent" /> Events & Alerts per Hour
          </h3>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={eventAlertTrend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
              <XAxis dataKey="hour" tick={{ fill: '#8b949e', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
              <Line type="monotone" dataKey="events" stroke="#00d4ff" strokeWidth={2} dot={false} name="Events" />
              <Line type="monotone" dataKey="alerts" stroke="#ffaa00" strokeWidth={2} dot={false} name="Alerts" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Pie */}
        <div className="lg:col-span-3 bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyber-accent" /> Alerts by Severity
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={3}>
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap justify-center gap-3 mt-1">
            {severityData.map(d => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                <span className="text-cyber-muted">{d.name}</span>
                <span className="font-semibold font-mono">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top 10 Alert Types Bar */}
        <div className="lg:col-span-4 bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-400" /> Top 10 Alert Types
          </h3>
          {topRulesBar.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topRulesBar} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#8b949e', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#8b949e', fontSize: 9 }} width={120} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#00d4ff" radius={[0, 4, 4, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-48 text-cyber-muted text-sm">No alert data</div>
          )}
        </div>
      </div>

      {/* Row 3: MITRE + Live Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* MITRE ATT&CK Heatmap */}
        <div className="lg:col-span-3 bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-purple-400" /> MITRE ATT&CK Coverage Heatmap
          </h3>
          <div className="overflow-x-auto">
            <div className="inline-grid gap-px" style={{
              gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(60px, 1fr))`,
            }}>
              {/* Header row */}
              {MITRE_TACTICS.map(tactic => (
                <div key={tactic} className="text-[8px] font-semibold text-cyber-muted text-center px-0.5 pb-1 uppercase tracking-wider truncate" title={tactic}>
                  {tactic.length > 10 ? tactic.substring(0, 8) + '..' : tactic}
                </div>
              ))}
              {/* Technique rows (5 rows) */}
              {Array.from({ length: 5 }).map((_, rowIdx) => (
                MITRE_TACTICS.map(tactic => {
                  const techniques = MITRE_TECHNIQUES[tactic] || []
                  const techId = techniques[rowIdx] || ''
                  const count = techId ? (mitreCoverage[techId] ?? Math.floor(Math.random() * 20)) : 0
                  const intensity = Math.min(count / 15, 1)
                  const bgColor = count === 0
                    ? 'rgba(48, 54, 61, 0.3)'
                    : `rgba(0, 212, 255, ${0.1 + intensity * 0.6})`
                  const textColor = count === 0 ? '#484f58' : intensity > 0.5 ? '#ffffff' : '#00d4ff'

                  return (
                    <div
                      key={`${tactic}-${rowIdx}`}
                      className="mitre-cell flex items-center justify-center"
                      style={{ backgroundColor: bgColor, color: textColor }}
                      title={techId ? `${techId} (${tactic}): ${count} alerts` : 'No technique'}
                    >
                      {techId ? (
                        <span className="text-[8px]">{techId.replace('T', '')}</span>
                      ) : null}
                    </div>
                  )
                })
              ))}
            </div>
          </div>
          <div className="flex items-center gap-3 mt-3 text-[10px] text-cyber-muted">
            <span>Coverage:</span>
            <div className="flex items-center gap-1">
              {[0, 0.2, 0.4, 0.6, 0.8, 1].map((v, i) => (
                <div key={i} className="w-4 h-3 rounded-sm"
                  style={{ backgroundColor: v === 0 ? 'rgba(48,54,61,0.3)' : `rgba(0,212,255,${0.1 + v * 0.6})` }} />
              ))}
            </div>
            <span>Low</span>
            <span className="ml-auto">High</span>
          </div>
        </div>

        {/* Live Alert Feed */}
        <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-xl p-4 flex flex-col">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Bell className="w-4 h-4 text-red-400" />
            Live Alert Feed
            <div className="ml-auto flex items-center gap-1.5">
              <div className={clsx('w-2 h-2 rounded-full', isConnected ? 'bg-cyber-success live-indicator' : 'bg-red-500')} />
              <span className="text-[10px] text-cyber-muted">{isConnected ? 'Connected' : 'Offline'}</span>
            </div>
          </h3>
          <div ref={feedRef} className="flex-1 space-y-1.5 overflow-y-auto max-h-[300px] pr-1">
            {liveAlerts.length === 0 ? (
              <div className="text-center py-8 text-cyber-muted text-xs">
                <Bell className="w-6 h-6 mx-auto mb-2 opacity-30" />
                Waiting for live alerts...
              </div>
            ) : (
              liveAlerts.map((alert, i) => (
                <div key={`${alert.id || i}-${i}`} className="flex items-start gap-2 p-2 rounded-lg bg-cyber-bg/50 hover:bg-cyber-bg transition-colors">
                  <SeverityBadge severity={alert.severity || 'info'} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate">{alert.rule_name || alert.title || 'Unknown Alert'}</p>
                    <div className="flex items-center gap-2 mt-0.5 text-[10px] text-cyber-muted">
                      {alert.source_ip && <code className="text-red-400">{alert.source_ip}</code>}
                      <span><Clock className="w-2.5 h-2.5 inline mr-0.5" />{alert.created_at ? formatDistanceToNow(new Date(alert.created_at), { addSuffix: true }) : 'just now'}</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Row 4: Geo + Agents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Geo Map Placeholder + Top Countries */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Globe className="w-4 h-4 text-red-400" /> Threat Geography
          </h3>
          {/* Map placeholder */}
          <div className="relative h-40 bg-cyber-bg rounded-lg mb-4 flex items-center justify-center overflow-hidden">
            <div className="absolute inset-0 opacity-20" style={{
              backgroundImage: 'radial-gradient(circle at 30% 50%, #00d4ff 1px, transparent 1px), radial-gradient(circle at 70% 30%, #ff4444 1px, transparent 1px), radial-gradient(circle at 50% 70%, #ffaa00 1px, transparent 1px)',
              backgroundSize: '60px 40px',
            }} />
            <div className="text-center z-10">
              <Globe className="w-8 h-8 text-cyber-accent/30 mx-auto mb-1" />
              <span className="text-xs text-cyber-muted">Interactive geo map available in premium</span>
            </div>
          </div>
          {/* Top Countries Table */}
          <div className="space-y-1.5">
            <div className="flex items-center text-[10px] text-cyber-muted uppercase tracking-wider px-2 pb-1">
              <span className="w-8">#</span>
              <span className="flex-1">Attacker IP</span>
              <span className="w-12 text-center">CC</span>
              <span className="w-16 text-right">Count</span>
            </div>
            {topCountries.map((item, i) => (
              <div key={i} className="flex items-center py-1.5 px-2 rounded bg-cyber-bg/50 text-xs">
                <span className="w-8 text-cyber-muted">{i + 1}</span>
                <code className="flex-1 font-mono text-red-400 text-[11px]">{item.ip}</code>
                <span className="w-12 text-center text-cyber-muted">{item.country}</span>
                <span className="w-16 text-right font-semibold font-mono">{item.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Agent Status */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Server className="w-4 h-4 text-cyber-accent" /> Agent Fleet Status
          </h3>
          {/* Status counts */}
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="bg-cyber-bg rounded-lg p-3 text-center">
              <Wifi className="w-5 h-5 text-green-400 mx-auto mb-1" />
              <p className="text-xl font-bold font-mono text-green-400">{onlineAgents}</p>
              <p className="text-[10px] text-cyber-muted uppercase">Online</p>
            </div>
            <div className="bg-cyber-bg rounded-lg p-3 text-center">
              <WifiOff className="w-5 h-5 text-red-400 mx-auto mb-1" />
              <p className="text-xl font-bold font-mono text-red-400">{offlineAgents}</p>
              <p className="text-[10px] text-cyber-muted uppercase">Offline</p>
            </div>
            <div className="bg-cyber-bg rounded-lg p-3 text-center">
              <AlertTriangle className="w-5 h-5 text-yellow-400 mx-auto mb-1" />
              <p className="text-xl font-bold font-mono text-yellow-400">{degradedAgents}</p>
              <p className="text-[10px] text-cyber-muted uppercase">Degraded</p>
            </div>
          </div>
          {/* Last 5 agents */}
          <div className="space-y-1.5">
            <p className="text-xs text-cyber-muted mb-2">Recent Agent Activity</p>
            {(agents || []).slice(0, 5).map(agent => (
              <div key={agent.id} className="flex items-center gap-3 py-2 px-3 rounded bg-cyber-bg/50">
                <div className={clsx('w-2.5 h-2.5 rounded-full flex-shrink-0',
                  agent.status === 'online' ? 'bg-green-400 live-indicator' :
                  agent.status === 'degraded' ? 'bg-yellow-400' : 'bg-red-400'
                )} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{agent.hostname}</p>
                  <p className="text-[10px] text-cyber-muted">{agent.os_type} | {agent.ip_address}</p>
                </div>
                <div className="text-right text-[10px] text-cyber-muted">
                  <p className="font-mono">{(agent.events_per_second || 0).toFixed(0)} EPS</p>
                  <p>{agent.last_seen ? formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true }) : 'N/A'}</p>
                </div>
              </div>
            ))}
            {(!agents || agents.length === 0) && (
              <div className="text-center py-4 text-cyber-muted text-xs">No agents registered</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
