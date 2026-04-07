import { useEffect, useState } from 'react'
import { Bell, Filter, ChevronDown, ExternalLink, User, Clock } from 'lucide-react'
import { api } from '../services/api'
import type { Alert } from '../types'
import { clsx } from 'clsx'
import { formatDistanceToNow } from 'date-fns'

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const
const STATUSES = ['all', 'new', 'acknowledged', 'investigating', 'resolved', 'false_positive'] as const

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`severity-${severity} px-2 py-0.5 rounded text-xs font-semibold uppercase`}>{severity}</span>
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-${status} px-2 py-0.5 rounded text-xs font-medium`}>{status.replace('_', ' ')}</span>
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('all')
  const [status, setStatus] = useState('all')
  const [selected, setSelected] = useState<Alert | null>(null)

  const loadAlerts = () => {
    let params = '?limit=200'
    if (severity !== 'all') params += `&severity=${severity}`
    if (status !== 'all') params += `&status=${status}`
    api.getAlerts(params).then(setAlerts).catch(console.error).finally(() => setLoading(false))
  }

  useEffect(() => { loadAlerts() }, [severity, status])

  const handleStatusChange = async (alert: Alert, newStatus: string) => {
    await api.updateAlert(alert.id, { status: newStatus })
    loadAlerts()
    if (selected?.id === alert.id) setSelected({ ...alert, status: newStatus as Alert['status'] })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Bell className="w-6 h-6 text-cyber-accent" /> Alert Center
        </h1>
        <span className="text-sm text-cyber-muted">{alerts.length} alerts</span>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1.5">
          <Filter className="w-4 h-4 text-cyber-muted" />
          <span className="text-xs text-cyber-muted">Severity:</span>
          <div className="flex gap-1">
            {SEVERITIES.map(s => (
              <button key={s} onClick={() => setSeverity(s)}
                className={clsx('px-2.5 py-1 rounded text-xs font-medium transition-colors',
                  severity === s ? 'bg-cyber-accent text-white' : 'bg-cyber-card text-cyber-muted hover:text-white'
                )}>
                {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-cyber-muted">Status:</span>
          <select value={status} onChange={e => setStatus(e.target.value)}
            className="bg-cyber-card border border-cyber-border rounded px-2 py-1 text-xs text-white">
            {STATUSES.map(s => <option key={s} value={s}>{s === 'all' ? 'All' : s.replace('_', ' ')}</option>)}
          </select>
        </div>
      </div>

      <div className="flex gap-4">
        {/* Alert Table */}
        <div className="flex-1 bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Time</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="text-center py-8 text-cyber-muted">Loading...</td></tr>
              ) : alerts.length === 0 ? (
                <tr><td colSpan={5} className="text-center py-8 text-cyber-muted">No alerts found</td></tr>
              ) : alerts.map(alert => (
                <tr key={alert.id} onClick={() => setSelected(alert)}
                  className={clsx('data-row cursor-pointer border-b border-cyber-border/50 transition-colors',
                    selected?.id === alert.id && 'bg-cyber-accent/5'
                  )}>
                  <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
                  <td className="px-4 py-3 max-w-[300px] truncate">{alert.title}</td>
                  <td className="px-4 py-3 font-mono text-xs text-red-400">{alert.source_ip || '—'}</td>
                  <td className="px-4 py-3"><StatusBadge status={alert.status} /></td>
                  <td className="px-4 py-3 text-xs text-cyber-muted">{formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail Panel */}
        {selected && (
          <div className="w-96 bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-4 overflow-y-auto max-h-[calc(100vh-220px)]">
            <div className="flex items-center justify-between">
              <SeverityBadge severity={selected.severity} />
              <StatusBadge status={selected.status} />
            </div>
            <h3 className="text-lg font-semibold">{selected.title}</h3>
            {selected.description && <p className="text-sm text-cyber-muted">{selected.description}</p>}

            <div className="grid grid-cols-2 gap-3 text-sm">
              <div><span className="text-cyber-muted block text-xs">Rule</span>{selected.rule_name || '—'}</div>
              <div><span className="text-cyber-muted block text-xs">Source IP</span><code className="text-red-400">{selected.source_ip || '—'}</code></div>
              <div><span className="text-cyber-muted block text-xs">Dest IP</span><code>{selected.destination_ip || '—'}</code></div>
              <div><span className="text-cyber-muted block text-xs">Hostname</span>{selected.hostname || '—'}</div>
              <div><span className="text-cyber-muted block text-xs">User</span>{selected.username || '—'}</div>
              <div><span className="text-cyber-muted block text-xs">Process</span>{selected.process_name || '—'}</div>
              <div><span className="text-cyber-muted block text-xs">Events</span>{selected.event_count}</div>
              <div><span className="text-cyber-muted block text-xs">Created</span>{new Date(selected.created_at).toLocaleString()}</div>
            </div>

            {selected.mitre_techniques && selected.mitre_techniques.length > 0 && (
              <div>
                <span className="text-xs text-cyber-muted">MITRE ATT&CK</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selected.mitre_techniques.map(t => (
                    <span key={t} className="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded">{t}</span>
                  ))}
                </div>
              </div>
            )}

            {selected.raw_log && (
              <div>
                <span className="text-xs text-cyber-muted">Raw Log</span>
                <pre className="mt-1 p-2 bg-cyber-bg rounded text-xs text-green-400 overflow-x-auto max-h-32 font-mono">
                  {selected.raw_log}
                </pre>
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-wrap gap-2 pt-2 border-t border-cyber-border">
              {selected.status === 'new' && (
                <button onClick={() => handleStatusChange(selected, 'acknowledged')}
                  className="px-3 py-1.5 bg-yellow-500/20 text-yellow-400 text-xs rounded hover:bg-yellow-500/30">
                  Acknowledge
                </button>
              )}
              <button onClick={() => handleStatusChange(selected, 'investigating')}
                className="px-3 py-1.5 bg-blue-500/20 text-blue-400 text-xs rounded hover:bg-blue-500/30">
                Investigate
              </button>
              <button onClick={() => handleStatusChange(selected, 'resolved')}
                className="px-3 py-1.5 bg-green-500/20 text-green-400 text-xs rounded hover:bg-green-500/30">
                Resolve
              </button>
              <button onClick={() => handleStatusChange(selected, 'false_positive')}
                className="px-3 py-1.5 bg-gray-500/20 text-gray-400 text-xs rounded hover:bg-gray-500/30">
                False Positive
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
