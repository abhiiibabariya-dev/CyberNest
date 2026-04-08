import { useState, useMemo, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Bell, Filter, X, Search, ChevronUp, ChevronDown, CheckSquare, Square,
  User, Clock, Shield, Play, ExternalLink, FileText, AlertTriangle,
  ChevronRight, Crosshair, ArrowRight,
} from 'lucide-react'
import { api } from '../services/api'
import type { Alert } from '../types'
import { clsx } from 'clsx'
import { formatDistanceToNow, format } from 'date-fns'
import { useAppStore } from '../store'

const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
const ALL_STATUSES = ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive', 'escalated'] as const

type SortField = 'severity' | 'title' | 'source_ip' | 'created_at' | 'status'
type SortDir = 'asc' | 'desc'

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`severity-${severity} px-2 py-0.5 rounded text-xs font-semibold uppercase`}>{severity}</span>
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-${status} px-2 py-0.5 rounded text-xs font-medium`}>{status.replace(/_/g, ' ')}</span>
}

export default function Alerts() {
  const queryClient = useQueryClient()
  const { selectedAlerts, toggleAlertSelection, selectAllAlerts, clearAlertSelection, sidePanel, openSidePanel, closeSidePanel } = useAppStore()

  // Filters
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set())
  const [statusFilter, setStatusFilter] = useState<Set<string>>(new Set())
  const [ruleSearch, setRuleSearch] = useState('')
  const [sourceIpFilter, setSourceIpFilter] = useState('')
  const [assigneeFilter, setAssigneeFilter] = useState('')
  const [dateRange, setDateRange] = useState('24h')
  const [sortField, setSortField] = useState<SortField>('created_at')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [detailTab, setDetailTab] = useState<'overview' | 'rawlog' | 'related' | 'threatintel' | 'mitre'>('overview')

  const { data: alerts = [], isLoading } = useQuery<Alert[]>({
    queryKey: ['alerts'],
    queryFn: () => api.getAlerts('?limit=500'),
    refetchInterval: 15_000,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { status?: string; assigned_to?: string } }) => api.updateAlert(id, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const toggleSeverity = (s: string) => {
    setSeverityFilter(prev => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })
  }

  const toggleStatus = (s: string) => {
    setStatusFilter(prev => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })
  }

  const filtered = useMemo(() => {
    let result = [...alerts]
    if (severityFilter.size > 0) result = result.filter(a => severityFilter.has(a.severity))
    if (statusFilter.size > 0) result = result.filter(a => statusFilter.has(a.status))
    if (ruleSearch) result = result.filter(a => (a.rule_name || a.title || '').toLowerCase().includes(ruleSearch.toLowerCase()))
    if (sourceIpFilter) result = result.filter(a => (a.source_ip || '').includes(sourceIpFilter))
    if (assigneeFilter) result = result.filter(a => (a.assignee_id || '').includes(assigneeFilter))

    result.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'severity': cmp = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5); break
        case 'title': cmp = (a.title || '').localeCompare(b.title || ''); break
        case 'source_ip': cmp = (a.source_ip || '').localeCompare(b.source_ip || ''); break
        case 'status': cmp = a.status.localeCompare(b.status); break
        case 'created_at': cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime(); break
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return result
  }, [alerts, severityFilter, statusFilter, ruleSearch, sourceIpFilter, assigneeFilter, sortField, sortDir])

  const selectedAlert = useMemo(() => {
    if (!sidePanel.open || !sidePanel.alertId) return null
    return alerts.find(a => a.id === sidePanel.alertId) ?? null
  }, [alerts, sidePanel])

  const handleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ChevronDown className="w-3 h-3 opacity-30" />
    return sortDir === 'asc' ? <ChevronUp className="w-3 h-3 text-cyber-accent" /> : <ChevronDown className="w-3 h-3 text-cyber-accent" />
  }

  const handleBulkAction = (action: string) => {
    const ids = Array.from(selectedAlerts)
    if (ids.length === 0) return
    ids.forEach(id => {
      if (action === 'acknowledge') updateMutation.mutate({ id, data: { status: 'acknowledged' } })
      else if (action === 'close') updateMutation.mutate({ id, data: { status: 'resolved' } })
    })
    clearAlertSelection()
  }

  const allSelected = filtered.length > 0 && filtered.every(a => selectedAlerts.has(a.id))

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Bell className="w-6 h-6 text-cyber-accent" /> Alert Center
        </h1>
        <span className="text-sm text-cyber-muted">{filtered.length} of {alerts.length} alerts</span>
      </div>

      {/* Filter Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4 text-cyber-muted flex-shrink-0" />

          {/* Severity chips */}
          <div className="flex items-center gap-1">
            <span className="text-xs text-cyber-muted mr-1">Severity:</span>
            {ALL_SEVERITIES.map(s => (
              <button key={s} onClick={() => toggleSeverity(s)}
                className={clsx('chip', severityFilter.has(s) ? 'chip-active' : 'chip-inactive')}>
                {s}
              </button>
            ))}
          </div>

          {/* Status chips */}
          <div className="flex items-center gap-1">
            <span className="text-xs text-cyber-muted mr-1">Status:</span>
            {ALL_STATUSES.map(s => (
              <button key={s} onClick={() => toggleStatus(s)}
                className={clsx('chip', statusFilter.has(s) ? 'chip-active' : 'chip-inactive')}>
                {s.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Rule search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
            <input value={ruleSearch} onChange={e => setRuleSearch(e.target.value)}
              placeholder="Search rule name..." className="w-full pl-8 pr-3 py-1.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent" />
          </div>

          {/* Source IP */}
          <input value={sourceIpFilter} onChange={e => setSourceIpFilter(e.target.value)}
            placeholder="Source IP" className="w-36 px-3 py-1.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-white font-mono placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent" />

          {/* Assignee */}
          <input value={assigneeFilter} onChange={e => setAssigneeFilter(e.target.value)}
            placeholder="Assignee" className="w-32 px-3 py-1.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent" />

          {/* Date range */}
          <select value={dateRange} onChange={e => setDateRange(e.target.value)}
            className="px-3 py-1.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs text-white">
            <option value="1h">Last 1h</option>
            <option value="4h">Last 4h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
            <option value="30d">Last 30d</option>
          </select>

          {/* Clear filters */}
          {(severityFilter.size > 0 || statusFilter.size > 0 || ruleSearch || sourceIpFilter || assigneeFilter) && (
            <button onClick={() => {
              setSeverityFilter(new Set()); setStatusFilter(new Set()); setRuleSearch(''); setSourceIpFilter(''); setAssigneeFilter('')
            }} className="flex items-center gap-1 text-xs text-cyber-accent hover:text-cyber-accent-hover">
              <X className="w-3 h-3" /> Clear
            </button>
          )}
        </div>

        {/* Bulk actions */}
        {selectedAlerts.size > 0 && (
          <div className="flex items-center gap-2 pt-2 border-t border-cyber-border">
            <span className="text-xs text-cyber-accent font-medium">{selectedAlerts.size} selected</span>
            <button onClick={() => handleBulkAction('acknowledge')} className="px-3 py-1 bg-yellow-500/20 text-yellow-400 text-xs rounded hover:bg-yellow-500/30">Acknowledge</button>
            <button onClick={() => handleBulkAction('close')} className="px-3 py-1 bg-green-500/20 text-green-400 text-xs rounded hover:bg-green-500/30">Close</button>
            <button className="px-3 py-1 bg-purple-500/20 text-purple-400 text-xs rounded hover:bg-purple-500/30">Create Case</button>
            <button onClick={clearAlertSelection} className="ml-auto text-xs text-cyber-muted hover:text-white">Deselect all</button>
          </div>
        )}
      </div>

      <div className="flex gap-4">
        {/* Alert Table */}
        <div className={clsx('bg-cyber-card border border-cyber-border rounded-xl overflow-hidden transition-all', sidePanel.open ? 'flex-1' : 'w-full')}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                  <th className="px-3 py-3 w-10">
                    <button onClick={() => allSelected ? clearAlertSelection() : selectAllAlerts(filtered.map(a => a.id))}>
                      {allSelected ? <CheckSquare className="w-4 h-4 text-cyber-accent" /> : <Square className="w-4 h-4" />}
                    </button>
                  </th>
                  <th className="px-3 py-3 cursor-pointer" onClick={() => handleSort('severity')}>
                    <span className="flex items-center gap-1">Severity <SortIcon field="severity" /></span>
                  </th>
                  <th className="px-3 py-3 cursor-pointer" onClick={() => handleSort('title')}>
                    <span className="flex items-center gap-1">Rule Name <SortIcon field="title" /></span>
                  </th>
                  <th className="px-3 py-3 cursor-pointer" onClick={() => handleSort('source_ip')}>
                    <span className="flex items-center gap-1">Source IP <SortIcon field="source_ip" /></span>
                  </th>
                  <th className="px-3 py-3">Dest IP</th>
                  <th className="px-3 py-3">Hostname</th>
                  <th className="px-3 py-3">User</th>
                  <th className="px-3 py-3 cursor-pointer" onClick={() => handleSort('created_at')}>
                    <span className="flex items-center gap-1">Time <SortIcon field="created_at" /></span>
                  </th>
                  <th className="px-3 py-3 cursor-pointer" onClick={() => handleSort('status')}>
                    <span className="flex items-center gap-1">Status <SortIcon field="status" /></span>
                  </th>
                  <th className="px-3 py-3">Assignee</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={10} className="text-center py-8 text-cyber-muted">Loading alerts...</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={10} className="text-center py-8 text-cyber-muted">No alerts match the current filters</td></tr>
                ) : filtered.map(alert => (
                  <tr key={alert.id}
                    className={clsx('data-row border-b border-cyber-border/30 cursor-pointer transition-colors',
                      sidePanel.alertId === alert.id && 'bg-cyber-accent/5',
                      selectedAlerts.has(alert.id) && 'bg-cyber-accent/8'
                    )}
                    onClick={() => openSidePanel(alert.id)}
                  >
                    <td className="px-3 py-2.5" onClick={e => { e.stopPropagation(); toggleAlertSelection(alert.id) }}>
                      {selectedAlerts.has(alert.id) ? <CheckSquare className="w-4 h-4 text-cyber-accent" /> : <Square className="w-4 h-4 text-cyber-muted" />}
                    </td>
                    <td className="px-3 py-2.5"><SeverityBadge severity={alert.severity} /></td>
                    <td className="px-3 py-2.5 max-w-[200px] truncate font-medium">{alert.rule_name || alert.title}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-red-400">{alert.source_ip || '--'}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-cyber-muted">{alert.destination_ip || '--'}</td>
                    <td className="px-3 py-2.5 text-xs">{alert.hostname || '--'}</td>
                    <td className="px-3 py-2.5 text-xs">{alert.username || '--'}</td>
                    <td className="px-3 py-2.5 text-xs text-cyber-muted whitespace-nowrap">{formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}</td>
                    <td className="px-3 py-2.5"><StatusBadge status={alert.status} /></td>
                    <td className="px-3 py-2.5 text-xs text-cyber-muted">{alert.assignee_id ? alert.assignee_id.substring(0, 8) : '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Side Panel */}
        {sidePanel.open && selectedAlert && (
          <div className="w-[420px] flex-shrink-0 bg-cyber-card border border-cyber-border rounded-xl slide-panel overflow-hidden flex flex-col max-h-[calc(100vh-220px)]">
            {/* Header */}
            <div className="p-4 border-b border-cyber-border">
              <div className="flex items-center justify-between mb-2">
                <SeverityBadge severity={selectedAlert.severity} />
                <button onClick={closeSidePanel} className="text-cyber-muted hover:text-white"><X className="w-4 h-4" /></button>
              </div>
              <h3 className="text-lg font-semibold">{selectedAlert.rule_name || selectedAlert.title}</h3>
              <p className="text-xs text-cyber-muted mt-1">
                {format(new Date(selectedAlert.created_at), 'MMM d, yyyy HH:mm:ss')}
              </p>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-cyber-border px-4">
              {(['overview', 'rawlog', 'related', 'threatintel', 'mitre'] as const).map(tab => (
                <button key={tab} onClick={() => setDetailTab(tab)}
                  className={clsx('px-3 py-2 text-xs font-medium border-b-2 transition-colors',
                    detailTab === tab ? 'border-cyber-accent text-cyber-accent' : 'border-transparent text-cyber-muted hover:text-white'
                  )}>
                  {tab === 'rawlog' ? 'Raw Log' : tab === 'threatintel' ? 'Threat Intel' : tab === 'mitre' ? 'MITRE' : tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto p-4">
              {detailTab === 'overview' && (
                <div className="space-y-3">
                  {selectedAlert.description && <p className="text-sm text-cyber-muted">{selectedAlert.description}</p>}
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Rule ID</span><code className="text-xs font-mono">{selectedAlert.rule_id || '--'}</code></div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Status</span><StatusBadge status={selectedAlert.status} /></div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Source IP</span><code className="text-red-400 text-xs font-mono">{selectedAlert.source_ip || '--'}</code></div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Dest IP</span><code className="text-xs font-mono">{selectedAlert.destination_ip || '--'}</code></div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Hostname</span>{selectedAlert.hostname || '--'}</div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">User</span>{selectedAlert.username || '--'}</div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Process</span>{selectedAlert.process_name || '--'}</div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Event Count</span><span className="font-mono">{selectedAlert.event_count}</span></div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Incident</span>{selectedAlert.incident_id ? <code className="text-xs font-mono text-cyber-accent">{selectedAlert.incident_id.substring(0, 8)}</code> : '--'}</div>
                    <div><span className="text-cyber-muted block text-xs mb-0.5">Assignee</span>{selectedAlert.assignee_id || 'Unassigned'}</div>
                  </div>

                  {selectedAlert.geo_data && Object.keys(selectedAlert.geo_data).length > 0 && (
                    <div>
                      <span className="text-xs text-cyber-muted block mb-1">Geo Data</span>
                      <pre className="p-2 bg-cyber-bg rounded text-xs text-cyber-accent font-mono overflow-x-auto">
                        {JSON.stringify(selectedAlert.geo_data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {detailTab === 'rawlog' && (
                <div>
                  {selectedAlert.raw_log ? (
                    <pre className="p-3 bg-cyber-bg rounded-lg text-xs text-green-400 font-mono whitespace-pre-wrap overflow-x-auto max-h-[400px]">
                      {selectedAlert.raw_log}
                    </pre>
                  ) : (
                    <p className="text-sm text-cyber-muted text-center py-8">No raw log available</p>
                  )}
                </div>
              )}

              {detailTab === 'related' && (
                <div className="text-center py-8">
                  <Search className="w-8 h-8 text-cyber-muted/30 mx-auto mb-2" />
                  <p className="text-sm text-cyber-muted">Related events based on source IP and timeframe</p>
                  <p className="text-xs text-cyber-muted mt-1">Source: {selectedAlert.source_ip || 'N/A'} | Window: +/- 5 minutes</p>
                </div>
              )}

              {detailTab === 'threatintel' && (
                <div className="space-y-3">
                  {selectedAlert.threat_intel && Object.keys(selectedAlert.threat_intel).length > 0 ? (
                    <pre className="p-3 bg-cyber-bg rounded-lg text-xs text-cyber-accent font-mono whitespace-pre-wrap overflow-x-auto">
                      {JSON.stringify(selectedAlert.threat_intel, null, 2)}
                    </pre>
                  ) : (
                    <div className="text-center py-8">
                      <Crosshair className="w-8 h-8 text-cyber-muted/30 mx-auto mb-2" />
                      <p className="text-sm text-cyber-muted">No threat intel enrichment available</p>
                      <p className="text-xs text-cyber-muted mt-1">Run IOC lookup to enrich this alert</p>
                    </div>
                  )}
                </div>
              )}

              {detailTab === 'mitre' && (
                <div className="space-y-3">
                  {selectedAlert.mitre_tactics && selectedAlert.mitre_tactics.length > 0 && (
                    <div>
                      <span className="text-xs text-cyber-muted block mb-1.5">Tactics</span>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAlert.mitre_tactics.map(t => (
                          <span key={t} className="px-2 py-1 bg-purple-500/15 text-purple-400 text-xs rounded">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedAlert.mitre_techniques && selectedAlert.mitre_techniques.length > 0 && (
                    <div>
                      <span className="text-xs text-cyber-muted block mb-1.5">Techniques</span>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAlert.mitre_techniques.map(t => (
                          <span key={t} className="px-2 py-1 bg-blue-500/15 text-blue-400 text-xs rounded font-mono">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(!selectedAlert.mitre_tactics || selectedAlert.mitre_tactics.length === 0) &&
                   (!selectedAlert.mitre_techniques || selectedAlert.mitre_techniques.length === 0) && (
                    <div className="text-center py-8">
                      <Shield className="w-8 h-8 text-cyber-muted/30 mx-auto mb-2" />
                      <p className="text-sm text-cyber-muted">No MITRE ATT&CK mapping</p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="p-4 border-t border-cyber-border space-y-2">
              <div className="flex items-center gap-2">
                <select
                  value={selectedAlert.status}
                  onChange={e => updateMutation.mutate({ id: selectedAlert.id, data: { status: e.target.value } })}
                  className="flex-1 px-3 py-1.5 bg-cyber-bg border border-cyber-border rounded text-xs text-white"
                >
                  {ALL_STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
                </select>
                <button className="px-3 py-1.5 bg-purple-500/20 text-purple-400 text-xs rounded hover:bg-purple-500/30 flex items-center gap-1">
                  <User className="w-3 h-3" /> Assign
                </button>
              </div>
              <div className="flex items-center gap-2">
                <button className="flex-1 px-3 py-1.5 bg-cyber-accent/15 text-cyber-accent text-xs rounded hover:bg-cyber-accent/25 flex items-center justify-center gap-1">
                  <FileText className="w-3 h-3" /> Create Case
                </button>
                <button className="flex-1 px-3 py-1.5 bg-green-500/15 text-green-400 text-xs rounded hover:bg-green-500/25 flex items-center justify-center gap-1">
                  <Play className="w-3 h-3" /> Run Playbook
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

