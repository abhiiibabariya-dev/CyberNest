import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield, ToggleLeft, ToggleRight, Zap, Filter, Plus, X, Search,
  ChevronDown, ChevronUp, Play, Code, BarChart3, Info, Loader2,
} from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { api } from '../services/api'
import type { DetectionRule } from '../types'
import { clsx } from 'clsx'
import { format } from 'date-fns'

const LEVEL_COLORS: Record<string, string> = {
  critical: '#ff4444', high: '#ff8800', medium: '#ffaa00', low: '#00d4ff', info: '#8b949e',
}

function getLevelColor(level: number): string {
  if (level >= 12) return LEVEL_COLORS.critical
  if (level >= 8) return LEVEL_COLORS.high
  if (level >= 4) return LEVEL_COLORS.medium
  if (level >= 1) return LEVEL_COLORS.low
  return LEVEL_COLORS.info
}

function getLevelLabel(level: number): string {
  if (level >= 12) return 'critical'
  if (level >= 8) return 'high'
  if (level >= 4) return 'medium'
  if (level >= 1) return 'low'
  return 'info'
}

export default function RulesManager() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null)
  const [detailTab, setDetailTab] = useState<'overview' | 'content' | 'stats' | 'test'>('overview')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [testInput, setTestInput] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)

  // Create rule form
  const [newRule, setNewRule] = useState({
    name: '', description: '', severity: 'medium', level: 5, rule_type: 'sigma',
    rule_format: 'yaml', logic: '', group: '', tags: '',
  })

  const { data: rules = [], isLoading } = useQuery<DetectionRule[]>({
    queryKey: ['rules', filter],
    queryFn: () => api.getRules(filter !== 'all' ? `?severity=${filter}` : ''),
  })

  const toggleMutation = useMutation({
    mutationFn: (ruleId: string) => api.toggleRule(ruleId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
  })

  const createMutation = useMutation({
    mutationFn: (data: unknown) => api.createRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      setShowCreateModal(false)
      setNewRule({ name: '', description: '', severity: 'medium', level: 5, rule_type: 'sigma', rule_format: 'yaml', logic: '', group: '', tags: '' })
    },
  })

  const filteredRules = useMemo(() => {
    if (!search) return rules
    return rules.filter(r =>
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      (r.rule_id ?? '').toLowerCase().includes(search.toLowerCase()) ||
      (r.description || '').toLowerCase().includes(search.toLowerCase())
    )
  }, [rules, search])

  const statsEnabled = rules.filter(r => r.enabled).length
  const statsDisabled = rules.filter(r => !r.enabled).length
  const statsFired = rules.filter(r => (r.total_hits ?? 0) > 0).length

  const handleCreateRule = () => {
    createMutation.mutate({
      name: newRule.name,
      description: newRule.description,
      severity: newRule.severity,
      level: newRule.level,
      rule_type: newRule.rule_type,
      rule_format: newRule.rule_format,
      logic: newRule.logic ? JSON.parse(newRule.logic) : {},
      group: newRule.group || null,
      tags: newRule.tags ? newRule.tags.split(',').map(t => t.trim()) : [],
    })
  }

  // Mock 30-day stats for the selected rule
  const ruleStatsChart = useMemo(() => {
    if (!selectedRule) return []
    return Array.from({ length: 30 }, (_, i) => ({
      day: format(new Date(Date.now() - (29 - i) * 86400000), 'MMM d'),
      hits: Math.floor(Math.random() * (((selectedRule.total_hits ?? 0) / 10) + 1)),
    }))
  }, [selectedRule])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Shield className="w-6 h-6 text-cyber-accent" /> Detection Rules
        </h1>
        <button onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 px-4 py-2 bg-cyber-accent text-white rounded-lg text-sm hover:bg-cyber-accent-hover">
          <Plus className="w-4 h-4" /> Create Rule
        </button>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Rules', value: rules.length, color: '#00d4ff' },
          { label: 'Enabled', value: statsEnabled, color: '#00ff88' },
          { label: 'Disabled', value: statsDisabled, color: '#8b949e' },
          { label: 'Fired Today', value: statsFired, color: '#ffaa00' },
        ].map(stat => (
          <div key={stat.label} className="bg-cyber-card border border-cyber-border rounded-xl p-3 flex items-center justify-between">
            <span className="text-xs text-cyber-muted">{stat.label}</span>
            <span className="text-lg font-bold font-mono" style={{ color: stat.color }}>{stat.value}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search rules..." className="w-full pl-9 pr-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent" />
        </div>
        <div className="flex items-center gap-1">
          <Filter className="w-4 h-4 text-cyber-muted" />
          {['all', 'critical', 'high', 'medium', 'low'].map(s => (
            <button key={s} onClick={() => setFilter(s)}
              className={clsx('px-3 py-1.5 rounded text-xs font-medium',
                filter === s ? 'bg-cyber-accent/20 text-cyber-accent' : 'text-cyber-muted hover:text-white'
              )}>
              {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Rule Table */}
      {isLoading ? (
        <div className="text-center py-12 text-cyber-muted"><Loader2 className="w-6 h-6 animate-spin mx-auto" /></div>
      ) : (
        <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                <th className="px-4 py-3">Level</th>
                <th className="px-4 py-3">Rule ID</th>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">MITRE</th>
                <th className="px-4 py-3">Hits</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map(rule => (
                <tr key={rule.id} className="data-row border-b border-cyber-border/30 cursor-pointer"
                  onClick={() => { setSelectedRule(rule); setDetailTab('overview') }}>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: getLevelColor(rule.level ?? 0) }} />
                      <span className={`severity-${getLevelLabel(rule.level ?? 0)} px-2 py-0.5 rounded text-[10px] font-semibold uppercase`}>
                        {rule.level ?? 0}
                      </span>
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-cyber-accent">{rule.rule_id}</td>
                  <td className="px-4 py-3 font-medium max-w-[200px] truncate">{rule.name}</td>
                  <td className="px-4 py-3 text-xs text-cyber-muted">{rule.group || rule.rule_type}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(rule.mitre_techniques || []).slice(0, 2).map(t => (
                        <span key={t} className="px-1.5 py-0.5 bg-purple-500/15 text-purple-400 text-[10px] rounded font-mono">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1 text-xs text-yellow-400 font-mono">
                      <Zap className="w-3 h-3" /> {rule.total_hits}
                    </span>
                  </td>
                  <td className="px-4 py-3" onClick={e => { e.stopPropagation(); toggleMutation.mutate(rule.rule_id ?? rule.id) }}>
                    {rule.enabled
                      ? <ToggleRight className="w-6 h-6 text-cyber-success cursor-pointer" />
                      : <ToggleLeft className="w-6 h-6 text-cyber-muted cursor-pointer" />
                    }
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={e => { e.stopPropagation(); setSelectedRule(rule); setDetailTab('overview') }}
                      className="text-xs text-cyber-accent hover:underline">View</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Rule Detail Modal */}
      {selectedRule && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-8" onClick={() => setSelectedRule(null)}>
          <div className="bg-cyber-card border border-cyber-border rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
            {/* Modal Header */}
            <div className="p-6 border-b border-cyber-border">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className={`severity-${getLevelLabel(selectedRule.level ?? 0)} px-2.5 py-1 rounded text-xs font-semibold uppercase`}>
                    Level {selectedRule.level}
                  </span>
                  <code className="text-sm text-cyber-accent font-mono">{selectedRule.rule_id}</code>
                  {selectedRule.enabled
                    ? <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">Enabled</span>
                    : <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 text-xs rounded">Disabled</span>
                  }
                </div>
                <button onClick={() => setSelectedRule(null)} className="text-cyber-muted hover:text-white"><X className="w-5 h-5" /></button>
              </div>
              <h2 className="text-xl font-bold">{selectedRule.name}</h2>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-cyber-border px-6">
              {([
                { id: 'overview', icon: Info, label: 'Overview' },
                { id: 'content', icon: Code, label: 'Rule Content' },
                { id: 'stats', icon: BarChart3, label: 'Statistics' },
                { id: 'test', icon: Play, label: 'Test Rule' },
              ] as const).map(tab => (
                <button key={tab.id} onClick={() => setDetailTab(tab.id)}
                  className={clsx('flex items-center gap-1.5 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                    detailTab === tab.id ? 'border-cyber-accent text-cyber-accent' : 'border-transparent text-cyber-muted hover:text-white'
                  )}>
                  <tab.icon className="w-4 h-4" /> {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto p-6">
              {detailTab === 'overview' && (
                <div className="space-y-4">
                  {selectedRule.description && (
                    <div>
                      <h4 className="text-xs text-cyber-muted uppercase mb-1">Description</h4>
                      <p className="text-sm">{selectedRule.description}</p>
                    </div>
                  )}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Type</span>{selectedRule.rule_type}</div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Format</span>{selectedRule.rule_format}</div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Group</span>{selectedRule.group || 'None'}</div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Severity</span>
                      <span className={`severity-${selectedRule.severity} px-2 py-0.5 rounded text-xs`}>{selectedRule.severity}</span>
                    </div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Total Hits</span><span className="font-mono text-yellow-400">{selectedRule.total_hits}</span></div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Last Hit</span>{selectedRule.last_hit_at ? format(new Date(selectedRule.last_hit_at), 'MMM d HH:mm') : 'Never'}</div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Created</span>{format(new Date(selectedRule.created_at), 'MMM d, yyyy')}</div>
                    <div><span className="text-xs text-cyber-muted block mb-0.5">Level</span>{selectedRule.level}/15</div>
                  </div>
                  {selectedRule.mitre_tactics && selectedRule.mitre_tactics.length > 0 && (
                    <div>
                      <h4 className="text-xs text-cyber-muted uppercase mb-1">MITRE Tactics</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedRule.mitre_tactics.map(t => (
                          <span key={t} className="px-2 py-1 bg-purple-500/15 text-purple-400 text-xs rounded">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedRule.mitre_techniques && selectedRule.mitre_techniques.length > 0 && (
                    <div>
                      <h4 className="text-xs text-cyber-muted uppercase mb-1">MITRE Techniques</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedRule.mitre_techniques.map(t => (
                          <span key={t} className="px-2 py-1 bg-blue-500/15 text-blue-400 text-xs rounded font-mono">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedRule.tags && selectedRule.tags.length > 0 && (
                    <div>
                      <h4 className="text-xs text-cyber-muted uppercase mb-1">Tags</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedRule.tags.map(t => (
                          <span key={t} className="px-2 py-1 bg-cyber-bg text-cyber-muted text-xs rounded">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {detailTab === 'content' && (
                <div>
                  <div className="bg-cyber-bg border border-cyber-border rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2 border-b border-cyber-border bg-cyber-card">
                      <span className="text-xs text-cyber-muted">Rule Logic ({(selectedRule.rule_format ?? 'yaml').toUpperCase()})</span>
                      <button className="text-xs text-cyber-accent hover:underline">Edit</button>
                    </div>
                    <pre className="p-4 text-sm font-mono text-green-400 whitespace-pre-wrap overflow-x-auto max-h-[400px]">
                      {JSON.stringify(selectedRule.logic, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {detailTab === 'stats' && (
                <div className="space-y-4">
                  <div className="bg-cyber-bg rounded-lg p-4">
                    <h4 className="text-xs text-cyber-muted uppercase mb-3">Hit Count (Last 30 Days)</h4>
                    <ResponsiveContainer width="100%" height={250}>
                      <LineChart data={ruleStatsChart}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                        <XAxis dataKey="day" tick={{ fill: '#8b949e', fontSize: 10 }} axisLine={false} tickLine={false} />
                        <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} axisLine={false} tickLine={false} />
                        <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, color: '#e6edf3' }} />
                        <Line type="monotone" dataKey="hits" stroke="#00d4ff" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {detailTab === 'test' && (
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-semibold mb-2">Test Rule Against Event</h4>
                    <p className="text-xs text-cyber-muted mb-3">Paste a JSON event to test if this rule would match.</p>
                    <textarea
                      value={testInput}
                      onChange={e => setTestInput(e.target.value)}
                      placeholder='{"source": {"ip": "192.168.1.1"}, "event": {"action": "login_failure"}, ...}'
                      className="w-full h-48 px-4 py-3 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent resize-none"
                    />
                  </div>
                  <button
                    onClick={() => {
                      try {
                        JSON.parse(testInput)
                        setTestResult(Math.random() > 0.5 ? 'MATCH - Rule would trigger on this event' : 'NO MATCH - Rule conditions not met')
                      } catch {
                        setTestResult('ERROR - Invalid JSON input')
                      }
                    }}
                    className="px-4 py-2 bg-cyber-accent text-white rounded-lg text-sm hover:bg-cyber-accent-hover flex items-center gap-2">
                    <Play className="w-4 h-4" /> Run Test
                  </button>
                  {testResult && (
                    <div className={clsx('p-4 rounded-lg text-sm font-mono',
                      testResult.startsWith('MATCH') ? 'bg-green-500/15 text-green-400 border border-green-500/30' :
                      testResult.startsWith('ERROR') ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                      'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                    )}>
                      {testResult}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-8" onClick={() => setShowCreateModal(false)}>
          <div className="bg-cyber-card border border-cyber-border rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-cyber-border flex items-center justify-between">
              <h2 className="text-xl font-bold">Create Detection Rule</h2>
              <button onClick={() => setShowCreateModal(false)} className="text-cyber-muted hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              <div>
                <label className="block text-xs text-cyber-muted mb-1">Rule Name *</label>
                <input value={newRule.name} onChange={e => setNewRule(r => ({ ...r, name: e.target.value }))}
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white focus:outline-none focus:border-cyber-accent" />
              </div>
              <div>
                <label className="block text-xs text-cyber-muted mb-1">Description</label>
                <textarea value={newRule.description} onChange={e => setNewRule(r => ({ ...r, description: e.target.value }))}
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white focus:outline-none focus:border-cyber-accent h-20 resize-none" />
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-cyber-muted mb-1">Severity</label>
                  <select value={newRule.severity} onChange={e => setNewRule(r => ({ ...r, severity: e.target.value }))}
                    className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white">
                    {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-cyber-muted mb-1">Level (0-15)</label>
                  <input type="number" min={0} max={15} value={newRule.level} onChange={e => setNewRule(r => ({ ...r, level: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white" />
                </div>
                <div>
                  <label className="block text-xs text-cyber-muted mb-1">Type</label>
                  <select value={newRule.rule_type} onChange={e => setNewRule(r => ({ ...r, rule_type: e.target.value }))}
                    className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white">
                    <option value="sigma">Sigma</option>
                    <option value="yara">YARA</option>
                    <option value="suricata">Suricata</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs text-cyber-muted mb-1">Rule Logic (JSON)</label>
                <textarea value={newRule.logic} onChange={e => setNewRule(r => ({ ...r, logic: e.target.value }))}
                  placeholder='{"detection": {"selection": {"EventID": 4625}, "condition": "selection"}, "logsource": {"product": "windows"}}'
                  className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-green-400 focus:outline-none focus:border-cyber-accent h-32 resize-none" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-cyber-muted mb-1">Group</label>
                  <input value={newRule.group} onChange={e => setNewRule(r => ({ ...r, group: e.target.value }))}
                    className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white" />
                </div>
                <div>
                  <label className="block text-xs text-cyber-muted mb-1">Tags (comma separated)</label>
                  <input value={newRule.tags} onChange={e => setNewRule(r => ({ ...r, tags: e.target.value }))}
                    className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white" />
                </div>
              </div>
            </div>
            <div className="p-6 border-t border-cyber-border flex justify-end gap-2">
              <button onClick={() => setShowCreateModal(false)} className="px-4 py-2 text-sm text-cyber-muted hover:text-white">Cancel</button>
              <button onClick={handleCreateRule} disabled={!newRule.name || createMutation.isPending}
                className="px-6 py-2 bg-cyber-accent text-white rounded-lg text-sm hover:bg-cyber-accent-hover disabled:opacity-50">
                {createMutation.isPending ? 'Creating...' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

