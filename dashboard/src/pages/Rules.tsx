import { useEffect, useState } from 'react'
import { Shield, ToggleLeft, ToggleRight, Zap, Filter } from 'lucide-react'
import { api } from '../services/api'
import type { DetectionRule } from '../types'
import { clsx } from 'clsx'

export default function Rules() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<string>('all')

  useEffect(() => {
    const params = filter !== 'all' ? `?severity=${filter}` : ''
    api.getRules(params).then(setRules).catch(console.error).finally(() => setLoading(false))
  }, [filter])

  const handleToggle = async (ruleId: string) => {
    await api.toggleRule(ruleId)
    setRules(prev => prev.map(r => r.rule_id === ruleId ? { ...r, enabled: !r.enabled } : r))
  }

  const severities = ['all', 'critical', 'high', 'medium', 'low']

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Shield className="w-6 h-6 text-cyber-accent" /> Detection Rules
        </h1>
        <span className="text-sm text-cyber-muted">{rules.length} rules loaded</span>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <Filter className="w-4 h-4 text-cyber-muted" />
        {severities.map(s => (
          <button key={s} onClick={() => setFilter(s)}
            className={clsx('px-3 py-1 rounded text-xs font-medium',
              filter === s ? 'bg-cyber-accent text-white' : 'bg-cyber-card text-cyber-muted hover:text-white'
            )}>
            {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>

      {/* Rules Grid */}
      {loading ? (
        <div className="text-center py-12 text-cyber-muted">Loading rules...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {rules.map(rule => (
            <div key={rule.id} className={clsx(
              'bg-cyber-card border rounded-xl p-4 transition-all',
              rule.enabled ? 'border-cyber-border' : 'border-cyber-border/50 opacity-60'
            )}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`severity-${rule.severity} px-2 py-0.5 rounded text-xs font-semibold uppercase`}>
                    {rule.severity}
                  </span>
                  <span className="text-xs text-cyber-muted font-mono">{rule.rule_id}</span>
                </div>
                <button onClick={() => handleToggle(rule.rule_id)}>
                  {rule.enabled
                    ? <ToggleRight className="w-5 h-5 text-cyber-success" />
                    : <ToggleLeft className="w-5 h-5 text-cyber-muted" />
                  }
                </button>
              </div>

              <h3 className="font-semibold text-sm mb-1">{rule.name}</h3>
              {rule.description && (
                <p className="text-xs text-cyber-muted line-clamp-2 mb-3">{rule.description}</p>
              )}

              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1 text-yellow-400">
                  <Zap className="w-3 h-3" />
                  <span>{rule.total_hits} hits</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-cyber-muted">Level:</span>
                  <span className="font-semibold">{rule.level}</span>
                </div>
                <span className="px-1.5 py-0.5 bg-cyber-bg rounded text-[10px] text-cyber-muted">
                  {rule.rule_type}
                </span>
              </div>

              {rule.mitre_techniques && rule.mitre_techniques.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-3">
                  {rule.mitre_techniques.slice(0, 4).map(t => (
                    <span key={t} className="px-1.5 py-0.5 bg-purple-500/15 text-purple-400 text-[10px] rounded">{t}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
