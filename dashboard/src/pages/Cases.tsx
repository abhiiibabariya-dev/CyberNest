import { useEffect, useState } from 'react'
import { FileText, Plus, Clock, User, Tag } from 'lucide-react'
import { api } from '../services/api'
import type { Incident } from '../types'
import { clsx } from 'clsx'
import { formatDistanceToNow } from 'date-fns'

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  in_progress: 'bg-blue-500/20 text-blue-400',
  contained: 'bg-yellow-500/20 text-yellow-400',
  eradicated: 'bg-purple-500/20 text-purple-400',
  recovered: 'bg-green-500/20 text-green-400',
  closed: 'bg-gray-500/20 text-gray-400',
}

export default function Cases() {
  const [cases, setCases] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Incident | null>(null)

  useEffect(() => {
    api.getCases().then(setCases).catch(console.error).finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <FileText className="w-6 h-6 text-cyber-accent" /> Cases / Incidents
        </h1>
        <button className="flex items-center gap-1.5 px-4 py-2 bg-cyber-accent text-white rounded-lg text-sm hover:bg-cyber-accent-hover">
          <Plus className="w-4 h-4" /> New Case
        </button>
      </div>

      <div className="flex gap-4">
        {/* Case List */}
        <div className="flex-1 space-y-3">
          {loading ? (
            <div className="text-center py-12 text-cyber-muted">Loading cases...</div>
          ) : cases.length === 0 ? (
            <div className="text-center py-12 text-cyber-muted">No cases found</div>
          ) : cases.map(c => (
            <div key={c.id} onClick={() => setSelected(c)}
              className={clsx(
                'bg-cyber-card border border-cyber-border rounded-xl p-4 cursor-pointer transition-all hover:border-cyber-accent/30',
                selected?.id === c.id && 'border-cyber-accent/50 bg-cyber-accent/5'
              )}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <code className="text-xs text-cyber-accent font-mono">{c.case_id}</code>
                  <span className={`severity-${c.severity} px-2 py-0.5 rounded text-xs font-semibold uppercase`}>
                    {c.severity}
                  </span>
                </div>
                <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', STATUS_COLORS[c.status] || STATUS_COLORS.open)}>
                  {c.status.replace('_', ' ')}
                </span>
              </div>
              <h3 className="font-semibold text-sm">{c.title}</h3>
              {c.description && <p className="text-xs text-cyber-muted mt-1 line-clamp-2">{c.description}</p>}
              <div className="flex items-center gap-4 mt-3 text-xs text-cyber-muted">
                <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{formatDistanceToNow(new Date(c.created_at), { addSuffix: true })}</span>
                {c.tags && c.tags.length > 0 && (
                  <span className="flex items-center gap-1"><Tag className="w-3 h-3" />{c.tags.join(', ')}</span>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Timeline Panel */}
        {selected && (
          <div className="w-96 bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-4 max-h-[calc(100vh-220px)] overflow-y-auto">
            <div className="flex items-center justify-between">
              <code className="text-cyber-accent font-mono text-sm">{selected.case_id}</code>
              <span className={clsx('px-2 py-0.5 rounded text-xs', STATUS_COLORS[selected.status])}>
                {selected.status.replace('_', ' ')}
              </span>
            </div>
            <h3 className="text-lg font-semibold">{selected.title}</h3>
            {selected.description && <p className="text-sm text-cyber-muted">{selected.description}</p>}

            {selected.mitre_techniques && selected.mitre_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {selected.mitre_techniques.map(t => (
                  <span key={t} className="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded">{t}</span>
                ))}
              </div>
            )}

            {/* Timeline */}
            <div>
              <h4 className="text-sm font-semibold mb-3">Timeline</h4>
              <div className="space-y-3 relative before:absolute before:left-3 before:top-2 before:bottom-2 before:w-px before:bg-cyber-border">
                {(selected.timeline || []).map((entry, i) => (
                  <div key={i} className="flex gap-3 pl-6 relative">
                    <div className="absolute left-1.5 top-1.5 w-3 h-3 rounded-full bg-cyber-accent border-2 border-cyber-card" />
                    <div>
                      <div className="flex items-center gap-2 text-xs text-cyber-muted">
                        <span>{new Date(entry.timestamp).toLocaleString()}</span>
                        <span className="text-cyber-accent">{entry.user}</span>
                      </div>
                      <p className="text-sm mt-0.5">{entry.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
