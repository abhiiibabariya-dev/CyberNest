import { useEffect, useState } from 'react'
import { Bot, Play, CheckCircle, XCircle, Clock, ToggleLeft, ToggleRight } from 'lucide-react'
import { api } from '../services/api'
import type { Playbook, PlaybookRun } from '../types'
import { clsx } from 'clsx'
import { formatDistanceToNow } from 'date-fns'

export default function Playbooks() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<'playbooks' | 'history'>('playbooks')

  useEffect(() => {
    Promise.all([
      api.getPlaybooks().then(setPlaybooks),
      api.getPlaybookRuns().then(setRuns),
    ]).catch(console.error).finally(() => setLoading(false))
  }, [])

  const handleTrigger = async (id: string) => {
    await api.triggerPlaybook({ playbook_id: id, dry_run: false })
    api.getPlaybookRuns().then(setRuns)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Bot className="w-6 h-6 text-cyber-accent" /> SOAR Playbooks
        </h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-cyber-card rounded-lg p-1 w-fit">
        <button onClick={() => setTab('playbooks')}
          className={clsx('px-4 py-1.5 rounded text-sm', tab === 'playbooks' ? 'bg-cyber-accent text-white' : 'text-cyber-muted')}>
          Playbooks ({playbooks.length})
        </button>
        <button onClick={() => setTab('history')}
          className={clsx('px-4 py-1.5 rounded text-sm', tab === 'history' ? 'bg-cyber-accent text-white' : 'text-cyber-muted')}>
          Execution History ({runs.length})
        </button>
      </div>

      {loading ? (
        <div className="text-center py-12 text-cyber-muted">Loading...</div>
      ) : tab === 'playbooks' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {playbooks.map(pb => (
            <div key={pb.id} className="bg-cyber-card border border-cyber-border rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className={clsx('px-2 py-0.5 rounded text-xs', pb.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400')}>
                  {pb.enabled ? 'Active' : 'Disabled'}
                </span>
                <span className="text-xs text-cyber-muted">v{pb.version}</span>
              </div>
              <h3 className="font-semibold mb-1">{pb.name}</h3>
              {pb.description && <p className="text-xs text-cyber-muted mb-3">{pb.description}</p>}

              <div className="space-y-1.5 mb-3">
                {pb.steps.slice(0, 4).map((step, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="w-5 h-5 rounded-full bg-cyber-accent/15 text-cyber-accent flex items-center justify-center text-[10px]">{i + 1}</span>
                    <span className="text-cyber-muted">{step.name}</span>
                  </div>
                ))}
                {pb.steps.length > 4 && (
                  <span className="text-xs text-cyber-muted ml-7">+{pb.steps.length - 4} more steps</span>
                )}
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-cyber-border">
                <div className="text-xs text-cyber-muted">
                  <span className="text-green-400">{pb.successful_runs}</span>/{pb.total_runs} runs
                </div>
                <button onClick={() => handleTrigger(pb.id)} disabled={!pb.enabled}
                  className="flex items-center gap-1 px-3 py-1.5 bg-cyber-accent/20 text-cyber-accent text-xs rounded hover:bg-cyber-accent/30 disabled:opacity-40">
                  <Play className="w-3 h-3" /> Execute
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Playbook</th>
                <th className="px-4 py-3">Steps</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">Started</th>
              </tr>
            </thead>
            <tbody>
              {runs.map(run => (
                <tr key={run.id} className="data-row border-b border-cyber-border/30">
                  <td className="px-4 py-3">
                    {run.status === 'completed' ? <CheckCircle className="w-4 h-4 text-green-400" /> :
                     run.status === 'failed' ? <XCircle className="w-4 h-4 text-red-400" /> :
                     <Clock className="w-4 h-4 text-yellow-400 animate-spin" />}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{run.playbook_id.substring(0, 8)}</td>
                  <td className="px-4 py-3 text-xs">{run.step_results?.length || 0} steps</td>
                  <td className="px-4 py-3 text-xs font-mono">{run.duration_ms ? `${run.duration_ms}ms` : '—'}</td>
                  <td className="px-4 py-3 text-xs text-cyber-muted">{formatDistanceToNow(new Date(run.started_at), { addSuffix: true })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
