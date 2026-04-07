import { useEffect, useState } from 'react'
import { Server, Wifi, WifiOff, Cpu, HardDrive, Activity } from 'lucide-react'
import { api } from '../services/api'
import type { Agent } from '../types'
import { clsx } from 'clsx'
import { formatDistanceToNow } from 'date-fns'

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getAgents().then(setAgents).catch(console.error).finally(() => setLoading(false))
    const interval = setInterval(() => { api.getAgents().then(setAgents).catch(() => {}) }, 15000)
    return () => clearInterval(interval)
  }, [])

  const online = agents.filter(a => a.status === 'online').length
  const offline = agents.filter(a => a.status === 'offline').length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Server className="w-6 h-6 text-cyber-accent" /> Agents
        </h1>
        <div className="flex items-center gap-4 text-sm">
          <span className="flex items-center gap-1.5 text-green-400"><Wifi className="w-4 h-4" /> {online} Online</span>
          <span className="flex items-center gap-1.5 text-red-400"><WifiOff className="w-4 h-4" /> {offline} Offline</span>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-cyber-muted">Loading agents...</div>
      ) : agents.length === 0 ? (
        <div className="text-center py-16 text-cyber-muted">
          <Server className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No agents registered</p>
          <p className="text-xs mt-1">Deploy the CyberNest Agent to start collecting logs</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {agents.map(agent => (
            <div key={agent.id} className={clsx(
              'bg-cyber-card border rounded-xl p-4',
              agent.status === 'online' ? 'border-green-500/30' : 'border-cyber-border'
            )}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={clsx('w-2.5 h-2.5 rounded-full',
                    agent.status === 'online' ? 'bg-green-400 live-indicator' : 'bg-red-400'
                  )} />
                  <span className="font-semibold">{agent.hostname}</span>
                </div>
                <span className="text-xs text-cyber-muted font-mono">{agent.os_type}</span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                <div className="flex items-center gap-1.5 text-cyber-muted">
                  <span>IP:</span> <code className="text-white">{agent.ip_address}</code>
                </div>
                <div className="flex items-center gap-1.5 text-cyber-muted">
                  <span>Ver:</span> <span className="text-white">{agent.agent_version}</span>
                </div>
              </div>

              {/* Health bars */}
              <div className="space-y-2 mb-3">
                <div className="flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5 text-cyber-muted" />
                  <div className="flex-1 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
                    <div className="h-full bg-cyber-accent rounded-full transition-all"
                      style={{ width: `${agent.cpu_usage || 0}%` }} />
                  </div>
                  <span className="text-xs text-cyber-muted w-10 text-right">{(agent.cpu_usage || 0).toFixed(0)}%</span>
                </div>
                <div className="flex items-center gap-2">
                  <HardDrive className="w-3.5 h-3.5 text-cyber-muted" />
                  <div className="flex-1 h-1.5 bg-cyber-bg rounded-full overflow-hidden">
                    <div className="h-full bg-purple-500 rounded-full transition-all"
                      style={{ width: `${agent.memory_usage || 0}%` }} />
                  </div>
                  <span className="text-xs text-cyber-muted w-10 text-right">{(agent.memory_usage || 0).toFixed(0)}%</span>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-cyber-muted pt-2 border-t border-cyber-border">
                <span className="flex items-center gap-1">
                  <Activity className="w-3 h-3" /> {(agent.events_per_second || 0).toFixed(0)} EPS
                </span>
                <span>
                  {agent.last_seen ? `Seen ${formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true })}` : 'Never'}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
