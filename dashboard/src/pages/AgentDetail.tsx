import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Monitor } from 'lucide-react';
import { api } from '../services/api';

export default function AgentDetail() {
  const { id = '' } = useParams();
  const { data: agent, isLoading } = useQuery({
    queryKey: ['agent', id],
    queryFn: () => api.getAgent(id),
    enabled: Boolean(id),
  });

  if (isLoading) return <div className="text-cyber-muted">Loading agent...</div>;
  if (!agent) return <div className="text-cyber-muted">Agent not found.</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Monitor className="w-6 h-6 text-cyber-accent" />
        <div>
          <h1 className="text-2xl font-bold">{agent.hostname}</h1>
          <p className="text-sm text-cyber-muted">{agent.id}</p>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-4">
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4"><div className="text-xs text-cyber-muted uppercase mb-2">Status</div><div>{agent.status}</div></div>
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4"><div className="text-xs text-cyber-muted uppercase mb-2">IP</div><div>{agent.ip_address}</div></div>
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4"><div className="text-xs text-cyber-muted uppercase mb-2">OS</div><div>{agent.os}</div></div>
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4"><div className="text-xs text-cyber-muted uppercase mb-2">Version</div><div>{agent.agent_version}</div></div>
      </div>
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 text-sm text-cyber-muted">
        Last seen: {agent.last_seen ?? 'unknown'}
      </div>
    </div>
  );
}
