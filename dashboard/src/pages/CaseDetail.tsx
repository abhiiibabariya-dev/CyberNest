import { useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { FileText } from 'lucide-react';
import { api } from '../services/api';

export default function CaseDetail() {
  const { id = '' } = useParams();
  const { data: item, isLoading } = useQuery({
    queryKey: ['case', id],
    queryFn: () => api.getCase(id),
    enabled: Boolean(id),
  });

  const tags = useMemo(() => item?.tags ?? [], [item]);

  if (isLoading) return <div className="text-cyber-muted">Loading case...</div>;
  if (!item) return <div className="text-cyber-muted">Case not found.</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <FileText className="w-6 h-6 text-cyber-accent" />
        <div>
          <h1 className="text-2xl font-bold">{item.title}</h1>
          <p className="text-sm text-cyber-muted">{item.case_id ?? item.id}</p>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <div className="text-xs text-cyber-muted uppercase mb-2">Status</div>
          <div className="text-sm">{item.status}</div>
        </div>
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <div className="text-xs text-cyber-muted uppercase mb-2">Severity</div>
          <div className="text-sm">{item.severity ?? item.priority ?? 'medium'}</div>
        </div>
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
          <div className="text-xs text-cyber-muted uppercase mb-2">Assignee</div>
          <div className="text-sm">{item.assignee_name ?? item.assignee_id ?? 'Unassigned'}</div>
        </div>
      </div>
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
        <div className="text-xs text-cyber-muted uppercase mb-2">Description</div>
        <p className="text-sm text-cyber-muted whitespace-pre-wrap">{item.description ?? 'No description available.'}</p>
      </div>
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
        <div className="text-xs text-cyber-muted uppercase mb-2">Tags</div>
        <div className="flex flex-wrap gap-2">
          {tags.length ? tags.map((tag) => (
            <span key={tag} className="px-2 py-1 rounded bg-cyber-bg text-xs text-cyber-accent">{tag}</span>
          )) : <span className="text-sm text-cyber-muted">No tags</span>}
        </div>
      </div>
    </div>
  );
}
