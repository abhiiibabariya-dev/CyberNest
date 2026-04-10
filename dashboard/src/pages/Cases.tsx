import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderOpen, Plus, Clock, User, Tag, Search, LayoutGrid,
  LayoutList, ChevronRight, AlertTriangle, Filter, X,
} from 'lucide-react';
import { api } from '../services/api';
import type { Incident } from '../types';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  in_progress: 'bg-blue-500/20 text-blue-400',
  closed: 'bg-green-500/20 text-green-400',
};

const KANBAN_COLUMNS = ['open', 'in_progress', 'closed'] as const;
const KANBAN_LABELS: Record<string, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  closed: 'Closed',
};
const KANBAN_COLORS: Record<string, string> = {
  open: 'border-red-500/50',
  in_progress: 'border-blue-500/50',
  closed: 'border-green-500/50',
};

type ViewMode = 'table' | 'kanban';

export default function Cases() {
  const navigate = useNavigate();
  const [cases, setCases] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<ViewMode>('table');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCase, setNewCase] = useState({ title: '', description: '', severity: 'medium', tags: '' });
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    loadCases();
  }, []);

  const loadCases = async () => {
    setLoading(true);
    try {
      const data = await api.getCases();
      setCases(data);
    } catch (err) {
      console.error('Failed to load cases:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !c.title.toLowerCase().includes(q) &&
          !c.case_id.toLowerCase().includes(q) &&
          !(c.description || '').toLowerCase().includes(q)
        )
          return false;
      }
      if (filterSeverity && c.severity !== filterSeverity) return false;
      if (filterStatus && c.status !== filterStatus) return false;
      return true;
    });
  }, [cases, searchQuery, filterSeverity, filterStatus]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      await api.createCase({
        title: newCase.title,
        description: newCase.description,
        severity: newCase.severity,
        tags: newCase.tags.split(',').map((t) => t.trim()).filter(Boolean),
      });
      setShowCreateModal(false);
      setNewCase({ title: '', description: '', severity: 'medium', tags: '' });
      loadCases();
    } catch (err) {
      console.error('Failed to create case:', err);
    } finally {
      setCreating(false);
    }
  };

  const caseCounts = useMemo(() => {
    const counts: Record<string, number> = { open: 0, in_progress: 0, closed: 0 };
    cases.forEach((c) => {
      if (counts[c.status] !== undefined) counts[c.status]++;
    });
    return counts;
  }, [cases]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
          <FolderOpen className="w-6 h-6 text-[#00d4ff]" /> Case Management
        </h1>
        <div className="flex items-center gap-3">
          {/* View toggle */}
          <div className="flex bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
            <button
              onClick={() => setViewMode('table')}
              className={`p-2 transition-colors ${
                viewMode === 'table' ? 'bg-[#00d4ff]/20 text-[#00d4ff]' : 'text-[#8b949e] hover:text-white'
              }`}
            >
              <LayoutList className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('kanban')}
              className={`p-2 transition-colors ${
                viewMode === 'kanban' ? 'bg-[#00d4ff]/20 text-[#00d4ff]' : 'text-[#8b949e] hover:text-white'
              }`}
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-4 py-2 bg-[#00d4ff] text-[#0d1117] rounded-lg text-sm font-semibold hover:bg-[#00bce0] transition-colors"
          >
            <Plus className="w-4 h-4" /> New Case
          </button>
        </div>
      </div>

      {/* Status summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {KANBAN_COLUMNS.map((status) => (
          <div
            key={status}
            className={`bg-[#161b22] border border-[#30363d] rounded-lg p-4 cursor-pointer hover:border-[#00d4ff]/30 transition-colors ${
              filterStatus === status ? 'border-[#00d4ff]/50' : ''
            }`}
            onClick={() => setFilterStatus(filterStatus === status ? '' : status)}
          >
            <div className="flex items-center justify-between">
              <span className="text-sm text-[#8b949e]">{KANBAN_LABELS[status]}</span>
              <span className={`text-2xl font-bold ${
                status === 'open' ? 'text-red-400' : status === 'in_progress' ? 'text-blue-400' : 'text-green-400'
              }`}>
                {caseCounts[status]}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#484f58]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search cases by title, ID, or description..."
            className="w-full pl-10 pr-4 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white placeholder-[#484f58] focus:outline-none focus:border-[#00d4ff]"
          />
        </div>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="px-3 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#00d4ff]"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        {(filterSeverity || filterStatus || searchQuery) && (
          <button
            onClick={() => { setFilterSeverity(''); setFilterStatus(''); setSearchQuery(''); }}
            className="p-2 text-[#8b949e] hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Content */}
      {loading ? (
        <div className="text-center py-20 text-[#8b949e]">Loading cases...</div>
      ) : viewMode === 'table' ? (
        /* TABLE VIEW */
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#30363d] text-left text-xs text-[#8b949e] uppercase">
                <th className="px-4 py-3">Case ID</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Assignee</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Updated</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-[#8b949e]">
                    No cases found
                  </td>
                </tr>
              ) : (
                filteredCases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => navigate(`/cases/${c.id}`)}
                    className="border-b border-[#30363d]/50 hover:bg-[#0d1117]/50 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3">
                      <code className="text-xs text-[#00d4ff] font-mono">{c.case_id}</code>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-white font-medium">{c.title}</span>
                      {c.tags && c.tags.length > 0 && (
                        <div className="flex gap-1 mt-1">
                          {c.tags.slice(0, 3).map((t) => (
                            <span key={t} className="px-1.5 py-0.5 bg-[#30363d] text-[#8b949e] text-[10px] rounded">
                              {t}
                            </span>
                          ))}
                          {c.tags.length > 3 && (
                            <span className="text-[10px] text-[#484f58]">+{c.tags.length - 3}</span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${SEVERITY_COLORS[c.severity] || SEVERITY_COLORS.medium}`}>
                        {c.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[c.status] || STATUS_COLORS.open}`}>
                        {(c.status || 'open').replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#8b949e]">
                      {(c as any).assignee_name || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#8b949e]">
                      {formatDistanceToNow(new Date(c.created_at), { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#8b949e]">
                      {c.updated_at ? formatDistanceToNow(new Date(c.updated_at), { addSuffix: true }) : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <ChevronRight className="w-4 h-4 text-[#484f58]" />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : (
        /* KANBAN VIEW */
        <div className="grid grid-cols-3 gap-4">
          {KANBAN_COLUMNS.map((status) => {
            const columnCases = filteredCases.filter((c) => c.status === status);
            return (
              <div key={status} className="space-y-3">
                <div className={`flex items-center justify-between p-3 bg-[#161b22] border-t-2 ${KANBAN_COLORS[status]} border-x border-b border-[#30363d] rounded-t-lg`}>
                  <span className="text-sm font-semibold text-white">{KANBAN_LABELS[status]}</span>
                  <span className="text-xs text-[#8b949e] bg-[#0d1117] px-2 py-0.5 rounded-full">
                    {columnCases.length}
                  </span>
                </div>
                <div className="space-y-2 min-h-[200px]">
                  {columnCases.map((c) => (
                    <div
                      key={c.id}
                      onClick={() => navigate(`/cases/${c.id}`)}
                      className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 cursor-pointer hover:border-[#00d4ff]/30 transition-all group"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <code className="text-[10px] text-[#00d4ff] font-mono">{c.case_id}</code>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${SEVERITY_COLORS[c.severity] || SEVERITY_COLORS.medium}`}>
                          {c.severity}
                        </span>
                      </div>
                      <h3 className="text-sm font-medium text-white group-hover:text-[#00d4ff] transition-colors line-clamp-2">
                        {c.title}
                      </h3>
                      {c.description && (
                        <p className="text-xs text-[#8b949e] mt-1 line-clamp-2">{c.description}</p>
                      )}
                      <div className="flex items-center justify-between mt-3">
                        <div className="flex items-center gap-1 text-[10px] text-[#484f58]">
                          <Clock className="w-3 h-3" />
                          {formatDistanceToNow(new Date(c.created_at), { addSuffix: true })}
                        </div>
                        {c.tags && c.tags.length > 0 && (
                          <div className="flex gap-1">
                            {c.tags.slice(0, 2).map((t) => (
                              <span key={t} className="px-1 py-0.5 bg-[#30363d] text-[#8b949e] text-[9px] rounded">
                                {t}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                  {columnCases.length === 0 && (
                    <div className="text-center py-8 text-[#484f58] text-xs">No cases</div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-lg p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Create New Case</h2>
              <button onClick={() => setShowCreateModal(false)} className="text-[#8b949e] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="block text-sm text-[#8b949e] mb-1">Title *</label>
                <input
                  type="text"
                  value={newCase.title}
                  onChange={(e) => setNewCase({ ...newCase, title: e.target.value })}
                  required
                  className="w-full px-3 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#00d4ff]"
                  placeholder="Case title"
                />
              </div>
              <div>
                <label className="block text-sm text-[#8b949e] mb-1">Description</label>
                <textarea
                  value={newCase.description}
                  onChange={(e) => setNewCase({ ...newCase, description: e.target.value })}
                  rows={3}
                  className="w-full px-3 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#00d4ff] resize-none"
                  placeholder="Describe the incident..."
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-[#8b949e] mb-1">Severity</label>
                  <select
                    value={newCase.severity}
                    onChange={(e) => setNewCase({ ...newCase, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#00d4ff]"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-[#8b949e] mb-1">Tags</label>
                  <input
                    type="text"
                    value={newCase.tags}
                    onChange={(e) => setNewCase({ ...newCase, tags: e.target.value })}
                    className="w-full px-3 py-2 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#00d4ff]"
                    placeholder="tag1, tag2, ..."
                  />
                </div>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-sm text-[#8b949e] hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !newCase.title}
                  className="px-4 py-2 bg-[#00d4ff] text-[#0d1117] rounded-lg text-sm font-semibold hover:bg-[#00bce0] disabled:opacity-50 transition-colors"
                >
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
