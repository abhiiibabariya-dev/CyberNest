import { useState, useMemo } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Search, Clock, Download, ChevronDown, ChevronRight, Save, Trash2,
  History, Bookmark, BarChart3, Loader2,
} from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { api } from '../services/api'
import { useAppStore } from '../store'
import type { SearchResult } from '../types'
import { clsx } from 'clsx'

const TIME_RANGES = [
  { label: '15m', value: 'now-15m' },
  { label: '1h', value: 'now-1h' },
  { label: '4h', value: 'now-4h' },
  { label: '24h', value: 'now-24h' },
  { label: '7d', value: 'now-7d' },
  { label: 'Custom', value: 'custom' },
]

const PAGE_SIZES = [25, 50, 100, 200]

export default function LogSearch() {
  const { searchHistory, addSearchHistory, clearSearchHistory, savedSearches, addSavedSearch, removeSavedSearch } = useAppStore()

  const [query, setQuery] = useState('')
  const [timeRange, setTimeRange] = useState('now-24h')
  const [index, setIndex] = useState('all')
  const [pageSize, setPageSize] = useState(50)
  const [results, setResults] = useState<SearchResult | null>(null)
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const [page, setPage] = useState(1)
  const [showHistory, setShowHistory] = useState(false)
  const [showSaved, setShowSaved] = useState(false)
  const [saveName, setSaveName] = useState('')
  const [showSaveModal, setShowSaveModal] = useState(false)

  const searchMutation = useMutation({
    mutationFn: (params: { q: string; from_time: string; size: number; index?: string }) =>
      api.searchEvents(params),
    onSuccess: (data) => {
      setResults(data)
      setPage(1)
      setExpandedRow(null)
      if (query.trim()) addSearchHistory(query.trim())
    },
  })

  const handleSearch = () => {
    if (!query.trim() && !index) return
    searchMutation.mutate({
      q: query.trim(),
      from_time: timeRange,
      size: pageSize * 4,
      ...(index !== 'all' && { index }),
    })
  }

  const handleSaveSearch = () => {
    if (!saveName.trim()) return
    addSavedSearch({ name: saveName.trim(), query, timeRange })
    setSaveName('')
    setShowSaveModal(false)
  }

  const loadSavedSearch = (search: { query: string; timeRange: string }) => {
    setQuery(search.query)
    setTimeRange(search.timeRange)
    setShowSaved(false)
  }

  const paginatedHits = useMemo(() => {
    if (!results?.hits) return []
    const start = (page - 1) * pageSize
    return results.hits.slice(start, start + pageSize)
  }, [results, page, pageSize])

  const totalPages = results ? Math.ceil(results.hits.length / pageSize) : 0

  const histogramData = useMemo(() => {
    if (!results?.hits.length) return []
    const buckets: Record<string, number> = {}
    results.hits.forEach((hit: any) => {
      const ts = hit['@timestamp'] || hit.timestamp || ''
      const hour = ts.substring(0, 13) || 'unknown'
      buckets[hour] = (buckets[hour] || 0) + 1
    })
    return Object.entries(buckets).sort().map(([hour, count]) => ({
      hour: hour.substring(11) || hour,
      count,
    }))
  }, [results])

  const exportData = (format: 'csv' | 'json') => {
    if (!results?.hits.length) return
    let content: string
    let mimeType: string
    let ext: string

    if (format === 'csv') {
      const headers = Object.keys(results.hits[0]).join(',')
      const rows = results.hits.map(h => Object.values(h).map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
      content = headers + '\n' + rows
      mimeType = 'text/csv'
      ext = 'csv'
    } else {
      content = JSON.stringify(results.hits, null, 2)
      mimeType = 'application/json'
      ext = 'json'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cybernest-search-${Date.now()}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <Search className="w-6 h-6 text-cyber-accent" /> Log Search
      </h1>

      {/* Search Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-3">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch()}
              onFocus={() => setShowHistory(true)}
              onBlur={() => setTimeout(() => setShowHistory(false), 200)}
              placeholder='Lucene query: field:value AND/OR, wildcards (*), "exact phrase", ranges [1 TO 100]'
              className="w-full pl-10 pr-4 py-3 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent font-mono"
            />
            {/* Query History Dropdown */}
            {showHistory && searchHistory.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-cyber-card border border-cyber-border rounded-lg shadow-lg z-20 max-h-48 overflow-y-auto">
                <div className="flex items-center justify-between px-3 py-2 border-b border-cyber-border">
                  <span className="text-xs text-cyber-muted flex items-center gap-1"><History className="w-3 h-3" /> Recent</span>
                  <button onClick={clearSearchHistory} className="text-xs text-red-400 hover:text-red-300">Clear</button>
                </div>
                {searchHistory.map((h, i) => (
                  <button key={i} onClick={() => { setQuery(h); setShowHistory(false) }}
                    className="w-full text-left px-3 py-2 text-xs font-mono text-cyber-muted hover:text-white hover:bg-cyber-bg/50">
                    {h}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={handleSearch} disabled={searchMutation.isPending}
            className="px-6 py-3 bg-cyber-accent text-white rounded-lg text-sm font-medium hover:bg-cyber-accent-hover disabled:opacity-50 flex items-center gap-2">
            {searchMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {searchMutation.isPending ? 'Searching...' : 'Search'}
          </button>
        </div>

        {/* Control Bar */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Time Range */}
          <div className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-cyber-muted" />
            {TIME_RANGES.map(t => (
              <button key={t.value} onClick={() => setTimeRange(t.value)}
                className={clsx('px-2.5 py-1 rounded text-xs font-medium transition-colors',
                  timeRange === t.value ? 'bg-cyber-accent/20 text-cyber-accent' : 'text-cyber-muted hover:text-white'
                )}>
                {t.label}
              </button>
            ))}
          </div>

          <div className="w-px h-5 bg-cyber-border" />

          {/* Index */}
          <select value={index} onChange={e => setIndex(e.target.value)}
            className="px-2 py-1 bg-cyber-bg border border-cyber-border rounded text-xs text-white">
            <option value="all">All Indices</option>
            <option value="syslog">syslog</option>
            <option value="wazuh">wazuh</option>
            <option value="suricata">suricata</option>
            <option value="windows">windows</option>
            <option value="auth">auth</option>
          </select>

          {/* Page size */}
          <select value={pageSize} onChange={e => setPageSize(Number(e.target.value))}
            className="px-2 py-1 bg-cyber-bg border border-cyber-border rounded text-xs text-white">
            {PAGE_SIZES.map(s => <option key={s} value={s}>{s} / page</option>)}
          </select>

          <div className="w-px h-5 bg-cyber-border" />

          {/* Export */}
          <button onClick={() => exportData('csv')} disabled={!results?.hits.length}
            className="flex items-center gap-1 px-2.5 py-1 text-xs text-cyber-muted hover:text-white disabled:opacity-30">
            <Download className="w-3 h-3" /> CSV
          </button>
          <button onClick={() => exportData('json')} disabled={!results?.hits.length}
            className="flex items-center gap-1 px-2.5 py-1 text-xs text-cyber-muted hover:text-white disabled:opacity-30">
            <Download className="w-3 h-3" /> JSON
          </button>

          <div className="w-px h-5 bg-cyber-border" />

          {/* Save Search */}
          <button onClick={() => setShowSaveModal(true)}
            className="flex items-center gap-1 px-2.5 py-1 text-xs text-cyber-accent hover:text-cyber-accent-hover">
            <Save className="w-3 h-3" /> Save
          </button>

          {/* Saved Searches */}
          <div className="relative">
            <button onClick={() => setShowSaved(!showSaved)}
              className="flex items-center gap-1 px-2.5 py-1 text-xs text-cyber-muted hover:text-white">
              <Bookmark className="w-3 h-3" /> Saved ({savedSearches.length})
            </button>
            {showSaved && savedSearches.length > 0 && (
              <div className="absolute top-full right-0 mt-1 w-64 bg-cyber-card border border-cyber-border rounded-lg shadow-lg z-20">
                {savedSearches.map((s, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2 hover:bg-cyber-bg/50">
                    <button onClick={() => loadSavedSearch(s)} className="text-xs text-left flex-1 truncate">
                      <span className="font-medium text-white">{s.name}</span>
                      <span className="block text-cyber-muted font-mono text-[10px] truncate">{s.query}</span>
                    </button>
                    <button onClick={() => removeSavedSearch(s.name)} className="text-red-400 hover:text-red-300 ml-2">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Save Modal */}
      {showSaveModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowSaveModal(false)}>
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 w-96" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold mb-4">Save Search</h3>
            <input value={saveName} onChange={e => setSaveName(e.target.value)}
              placeholder="Search name" className="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white mb-3 focus:outline-none focus:border-cyber-accent" />
            <p className="text-xs text-cyber-muted mb-4 font-mono truncate">{query || '(empty query)'}</p>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowSaveModal(false)} className="px-4 py-2 text-sm text-cyber-muted hover:text-white">Cancel</button>
              <button onClick={handleSaveSearch} className="px-4 py-2 bg-cyber-accent text-white rounded-lg text-sm hover:bg-cyber-accent-hover">Save</button>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Stats bar */}
          <div className="flex items-center justify-between bg-cyber-card border border-cyber-border rounded-xl px-4 py-3">
            <div className="flex items-center gap-4">
              <span className="text-sm">
                Found <span className="font-bold text-cyber-accent font-mono">{results.total.toLocaleString()}</span> events
              </span>
              <span className="text-xs text-cyber-muted">in {results.took_ms}ms</span>
            </div>
            <span className="text-xs text-cyber-muted">
              Page {page} of {totalPages} | Showing {paginatedHits.length} results
            </span>
          </div>

          {/* Histogram */}
          {histogramData.length > 1 && (
            <div className="bg-cyber-card border border-cyber-border rounded-xl p-4">
              <h3 className="text-xs font-semibold text-cyber-muted mb-2 flex items-center gap-1">
                <BarChart3 className="w-3.5 h-3.5" /> Event Distribution
              </h3>
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={histogramData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
                  <XAxis dataKey="hour" tick={{ fill: '#8b949e', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#8b949e', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, color: '#e6edf3', fontSize: 12 }} />
                  <Bar dataKey="count" fill="#00d4ff" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Results Table */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                  <th className="px-3 py-2 w-8"></th>
                  <th className="px-3 py-2">Timestamp</th>
                  <th className="px-3 py-2">Source IP</th>
                  <th className="px-3 py-2">Event Type</th>
                  <th className="px-3 py-2">Rule</th>
                  <th className="px-3 py-2">Message</th>
                </tr>
              </thead>
              <tbody>
                {paginatedHits.map((hit, i) => {
                  const event = hit as Record<string, any>
                  const globalIdx = (page - 1) * pageSize + i
                  return (
                    <tbody key={globalIdx}>
                      <tr className="data-row border-b border-cyber-border/30 cursor-pointer"
                        onClick={() => setExpandedRow(expandedRow === globalIdx ? null : globalIdx)}>
                        <td className="px-3 py-2 text-cyber-muted">
                          {expandedRow === globalIdx ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>
                        <td className="px-3 py-2 text-xs font-mono text-cyber-muted whitespace-nowrap">
                          {(event['@timestamp'] || event.timestamp || '').substring(0, 19).replace('T', ' ')}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-red-400">{event.source?.ip || event.src_ip || '--'}</td>
                        <td className="px-3 py-2 text-xs text-cyber-accent">{event.event?.module || event.event_type || '--'}</td>
                        <td className="px-3 py-2 text-xs">{event.rule?.description || event.rule?.name || '--'}</td>
                        <td className="px-3 py-2 text-xs truncate max-w-[300px] text-cyber-muted">
                          {event.message || event.raw?.substring(0, 120) || '--'}
                        </td>
                      </tr>
                      {expandedRow === globalIdx && (
                        <tr>
                          <td colSpan={6} className="px-6 py-3 bg-cyber-bg/50">
                            <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap max-h-64 overflow-y-auto">
                              {JSON.stringify(event, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1.5 bg-cyber-card border border-cyber-border rounded text-xs text-cyber-muted hover:text-white disabled:opacity-30">
                Previous
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                let pageNum: number
                if (totalPages <= 7) pageNum = i + 1
                else if (page <= 4) pageNum = i + 1
                else if (page >= totalPages - 3) pageNum = totalPages - 6 + i
                else pageNum = page - 3 + i
                return (
                  <button key={pageNum} onClick={() => setPage(pageNum)}
                    className={clsx('px-3 py-1.5 rounded text-xs font-medium',
                      page === pageNum ? 'bg-cyber-accent text-white' : 'bg-cyber-card border border-cyber-border text-cyber-muted hover:text-white'
                    )}>
                    {pageNum}
                  </button>
                )
              })}
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="px-3 py-1.5 bg-cyber-card border border-cyber-border rounded text-xs text-cyber-muted hover:text-white disabled:opacity-30">
                Next
              </button>
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!results && !searchMutation.isPending && (
        <div className="text-center py-20 text-cyber-muted">
          <Search className="w-16 h-16 mx-auto mb-4 opacity-20" />
          <p className="text-lg mb-1">Search across all indexed events</p>
          <p className="text-xs">Supports Lucene syntax: field:value, wildcards (*), boolean operators (AND/OR/NOT), ranges [1 TO 100]</p>
        </div>
      )}
    </div>
  )
}
