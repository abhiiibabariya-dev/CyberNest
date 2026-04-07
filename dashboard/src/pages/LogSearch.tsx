import { useState } from 'react'
import { Search, Clock, Download, ChevronDown, ChevronRight } from 'lucide-react'
import { api } from '../services/api'
import type { SearchResult } from '../types'

const TIME_RANGES = [
  { label: 'Last 15m', value: 'now-15m' },
  { label: 'Last 1h', value: 'now-1h' },
  { label: 'Last 4h', value: 'now-4h' },
  { label: 'Last 24h', value: 'now-24h' },
  { label: 'Last 7d', value: 'now-7d' },
  { label: 'Last 30d', value: 'now-30d' },
]

export default function LogSearch() {
  const [query, setQuery] = useState('')
  const [timeRange, setTimeRange] = useState('now-24h')
  const [results, setResults] = useState<SearchResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [expandedRow, setExpandedRow] = useState<number | null>(null)

  const handleSearch = async () => {
    setLoading(true)
    try {
      const res = await api.searchEvents({
        q: query,
        from_time: timeRange,
        size: 200,
      })
      setResults(res)
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  const exportCSV = () => {
    if (!results?.hits.length) return
    const headers = Object.keys(results.hits[0]).join(',')
    const rows = results.hits.map(h => Object.values(h).map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([headers + '\n' + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cybernest-search-${Date.now()}.csv`
    a.click()
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <Search className="w-6 h-6 text-cyber-accent" /> Log Search
      </h1>

      {/* Search bar */}
      <div className="flex gap-2">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder='Search: field:value AND/OR, wildcards (*), ranges [1 TO 100]'
            className="w-full pl-10 pr-4 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent font-mono"
          />
        </div>
        <select value={timeRange} onChange={e => setTimeRange(e.target.value)}
          className="bg-cyber-card border border-cyber-border rounded-lg px-3 text-sm text-white">
          {TIME_RANGES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
        <button onClick={handleSearch} disabled={loading}
          className="px-5 py-2.5 bg-cyber-accent text-white rounded-lg text-sm font-medium hover:bg-cyber-accent-hover disabled:opacity-50">
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {/* Results */}
      {results && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-cyber-muted">
              {results.total.toLocaleString()} results in {results.took_ms}ms
            </span>
            <button onClick={exportCSV} className="flex items-center gap-1 text-cyber-accent hover:underline text-xs">
              <Download className="w-3.5 h-3.5" /> Export CSV
            </button>
          </div>

          <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                  <th className="px-4 py-2 w-8"></th>
                  <th className="px-4 py-2">Time</th>
                  <th className="px-4 py-2">Module</th>
                  <th className="px-4 py-2">Action</th>
                  <th className="px-4 py-2">Source</th>
                  <th className="px-4 py-2">User</th>
                  <th className="px-4 py-2">Message</th>
                </tr>
              </thead>
              <tbody>
                {results.hits.map((hit, i) => {
                  const event = hit as Record<string, any>
                  return (
                    <>
                      <tr key={i} className="data-row border-b border-cyber-border/30 cursor-pointer"
                        onClick={() => setExpandedRow(expandedRow === i ? null : i)}>
                        <td className="px-4 py-2 text-cyber-muted">
                          {expandedRow === i ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>
                        <td className="px-4 py-2 text-xs font-mono text-cyber-muted whitespace-nowrap">{event['@timestamp']?.substring(11, 19) || '—'}</td>
                        <td className="px-4 py-2 text-xs">{event.event?.module || '—'}</td>
                        <td className="px-4 py-2 text-xs text-cyber-accent">{event.event?.action || '—'}</td>
                        <td className="px-4 py-2 font-mono text-xs text-red-400">{event.source?.ip || '—'}</td>
                        <td className="px-4 py-2 text-xs">{event.user?.name || '—'}</td>
                        <td className="px-4 py-2 text-xs truncate max-w-[300px]">{event.message || event.raw?.substring(0, 100) || '—'}</td>
                      </tr>
                      {expandedRow === i && (
                        <tr key={`${i}-exp`}>
                          <td colSpan={7} className="px-6 py-3 bg-cyber-bg/50">
                            <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap max-h-48 overflow-y-auto">
                              {JSON.stringify(event, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {!results && !loading && (
        <div className="text-center py-16 text-cyber-muted">
          <Search className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>Enter a search query to explore events</p>
          <p className="text-xs mt-1">Supports Lucene syntax: field:value, wildcards, boolean operators</p>
        </div>
      )}
    </div>
  )
}
