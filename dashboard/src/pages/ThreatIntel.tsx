import { useState } from 'react'
import { Globe, Search, AlertTriangle, Shield } from 'lucide-react'
import { api } from '../services/api'

export default function ThreatIntel() {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const handleLookup = async () => {
    if (!query.trim()) return
    setLoading(true)
    try {
      const res = await api.lookupIOC(query.trim())
      setResult(res)
    } catch (e) {
      setResult({ found: false, value: query, results: [] })
    }
    setLoading(false)
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <Globe className="w-6 h-6 text-cyber-accent" /> Threat Intelligence
      </h1>

      {/* IOC Lookup */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4">IOC Lookup</h2>
        <div className="flex gap-2 max-w-xl">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleLookup()}
              placeholder="Enter IP, domain, hash, URL, or email..."
              className="w-full pl-10 pr-4 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent font-mono"
            />
          </div>
          <button onClick={handleLookup} disabled={loading}
            className="px-5 py-2.5 bg-cyber-accent text-white rounded-lg text-sm font-medium hover:bg-cyber-accent-hover disabled:opacity-50">
            {loading ? 'Searching...' : 'Lookup'}
          </button>
        </div>

        {result && (
          <div className="mt-6">
            {result.found ? (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <span className="text-lg font-semibold text-red-400">Threat Found</span>
                </div>
                {result.results.map((r: any, i: number) => (
                  <div key={i} className="bg-cyber-bg rounded-lg p-4 space-y-2">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                      <div><span className="text-xs text-cyber-muted block">Type</span>{r.ioc_type}</div>
                      <div><span className="text-xs text-cyber-muted block">Threat Score</span>
                        <span className={r.threat_score > 70 ? 'text-red-400' : r.threat_score > 40 ? 'text-yellow-400' : 'text-green-400'}>
                          {r.threat_score}/100
                        </span>
                      </div>
                      <div><span className="text-xs text-cyber-muted block">Confidence</span>{r.confidence}%</div>
                      <div><span className="text-xs text-cyber-muted block">Sources</span>{r.source_count}</div>
                      <div><span className="text-xs text-cyber-muted block">Threat Type</span>{r.threat_type || 'Unknown'}</div>
                      <div><span className="text-xs text-cyber-muted block">Malware Family</span>{r.malware_family || 'N/A'}</div>
                      <div><span className="text-xs text-cyber-muted block">First Seen</span>{r.first_seen?.substring(0, 10) || '—'}</div>
                      <div><span className="text-xs text-cyber-muted block">Last Seen</span>{r.last_seen?.substring(0, 10) || '—'}</div>
                    </div>
                    {r.tags && r.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {r.tags.map((t: string) => (
                          <span key={t} className="px-2 py-0.5 bg-red-500/15 text-red-400 text-xs rounded">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-green-400">
                <Shield className="w-5 h-5" />
                <span>No threats found for <code className="font-mono">{result.value}</code></span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
