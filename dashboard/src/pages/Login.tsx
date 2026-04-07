import { useState } from 'react'
import { Siren, Eye, EyeOff } from 'lucide-react'
import { api } from '../services/api'

interface LoginProps {
  onLogin: (user: any) => void
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.login(username, password)
      api.setToken(res.access_token)
      onLogin(res.user)
    } catch (err: any) {
      setError(err.message || 'Login failed')
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Siren className="w-10 h-10 text-cyber-accent" />
            <span className="text-3xl font-bold text-white">CyberNest</span>
          </div>
          <p className="text-sm text-cyber-muted">Enterprise SIEM + SOAR Platform</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="bg-cyber-card border border-cyber-border rounded-xl p-6 space-y-4">
          <div>
            <label className="block text-xs text-cyber-muted mb-1.5">Username</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              className="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white focus:outline-none focus:border-cyber-accent"
              placeholder="Enter username"
              required
            />
          </div>

          <div>
            <label className="block text-xs text-cyber-muted mb-1.5">Password</label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-white focus:outline-none focus:border-cyber-accent pr-10"
                placeholder="Enter password"
                required
              />
              <button type="button" onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-white">
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div className="px-3 py-2 bg-red-500/15 border border-red-500/30 rounded text-xs text-red-400">
              {error}
            </div>
          )}

          <button type="submit" disabled={loading}
            className="w-full py-2.5 bg-cyber-accent text-white rounded-lg text-sm font-semibold hover:bg-cyber-accent-hover disabled:opacity-50">
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <p className="text-center text-xs text-cyber-muted mt-4">
          Default: admin / admin123
        </p>
      </div>
    </div>
  )
}
