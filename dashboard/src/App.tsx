import { useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import LogSearch from './pages/LogSearch'
import Rules from './pages/Rules'
import Cases from './pages/Cases'
import Playbooks from './pages/Playbooks'
import ThreatIntel from './pages/ThreatIntel'
import Agents from './pages/Agents'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import { api } from './services/api'
import { useWebSocket } from './hooks/useWebSocket'

export default function App() {
  const [user, setUser] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [alertCount, setAlertCount] = useState(0)
  const [eps, setEps] = useState(0)

  const { messages: liveAlerts, isConnected } = useWebSocket('/ws/alerts/live')

  // Check auth on mount
  useEffect(() => {
    if (api.isAuthenticated()) {
      api.getMe()
        .then(u => setUser(u))
        .catch(() => api.clearToken())
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  // Update alert count from live feed
  useEffect(() => {
    setAlertCount(prev => prev + liveAlerts.length)
  }, [liveAlerts])

  // Periodic stats refresh
  useEffect(() => {
    if (!user) return
    const refresh = () => {
      api.getDashboardStats()
        .then(stats => {
          setAlertCount(stats.critical_alerts + stats.high_alerts)
          setEps(stats.events_per_second)
        })
        .catch(() => {})
    }
    refresh()
    const interval = setInterval(refresh, 30000)
    return () => clearInterval(interval)
  }, [user])

  const handleLogin = (userData: any) => setUser(userData)
  const handleLogout = () => {
    api.clearToken()
    setUser(null)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-bg flex items-center justify-center">
        <div className="text-cyber-accent animate-pulse text-lg">Loading CyberNest...</div>
      </div>
    )
  }

  if (!user) {
    return <Login onLogin={handleLogin} />
  }

  return (
    <Layout user={user} onLogout={handleLogout} alertCount={alertCount} eps={eps}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/search" element={<LogSearch />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/playbooks" element={<Playbooks />} />
        <Route path="/threat-intel" element={<ThreatIntel />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}
