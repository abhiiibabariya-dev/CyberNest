import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Bell, Search, Shield, FileText, Siren,
  Bot, Globe, Server, BarChart3, Settings, LogOut,
  ChevronLeft, ChevronRight, Activity, Menu,
} from 'lucide-react'
import { clsx } from 'clsx'

const NAV_ITEMS = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/alerts', icon: Bell, label: 'Alert Center' },
  { path: '/search', icon: Search, label: 'Log Search' },
  { path: '/rules', icon: Shield, label: 'Detection Rules' },
  { path: '/cases', icon: FileText, label: 'Cases' },
  { path: '/playbooks', icon: Bot, label: 'Playbooks' },
  { path: '/threat-intel', icon: Globe, label: 'Threat Intel' },
  { path: '/agents', icon: Server, label: 'Agents' },
  { path: '/reports', icon: BarChart3, label: 'Reports' },
  { path: '/settings', icon: Settings, label: 'Settings' },
]

interface LayoutProps {
  children: React.ReactNode
  user: { full_name: string; role: string } | null
  onLogout: () => void
  alertCount: number
  eps: number
}

export default function Layout({ children, user, onLogout, alertCount, eps }: LayoutProps) {
  const [collapsed, setCollapsed] = useState(false)
  const location = useLocation()

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className={clsx(
        'flex flex-col bg-cyber-surface border-r border-cyber-border transition-all duration-300',
        collapsed ? 'w-16' : 'w-60'
      )}>
        {/* Logo */}
        <div className="flex items-center h-14 px-4 border-b border-cyber-border">
          <Siren className="w-6 h-6 text-cyber-accent flex-shrink-0" />
          {!collapsed && <span className="ml-3 font-bold text-lg text-white">CyberNest</span>}
        </div>

        {/* Nav */}
        <nav className="flex-1 py-2 overflow-y-auto">
          {NAV_ITEMS.map(item => {
            const active = location.pathname === item.path ||
              (item.path !== '/' && location.pathname.startsWith(item.path))
            return (
              <Link
                key={item.path}
                to={item.path}
                className={clsx(
                  'flex items-center px-4 py-2.5 mx-2 rounded-lg text-sm transition-colors',
                  active
                    ? 'bg-cyber-accent/10 text-cyber-accent'
                    : 'text-cyber-muted hover:text-white hover:bg-white/5'
                )}
              >
                <item.icon className="w-5 h-5 flex-shrink-0" />
                {!collapsed && <span className="ml-3">{item.label}</span>}
                {!collapsed && item.path === '/alerts' && alertCount > 0 && (
                  <span className="ml-auto bg-red-500 text-white text-xs px-1.5 py-0.5 rounded-full">
                    {alertCount > 99 ? '99+' : alertCount}
                  </span>
                )}
              </Link>
            )
          })}
        </nav>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center justify-center h-10 border-t border-cyber-border text-cyber-muted hover:text-white"
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="flex items-center h-14 px-6 bg-cyber-surface border-b border-cyber-border">
          <div className="flex items-center gap-4 flex-1">
            {/* Live indicator */}
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-cyber-success live-indicator" />
              <span className="text-xs text-cyber-muted">LIVE</span>
            </div>

            {/* EPS */}
            <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-cyber-card">
              <Activity className="w-3.5 h-3.5 text-cyber-accent" />
              <span className="text-xs font-mono text-cyber-accent">{eps.toFixed(0)} EPS</span>
            </div>

            {/* Global search */}
            <div className="flex-1 max-w-md">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                <input
                  type="text"
                  placeholder="Search events, alerts, IPs... (Ctrl+K)"
                  className="w-full pl-10 pr-4 py-1.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent"
                />
              </div>
            </div>
          </div>

          {/* Right side */}
          <div className="flex items-center gap-4">
            <Link to="/alerts" className="relative">
              <Bell className="w-5 h-5 text-cyber-muted hover:text-white" />
              {alertCount > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-[10px] text-white flex items-center justify-center">
                  {alertCount > 9 ? '9+' : alertCount}
                </span>
              )}
            </Link>

            {user && (
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-full bg-cyber-accent/20 flex items-center justify-center">
                  <span className="text-xs font-semibold text-cyber-accent">
                    {user.full_name.charAt(0).toUpperCase()}
                  </span>
                </div>
                <div className="hidden lg:block">
                  <div className="text-sm font-medium">{user.full_name}</div>
                  <div className="text-xs text-cyber-muted">{user.role}</div>
                </div>
                <button onClick={onLogout} className="ml-2 text-cyber-muted hover:text-red-400">
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6 bg-cyber-bg">
          {children}
        </main>
      </div>
    </div>
  )
}
