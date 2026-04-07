import { useEffect, useState } from 'react'
import { Settings as SettingsIcon, Users, Bell, Database, Shield, Key } from 'lucide-react'
import { api } from '../services/api'
import type { User } from '../types'

const ROLE_COLORS: Record<string, string> = {
  super_admin: 'bg-red-500/20 text-red-400',
  admin: 'bg-orange-500/20 text-orange-400',
  soc_lead: 'bg-blue-500/20 text-blue-400',
  analyst: 'bg-green-500/20 text-green-400',
  read_only: 'bg-gray-500/20 text-gray-400',
}

export default function Settings() {
  const [tab, setTab] = useState('users')
  const [users, setUsers] = useState<User[]>([])

  useEffect(() => {
    if (tab === 'users') api.getUsers().then(setUsers).catch(() => {})
  }, [tab])

  const tabs = [
    { id: 'users', icon: Users, label: 'User Management' },
    { id: 'notifications', icon: Bell, label: 'Notifications' },
    { id: 'retention', icon: Database, label: 'Data Retention' },
    { id: 'auth', icon: Key, label: 'Authentication' },
    { id: 'security', icon: Shield, label: 'Security' },
  ]

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <SettingsIcon className="w-6 h-6 text-cyber-accent" /> Settings
      </h1>

      <div className="flex gap-6">
        {/* Sidebar tabs */}
        <div className="w-52 space-y-1">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-left transition-colors ${
                tab === t.id ? 'bg-cyber-accent/10 text-cyber-accent' : 'text-cyber-muted hover:text-white'
              }`}>
              <t.icon className="w-4 h-4" /> {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 bg-cyber-card border border-cyber-border rounded-xl p-6">
          {tab === 'users' && (
            <div>
              <h2 className="text-lg font-semibold mb-4">User Management</h2>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-cyber-border text-left text-xs text-cyber-muted uppercase">
                    <th className="pb-3">User</th>
                    <th className="pb-3">Email</th>
                    <th className="pb-3">Role</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3">Last Login</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id} className="border-b border-cyber-border/30 data-row">
                      <td className="py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-full bg-cyber-accent/20 flex items-center justify-center text-xs font-semibold text-cyber-accent">
                            {u.full_name.charAt(0)}
                          </div>
                          {u.full_name}
                        </div>
                      </td>
                      <td className="py-3 text-cyber-muted">{u.email}</td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-xs ${ROLE_COLORS[u.role] || ''}`}>
                          {u.role.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-3">
                        <span className={`w-2 h-2 inline-block rounded-full mr-1.5 ${u.is_active ? 'bg-green-400' : 'bg-red-400'}`} />
                        {u.is_active ? 'Active' : 'Disabled'}
                      </td>
                      <td className="py-3 text-xs text-cyber-muted">{u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Never'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'notifications' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Notification Channels</h2>
              {['Slack Webhook', 'Email (SMTP)', 'PagerDuty', 'Microsoft Teams', 'Custom Webhook'].map(ch => (
                <div key={ch} className="flex items-center justify-between py-3 border-b border-cyber-border/30">
                  <span>{ch}</span>
                  <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 text-xs rounded">Not configured</span>
                </div>
              ))}
            </div>
          )}

          {tab === 'retention' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Data Retention Policies</h2>
              {[
                { label: 'Hot (SSD)', days: '0-7 days', color: 'text-red-400' },
                { label: 'Warm (HDD)', days: '7-30 days', color: 'text-yellow-400' },
                { label: 'Cold (Compressed)', days: '30-90 days', color: 'text-blue-400' },
                { label: 'Delete', days: 'After 365 days', color: 'text-gray-400' },
              ].map(p => (
                <div key={p.label} className="flex items-center justify-between py-3 border-b border-cyber-border/30">
                  <span className={p.color}>{p.label}</span>
                  <span className="text-sm text-cyber-muted">{p.days}</span>
                </div>
              ))}
            </div>
          )}

          {tab === 'auth' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Authentication Settings</h2>
              {[
                { label: 'JWT Token Expiry', value: '8 hours' },
                { label: 'MFA (TOTP)', value: 'Supported' },
                { label: 'LDAP/AD Integration', value: 'Not configured' },
                { label: 'Password Min Length', value: '8 characters' },
                { label: 'Brute Force Protection', value: '10 attempts / 60s' },
              ].map(s => (
                <div key={s.label} className="flex items-center justify-between py-3 border-b border-cyber-border/30">
                  <span>{s.label}</span>
                  <span className="text-sm text-cyber-muted">{s.value}</span>
                </div>
              ))}
            </div>
          )}

          {tab === 'security' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Security Settings</h2>
              <div className="bg-cyber-bg rounded-lg p-4 text-sm">
                <p className="text-cyber-muted">Platform security features:</p>
                <ul className="mt-2 space-y-1 text-xs text-cyber-muted list-disc list-inside">
                  <li>TLS 1.2/1.3 encryption for all traffic</li>
                  <li>Rate limiting on all API endpoints</li>
                  <li>Full audit logging of all user actions</li>
                  <li>RBAC with 5 role levels</li>
                  <li>JWT token authentication with configurable expiry</li>
                  <li>Redis-backed session management</li>
                  <li>CSP security headers via Nginx</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
