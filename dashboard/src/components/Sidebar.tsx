import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Bell, Search, Shield, FolderOpen, Zap,
  Globe, Server, Monitor, FileText, Settings, ChevronLeft, ChevronRight,
} from 'lucide-react';
import { useCyberNestStore } from '../store';

const NAV_ITEMS = [
  { path: '/', icon: LayoutDashboard, label: 'Overview' },
  { path: '/alerts', icon: Bell, label: 'Alerts', showBadge: true },
  { path: '/search', icon: Search, label: 'Log Search' },
  { path: '/rules', icon: Shield, label: 'Detection Rules' },
  { path: '/cases', icon: FolderOpen, label: 'Cases' },
  { path: '/playbooks', icon: Zap, label: 'Playbooks' },
  { path: '/threat-intel', icon: Globe, label: 'Threat Intel' },
  { path: '/assets', icon: Server, label: 'Assets' },
  { path: '/agents', icon: Monitor, label: 'Agents' },
  { path: '/reports', icon: FileText, label: 'Reports' },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  const location = useLocation();
  const collapsed = useCyberNestStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useCyberNestStore((s) => s.toggleSidebar);
  const liveAlertCount = useCyberNestStore((s) => s.liveAlertCount);

  return (
    <aside
      className={`flex flex-col bg-cyber-surface border-r border-cyber-border transition-all duration-300 ${
        collapsed ? 'w-16' : 'w-60'
      }`}
    >
      {/* Logo */}
      <div className="flex items-center h-14 px-4 border-b border-cyber-border">
        <div className="flex-shrink-0">
          <svg
            width="28"
            height="28"
            viewBox="0 0 32 32"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M16 2L4 8v8c0 7.73 5.12 14.95 12 16.73C22.88 30.95 28 23.73 28 16V8L16 2z"
              fill="none"
              stroke="#00d4ff"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            <path
              d="M16 6L8 10v6c0 5.52 3.41 10.67 8 11.94C20.59 26.67 24 21.52 24 16v-6L16 6z"
              fill="rgba(0, 212, 255, 0.1)"
              stroke="#00d4ff"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
            <path
              d="M12 15l3 3 5-5"
              stroke="#00ff88"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        {!collapsed && (
          <span className="ml-3 font-bold text-lg text-white tracking-tight">
            Cyber<span className="text-cyber-accent">Nest</span>
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const active =
            location.pathname === item.path ||
            (item.path !== '/' && location.pathname.startsWith(item.path));
          return (
            <Link
              key={item.path}
              to={item.path}
              title={collapsed ? item.label : undefined}
              className={`flex items-center px-4 py-2.5 mx-2 rounded-lg text-sm transition-colors ${
                active
                  ? 'bg-cyber-accent/10 text-cyber-accent'
                  : 'text-cyber-muted hover:text-white hover:bg-white/5'
              }`}
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {!collapsed && <span className="ml-3">{item.label}</span>}
              {!collapsed && item.showBadge && liveAlertCount > 0 && (
                <span className="ml-auto bg-red-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
                  {liveAlertCount > 99 ? '99+' : liveAlertCount}
                </span>
              )}
              {collapsed && item.showBadge && liveAlertCount > 0 && (
                <span className="absolute left-11 top-1 w-2 h-2 bg-red-500 rounded-full" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center h-10 border-t border-cyber-border text-cyber-muted hover:text-white transition-colors"
      >
        {collapsed ? (
          <ChevronRight className="w-4 h-4" />
        ) : (
          <ChevronLeft className="w-4 h-4" />
        )}
      </button>
    </aside>
  );
}
