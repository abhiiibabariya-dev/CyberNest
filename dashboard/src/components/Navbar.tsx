import { useState, useEffect, useRef } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Bell, Search, User, LogOut, KeyRound } from 'lucide-react';
import { useCyberNestStore } from '../store';
import type { User as CyberNestUser } from '../types';

const PAGE_TITLES: Record<string, string> = {
  '/': 'Security Overview',
  '/alerts': 'Alert Center',
  '/search': 'Log Search',
  '/rules': 'Detection Rules',
  '/cases': 'Cases',
  '/playbooks': 'SOAR Playbooks',
  '/threat-intel': 'Threat Intelligence',
  '/assets': 'Asset Inventory',
  '/agents': 'Agent Fleet',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

interface NavbarProps {
  user?: CyberNestUser | null;
  onLogout?: () => void;
  alertCount?: number;
  eps?: number;
}

export default function Navbar({ user: propUser, onLogout }: NavbarProps = {}) {
  const location = useLocation();
  const navigate = useNavigate();
  const storeUser = useCyberNestStore((s) => s.user);
  const liveAlertCount = useCyberNestStore((s) => s.liveAlertCount);
  const resetLiveAlertCount = useCyberNestStore((s) => s.resetLiveAlertCount);
  const webSocketConnected = useCyberNestStore((s) => s.webSocketConnected);
  const logout = useCyberNestStore((s) => s.logout);
  const user = propUser ?? storeUser;

  const [clock, setClock] = useState(new Date());
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const timer = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const pageTitle =
    PAGE_TITLES[location.pathname] ||
    Object.entries(PAGE_TITLES).find(([k]) => k !== '/' && location.pathname.startsWith(k))?.[1] ||
    'CyberNest';

  const handleLogout = () => {
    if (onLogout) {
      onLogout();
    } else {
      logout();
    }
    navigate('/login');
  };

  return (
    <header className="flex items-center h-14 px-6 bg-cyber-surface border-b border-cyber-border">
      <div className="flex items-center gap-4 flex-1">
        <h2 className="text-sm font-semibold text-white">{pageTitle}</h2>
        <div className="w-px h-5 bg-cyber-border" />
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${webSocketConnected ? 'bg-cyber-success live-indicator' : 'bg-red-400'}`} />
          <span className="text-xs text-cyber-muted">{webSocketConnected ? 'LIVE' : 'OFFLINE'}</span>
        </div>
        <div className="text-xs font-mono text-cyber-muted">{clock.toLocaleTimeString('en-US', { hour12: false })}</div>
        <div className="flex-1 max-w-md">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              placeholder="Search events, alerts, IPs... (Ctrl+K)"
              className="w-full pl-10 pr-4 py-1.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-white placeholder:text-cyber-muted focus:outline-none focus:border-cyber-accent"
              onFocus={() => navigate('/search')}
              readOnly
            />
          </div>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <Link to="/alerts" className="relative p-1.5 rounded-lg hover:bg-white/5 transition-colors" onClick={() => resetLiveAlertCount()}>
          <Bell className="w-5 h-5 text-cyber-muted hover:text-white" />
          {liveAlertCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 w-4.5 h-4.5 bg-red-500 rounded-full text-[10px] text-white flex items-center justify-center font-bold min-w-[18px] px-1">
              {liveAlertCount > 9 ? '9+' : liveAlertCount}
            </span>
          )}
        </Link>
        {user && (
          <div className="relative" ref={dropdownRef}>
            <button onClick={() => setShowDropdown(!showDropdown)} className="flex items-center gap-2 p-1 rounded-lg hover:bg-white/5 transition-colors">
              <div className="w-7 h-7 rounded-full bg-cyber-accent/20 flex items-center justify-center">
                <span className="text-xs font-semibold text-cyber-accent">
                  {user.full_name?.charAt(0)?.toUpperCase() || user.username?.charAt(0)?.toUpperCase() || 'U'}
                </span>
              </div>
              <div className="hidden lg:block text-left">
                <div className="text-sm font-medium text-white">{user.full_name || user.username}</div>
                <div className="text-[10px] text-cyber-muted capitalize">{user.role}</div>
              </div>
            </button>
            {showDropdown && (
              <div className="absolute right-0 top-full mt-1 w-48 bg-cyber-surface border border-cyber-border rounded-xl shadow-lg py-1 z-50">
                <Link to="/settings" onClick={() => setShowDropdown(false)} className="flex items-center gap-2 px-4 py-2 text-sm text-cyber-muted hover:text-white hover:bg-white/5">
                  <User className="w-4 h-4" />
                  Profile
                </Link>
                <Link to="/settings" onClick={() => setShowDropdown(false)} className="flex items-center gap-2 px-4 py-2 text-sm text-cyber-muted hover:text-white hover:bg-white/5">
                  <KeyRound className="w-4 h-4" />
                  Change Password
                </Link>
                <div className="border-t border-cyber-border my-1" />
                <button onClick={handleLogout} className="flex items-center gap-2 px-4 py-2 text-sm text-red-400 hover:bg-red-500/10 w-full">
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}
