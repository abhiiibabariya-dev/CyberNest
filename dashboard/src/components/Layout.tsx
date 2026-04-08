import { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Navbar from './Navbar';
import { useCyberNestStore } from '../store';
import { useWebSocket } from '../hooks/useWebSocket';
import { authApi } from '../api/cybernest';
import type { Alert, User } from '../types';

interface LayoutProps {
  children: React.ReactNode;
  user?: User | null;
  onLogout?: () => void;
  alertCount?: number;
  eps?: number;
}

export default function Layout({ children, user: propUser, onLogout, alertCount, eps }: LayoutProps) {
  const user = useCyberNestStore((s) => s.user) ?? propUser ?? null;
  const setUser = useCyberNestStore((s) => s.setUser);
  const addLiveAlert = useCyberNestStore((s) => s.addLiveAlert);
  const location = useLocation();

  useWebSocket('/ws/alerts/live', {
    onMessage: (data) => {
      if (data && typeof data === 'object' && 'id' in (data as Record<string, unknown>)) {
        addLiveAlert(data as Alert);
      }
    },
  });

  useWebSocket('/ws/dashboard/live');

  useEffect(() => {
    const token = localStorage.getItem('cybernest_token');
    if (token && !user) {
      authApi.me().then(setUser).catch(() => {
        localStorage.removeItem('cybernest_token');
      });
    }
  }, [user, setUser]);

  const token = localStorage.getItem('cybernest_token');
  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return (
    <div className="flex h-screen overflow-hidden bg-cyber-bg">
      <div className="scan-line" />
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Navbar user={user} onLogout={onLogout} alertCount={alertCount} eps={eps} />
        <main className="flex-1 overflow-y-auto p-6 bg-cyber-bg">{children}</main>
      </div>
    </div>
  );
}
