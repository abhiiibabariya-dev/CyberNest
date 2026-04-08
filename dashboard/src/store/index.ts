import { create } from 'zustand';
import type { Alert, User } from '../types';

// ─── Persistence helpers ─────────────────────────────────────────────────────

function loadFromStorage<T>(key: string, fallback: T): T {
  try {
    const val = localStorage.getItem(key);
    return val ? JSON.parse(val) : fallback;
  } catch {
    return fallback;
  }
}

// ─── Agent status entry ──────────────────────────────────────────────────────

interface AgentStatusEntry {
  id: string;
  hostname: string;
  status: 'online' | 'offline' | 'degraded';
}

// ─── Store shape ─────────────────────────────────────────────────────────────

interface CyberNestState {
  // User
  user: User | null;
  setUser: (user: User | null) => void;

  // Alerts
  alerts: Alert[];
  liveAlertCount: number;
  addLiveAlert: (alert: Alert) => void;
  setAlerts: (alerts: Alert[]) => void;
  resetLiveAlertCount: () => void;
  clearLiveAlerts: () => void;

  // Alert selection
  selectedAlerts: Set<string>;
  toggleAlertSelection: (id: string) => void;
  selectAllAlerts: (ids: string[]) => void;
  clearAlertSelection: () => void;

  // Side panel
  sidePanel: { open: boolean; alertId: string | null };
  openSidePanel: (alertId: string) => void;
  closeSidePanel: () => void;

  // Agents
  agentStatus: AgentStatusEntry[];
  setAgentStatus: (agents: AgentStatusEntry[]) => void;

  // WebSocket
  webSocketConnected: boolean;
  setWebSocketConnected: (connected: boolean) => void;

  // UI
  theme: 'dark';
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;

  // Search
  searchHistory: string[];
  addSearchHistory: (query: string) => void;
  clearSearchHistory: () => void;
  savedSearches: { name: string; query: string; timeRange: string }[];
  addSavedSearch: (search: { name: string; query: string; timeRange: string }) => void;
  removeSavedSearch: (name: string) => void;

  // Auth
  logout: () => void;
}

// ─── Store ───────────────────────────────────────────────────────────────────

export const useCyberNestStore = create<CyberNestState>((set) => ({
  // User
  user: null,
  setUser: (user) => set({ user }),

  // Alerts
  alerts: [],
  liveAlertCount: 0,
  addLiveAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, 500),
      liveAlertCount: state.liveAlertCount + 1,
    })),
  setAlerts: (alerts) => set({ alerts }),
  resetLiveAlertCount: () => set({ liveAlertCount: 0 }),
  clearLiveAlerts: () => set({ alerts: [], liveAlertCount: 0 }),

  // Alert selection
  selectedAlerts: new Set(),
  toggleAlertSelection: (id) =>
    set((s) => {
      const next = new Set(s.selectedAlerts);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return { selectedAlerts: next };
    }),
  selectAllAlerts: (ids) => set({ selectedAlerts: new Set(ids) }),
  clearAlertSelection: () => set({ selectedAlerts: new Set() }),

  // Side panel
  sidePanel: { open: false, alertId: null },
  openSidePanel: (alertId) => set({ sidePanel: { open: true, alertId } }),
  closeSidePanel: () => set({ sidePanel: { open: false, alertId: null } }),

  // Agents
  agentStatus: [],
  setAgentStatus: (agents) => set({ agentStatus: agents }),

  // WebSocket
  webSocketConnected: false,
  setWebSocketConnected: (connected) => set({ webSocketConnected: connected }),

  // UI
  theme: 'dark',
  sidebarCollapsed: false,
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

  // Search
  searchHistory: loadFromStorage<string[]>('cybernest_search_history', []),
  addSearchHistory: (query) =>
    set((s) => {
      const next = [query, ...s.searchHistory.filter((q) => q !== query)].slice(0, 20);
      localStorage.setItem('cybernest_search_history', JSON.stringify(next));
      return { searchHistory: next };
    }),
  clearSearchHistory: () => {
    localStorage.removeItem('cybernest_search_history');
    set({ searchHistory: [] });
  },
  savedSearches: loadFromStorage('cybernest_saved_searches', []),
  addSavedSearch: (search) =>
    set((s) => {
      const next = [...s.savedSearches.filter((ss) => ss.name !== search.name), search];
      localStorage.setItem('cybernest_saved_searches', JSON.stringify(next));
      return { savedSearches: next };
    }),
  removeSavedSearch: (name) =>
    set((s) => {
      const next = s.savedSearches.filter((ss) => ss.name !== name);
      localStorage.setItem('cybernest_saved_searches', JSON.stringify(next));
      return { savedSearches: next };
    }),

  // Auth
  logout: () => {
    localStorage.removeItem('cybernest_token');
    localStorage.removeItem('cybernest_refresh_token');
    set({
      user: null,
      alerts: [],
      liveAlertCount: 0,
      webSocketConnected: false,
      selectedAlerts: new Set(),
    });
  },
}));

// backward compat alias
export const useAppStore = useCyberNestStore;
