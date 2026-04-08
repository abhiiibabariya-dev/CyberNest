import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import type {
  Alert, AlertComment, AlertStats, Agent, Asset, AuthTokens, Case,
  CaseComment, CaseObservable, CaseTask, CaseTimelineEntry,
  DashboardStats, IOC, LoginResponse, NotificationChannel,
  Playbook, PlaybookExecution, Rule, RuleStats, SearchResult,
  ThreatFeed, ThreatLookupResult, User,
} from '@/types';

// ─── Axios Instance ──────────────────────────────────────────────────────────

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
});

// ─── Token helpers ───────────────────────────────────────────────────────────

function getAccessToken(): string | null {
  return localStorage.getItem('cybernest_token');
}
function getRefreshToken(): string | null {
  return localStorage.getItem('cybernest_refresh_token');
}
function setTokens(access: string, refresh?: string) {
  localStorage.setItem('cybernest_token', access);
  if (refresh) localStorage.setItem('cybernest_refresh_token', refresh);
}
function clearTokens() {
  localStorage.removeItem('cybernest_token');
  localStorage.removeItem('cybernest_refresh_token');
}

// ─── Request interceptor: inject JWT ─────────────────────────────────────────

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getAccessToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ─── Response interceptor: refresh on 401 ────────────────────────────────────

let isRefreshing = false;
let failedQueue: { resolve: (t: string) => void; reject: (e: unknown) => void }[] = [];

function processQueue(error: unknown, token: string | null) {
  failedQueue.forEach(p => (error ? p.reject(error) : p.resolve(token!)));
  failedQueue = [];
}

api.interceptors.response.use(
  res => res,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    if (error.response?.status === 401 && !originalRequest._retry) {
      const refresh = getRefreshToken();
      if (!refresh) {
        clearTokens();
        window.location.href = '/login';
        return Promise.reject(error);
      }

      if (isRefreshing) {
        return new Promise<string>((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${token}`;
          }
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await axios.post(
          `${import.meta.env.VITE_API_BASE_URL || '/api/v1'}/auth/refresh`,
          { refresh_token: refresh },
        );
        const newToken = data.access_token;
        setTokens(newToken, data.refresh_token || refresh);
        processQueue(null, newToken);
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
        }
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        clearTokens();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  },
);

// ─── Auth API ────────────────────────────────────────────────────────────────

export const authApi = {
  login: (credentials: { email?: string; username?: string; password: string; totp_code?: string }) =>
    api.post<LoginResponse>('/auth/login', credentials).then(r => r.data),

  register: (data: { email: string; username: string; password: string; full_name: string }) =>
    api.post<User>('/auth/register', data).then(r => r.data),

  refresh: (refreshToken: string) =>
    api.post<AuthTokens>('/auth/refresh', { refresh_token: refreshToken }).then(r => r.data),

  logout: () =>
    api.post('/auth/logout').then(r => r.data).catch(() => {}).finally(clearTokens),

  me: () =>
    api.get<User>('/auth/me').then(r => r.data),

  setupMfa: () =>
    api.post<{ secret: string; qr_code: string }>('/auth/mfa/setup').then(r => r.data),

  verifyMfa: (code: string) =>
    api.post('/auth/mfa/verify', { totp_code: code }).then(r => r.data),

  disableMfa: (code: string) =>
    api.post('/auth/mfa/disable', { totp_code: code }).then(r => r.data),
};

// ─── Alerts API ──────────────────────────────────────────────────────────────

export const alertsApi = {
  list: (params?: string) =>
    api.get<Alert[]>(`/alerts${params || ''}`).then(r => r.data),

  get: (id: string) =>
    api.get<Alert>(`/alerts/${id}`).then(r => r.data),

  updateStatus: (id: string, data: { status: string; assigned_to?: string }) =>
    api.patch<Alert>(`/alerts/${id}`, data).then(r => r.data),

  assign: (id: string, userId: string) =>
    api.patch<Alert>(`/alerts/${id}`, { assignee_id: userId }).then(r => r.data),

  stats: () =>
    api.get<AlertStats>('/alerts/stats').then(r => r.data),

  comment: (id: string, content: string) =>
    api.post<AlertComment>(`/alerts/${id}/comments`, { content }).then(r => r.data),

  getComments: (id: string) =>
    api.get<AlertComment[]>(`/alerts/${id}/comments`).then(r => r.data),

  createCase: (id: string, data: { title: string; description?: string }) =>
    api.post<Case>(`/alerts/${id}/create-case`, data).then(r => r.data),
};

// ─── Agents API ──────────────────────────────────────────────────────────────

export const agentsApi = {
  list: (params?: string) =>
    api.get<Agent[]>(`/agents${params || ''}`).then(r => r.data),

  get: (id: string) =>
    api.get<Agent>(`/agents/${id}`).then(r => r.data),

  register: (data: { hostname: string; ip_address: string; os: string }) =>
    api.post<Agent>('/agents/register', data).then(r => r.data),

  command: (id: string, command: { action: string; parameters?: Record<string, unknown> }) =>
    api.post(`/agents/${id}/command`, command).then(r => r.data),

  events: (id: string, params?: string) =>
    api.get(`/agents/${id}/events${params || ''}`).then(r => r.data),
};

// ─── Rules API ───────────────────────────────────────────────────────────────

export const rulesApi = {
  list: (params?: string) =>
    api.get<Rule[]>(`/rules${params || ''}`).then(r => r.data),

  get: (id: string) =>
    api.get<Rule>(`/rules/${id}`).then(r => r.data),

  create: (data: Partial<Rule>) =>
    api.post<Rule>('/rules', data).then(r => r.data),

  update: (id: string, data: Partial<Rule>) =>
    api.put<Rule>(`/rules/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    api.delete(`/rules/${id}`).then(r => r.data),

  toggle: (id: string) =>
    api.post<Rule>(`/rules/${id}/toggle`).then(r => r.data),

  import: (data: { format: string; content: string }) =>
    api.post<Rule[]>('/rules/import', data).then(r => r.data),

  test: (data: { rule_content: string; test_event: Record<string, unknown> }) =>
    api.post<{ matched: boolean; details: string }>('/rules/test', data).then(r => r.data),

  stats: () =>
    api.get<RuleStats>('/rules/stats').then(r => r.data),
};

// ─── Cases API ───────────────────────────────────────────────────────────────

export const casesApi = {
  list: (params?: string) =>
    api.get<Case[]>(`/cases${params || ''}`).then(r => r.data),

  get: (id: string) =>
    api.get<Case>(`/cases/${id}`).then(r => r.data),

  create: (data: Partial<Case>) =>
    api.post<Case>('/cases', data).then(r => r.data),

  update: (id: string, data: Partial<Case>) =>
    api.patch<Case>(`/cases/${id}`, data).then(r => r.data),

  tasks: (id: string) =>
    api.get<CaseTask[]>(`/cases/${id}/tasks`).then(r => r.data),

  createTask: (id: string, data: Partial<CaseTask>) =>
    api.post<CaseTask>(`/cases/${id}/tasks`, data).then(r => r.data),

  observables: (id: string) =>
    api.get<CaseObservable[]>(`/cases/${id}/observables`).then(r => r.data),

  addObservable: (id: string, data: Partial<CaseObservable>) =>
    api.post<CaseObservable>(`/cases/${id}/observables`, data).then(r => r.data),

  comments: (id: string) =>
    api.get<CaseComment[]>(`/cases/${id}/comments`).then(r => r.data),

  addComment: (id: string, content: string) =>
    api.post<CaseComment>(`/cases/${id}/comments`, { content }).then(r => r.data),

  timeline: (id: string) =>
    api.get<CaseTimelineEntry[]>(`/cases/${id}/timeline`).then(r => r.data),

  exportPdf: (id: string) =>
    api.get(`/cases/${id}/export/pdf`, { responseType: 'blob' }).then(r => r.data),
};

// ─── Search API ──────────────────────────────────────────────────────────────

export const searchApi = {
  query: (data: { q: string; from_time?: string; to_time?: string; size?: number; source?: string }) =>
    api.post<SearchResult>('/events/search', data).then(r => r.data),
};

// ─── Dashboard API ───────────────────────────────────────────────────────────

export const dashboardApi = {
  stats: () =>
    api.get<DashboardStats>('/dashboard/stats').then(r => r.data),
};

// ─── Playbooks API ───────────────────────────────────────────────────────────

export const playbooksApi = {
  list: (params?: string) =>
    api.get<Playbook[]>(`/playbooks${params || ''}`).then(r => r.data),

  get: (id: string) =>
    api.get<Playbook>(`/playbooks/${id}`).then(r => r.data),

  create: (data: Partial<Playbook>) =>
    api.post<Playbook>('/playbooks', data).then(r => r.data),

  trigger: (data: { playbook_id: string; alert_id?: string; dry_run?: boolean }) =>
    api.post<PlaybookExecution>('/playbooks/trigger', data).then(r => r.data),

  history: (params?: string) =>
    api.get<PlaybookExecution[]>(`/playbooks/runs${params || ''}`).then(r => r.data),
};

// ─── Threat Intel API ────────────────────────────────────────────────────────

export const threatIntelApi = {
  lookup: (value: string) =>
    api.get<ThreatLookupResult>(`/threat-intel/lookup?value=${encodeURIComponent(value)}`).then(r => r.data),

  iocs: (params?: string) =>
    api.get<IOC[]>(`/threat-intel/iocs${params || ''}`).then(r => r.data),

  feeds: () =>
    api.get<ThreatFeed[]>('/threat-intel/feeds').then(r => r.data),
};

// ─── Users API ───────────────────────────────────────────────────────────────

export const usersApi = {
  list: () =>
    api.get<User[]>('/users').then(r => r.data),

  get: (id: string) =>
    api.get<User>(`/users/${id}`).then(r => r.data),

  create: (data: Partial<User> & { password: string }) =>
    api.post<User>('/users', data).then(r => r.data),

  update: (id: string, data: Partial<User>) =>
    api.patch<User>(`/users/${id}`, data).then(r => r.data),

  me: () =>
    api.get<User>('/auth/me').then(r => r.data),
};

// ─── Assets API ──────────────────────────────────────────────────────────────

export const assetsApi = {
  list: (params?: string) =>
    api.get<Asset[]>(`/assets${params || ''}`).then(r => r.data),

  get: (id: string) =>
    api.get<Asset>(`/assets/${id}`).then(r => r.data),
};

// ─── Notifications API ───────────────────────────────────────────────────────

export const notificationsApi = {
  channels: () =>
    api.get<NotificationChannel[]>('/notifications/channels').then(r => r.data),

  createChannel: (data: Partial<NotificationChannel>) =>
    api.post<NotificationChannel>('/notifications/channels', data).then(r => r.data),

  updateChannel: (id: string, data: Partial<NotificationChannel>) =>
    api.patch<NotificationChannel>(`/notifications/channels/${id}`, data).then(r => r.data),

  deleteChannel: (id: string) =>
    api.delete(`/notifications/channels/${id}`).then(r => r.data),
};

// ─── Legacy compat export ────────────────────────────────────────────────────

export { api as axiosInstance, setTokens, clearTokens, getAccessToken };

export default api;
