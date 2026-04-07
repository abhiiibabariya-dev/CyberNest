const API_BASE = '/api/v1'

let authToken: string | null = localStorage.getItem('cybernest_token')

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (res.status === 401) {
    localStorage.removeItem('cybernest_token')
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(error.detail || res.statusText)
  }

  if (res.status === 204) return {} as T
  return res.json()
}

function get<T>(path: string) { return request<T>(path) }
function post<T>(path: string, body?: unknown) { return request<T>(path, { method: 'POST', body: JSON.stringify(body) }) }
function patch<T>(path: string, body?: unknown) { return request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }) }
function put<T>(path: string, body?: unknown) { return request<T>(path, { method: 'PUT', body: JSON.stringify(body) }) }
function del<T>(path: string) { return request<T>(path, { method: 'DELETE' }) }

export const api = {
  setToken(token: string) {
    authToken = token
    localStorage.setItem('cybernest_token', token)
  },
  clearToken() {
    authToken = null
    localStorage.removeItem('cybernest_token')
  },
  isAuthenticated() { return !!authToken },

  // Auth
  login: (username: string, password: string) => post<{ access_token: string; user: unknown }>('/auth/login', { username, password }),
  register: (data: unknown) => post('/auth/register', data),
  getMe: () => get<unknown>('/auth/me'),

  // Dashboard
  getDashboardStats: () => get<import('../types').DashboardStats>('/dashboard/stats'),

  // Alerts
  getAlerts: (params = '') => get<import('../types').Alert[]>(`/alerts${params}`),
  getAlert: (id: string) => get<import('../types').Alert>(`/alerts/${id}`),
  updateAlert: (id: string, data: unknown) => patch<import('../types').Alert>(`/alerts/${id}`, data),
  getAlertStats: () => get<unknown>('/alerts/stats'),

  // Events / Search
  searchEvents: (data: unknown) => post<import('../types').SearchResult>('/events/search', data),
  ingestLog: (data: unknown) => post('/events/ingest', data),

  // Rules
  getRules: (params = '') => get<import('../types').DetectionRule[]>(`/rules${params}`),
  getRule: (id: string) => get<import('../types').DetectionRule>(`/rules/${id}`),
  createRule: (data: unknown) => post('/rules', data),
  updateRule: (id: string, data: unknown) => put(`/rules/${id}`, data),
  deleteRule: (id: string) => del(`/rules/${id}`),
  toggleRule: (id: string) => post(`/rules/${id}/toggle`),

  // Cases / Incidents
  getCases: (params = '') => get<import('../types').Incident[]>(`/cases${params}`),
  getCase: (id: string) => get<import('../types').Incident>(`/cases/${id}`),
  createCase: (data: unknown) => post('/cases', data),
  updateCase: (id: string, data: unknown) => patch(`/cases/${id}`, data),
  getCaseTasks: (id: string) => get(`/cases/${id}/tasks`),
  createCaseTask: (id: string, data: unknown) => post(`/cases/${id}/tasks`, data),
  getCaseObservables: (id: string) => get(`/cases/${id}/observables`),
  addObservable: (id: string, data: unknown) => post(`/cases/${id}/observables`, data),

  // Playbooks
  getPlaybooks: (params = '') => get<import('../types').Playbook[]>(`/playbooks${params}`),
  getPlaybook: (id: string) => get<import('../types').Playbook>(`/playbooks/${id}`),
  triggerPlaybook: (data: unknown) => post('/playbooks/trigger', data),
  getPlaybookRuns: (params = '') => get<import('../types').PlaybookRun[]>(`/playbooks/runs${params}`),

  // Agents
  getAgents: (params = '') => get<import('../types').Agent[]>(`/agents${params}`),
  getAgent: (id: string) => get<import('../types').Agent>(`/agents/${id}`),

  // Threat Intel
  lookupIOC: (value: string) => post('/threat-intel/lookup', undefined).then(() => get(`/threat-intel/lookup?value=${value}`)),
  getIOCs: (params = '') => get(`/threat-intel/iocs${params}`),
  getFeeds: () => get('/threat-intel/feeds'),

  // Users
  getUsers: () => get<import('../types').User[]>('/users'),
  createUser: (data: unknown) => post('/users', data),
  updateUser: (id: string, data: unknown) => patch(`/users/${id}`, data),
}
