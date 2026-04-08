// Re-export from new API module + legacy compat wrapper
import axiosInstance, {
  authApi, alertsApi, agentsApi, rulesApi, casesApi, searchApi,
  dashboardApi, playbooksApi, threatIntelApi, usersApi,
  setTokens, clearTokens, getAccessToken,
} from '../api/cybernest';
import type { Rule, Case, PlaybookExecution, User } from '../types';

export const api = {
  setToken(token: string) { setTokens(token); },
  clearToken() { clearTokens(); },
  isAuthenticated() { return !!getAccessToken(); },

  login: (username: string, password: string) =>
    authApi.login({ username, password }) as Promise<{ access_token: string; user: User }>,
  register: (data: unknown) => authApi.register(data as Parameters<typeof authApi.register>[0]),
  getMe: () => authApi.me(),

  getDashboardStats: () => dashboardApi.stats(),

  getAlerts: (params = '') => alertsApi.list(params),
  getAlert: (id: string) => alertsApi.get(id),
  updateAlert: (id: string, data: { status?: string; assigned_to?: string }) =>
    alertsApi.updateStatus(id, { status: data.status ?? 'in_progress', assigned_to: data.assigned_to }),
  getAlertStats: () => alertsApi.stats(),

  searchEvents: (data: { q: string; from_time?: string; size?: number }) =>
    searchApi.query(data),
  ingestLog: (data: unknown) =>
    axiosInstance.post('/events/ingest', data).then((r) => r.data),

  getRules: (params = '') => rulesApi.list(params),
  getRule: (id: string) => rulesApi.get(id),
  createRule: (data: unknown) => rulesApi.create(data as Partial<Rule>),
  updateRule: (id: string, data: unknown) => rulesApi.update(id, data as Partial<Rule>),
  deleteRule: (id: string) => rulesApi.delete(id),
  toggleRule: (id: string) => rulesApi.toggle(id),

  getCases: (params = '') => casesApi.list(params),
  getCase: (id: string) => casesApi.get(id),
  createCase: (data: unknown) => casesApi.create(data as Partial<Case>),
  updateCase: (id: string, data: unknown) => casesApi.update(id, data as Partial<Case>),
  getCaseTasks: (id: string) => casesApi.tasks(id),
  createCaseTask: (id: string, data: unknown) => casesApi.createTask(id, data as Record<string, unknown>),
  getCaseObservables: (id: string) => casesApi.observables(id),
  addObservable: (id: string, data: unknown) => casesApi.addObservable(id, data as Record<string, unknown>),

  getPlaybooks: (params = '') => playbooksApi.list(params),
  getPlaybook: (id: string) => playbooksApi.get(id),
  triggerPlaybook: (data: { playbook_id: string; dry_run?: boolean }) => playbooksApi.trigger(data),
  getPlaybookRuns: (params = '') => playbooksApi.history(params) as Promise<PlaybookExecution[]>,

  getAgents: (params = '') => agentsApi.list(params),
  getAgent: (id: string) => agentsApi.get(id),

  lookupIOC: (value: string) => threatIntelApi.lookup(value),
  getIOCs: (params = '') => threatIntelApi.iocs(params),
  getFeeds: () => threatIntelApi.feeds(),

  getUsers: () => usersApi.list(),
  createUser: (data: unknown) => usersApi.create(data as Parameters<typeof usersApi.create>[0]),
  updateUser: (id: string, data: unknown) => usersApi.update(id, data as Partial<User>),
};
