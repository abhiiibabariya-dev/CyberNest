// ─── CyberNest SIEM+SOAR Type Definitions ───────────────────────────────────

export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'viewer' | 'super_admin' | 'soc_lead' | 'read_only';
  is_active: boolean;
  mfa_enabled: boolean;
  avatar_url?: string;
  department?: string | null;
  last_login?: string | null;
  created_at: string;
  updated_at?: string;
}

export interface Agent {
  id: string;
  hostname: string;
  ip_address: string;
  os: string;
  os_type?: string;
  os_version: string | null;
  agent_version: string;
  status: 'online' | 'offline' | 'degraded' | 'installing' | 'pending';
  last_seen: string | null;
  labels: Record<string, string> | null;
  group?: string | null;
  cpu_usage?: number | null;
  memory_usage?: number | null;
  disk_usage?: number | null;
  events_per_second?: number | null;
  enrolled_at?: string;
  registered_at?: string;
  config?: Record<string, unknown>;
}

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'info';
export type AlertStatus = 'new' | 'acknowledged' | 'in_progress' | 'investigating' | 'resolved' | 'closed' | 'false_positive' | 'escalated';

export interface Alert {
  id: string;
  title: string;
  description: string | null;
  severity: AlertSeverity;
  status: AlertStatus;
  source: string;
  rule_id?: string | null;
  rule_name?: string | null;
  agent_id?: string | null;
  agent_hostname?: string | null;
  assigned_to?: string | null;
  assigned_to_name?: string | null;
  assignee_id?: string | null;
  case_id?: string | null;
  incident_id?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  hostname?: string | null;
  username?: string | null;
  process_name?: string | null;
  tags: string[];
  mitre_tactics: string[] | null;
  mitre_techniques: string[] | null;
  threat_intel?: Record<string, unknown> | null;
  geo_data?: Record<string, unknown> | null;
  raw_event?: Record<string, unknown>;
  raw_log?: string | null;
  observables: AlertObservable[];
  event_count?: number;
  comment_count?: number;
  created_at: string;
  updated_at?: string;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
}

export interface AlertObservable {
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'file' | 'registry' | 'process';
  value: string;
  tags?: string[];
}

export interface AlertComment {
  id: string;
  alert_id: string;
  user_id: string;
  user_name: string;
  content: string;
  created_at: string;
}

export interface Rule {
  id: string;
  rule_id?: string;
  name: string;
  description: string | null;
  severity: AlertSeverity;
  level?: number;
  enabled: boolean;
  rule_type: string;
  rule_format?: string;
  language?: string;
  content?: string;
  logic?: Record<string, unknown>;
  data_sources?: string[];
  mitre_tactics: string[] | null;
  mitre_techniques: string[] | null;
  group?: string | null;
  tags: string[] | null;
  false_positive_rate?: number;
  total_hits?: number;
  match_count_24h?: number;
  last_match?: string | null;
  last_hit_at?: string | null;
  author?: string;
  created_at: string;
  updated_at?: string;
}

// Alias for backward compat
export type DetectionRule = Rule;

export interface RuleStats {
  total_rules: number;
  enabled_rules: number;
  disabled_rules: number;
  matches_24h: number;
  top_firing_rules: { rule_id: string; rule_name: string; count: number }[];
  rules_by_severity: Record<AlertSeverity, number>;
}

export type CaseStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed' | 'contained' | 'eradicated' | 'recovered';
export type CasePriority = 'critical' | 'high' | 'medium' | 'low';

export interface Case {
  id: string;
  case_id?: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  severity?: string;
  priority?: CasePriority;
  assignee_id?: string | null;
  assignee_name?: string;
  owner_id?: string;
  owner_name?: string;
  template?: string | null;
  tags: string[] | null;
  mitre_tactics?: string[] | null;
  mitre_techniques?: string[] | null;
  alert_count?: number;
  task_count?: number;
  tasks_completed?: number;
  observable_count?: number;
  tlp?: 'white' | 'green' | 'amber' | 'red';
  pap?: 'white' | 'green' | 'amber' | 'red';
  timeline?: TimelineEntry[] | null;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
  resolution_summary?: string;
}

// Alias for backward compat
export type Incident = Case;

export interface TimelineEntry {
  timestamp: string;
  action: string;
  user: string;
  detail: string;
}

export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'cancelled';

export interface CaseTask {
  id: string;
  case_id: string;
  title: string;
  description: string;
  status: TaskStatus;
  assignee_id?: string;
  assignee_name?: string;
  due_date?: string;
  order: number;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

export interface CaseObservable {
  id: string;
  case_id: string;
  type: string;
  value: string;
  description?: string;
  tlp: 'white' | 'green' | 'amber' | 'red';
  is_ioc: boolean;
  tags: string[];
  enrichments?: Record<string, unknown>;
  created_at: string;
}

export interface CaseComment {
  id: string;
  case_id: string;
  user_id: string;
  user_name: string;
  content: string;
  created_at: string;
}

export interface CaseTimelineEntry {
  id: string;
  case_id: string;
  event_type: string;
  description: string;
  user_name?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export type PlaybookStatus = 'active' | 'draft' | 'disabled';

export interface Playbook {
  id: string;
  name: string;
  description: string | null;
  status?: PlaybookStatus;
  enabled?: boolean;
  version?: number;
  trigger_type: string;
  trigger_conditions?: Record<string, unknown>;
  steps: PlaybookStep[];
  tags: string[] | null;
  execution_count?: number;
  total_runs?: number;
  successful_runs?: number;
  last_executed?: string;
  avg_duration_seconds?: number;
  author?: string;
  created_at: string;
  updated_at?: string;
}

export interface PlaybookStep {
  id?: string;
  name: string;
  type?: 'action' | 'condition' | 'loop' | 'parallel' | 'wait';
  action: string;
  input?: string;
  parameters?: Record<string, unknown>;
  condition?: string;
  output?: string;
  on_success?: string;
  on_failure?: string;
  timeout_seconds?: number;
}

export type ExecutionStatus = 'running' | 'completed' | 'failed' | 'cancelled';

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_name?: string;
  status: ExecutionStatus | string;
  is_dry_run?: boolean;
  trigger?: string;
  triggered_by?: string;
  alert_id?: string;
  case_id?: string;
  steps_completed?: number;
  steps_total?: number;
  step_results?: StepResult[] | null;
  error_message?: string;
  started_at: string;
  completed_at?: string | null;
  duration_seconds?: number;
  duration_ms?: number | null;
  results?: Record<string, unknown>;
}

// Alias for backward compat
export type PlaybookRun = PlaybookExecution;

export interface StepResult {
  step: string;
  action: string;
  status: string;
  result?: Record<string, unknown>;
  error?: string;
}

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'url' | 'email' | 'cve';
  value: string;
  description?: string;
  severity: AlertSeverity;
  confidence: number;
  source: string;
  feed_id?: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  expiration?: string;
  is_active: boolean;
  sightings: number;
  related_alerts: number;
}

export interface ThreatFeed {
  id: string;
  name: string;
  provider: string;
  feed_type: 'stix' | 'csv' | 'json' | 'taxii' | 'misp';
  url: string;
  enabled: boolean;
  ioc_count: number;
  last_fetched?: string;
  fetch_interval_minutes: number;
  status: 'active' | 'error' | 'disabled';
  error_message?: string;
  created_at: string;
}

export interface ThreatLookupResult {
  query: string;
  type: string;
  found: boolean;
  value?: string;
  results?: ThreatLookupSource[];
  sources?: ThreatLookupSource[];
  related_alerts?: Alert[];
  whois?: Record<string, unknown>;
  dns?: Record<string, unknown>;
  geo?: {
    country: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    asn?: string;
    org?: string;
  };
}

export interface ThreatLookupSource {
  name?: string;
  ioc_type?: string;
  severity?: AlertSeverity;
  confidence?: number;
  threat_score?: number;
  threat_type?: string;
  malware_family?: string;
  source_count?: number;
  description?: string;
  tags?: string[];
  first_seen?: string;
  last_seen?: string;
  reference_url?: string;
}

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  mac_address?: string;
  os: string;
  os_version?: string;
  asset_type: 'server' | 'workstation' | 'network_device' | 'iot' | 'cloud' | 'other';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  owner?: string;
  department?: string;
  location?: string;
  agent_id?: string;
  agent_status?: 'online' | 'offline';
  tags: string[];
  vulnerabilities_count?: number;
  last_seen?: string;
  created_at: string;
  updated_at: string;
}

export interface NotificationChannel {
  id: string;
  name: string;
  type: 'email' | 'slack' | 'webhook' | 'teams' | 'pagerduty' | 'telegram';
  enabled: boolean;
  config: Record<string, unknown>;
  severity_filter: AlertSeverity[];
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_alerts?: number;
  open_alerts?: number;
  total_events_24h: number;
  total_alerts_24h: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  resolved_today?: number;
  mttr_minutes?: number;
  active_agents: number;
  total_agents: number;
  online_agents?: number;
  offline_agents?: number;
  events_per_second: number;
  active_incidents: number;
  total_rules?: number;
  active_rules?: number;
  open_cases?: number;
  total_iocs?: number;
  active_playbooks?: number;
  alerts_by_severity?: { severity: AlertSeverity; count: number }[];
  alerts_by_source?: { source: string; count: number }[];
  alerts_trend_24h?: { timestamp: string; count: number }[];
  alert_trend: { hour: string; count: number }[];
  top_mitre_techniques?: { technique: string; count: number }[];
  top_attackers: { ip: string; count: number }[];
  top_rules: { rule: string; count: number }[];
  mitre_coverage: Record<string, number>;
  recent_alerts?: Alert[];
}

export interface SearchResult {
  total: number;
  took_ms: number;
  hits: Record<string, unknown>[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface AlertStats {
  total: number;
  by_severity: Record<AlertSeverity, number>;
  by_status: Record<AlertStatus, number>;
  trend: { timestamp: string; count: number }[];
}

export interface AuthTokens {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
}

export interface LoginRequest {
  email?: string;
  username?: string;
  password: string;
  totp_code?: string;
}

export interface LoginResponse {
  access_token?: string;
  tokens?: AuthTokens;
  mfa_required?: boolean;
  user?: User;
}

export interface ApiError {
  detail: string;
  status_code: number;
}
