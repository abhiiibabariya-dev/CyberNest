export interface User {
  id: string
  username: string
  email: string
  full_name: string
  role: string
  is_active: boolean
  is_mfa_enabled: boolean
  department: string | null
  created_at: string
  last_login: string | null
}

export interface Alert {
  id: string
  title: string
  description: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive' | 'escalated'
  rule_id: string | null
  rule_name: string | null
  source_ip: string | null
  destination_ip: string | null
  hostname: string | null
  username: string | null
  process_name: string | null
  mitre_tactics: string[] | null
  mitre_techniques: string[] | null
  threat_intel: Record<string, unknown> | null
  geo_data: Record<string, unknown> | null
  event_count: number
  raw_log: string | null
  assignee_id: string | null
  incident_id: string | null
  created_at: string
  acknowledged_at: string | null
  resolved_at: string | null
}

export interface DetectionRule {
  id: string
  rule_id: string
  name: string
  description: string | null
  severity: string
  level: number
  rule_type: string
  rule_format: string
  logic: Record<string, unknown>
  mitre_tactics: string[] | null
  mitre_techniques: string[] | null
  group: string | null
  tags: string[] | null
  enabled: boolean
  total_hits: number
  last_hit_at: string | null
  created_at: string
}

export interface Incident {
  id: string
  case_id: string
  title: string
  description: string | null
  severity: string
  status: string
  template: string | null
  assignee_id: string | null
  tags: string[] | null
  mitre_tactics: string[] | null
  mitre_techniques: string[] | null
  timeline: TimelineEntry[] | null
  created_at: string
  updated_at: string
  closed_at: string | null
}

export interface TimelineEntry {
  timestamp: string
  action: string
  user: string
  detail: string
}

export interface Agent {
  id: string
  hostname: string
  ip_address: string
  os_type: string
  os_version: string | null
  agent_version: string
  status: 'online' | 'offline' | 'degraded' | 'pending'
  group: string | null
  labels: Record<string, string> | null
  last_seen: string | null
  cpu_usage: number | null
  memory_usage: number | null
  events_per_second: number | null
  registered_at: string
}

export interface Playbook {
  id: string
  name: string
  description: string | null
  version: number
  enabled: boolean
  trigger_type: string
  steps: PlaybookStep[]
  tags: string[] | null
  total_runs: number
  successful_runs: number
  created_at: string
}

export interface PlaybookStep {
  name: string
  action: string
  input: string
  condition?: string
  output?: string
  on_failure?: string
}

export interface PlaybookRun {
  id: string
  playbook_id: string
  status: string
  is_dry_run: boolean
  step_results: StepResult[] | null
  started_at: string
  completed_at: string | null
  duration_ms: number | null
}

export interface StepResult {
  step: string
  action: string
  status: string
  result?: Record<string, unknown>
  error?: string
}

export interface DashboardStats {
  total_events_24h: number
  total_alerts_24h: number
  critical_alerts: number
  high_alerts: number
  medium_alerts: number
  low_alerts: number
  active_agents: number
  total_agents: number
  active_incidents: number
  events_per_second: number
  top_attackers: { ip: string; count: number }[]
  top_rules: { rule: string; count: number }[]
  alert_trend: { hour: string; count: number }[]
  mitre_coverage: Record<string, number>
}

export interface SearchResult {
  total: number
  took_ms: number
  hits: Record<string, unknown>[]
}
