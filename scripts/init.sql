-- =============================================================================
-- CyberNest SIEM + SOAR Platform - PostgreSQL Schema
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- ENUM TYPES
-- =============================================================================

CREATE TYPE user_role AS ENUM ('super_admin', 'admin', 'soc_lead', 'analyst', 'readonly');
CREATE TYPE agent_status AS ENUM ('online', 'offline', 'degraded');
CREATE TYPE alert_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE alert_status AS ENUM ('new', 'in_progress', 'resolved', 'false_positive', 'escalated');
CREATE TYPE case_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE case_status AS ENUM ('open', 'in_progress', 'closed');
CREATE TYPE tlp_level AS ENUM ('white', 'green', 'amber', 'red');
CREATE TYPE playbook_exec_status AS ENUM ('pending', 'running', 'success', 'failure', 'cancelled', 'timed_out');
CREATE TYPE ioc_type AS ENUM ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'filename', 'registry_key', 'cve', 'ja3', 'cidr');
CREATE TYPE feed_type AS ENUM ('stix', 'csv', 'json', 'misp', 'otx', 'abuse_ipdb', 'custom');
CREATE TYPE asset_criticality AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE channel_type AS ENUM ('email', 'slack', 'webhook', 'pagerduty', 'teams', 'telegram', 'syslog');
CREATE TYPE observable_data_type AS ENUM ('ip', 'domain', 'url', 'hash', 'email', 'filename', 'registry', 'other');
CREATE TYPE task_status AS ENUM ('pending', 'in_progress', 'completed', 'cancelled');

-- =============================================================================
-- USERS
-- =============================================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(150) NOT NULL UNIQUE,
    email           VARCHAR(254) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            user_role NOT NULL DEFAULT 'analyst',
    mfa_secret      VARCHAR(64),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- AGENTS
-- =============================================================================

CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        VARCHAR(64) NOT NULL UNIQUE,
    hostname        VARCHAR(255) NOT NULL,
    ip              INET NOT NULL,
    os              VARCHAR(50) NOT NULL,
    os_version      VARCHAR(100),
    architecture    VARCHAR(20),
    version         VARCHAR(20) NOT NULL,
    status          agent_status NOT NULL DEFAULT 'offline',
    api_key_hash    VARCHAR(255) NOT NULL,
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    config_json     JSONB DEFAULT '{}'::jsonb,
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- RULES (Detection / Sigma)
-- =============================================================================

CREATE TABLE rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id             VARCHAR(64) NOT NULL UNIQUE,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    level               INTEGER NOT NULL CHECK (level BETWEEN 0 AND 15),
    category            VARCHAR(100),
    mitre_tactic        VARCHAR(100),
    mitre_technique     TEXT[] DEFAULT '{}',
    content_yaml        TEXT NOT NULL,
    sigma_id            VARCHAR(64),
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    hit_count           BIGINT NOT NULL DEFAULT 0,
    false_positive_count BIGINT NOT NULL DEFAULT 0,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- CASES
-- =============================================================================

CREATE TABLE cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         VARCHAR(64) NOT NULL UNIQUE,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        case_severity NOT NULL DEFAULT 'medium',
    status          case_status NOT NULL DEFAULT 'open',
    assignee        UUID REFERENCES users(id) ON DELETE SET NULL,
    tags            TEXT[] DEFAULT '{}',
    tlp             tlp_level NOT NULL DEFAULT 'amber',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ALERTS
-- =============================================================================

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        VARCHAR(64) NOT NULL UNIQUE,
    rule_id         UUID REFERENCES rules(id) ON DELETE SET NULL,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    severity        alert_severity NOT NULL DEFAULT 'medium',
    status          alert_status NOT NULL DEFAULT 'new',
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    source_ip       INET,
    destination_ip  INET,
    username        VARCHAR(255),
    raw_log         TEXT,
    parsed_event    JSONB DEFAULT '{}'::jsonb,
    mitre_tactic    VARCHAR(100),
    mitre_technique VARCHAR(100),
    mitre_subtechnique VARCHAR(100),
    assignee        UUID REFERENCES users(id) ON DELETE SET NULL,
    case_id         UUID REFERENCES cases(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- CASE TASKS
-- =============================================================================

CREATE TABLE case_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    status          task_status NOT NULL DEFAULT 'pending',
    assignee        UUID REFERENCES users(id) ON DELETE SET NULL,
    due_date        TIMESTAMPTZ,
    order_index     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- CASE OBSERVABLES
-- =============================================================================

CREATE TABLE case_observables (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    data_type       observable_data_type NOT NULL,
    value           TEXT NOT NULL,
    description     TEXT,
    is_ioc          BOOLEAN NOT NULL DEFAULT FALSE,
    tlp             tlp_level NOT NULL DEFAULT 'amber',
    tags            TEXT[] DEFAULT '{}',
    sighted_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- CASE COMMENTS
-- =============================================================================

CREATE TABLE case_comments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- CASE ATTACHMENTS
-- =============================================================================

CREATE TABLE case_attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    filename        VARCHAR(500) NOT NULL,
    content_type    VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
    file_size       BIGINT NOT NULL DEFAULT 0,
    storage_path    TEXT NOT NULL,
    sha256_hash     VARCHAR(64),
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PLAYBOOKS
-- =============================================================================

CREATE TABLE playbooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    trigger_type    VARCHAR(50) NOT NULL DEFAULT 'manual',
    trigger_rule_id VARCHAR(64),
    trigger_severity VARCHAR(100),
    trigger_category VARCHAR(100),
    trigger_conditions JSONB DEFAULT '{}'::jsonb,
    content_yaml    TEXT NOT NULL,
    is_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    run_count       BIGINT NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PLAYBOOK EXECUTIONS
-- =============================================================================

CREATE TABLE playbook_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
    triggered_by    VARCHAR(100) NOT NULL DEFAULT 'manual',
    trigger_context JSONB DEFAULT '{}'::jsonb,
    status          playbook_exec_status NOT NULL DEFAULT 'pending',
    steps_log       JSONB DEFAULT '[]'::jsonb,
    result_summary  TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    duration_ms     INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- THREAT INTEL - IOCs
-- =============================================================================

CREATE TABLE threat_intel_iocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type        ioc_type NOT NULL,
    value           TEXT NOT NULL,
    source          VARCHAR(255) NOT NULL,
    confidence      INTEGER NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    tags            TEXT[] DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    hit_count       BIGINT NOT NULL DEFAULT 0,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- THREAT INTEL - FEEDS
-- =============================================================================

CREATE TABLE threat_intel_feeds (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(255) NOT NULL,
    feed_type           feed_type NOT NULL,
    url                 TEXT NOT NULL,
    api_key             VARCHAR(500),
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    last_fetched        TIMESTAMPTZ,
    ioc_count           INTEGER NOT NULL DEFAULT 0,
    fetch_interval_hours INTEGER NOT NULL DEFAULT 6,
    config_json         JSONB DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ASSETS
-- =============================================================================

CREATE TABLE assets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname            VARCHAR(255) NOT NULL,
    ip                  INET,
    mac                 MACADDR,
    os                  VARCHAR(100),
    os_version          VARCHAR(100),
    owner               VARCHAR(255),
    department          VARCHAR(255),
    criticality         asset_criticality NOT NULL DEFAULT 'medium',
    role                VARCHAR(100),
    tags                TEXT[] DEFAULT '{}',
    risk_score          INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    last_scanned_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- NOTIFICATION CHANNELS
-- =============================================================================

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    channel_type    channel_type NOT NULL,
    config_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- AUDIT LOG
-- =============================================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     VARCHAR(100),
    details         JSONB DEFAULT '{}'::jsonb,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Alerts
CREATE INDEX idx_alerts_status_severity_created ON alerts (status, severity, created_at DESC);
CREATE INDEX idx_alerts_source_ip ON alerts (source_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX idx_alerts_rule_id ON alerts (rule_id) WHERE rule_id IS NOT NULL;
CREATE INDEX idx_alerts_case_id ON alerts (case_id) WHERE case_id IS NOT NULL;
CREATE INDEX idx_alerts_assignee ON alerts (assignee) WHERE assignee IS NOT NULL;
CREATE INDEX idx_alerts_created_at ON alerts (created_at DESC);

-- Agents
CREATE INDEX idx_agents_status ON agents (status);
CREATE INDEX idx_agents_last_seen ON agents (last_seen DESC);

-- IOCs
CREATE INDEX idx_iocs_value_type ON threat_intel_iocs (value, ioc_type);
CREATE INDEX idx_iocs_active ON threat_intel_iocs (is_active) WHERE is_active = TRUE;
CREATE INDEX idx_iocs_expires_at ON threat_intel_iocs (expires_at) WHERE expires_at IS NOT NULL;

-- Cases
CREATE INDEX idx_cases_status ON cases (status);
CREATE INDEX idx_cases_assignee ON cases (assignee) WHERE assignee IS NOT NULL;

-- Rules
CREATE INDEX idx_rules_enabled ON rules (is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX idx_rules_category ON rules (category);

-- Playbook executions
CREATE INDEX idx_pb_exec_playbook ON playbook_executions (playbook_id);
CREATE INDEX idx_pb_exec_status ON playbook_executions (status);
CREATE INDEX idx_pb_exec_started ON playbook_executions (started_at DESC);

-- Audit log
CREATE INDEX idx_audit_user ON audit_log (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_id);
CREATE INDEX idx_audit_created ON audit_log (created_at DESC);

-- Assets
CREATE INDEX idx_assets_hostname ON assets (hostname);
CREATE INDEX idx_assets_ip ON assets (ip) WHERE ip IS NOT NULL;
CREATE INDEX idx_assets_criticality ON assets (criticality);

-- Case sub-tables
CREATE INDEX idx_case_tasks_case ON case_tasks (case_id);
CREATE INDEX idx_case_observables_case ON case_observables (case_id);
CREATE INDEX idx_case_comments_case ON case_comments (case_id);
CREATE INDEX idx_case_attachments_case ON case_attachments (case_id);

-- =============================================================================
-- UPDATED_AT TRIGGER FUNCTION
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to all relevant tables
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN
        SELECT unnest(ARRAY[
            'users', 'agents', 'rules', 'cases', 'alerts',
            'case_tasks', 'case_observables', 'case_comments',
            'playbooks', 'threat_intel_iocs', 'threat_intel_feeds',
            'assets', 'notification_channels'
        ])
    LOOP
        EXECUTE format(
            'CREATE TRIGGER trg_%s_updated_at
             BEFORE UPDATE ON %I
             FOR EACH ROW
             EXECUTE FUNCTION update_updated_at_column()',
            tbl, tbl
        );
    END LOOP;
END;
$$;

-- =============================================================================
-- DEFAULT DATA
-- =============================================================================

-- Default admin user: username=admin, password=CyberNest@2025!
-- bcrypt hash generated with cost factor 12
INSERT INTO users (username, email, password_hash, role, is_active)
VALUES (
    'admin',
    'admin@cybernest.local',
    '$2a$12$LJ3m4ys3Lk0TSwHjGB3gmuCBRq0kSXnQEOflCNiFIHRvSTgG3TKSC',
    'super_admin',
    TRUE
);

-- Record the admin creation in audit log
INSERT INTO audit_log (user_id, action, resource_type, resource_id, details)
SELECT
    id,
    'create',
    'user',
    id::text,
    '{"description": "Default admin user created during initialization"}'::jsonb
FROM users WHERE username = 'admin';
