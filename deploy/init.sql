-- CyberNest — PostgreSQL Schema
-- Full database initialization for all platform tables

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ════════════════════════════════════════════════════════════
-- USERS & AUTH
-- ════════════════════════════════════════════════════════════

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(64) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    full_name       VARCHAR(128) NOT NULL DEFAULT '',
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(32) NOT NULL DEFAULT 'analyst'
                    CHECK (role IN ('super_admin','admin','soc_lead','analyst','read_only')),
    mfa_secret      VARCHAR(64),
    is_active       BOOLEAN DEFAULT TRUE,
    department      VARCHAR(128),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- ════════════════════════════════════════════════════════════
-- API KEYS
-- ════════════════════════════════════════════════════════════

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(128) NOT NULL,
    key_hash        VARCHAR(255) UNIQUE NOT NULL,
    scopes          TEXT[],
    is_active       BOOLEAN DEFAULT TRUE,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- ════════════════════════════════════════════════════════════
-- AGENTS
-- ════════════════════════════════════════════════════════════

CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        VARCHAR(64) UNIQUE NOT NULL,
    hostname        VARCHAR(255) NOT NULL,
    ip_address      VARCHAR(45) NOT NULL,
    os_type         VARCHAR(32) NOT NULL,
    os_version      VARCHAR(128),
    agent_version   VARCHAR(32) NOT NULL,
    status          VARCHAR(16) DEFAULT 'pending'
                    CHECK (status IN ('online','offline','degraded','pending','updating')),
    api_key_hash    VARCHAR(255),
    config_json     JSONB,
    labels          JSONB,
    agent_group     VARCHAR(128) DEFAULT 'default',
    cpu_usage       REAL,
    memory_usage    REAL,
    eps             REAL,
    last_seen       TIMESTAMPTZ,
    last_heartbeat  TIMESTAMPTZ,
    enrolled_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_agents_agent_id ON agents(agent_id);
CREATE INDEX idx_agents_hostname ON agents(hostname);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_last_seen ON agents(last_seen);

-- ════════════════════════════════════════════════════════════
-- DETECTION RULES
-- ════════════════════════════════════════════════════════════

CREATE TABLE rules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id         VARCHAR(32) UNIQUE NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium'
                    CHECK (severity IN ('critical','high','medium','low','info')),
    level           INTEGER DEFAULT 5 CHECK (level BETWEEN 0 AND 15),
    category        VARCHAR(64),
    rule_type       VARCHAR(32) DEFAULT 'threshold',
    rule_format     VARCHAR(16) DEFAULT 'xml',
    content_xml     TEXT,
    content_json    JSONB,
    sigma_yaml      TEXT,
    mitre_tactic    TEXT[],
    mitre_technique TEXT[],
    tags            TEXT[],
    author          VARCHAR(128),
    version         INTEGER DEFAULT 1,
    is_enabled      BOOLEAN DEFAULT TRUE,
    hit_count       BIGINT DEFAULT 0,
    last_hit_at     TIMESTAMPTZ,
    false_positives TEXT,
    references_     TEXT[],
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_rules_rule_id ON rules(rule_id);
CREATE INDEX idx_rules_severity ON rules(severity);
CREATE INDEX idx_rules_enabled ON rules(is_enabled);
CREATE INDEX idx_rules_mitre ON rules USING GIN(mitre_technique);

-- ════════════════════════════════════════════════════════════
-- ALERTS
-- ════════════════════════════════════════════════════════════

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id        VARCHAR(64) UNIQUE NOT NULL,
    rule_id         VARCHAR(32) REFERENCES rules(rule_id) ON DELETE SET NULL,
    rule_name       VARCHAR(255),
    agent_id        VARCHAR(64),
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',
    status          VARCHAR(24) DEFAULT 'new'
                    CHECK (status IN ('new','acknowledged','investigating','resolved','false_positive','escalated','suppressed')),
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    source_ip       VARCHAR(45),
    source_port     INTEGER,
    dest_ip         VARCHAR(45),
    dest_port       INTEGER,
    protocol        VARCHAR(16),
    hostname        VARCHAR(255),
    username        VARCHAR(128),
    process_name    VARCHAR(255),
    raw_log         TEXT,
    parsed_event    JSONB,
    ioc_type        VARCHAR(32),
    ioc_value       VARCHAR(512),
    mitre_tactic    TEXT[],
    mitre_technique TEXT[],
    geo_data        JSONB,
    threat_intel    JSONB,
    asset_info      JSONB,
    event_count     INTEGER DEFAULT 1,
    event_ids       TEXT[],
    assignee_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    incident_id     UUID,
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    ttd_ms          BIGINT,
    ttr_ms          BIGINT,
    comments        JSONB DEFAULT '[]'::JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_assignee ON alerts(assignee_id);
CREATE INDEX idx_alerts_mitre ON alerts USING GIN(mitre_technique);

-- ════════════════════════════════════════════════════════════
-- CASES / INCIDENTS
-- ════════════════════════════════════════════════════════════

CREATE TABLE cases (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id         VARCHAR(32) UNIQUE NOT NULL,
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',
    status          VARCHAR(24) DEFAULT 'open'
                    CHECK (status IN ('open','in_progress','contained','eradicated','recovered','closed')),
    template        VARCHAR(128),
    assignee_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    tags            TEXT[],
    mitre_tactic    TEXT[],
    mitre_technique TEXT[],
    affected_assets TEXT[],
    affected_users  TEXT[],
    timeline        JSONB DEFAULT '[]'::JSONB,
    sla_due_at      TIMESTAMPTZ,
    ttc_ms          BIGINT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    closed_at       TIMESTAMPTZ
);
CREATE INDEX idx_cases_case_id ON cases(case_id);
CREATE INDEX idx_cases_status ON cases(status);
CREATE INDEX idx_cases_severity ON cases(severity);
CREATE INDEX idx_cases_assignee ON cases(assignee_id);
CREATE INDEX idx_cases_created ON cases(created_at);

CREATE TABLE case_tasks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    status          VARCHAR(24) DEFAULT 'pending'
                    CHECK (status IN ('pending','in_progress','completed','cancelled')),
    assignee_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    due_date        TIMESTAMPTZ,
    sort_order      INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX idx_case_tasks_case ON case_tasks(case_id);

CREATE TABLE case_observables (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ioc_type        VARCHAR(32) NOT NULL,
    value           VARCHAR(512) NOT NULL,
    description     TEXT,
    tags            TEXT[],
    is_ioc          BOOLEAN DEFAULT TRUE,
    sighted         BOOLEAN DEFAULT FALSE,
    tlp             VARCHAR(16) DEFAULT 'amber',
    threat_score    REAL,
    enrichment      JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_observables_case ON case_observables(case_id);
CREATE INDEX idx_observables_value ON case_observables(value);
CREATE INDEX idx_observables_type ON case_observables(ioc_type);

-- ════════════════════════════════════════════════════════════
-- PLAYBOOKS & SOAR
-- ════════════════════════════════════════════════════════════

CREATE TABLE playbooks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    trigger_type    VARCHAR(32) DEFAULT 'manual'
                    CHECK (trigger_type IN ('manual','alert','schedule')),
    trigger_rule_id VARCHAR(32),
    trigger_severity VARCHAR(16),
    trigger_conditions JSONB,
    content_yaml    TEXT,
    steps           JSONB DEFAULT '[]'::JSONB,
    tags            TEXT[],
    author          VARCHAR(128),
    version         INTEGER DEFAULT 1,
    is_enabled      BOOLEAN DEFAULT TRUE,
    total_runs      INTEGER DEFAULT 0,
    successful_runs INTEGER DEFAULT 0,
    avg_duration_ms BIGINT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_playbooks_trigger ON playbooks(trigger_rule_id);
CREATE INDEX idx_playbooks_enabled ON playbooks(is_enabled);

CREATE TABLE playbook_executions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id     UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id        VARCHAR(64),
    incident_id     UUID,
    triggered_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    status          VARCHAR(24) DEFAULT 'pending'
                    CHECK (status IN ('pending','running','completed','failed','cancelled','awaiting_approval')),
    is_dry_run      BOOLEAN DEFAULT FALSE,
    input_data      JSONB,
    steps_log       JSONB DEFAULT '[]'::JSONB,
    error_message   TEXT,
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    duration_ms     BIGINT
);
CREATE INDEX idx_pb_exec_playbook ON playbook_executions(playbook_id);
CREATE INDEX idx_pb_exec_status ON playbook_executions(status);
CREATE INDEX idx_pb_exec_started ON playbook_executions(started_at);

-- ════════════════════════════════════════════════════════════
-- THREAT INTELLIGENCE
-- ════════════════════════════════════════════════════════════

CREATE TABLE threat_feeds (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    feed_type       VARCHAR(32) NOT NULL,
    url             VARCHAR(1024) NOT NULL,
    api_key         VARCHAR(512),
    is_enabled      BOOLEAN DEFAULT TRUE,
    refresh_interval INTEGER DEFAULT 21600,
    ioc_count       INTEGER DEFAULT 0,
    last_fetch_at   TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE threat_intel_iocs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type        VARCHAR(32) NOT NULL
                    CHECK (ioc_type IN ('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','cve','filename')),
    value           VARCHAR(512) NOT NULL,
    description     TEXT,
    threat_score    REAL DEFAULT 50.0,
    confidence      REAL DEFAULT 50.0,
    source          VARCHAR(128),
    source_count    INTEGER DEFAULT 1,
    sources         TEXT[],
    threat_type     VARCHAR(64),
    malware_family  VARCHAR(128),
    tags            TEXT[],
    tlp             VARCHAR(16) DEFAULT 'amber',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT TRUE,
    enrichment      JSONB,
    whois_data      JSONB,
    geo_data        JSONB,
    UNIQUE(ioc_type, value)
);
CREATE INDEX idx_ioc_type ON threat_intel_iocs(ioc_type);
CREATE INDEX idx_ioc_value ON threat_intel_iocs(value);
CREATE INDEX idx_ioc_type_value ON threat_intel_iocs(ioc_type, value);
CREATE INDEX idx_ioc_expires ON threat_intel_iocs(expires_at);
CREATE INDEX idx_ioc_active ON threat_intel_iocs(is_active);
CREATE INDEX idx_ioc_score ON threat_intel_iocs(threat_score);

-- ════════════════════════════════════════════════════════════
-- ASSETS / CMDB
-- ════════════════════════════════════════════════════════════

CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname        VARCHAR(255) NOT NULL,
    ip_address      VARCHAR(45) NOT NULL,
    mac_address     VARCHAR(17),
    os_type         VARCHAR(32),
    os_version      VARCHAR(128),
    asset_type      VARCHAR(64),
    criticality     VARCHAR(16) DEFAULT 'medium'
                    CHECK (criticality IN ('critical','high','medium','low')),
    department      VARCHAR(128),
    owner           VARCHAR(128),
    location        VARCHAR(255),
    asset_group     VARCHAR(128),
    tags            TEXT[],
    subnet          VARCHAR(18),
    open_ports      INTEGER[],
    services        JSONB,
    risk_score      REAL DEFAULT 0.0,
    vuln_count      INTEGER DEFAULT 0,
    alert_count     INTEGER DEFAULT 0,
    agent_id        VARCHAR(64),
    discovered_by   VARCHAR(32),
    is_managed      BOOLEAN DEFAULT FALSE,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_ip ON assets(ip_address);
CREATE INDEX idx_assets_criticality ON assets(criticality);

-- ════════════════════════════════════════════════════════════
-- NOTIFICATION CHANNELS
-- ════════════════════════════════════════════════════════════

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(128) NOT NULL,
    channel_type    VARCHAR(32) NOT NULL
                    CHECK (channel_type IN ('email','slack','pagerduty','teams','webhook','sms')),
    config_json     JSONB NOT NULL,
    is_enabled      BOOLEAN DEFAULT TRUE,
    min_severity    VARCHAR(16) DEFAULT 'medium',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ════════════════════════════════════════════════════════════
-- AUDIT LOG
-- ════════════════════════════════════════════════════════════

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(64) NOT NULL,
    resource_type   VARCHAR(64) NOT NULL,
    resource_id     VARCHAR(255),
    details         TEXT,
    ip_address      VARCHAR(45),
    user_agent      VARCHAR(512),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created ON audit_log(created_at);

-- ════════════════════════════════════════════════════════════
-- SAVED SEARCHES
-- ════════════════════════════════════════════════════════════

CREATE TABLE saved_searches (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    query           TEXT NOT NULL,
    index_pattern   VARCHAR(128) DEFAULT 'cybernest-events-*',
    filters         JSONB,
    time_range      VARCHAR(32),
    is_public       BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ════════════════════════════════════════════════════════════
-- SEED: default admin user (password: CyberNest@2025!)
-- ════════════════════════════════════════════════════════════

INSERT INTO users (username, email, full_name, password_hash, role)
VALUES (
    'admin',
    'admin@cybernest.local',
    'CyberNest Admin',
    -- bcrypt hash of 'CyberNest@2025!'
    '$2b$12$LJ3m4ys3Gz8y8M6r0F5dNOJvYyBpz.wm5U3IH.X0hFqt1p.yqOjIu',
    'super_admin'
);

-- Default notification channel (stdout for dev)
INSERT INTO notification_channels (name, channel_type, config_json, min_severity)
VALUES ('Console Logger', 'webhook', '{"url": "http://localhost:5000/api/v1/debug/log"}', 'info');
