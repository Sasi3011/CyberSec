-- CyberSec Enterprise — Initial Schema
-- PostgreSQL 15+

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- ---------------------------------------------------------------------------
-- Reference
-- ---------------------------------------------------------------------------
CREATE TABLE countries (
    code        CHAR(2) PRIMARY KEY,
    name        TEXT NOT NULL,
    region      TEXT
);

-- ---------------------------------------------------------------------------
-- Multi-tenant core
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        CITEXT NOT NULL UNIQUE,
    api_key_hash TEXT NOT NULL,
    settings    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE user_role AS ENUM ('admin', 'soc_analyst', 'viewer', 'auditor');

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           CITEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    role            user_role NOT NULL DEFAULT 'viewer',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);

CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Agents (endpoints)
-- ---------------------------------------------------------------------------
CREATE TYPE agent_status AS ENUM ('online', 'offline', 'degraded', 'unregistered');

CREATE TABLE agents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname            TEXT NOT NULL,
    username            TEXT,
    os_version          TEXT,
    agent_version       TEXT,
    engine_version      TEXT,
    mac_address         TEXT,
    department          TEXT,
    status              agent_status NOT NULL DEFAULT 'unregistered',
    agent_token_hash    TEXT NOT NULL,
    public_ip           INET,
    local_ip            INET,
    country_code        CHAR(2) REFERENCES countries(code),
    geo_lat             DOUBLE PRECISION,
    geo_lon             DOUBLE PRECISION,
    health              TEXT DEFAULT 'unknown',
    engine_status       TEXT DEFAULT 'unknown',
    firewall_status     TEXT DEFAULT 'unknown',
    last_seen_at        TIMESTAMPTZ,
    registered_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_agents_org_last_seen ON agents (organization_id, last_seen_at DESC);
CREATE INDEX idx_agents_org_status ON agents (organization_id, status);

CREATE TABLE agent_tags (
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    PRIMARY KEY (agent_id, tag)
);

-- ---------------------------------------------------------------------------
-- Telemetry
-- ---------------------------------------------------------------------------
CREATE TABLE heartbeats (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_heartbeats_agent_time ON heartbeats (agent_id, received_at DESC);

CREATE TABLE metrics (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    metric_name     TEXT NOT NULL,
    metric_value    DOUBLE PRECISION NOT NULL,
    labels          JSONB NOT NULL DEFAULT '{}',
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_metrics_org_time ON metrics (organization_id, recorded_at DESC);

-- ---------------------------------------------------------------------------
-- Detection data
-- ---------------------------------------------------------------------------
CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    local_alert_id  TEXT,
    scenario        TEXT NOT NULL,
    source_ip       INET NOT NULL,
    country_code    CHAR(2),
    asn             BIGINT,
    isp             TEXT,
    confidence      INT CHECK (confidence BETWEEN 0 AND 100),
    severity        TEXT NOT NULL DEFAULT 'medium',
    evidence        JSONB NOT NULL DEFAULT '[]',
    mitre_ids       TEXT[] DEFAULT '{}',
    detected_at     TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_org_detected ON alerts (organization_id, detected_at DESC);
CREATE INDEX idx_alerts_source_ip ON alerts (organization_id, source_ip);

CREATE TABLE decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    decision_type   TEXT NOT NULL DEFAULT 'ban',
    duration        TEXT,
    scenario        TEXT,
    origin          TEXT,
    created_at      TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_decisions_org_ip ON decisions (organization_id, ip);

CREATE TABLE firewall_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    action          TEXT NOT NULL, -- block, unblock
    source          TEXT NOT NULL, -- local, ioc_propagation, manual
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Threat intelligence
-- ---------------------------------------------------------------------------
CREATE TABLE threat_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    feed_url        TEXT,
    feed_type       TEXT NOT NULL DEFAULT 'custom',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE threat_intel (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    feed_id         UUID REFERENCES threat_feeds(id) ON DELETE SET NULL,
    ip              INET NOT NULL,
    cidr            CIDR,
    confidence      INT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    severity        TEXT NOT NULL DEFAULT 'medium',
    scenario        TEXT,
    country_code    CHAR(2),
    asn             BIGINT,
    isp             TEXT,
    source          TEXT NOT NULL DEFAULT 'engine',
    reason          TEXT,
    ref_links       JSONB NOT NULL DEFAULT '[]',
    score           INT NOT NULL DEFAULT 0,
    version         BIGINT NOT NULL DEFAULT 1,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_threat_intel_org_ip ON threat_intel (organization_id, ip) WHERE is_active = true;
CREATE INDEX idx_threat_intel_org_version ON threat_intel (organization_id, version);

-- ---------------------------------------------------------------------------
-- Policies & notifications
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    rules           JSONB NOT NULL DEFAULT '[]',
    version         INT NOT NULL DEFAULT 1,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    channel         TEXT NOT NULL, -- email, slack, discord, teams, webhook
    config          JSONB NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    details         JSONB NOT NULL DEFAULT '{}',
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_org_time ON audit_logs (organization_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- IOC propagation version counter (per org)
-- ---------------------------------------------------------------------------
CREATE TABLE org_ioc_versions (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    current_version BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Seed demo organization (development only)
-- ---------------------------------------------------------------------------
INSERT INTO countries (code, name, region) VALUES
    ('IN', 'India', 'Asia'),
    ('US', 'United States', 'Americas'),
    ('RU', 'Russia', 'Europe'),
    ('CN', 'China', 'Asia'),
    ('BR', 'Brazil', 'Americas')
ON CONFLICT DO NOTHING;

-- api_key for dev: cybersec_dev_org_key (replace in production)
INSERT INTO organizations (name, slug, api_key_hash, settings)
VALUES (
    'Demo Organization',
    'demo-org',
    encode(digest('cybersec_dev_org_key', 'sha256'), 'hex'),
    '{"offices": ["Chennai", "Bangalore", "Mumbai"], "heartbeat_interval_sec": 30}'
);

INSERT INTO org_ioc_versions (organization_id, current_version)
SELECT id, 0 FROM organizations WHERE slug = 'demo-org';
