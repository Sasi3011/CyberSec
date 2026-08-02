-- Unique active IOC per org + IP for upsert
CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_intel_org_ip_active
    ON threat_intel (organization_id, ip)
    WHERE is_active = true;
