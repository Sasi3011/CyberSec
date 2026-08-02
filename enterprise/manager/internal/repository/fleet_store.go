package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

func (s *PostgresStore) GetAgent(ctx context.Context, orgID, agentID string) (domain.Agent, error) {
	var a domain.Agent
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, organization_id::text, hostname, COALESCE(username, ''), COALESCE(os_version, ''),
			COALESCE(agent_version, ''), COALESCE(department, ''), status::text,
			COALESCE(host(public_ip), ''), COALESCE(host(local_ip), ''),
			COALESCE(health, ''), COALESCE(engine_status, ''), COALESCE(firewall_status, ''),
			last_seen_at
		FROM agents WHERE organization_id = $1::uuid AND id = $2::uuid
	`, orgID, agentID).Scan(
		&a.ID, &a.OrganizationID, &a.Hostname, &a.Username, &a.OSVersion,
		&a.AgentVersion, &a.Department, &a.Status,
		&a.PublicIP, &a.LocalIP, &a.Health, &a.EngineStatus, &a.FirewallStatus,
		&a.LastSeenAt,
	)
	if err != nil {
		return a, fmt.Errorf("agent not found: %w", err)
	}
	return a, nil
}

func (s *PostgresStore) ListAlertsForAgent(ctx context.Context, orgID, agentID string, limit int) ([]models.AlertSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, agent_id::text, scenario, host(source_ip), severity, confidence, detected_at
		FROM alerts WHERE organization_id = $1::uuid AND agent_id = $2::uuid
		ORDER BY detected_at DESC LIMIT $3
	`, orgID, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AlertSummary
	for rows.Next() {
		var a models.AlertSummary
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Scenario, &a.SourceIP, &a.Severity, &a.Confidence, &a.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListIncidents(ctx context.Context, orgID string, hours int) ([]models.IncidentSummary, error) {
	if hours <= 0 {
		hours = 24
	}
	rows, err := s.pool.Query(ctx, `
		SELECT host(source_ip), scenario, COUNT(*)::int, COUNT(DISTINCT agent_id)::int,
			MIN(detected_at), MAX(detected_at),
			MAX(severity)
		FROM alerts
		WHERE organization_id = $1::uuid AND detected_at > now() - ($2 || ' hours')::interval
		GROUP BY source_ip, scenario
		ORDER BY MAX(detected_at) DESC
		LIMIT 200
	`, orgID, fmt.Sprintf("%d", hours))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.IncidentSummary
	for rows.Next() {
		var inc models.IncidentSummary
		if err := rows.Scan(&inc.SourceIP, &inc.Scenario, &inc.Count, &inc.AffectedAgents,
			&inc.FirstSeen, &inc.LastSeen, &inc.MaxSeverity); err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListRevokedSince(ctx context.Context, orgID string, sinceVersion int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT host(ip) FROM threat_intel
		WHERE organization_id = $1::uuid AND is_active = false AND revoked_at IS NOT NULL
		  AND version > $2
	`, orgID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (s *PostgresStore) RevokeIOCsByIP(ctx context.Context, orgID string, ips []string) (int64, []string, error) {
	if len(ips) == 0 {
		v, err := s.GetIOCVersion(ctx, orgID)
		return v, nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)

	var version int64
	err = tx.QueryRow(ctx, `
		INSERT INTO org_ioc_versions (organization_id, current_version, updated_at)
		VALUES ($1::uuid, 1, now())
		ON CONFLICT (organization_id) DO UPDATE SET
			current_version = org_ioc_versions.current_version + 1,
			updated_at = now()
		RETURNING current_version
	`, orgID).Scan(&version)
	if err != nil {
		return 0, nil, err
	}

	revoked := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		tag, err := tx.Exec(ctx, `
			UPDATE threat_intel SET is_active = false, revoked_at = now(), version = $3
			WHERE organization_id = $1::uuid AND ip = $2::inet AND is_active = true
		`, orgID, ip, version)
		if err != nil {
			return 0, nil, err
		}
		if tag.RowsAffected() > 0 {
			revoked = append(revoked, ip)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, nil, err
	}
	return version, revoked, nil
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, orgID string, limit int) ([]models.AuditLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, COALESCE(user_id::text, ''), action,
			COALESCE(resource_type, ''), COALESCE(resource_id, ''), COALESCE(details, '{}'::jsonb), created_at
		FROM audit_logs WHERE organization_id = $1::uuid
		ORDER BY created_at DESC LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AuditLogEntry
	for rows.Next() {
		var e models.AuditLogEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.ResourceType, &e.ResourceID, &e.Details, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PostgresStore) LastHeartbeatPayload(ctx context.Context, agentID string) (models.HeartbeatRequest, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT payload FROM heartbeats WHERE agent_id = $1::uuid
		ORDER BY created_at DESC LIMIT 1
	`, agentID).Scan(&raw)
	if err != nil {
		return models.HeartbeatRequest{}, err
	}
	var req models.HeartbeatRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return models.HeartbeatRequest{}, err
	}
	return req, nil
}
