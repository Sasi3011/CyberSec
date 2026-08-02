package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

// PostgresStore implements PostgreSQL persistence for the Central Manager.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) FindOrganizationByAPIKeyHash(ctx context.Context, hash string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT id::text FROM organizations WHERE api_key_hash = $1`, hash,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("organization not found: %w", err)
	}
	return id, nil
}

func (s *PostgresStore) FindAgentByTokenHash(ctx context.Context, tokenHash string) (domain.AgentAuth, error) {
	var auth domain.AgentAuth
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, organization_id::text, hostname
		FROM agents WHERE agent_token_hash = $1
	`, tokenHash).Scan(&auth.AgentID, &auth.OrganizationID, &auth.Hostname)
	if err != nil {
		return auth, fmt.Errorf("agent not found: %w", err)
	}
	return auth, nil
}

func (s *PostgresStore) CreateAgent(ctx context.Context, orgID, hostname, tokenHash string, meta map[string]string, tags []string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO agents (organization_id, hostname, agent_token_hash, username, os_version, agent_version, mac_address, department, status)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'online')
		RETURNING id::text
	`, orgID, hostname, tokenHash, meta["username"], meta["os_version"], meta["agent_version"], meta["mac_address"], meta["department"]).Scan(&id)
	if err != nil {
		return "", err
	}
	for _, tag := range tags {
		if tag == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_tags (agent_id, tag) VALUES ($1::uuid, $2) ON CONFLICT DO NOTHING`, id, tag); err != nil {
			return "", err
		}
	}
	return id, tx.Commit(ctx)
}

func (s *PostgresStore) UpdateHeartbeat(ctx context.Context, agentID, orgID string, req models.HeartbeatRequest) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	status := "online"
	if req.EngineStatus != "" && req.EngineStatus != "running" {
		status = "degraded"
	}
	health := req.Health
	if health == "" {
		health = "healthy"
	}

	_, err = tx.Exec(ctx, `
		UPDATE agents SET
			status = $13::agent_status,
			public_ip = NULLIF($2, '')::inet,
			local_ip = NULLIF($3, '')::inet,
			health = $4,
			engine_status = $5,
			firewall_status = $6,
			agent_version = COALESCE(NULLIF($7, ''), agent_version),
			engine_version = COALESCE(NULLIF($8, ''), engine_version),
			country_code = COALESCE(NULLIF($9, ''), country_code),
			geo_lat = COALESCE($10, geo_lat),
			geo_lon = COALESCE($11, geo_lon),
			last_seen_at = now(),
			updated_at = now()
		WHERE id = $1::uuid AND organization_id = $12::uuid
	`, agentID, req.PublicIP, req.LocalIP, health, req.EngineStatus, req.FirewallStatus,
		req.AgentVersion, req.EngineVersion, geoCountry(req), geoLat(req), geoLon(req), orgID, status)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO heartbeats (agent_id, organization_id, payload)
		VALUES ($1::uuid, $2::uuid, $3::jsonb)
	`, agentID, orgID, payload)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func geoCountry(req models.HeartbeatRequest) string {
	if req.Geo != nil {
		return req.Geo.Country
	}
	return ""
}

func geoLat(req models.HeartbeatRequest) *float64 {
	if req.Geo != nil && req.Geo.Lat != 0 {
		v := req.Geo.Lat
		return &v
	}
	return nil
}

func geoLon(req models.HeartbeatRequest) *float64 {
	if req.Geo != nil && req.Geo.Lon != 0 {
		v := req.Geo.Lon
		return &v
	}
	return nil
}

func (s *PostgresStore) InsertAlerts(ctx context.Context, orgID, agentID string, alerts []models.AlertUpload) (int, error) {
	count := 0
	for _, a := range alerts {
		if a.SourceIP == "" || a.Scenario == "" {
			continue
		}
		evidence, _ := json.Marshal(a.Evidence)
		confidence := a.Confidence
		if confidence == 0 {
			confidence = 70
		}
		severity := a.Severity
		if severity == "" {
			severity = "medium"
		}
		detectedAt := a.DetectedAt
		if detectedAt.IsZero() {
			detectedAt = time.Now().UTC()
		}
		_, err := s.pool.Exec(ctx, `
			INSERT INTO alerts (
				organization_id, agent_id, local_alert_id, scenario, source_ip,
				country_code, asn, isp, confidence, severity, evidence, detected_at
			) VALUES (
				$1::uuid, $2::uuid, $3, $4, $5::inet,
				NULLIF($6, ''), NULLIF($7, 0), NULLIF($8, ''), $9, $10, $11::jsonb, $12
			)
		`, orgID, agentID, a.ID, a.Scenario, a.SourceIP, a.Country, a.ASN, a.ISP, confidence, severity, string(evidence), detectedAt)
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *PostgresStore) InsertDecisionsAndIOCs(ctx context.Context, orgID, agentID string, decisions []models.DecisionUpload) (int, []domain.ThreatIOC, int64, error) {
	if len(decisions) == 0 {
		ver, err := s.GetIOCVersion(ctx, orgID)
		return 0, nil, ver, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, nil, 0, err
	}
	defer tx.Rollback(ctx)

	inserted := 0
	var iocs []domain.ThreatIOC

	for _, d := range decisions {
		if d.IP == "" {
			continue
		}
		createdAt := d.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		decType := d.Type
		if decType == "" {
			decType = "ban"
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO decisions (organization_id, agent_id, ip, decision_type, duration, scenario, origin, created_at)
			VALUES ($1::uuid, $2::uuid, $3::inet, $4, $5, $6, $7, $8)
		`, orgID, agentID, d.IP, decType, d.Duration, d.Scenario, d.Origin, createdAt); err != nil {
			return inserted, iocs, 0, err
		}
		inserted++

		if decType != "ban" {
			continue
		}

		expiresAt := createdAt.Add(4 * time.Hour)
		if d.Duration == "24h" {
			expiresAt = createdAt.Add(24 * time.Hour)
		}
		confidence := 80
		severity := "high"
		scenario := d.Scenario
		if scenario == "" {
			scenario = "engine-ban"
		}
		reason := fmt.Sprintf("ban from agent %s", agentID)

		_, _ = tx.Exec(ctx, `
			UPDATE threat_intel SET is_active = false, revoked_at = now()
			WHERE organization_id = $1::uuid AND ip = $2::inet AND is_active = true
		`, orgID, d.IP)

		var ioc domain.ThreatIOC
		err := tx.QueryRow(ctx, `
			INSERT INTO threat_intel (
				organization_id, source_agent_id, ip, confidence, severity, scenario,
				source, reason, score, expires_at, is_active
			) VALUES ($1::uuid, $2::uuid, $3::inet, $4, $5, $6, 'engine', $7, $8, $9, true)
			RETURNING id::text, ip::text, confidence, severity, COALESCE(scenario, ''), COALESCE(country_code, ''), COALESCE(asn, 0), expires_at
		`, orgID, agentID, d.IP, confidence, severity, scenario, reason, confidence, expiresAt).Scan(
			&ioc.ID, &ioc.IP, &ioc.Confidence, &ioc.Severity, &ioc.Scenario, &ioc.Country, &ioc.ASN, &ioc.ExpiresAt,
		)
		if err != nil {
			return inserted, iocs, 0, err
		}
		iocs = append(iocs, ioc)
	}

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
		return inserted, iocs, 0, err
	}

	if len(iocs) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE threat_intel SET version = $2
			WHERE organization_id = $1::uuid AND is_active = true AND (version IS NULL OR version < $2)
		`, orgID, version)
		if err != nil {
			return inserted, iocs, 0, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return inserted, iocs, version, err
	}
	return inserted, iocs, version, nil
}

func (s *PostgresStore) GetIOCVersion(ctx context.Context, orgID string) (int64, error) {
	var version int64
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(current_version, 0) FROM org_ioc_versions WHERE organization_id = $1::uuid
	`, orgID).Scan(&version)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	return version, err
}

func (s *PostgresStore) GetLatestPolicyVersion(ctx context.Context, orgID string) (int, error) {
	var version int
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM policies WHERE organization_id = $1::uuid AND is_active = true
	`, orgID).Scan(&version)
	return version, err
}

func (s *PostgresStore) ListIOCsSince(ctx context.Context, orgID string, sinceVersion int64) (int64, []models.IOC, error) {
	version, err := s.GetIOCVersion(ctx, orgID)
	if err != nil {
		return 0, nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, ip::text, confidence, severity, COALESCE(scenario, ''),
			COALESCE(country_code, ''), COALESCE(asn, 0), expires_at
		FROM threat_intel
		WHERE organization_id = $1::uuid AND is_active = true AND version > $2
		ORDER BY version ASC
	`, orgID, sinceVersion)
	if err != nil {
		return version, nil, err
	}
	defer rows.Close()

	var iocs []models.IOC
	for rows.Next() {
		var ioc models.IOC
		if err := rows.Scan(&ioc.ID, &ioc.IP, &ioc.Confidence, &ioc.Severity, &ioc.Scenario, &ioc.Country, &ioc.ASN, &ioc.ExpiresAt); err != nil {
			return version, nil, err
		}
		ioc.Action = "block"
		iocs = append(iocs, ioc)
	}
	return version, iocs, rows.Err()
}

func (s *PostgresStore) ListAgents(ctx context.Context, orgID string) ([]domain.Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, organization_id::text, hostname, COALESCE(username, ''), COALESCE(os_version, ''),
			COALESCE(agent_version, ''), COALESCE(department, ''), status::text,
			COALESCE(host(public_ip), ''), COALESCE(host(local_ip), ''),
			COALESCE(health, ''), COALESCE(engine_status, ''), COALESCE(firewall_status, ''),
			last_seen_at
		FROM agents WHERE organization_id = $1::uuid
		ORDER BY last_seen_at DESC NULLS LAST
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []domain.Agent
	for rows.Next() {
		var a domain.Agent
		if err := rows.Scan(
			&a.ID, &a.OrganizationID, &a.Hostname, &a.Username, &a.OSVersion,
			&a.AgentVersion, &a.Department, &a.Status,
			&a.PublicIP, &a.LocalIP, &a.Health, &a.EngineStatus, &a.FirewallStatus,
			&a.LastSeenAt,
		); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (s *PostgresStore) CountAlerts(ctx context.Context, orgID string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE organization_id = $1::uuid`, orgID).Scan(&n)
	return n, err
}
