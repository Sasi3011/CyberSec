package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type UserRecord struct {
	ID             string
	OrganizationID string
	Email          string
	PasswordHash   string
	Role           string
}

func (s *PostgresStore) FindUserByEmail(ctx context.Context, email string) (UserRecord, error) {
	var u UserRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, organization_id::text, email, password_hash, role::text
		FROM users WHERE email = $1 AND is_active = true
	`, email).Scan(&u.ID, &u.OrganizationID, &u.Email, &u.PasswordHash, &u.Role)
	if err != nil {
		return u, fmt.Errorf("user not found: %w", err)
	}
	return u, nil
}

func (s *PostgresStore) VerifyPassword(ctx context.Context, hash, password string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT crypt($1, $2) = $2`, password, hash).Scan(&ok)
	return ok, err
}

func (s *PostgresStore) SaveRefreshToken(ctx context.Context, userID, tokenHash string, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1::uuid, $2, $3)
	`, userID, tokenHash, expires)
	return err
}

func (s *PostgresStore) InsertAuditLog(ctx context.Context, orgID, userID, action, resourceType, resourceID string, details map[string]interface{}) error {
	raw, _ := json.Marshal(details)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (organization_id, user_id, action, resource_type, resource_id, details)
		VALUES (NULLIF($1,'')::uuid, NULLIF($2,'')::uuid, $3, $4, $5, $6::jsonb)
	`, orgID, userID, action, resourceType, resourceID, string(raw))
	return err
}

func (s *PostgresStore) ListAlertsForOrg(ctx context.Context, orgID string, limit int) ([]models.AlertSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, agent_id::text, scenario, host(source_ip), severity, confidence, detected_at
		FROM alerts WHERE organization_id = $1::uuid
		ORDER BY detected_at DESC LIMIT $2
	`, orgID, limit)
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

func (s *PostgresStore) ListActiveIOCs(ctx context.Context, orgID string) ([]models.IOC, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, ip::text, confidence, severity, COALESCE(scenario, ''),
			COALESCE(country_code, ''), COALESCE(asn, 0), expires_at
		FROM threat_intel
		WHERE organization_id = $1::uuid AND is_active = true
		ORDER BY expires_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var iocs []models.IOC
	for rows.Next() {
		var ioc models.IOC
		if err := rows.Scan(&ioc.ID, &ioc.IP, &ioc.Confidence, &ioc.Severity, &ioc.Scenario, &ioc.Country, &ioc.ASN, &ioc.ExpiresAt); err != nil {
			return nil, err
		}
		ioc.Action = "block"
		iocs = append(iocs, ioc)
	}
	return iocs, rows.Err()
}

func (s *PostgresStore) BumpIOCVersion(ctx context.Context, orgID string) (int64, error) {
	var version int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO org_ioc_versions (organization_id, current_version, updated_at)
		VALUES ($1::uuid, 1, now())
		ON CONFLICT (organization_id) DO UPDATE SET
			current_version = org_ioc_versions.current_version + 1,
			updated_at = now()
		RETURNING current_version
	`, orgID).Scan(&version)
	return version, err
}

func (s *PostgresStore) ImportThreatFeed(ctx context.Context, orgID, source string, entries []models.ThreatFeedEntry) (int, int64, error) {
	if len(entries) == 0 {
		v, err := s.GetIOCVersion(ctx, orgID)
		return 0, v, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	imported := 0
	for _, e := range entries {
		if e.IP == "" {
			continue
		}
		confidence := e.Confidence
		if confidence == 0 {
			confidence = 75
		}
		severity := e.Severity
		if severity == "" {
			severity = "medium"
		}
		scenario := e.Scenario
		if scenario == "" {
			scenario = "feed/" + source
		}
		expires := time.Now().UTC().Add(24 * time.Hour)
		_, _ = tx.Exec(ctx, `
			UPDATE threat_intel SET is_active = false, revoked_at = now()
			WHERE organization_id = $1::uuid AND ip = $2::inet AND is_active = true
		`, orgID, e.IP)
		_, err := tx.Exec(ctx, `
			INSERT INTO threat_intel (
				organization_id, ip, confidence, severity, scenario, source, reason, score, expires_at, is_active
			) VALUES ($1::uuid, $2::inet, $3, $4, $5, $6, 'threat-feed-import', $3, $7, true)
		`, orgID, e.IP, confidence, severity, scenario, source, expires)
		if err != nil {
			return imported, 0, err
		}
		imported++
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
		return imported, 0, err
	}
	_, _ = tx.Exec(ctx, `
		UPDATE threat_intel SET version = $2
		WHERE organization_id = $1::uuid AND is_active = true AND (version IS NULL OR version < $2)
	`, orgID, version)

	if err := tx.Commit(ctx); err != nil {
		return imported, version, err
	}
	return imported, version, nil
}

func (s *PostgresStore) RotateOrgAPIKey(ctx context.Context, orgID, newHash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE organizations SET api_key_hash = $2, updated_at = now() WHERE id = $1::uuid`, orgID, newHash)
	return err
}

func (s *PostgresStore) ListOrganizations(ctx context.Context) ([]map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, name, slug::text FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, name, slug string
		if err := rows.Scan(&id, &name, &slug); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{"id": id, "name": name, "slug": slug})
	}
	return out, rows.Err()
}
