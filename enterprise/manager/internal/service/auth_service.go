package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/crypto"
	jwtpkg "github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/jwt"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/repository"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type AuthStore interface {
	FindUserByEmail(ctx context.Context, email string) (repository.UserRecord, error)
	VerifyPassword(ctx context.Context, hash, password string) (bool, error)
	SaveRefreshToken(ctx context.Context, userID, tokenHash string, expires time.Time) error
	InsertAuditLog(ctx context.Context, orgID, userID, action, resourceType, resourceID string, details map[string]interface{}) error
}

type AuthService struct {
	store  AuthStore
	secret string
}

func NewAuthService(store AuthStore, secret string) *AuthService {
	return &AuthService{store: store, secret: secret}
}

func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*models.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, fmt.Errorf("email and password required")
	}
	user, err := s.store.FindUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	ok, err := s.store.VerifyPassword(ctx, user.PasswordHash, req.Password)
	if err != nil || !ok {
		return nil, fmt.Errorf("invalid credentials")
	}
	access, err := jwtpkg.IssueAccess(s.secret, user.ID, user.OrganizationID, user.Role, user.Email, time.Hour)
	if err != nil {
		return nil, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	_ = s.store.SaveRefreshToken(ctx, user.ID, crypto.HashToken(refresh), time.Now().Add(7*24*time.Hour))
	_ = s.store.InsertAuditLog(ctx, user.OrganizationID, user.ID, "login", "user", user.ID, nil)
	return &models.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    3600,
		Role:         user.Role,
		Organization: user.OrganizationID,
	}, nil
}

type AdminStore interface {
	ListAlertsForOrg(ctx context.Context, orgID string, limit int) ([]models.AlertSummary, error)
	ListActiveIOCs(ctx context.Context, orgID string) ([]models.IOC, error)
	ImportThreatFeed(ctx context.Context, orgID, source string, entries []models.ThreatFeedEntry) (int, int64, error)
	RevokeIOCsByIP(ctx context.Context, orgID string, ips []string) (int64, []string, error)
	ListIncidents(ctx context.Context, orgID string, hours int) ([]models.IncidentSummary, error)
	ListAuditLogs(ctx context.Context, orgID string, limit int) ([]models.AuditLogEntry, error)
	InsertAuditLog(ctx context.Context, orgID, userID, action, resourceType, resourceID string, details map[string]interface{}) error
	ListOrganizations(ctx context.Context) ([]map[string]string, error)
}

type AdminService struct {
	store AdminStore
}

func NewAdminService(store AdminStore) *AdminService {
	return &AdminService{store: store}
}

func (s *AdminService) Alerts(ctx context.Context, orgID string) ([]models.AlertSummary, error) {
	return s.store.ListAlertsForOrg(ctx, orgID, 200)
}

func (s *AdminService) ThreatIntel(ctx context.Context, orgID string) ([]models.IOC, error) {
	return s.store.ListActiveIOCs(ctx, orgID)
}

func (s *AdminService) ImportFeed(ctx context.Context, orgID, userID, source string, req models.ThreatFeedImportRequest) (int, int64, error) {
	if source == "" {
		source = req.Source
	}
	if source == "" {
		source = "manual"
	}
	n, ver, err := s.store.ImportThreatFeed(ctx, orgID, source, req.IOCs)
	if err == nil {
		_ = s.store.InsertAuditLog(ctx, orgID, userID, "import_threat_feed", "threat_intel", source, map[string]interface{}{"count": n})
	}
	return n, ver, err
}

func (s *AdminService) Incidents(ctx context.Context, orgID string) ([]models.IncidentSummary, error) {
	inc, err := s.store.ListIncidents(ctx, orgID, 24)
	if err != nil {
		return nil, err
	}
	if inc == nil {
		inc = []models.IncidentSummary{}
	}
	return inc, nil
}

func (s *AdminService) RevokeIOCs(ctx context.Context, orgID, userID string, ips []string) (int64, []string, error) {
	version, revoked, err := s.store.RevokeIOCsByIP(ctx, orgID, ips)
	if err == nil && len(revoked) > 0 {
		_ = s.store.InsertAuditLog(ctx, orgID, userID, "revoke_ioc", "threat_intel", "", map[string]interface{}{
			"ips": revoked, "ioc_version": version,
		})
	}
	return version, revoked, err
}

func (s *AdminService) AuditLogs(ctx context.Context, orgID string, limit int) ([]models.AuditLogEntry, error) {
	logs, err := s.store.ListAuditLogs(ctx, orgID, limit)
	if err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []models.AuditLogEntry{}
	}
	return logs, nil
}

func (s *AdminService) Organizations(ctx context.Context) ([]map[string]string, error) {
	return s.store.ListOrganizations(ctx)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Ensure domain import used for future admin extensions.
var _ = domain.Agent{}
