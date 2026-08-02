package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/iocbus"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/crypto"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

// Store defines persistence operations for Phase 2 manager.
type Store interface {
	FindOrganizationByAPIKeyHash(ctx context.Context, hash string) (string, error)
	CreateAgent(ctx context.Context, orgID, hostname, tokenHash string, meta map[string]string, tags []string) (string, error)
	UpdateHeartbeat(ctx context.Context, agentID, orgID string, req models.HeartbeatRequest) error
	InsertAlerts(ctx context.Context, orgID, agentID string, alerts []models.AlertUpload) (int, error)
	InsertDecisionsAndIOCs(ctx context.Context, orgID, agentID string, decisions []models.DecisionUpload) (int, []domain.ThreatIOC, int64, error)
	GetIOCVersion(ctx context.Context, orgID string) (int64, error)
	GetLatestPolicyVersion(ctx context.Context, orgID string) (int, error)
	ListIOCsSince(ctx context.Context, orgID string, sinceVersion int64) (int64, []models.IOC, error)
	ListRevokedSince(ctx context.Context, orgID string, sinceVersion int64) ([]string, error)
	ListAgents(ctx context.Context, orgID string) ([]domain.Agent, error)
	CountAlerts(ctx context.Context, orgID string) (int64, error)
}

// AgentService handles registration and heartbeats.
type AgentService struct {
	store Store
}

func NewAgentService(store Store) *AgentService {
	return &AgentService{store: store}
}

func (s *AgentService) Register(ctx context.Context, req models.AgentRegisterRequest) (*models.AgentRegisterResponse, error) {
	if req.OrganizationAPIKey == "" || req.Hostname == "" {
		return nil, fmt.Errorf("organization_api_key and hostname required")
	}
	orgID, err := s.store.FindOrganizationByAPIKeyHash(ctx, crypto.HashToken(req.OrganizationAPIKey))
	if err != nil {
		return nil, fmt.Errorf("invalid organization api key")
	}
	agentToken, err := generateToken(32)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{
		"username":      req.Username,
		"os_version":    req.OSVersion,
		"agent_version": req.AgentVersion,
		"mac_address":   req.MACAddress,
		"department":    req.Department,
	}
	agentID, err := s.store.CreateAgent(ctx, orgID, req.Hostname, crypto.HashToken(agentToken), meta, req.Tags)
	if err != nil {
		return nil, err
	}
	return &models.AgentRegisterResponse{
		AgentID:              agentID,
		AgentToken:           agentToken,
		HeartbeatIntervalSec: models.DefaultHeartbeatIntervalSec,
	}, nil
}

func (s *AgentService) Heartbeat(ctx context.Context, auth domain.AgentAuth, req models.HeartbeatRequest) (*models.HeartbeatResponse, error) {
	if req.AgentID != "" && req.AgentID != auth.AgentID {
		return nil, fmt.Errorf("agent_id mismatch")
	}
	req.AgentID = auth.AgentID
	if err := s.store.UpdateHeartbeat(ctx, auth.AgentID, auth.OrganizationID, req); err != nil {
		return nil, err
	}
	policyVer, _ := s.store.GetLatestPolicyVersion(ctx, auth.OrganizationID)
	iocVer, _ := s.store.GetIOCVersion(ctx, auth.OrganizationID)
	return &models.HeartbeatResponse{
		OK:            true,
		ServerTime:    time.Now().UTC(),
		PolicyVersion: policyVer,
		IOCVersion:    iocVer,
	}, nil
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AlertService ingests detection alerts.
type AlertService struct {
	store Store
	hub   AlertPublisher
}

type AlertPublisher interface {
	Publish(alert models.AlertSummary)
}

func NewAlertService(store Store) *AlertService {
	return &AlertService{store: store}
}

func NewAlertServiceWithHub(store Store, hub AlertPublisher) *AlertService {
	return &AlertService{store: store, hub: hub}
}

func (s *AlertService) Upload(ctx context.Context, auth domain.AgentAuth, req models.AlertsBatchRequest) (*models.BatchUploadResponse, error) {
	if len(req.Alerts) == 0 {
		return &models.BatchUploadResponse{Accepted: 0}, nil
	}
	n, err := s.store.InsertAlerts(ctx, auth.OrganizationID, auth.AgentID, req.Alerts)
	if err != nil {
		return nil, err
	}
	if s.hub != nil {
		for _, a := range req.Alerts {
			s.hub.Publish(models.AlertSummary{
				AgentID: auth.AgentID, Scenario: a.Scenario, SourceIP: a.SourceIP,
				Severity: a.Severity, Confidence: a.Confidence, DetectedAt: a.DetectedAt,
			})
		}
	}
	return &models.BatchUploadResponse{Accepted: n}, nil
}

// DecisionService ingests bans and publishes IOCs.
type DecisionService struct {
	store     Store
	publisher *iocbus.Publisher
}

func NewDecisionService(store Store, publisher *iocbus.Publisher) *DecisionService {
	return &DecisionService{store: store, publisher: publisher}
}

func (s *DecisionService) Upload(ctx context.Context, auth domain.AgentAuth, req models.DecisionsBatchRequest) (*models.BatchUploadResponse, error) {
	n, iocs, version, err := s.store.InsertDecisionsAndIOCs(ctx, auth.OrganizationID, auth.AgentID, req.Decisions)
	if err != nil {
		return nil, err
	}
	if s.publisher != nil && len(iocs) > 0 {
		_ = s.publisher.Publish(ctx, auth.OrganizationID, version, iocs)
	}
	return &models.BatchUploadResponse{Accepted: n, IOCVersion: version}, nil
}

// IOCService serves IOC delta sync to agents.
type IOCService struct {
	store Store
}

func NewIOCService(store Store) *IOCService {
	return &IOCService{store: store}
}

func (s *IOCService) ListSince(ctx context.Context, auth domain.AgentAuth, sinceVersion int64) (*models.IOCListResponse, error) {
	version, iocs, err := s.store.ListIOCsSince(ctx, auth.OrganizationID, sinceVersion)
	if err != nil {
		return nil, err
	}
	if iocs == nil {
		iocs = []models.IOC{}
	}
	revoked, _ := s.store.ListRevokedSince(ctx, auth.OrganizationID, sinceVersion)
	if revoked == nil {
		revoked = []string{}
	}
	return &models.IOCListResponse{Version: version, IOCs: iocs, Revoked: revoked}, nil
}

// EndpointService lists fleet endpoints (SOC API stub — org from agent token for now).
type EndpointService struct {
	store Store
}

func NewEndpointService(store Store) *EndpointService {
	return &EndpointService{store: store}
}

func (s *EndpointService) ListForOrg(ctx context.Context, orgID string) ([]domain.Agent, error) {
	return s.store.ListAgents(ctx, orgID)
}

type FleetStore interface {
	GetAgent(ctx context.Context, orgID, agentID string) (domain.Agent, error)
	ListAlertsForAgent(ctx context.Context, orgID, agentID string, limit int) ([]models.AlertSummary, error)
	LastHeartbeatPayload(ctx context.Context, agentID string) (models.HeartbeatRequest, error)
}

type FleetDetailService struct {
	store FleetStore
}

func NewFleetDetailService(store FleetStore) *FleetDetailService {
	return &FleetDetailService{store: store}
}

func (s *FleetDetailService) Get(ctx context.Context, orgID, agentID string) (*models.EndpointDetail, error) {
	a, err := s.store.GetAgent(ctx, orgID, agentID)
	if err != nil {
		return nil, err
	}
	alerts, _ := s.store.ListAlertsForAgent(ctx, orgID, agentID, 50)
	if alerts == nil {
		alerts = []models.AlertSummary{}
	}
	detail := &models.EndpointDetail{
		EndpointSummary: models.EndpointSummary{
			ID: a.ID, Hostname: a.Hostname, Status: a.Status,
			PublicIP: a.PublicIP, LocalIP: a.LocalIP,
			AgentVersion: a.AgentVersion, Health: a.Health,
			EngineStatus: a.EngineStatus, FirewallStatus: a.FirewallStatus,
			Department: a.Department, LastSeenAt: a.LastSeenAt,
		},
		Username:     a.Username,
		OSVersion:    a.OSVersion,
		RecentAlerts: alerts,
	}
	if hb, err := s.store.LastHeartbeatPayload(ctx, agentID); err == nil {
		detail.CPUPercent = hb.CPUPercent
		detail.RAMPercent = hb.RAMPercent
		detail.DiskPercent = hb.DiskPercent
	}
	return detail, nil
}

// OverviewService aggregates dashboard stats.
type OverviewService struct {
	store Store
}

func NewOverviewService(store Store) *OverviewService {
	return &OverviewService{store: store}
}

func (s *OverviewService) Stats(ctx context.Context, orgID string) (*models.OverviewStats, error) {
	agents, err := s.store.ListAgents(ctx, orgID)
	if err != nil {
		return nil, err
	}
	online, offline, degraded, engineDown := 0, 0, 0, 0
	byDept := map[string]int{}
	byStatus := map[string]int{}
	for _, a := range agents {
		byStatus[a.Status]++
		dept := a.Department
		if dept == "" {
			dept = "Unassigned"
		}
		byDept[dept]++
		switch a.Status {
		case "online":
			online++
		case "degraded":
			degraded++
		default:
			offline++
		}
		if a.EngineStatus != "" && a.EngineStatus != "running" {
			engineDown++
		}
	}
	alertCount, _ := s.store.CountAlerts(ctx, orgID)
	iocVer, _ := s.store.GetIOCVersion(ctx, orgID)
	return &models.OverviewStats{
		OnlineAgents:    online,
		OfflineAgents:   offline,
		DegradedAgents:  degraded,
		TotalAgents:     len(agents),
		TotalAlerts:     alertCount,
		IOCVersion:      iocVer,
		EngineDownCount: engineDown,
		ByDepartment:    byDept,
		ByStatus:        byStatus,
	}, nil
}
