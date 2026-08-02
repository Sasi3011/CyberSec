package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/service"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type mockStore struct {
	orgID string
}

func (m *mockStore) FindOrganizationByAPIKeyHash(_ context.Context, _ string) (string, error) {
	return m.orgID, nil
}
func (m *mockStore) CreateAgent(_ context.Context, _, _, _ string, _ map[string]string, _ []string) (string, error) {
	return "agent-uuid-1", nil
}
func (m *mockStore) UpdateHeartbeat(_ context.Context, _, _ string, _ models.HeartbeatRequest) error {
	return nil
}
func (m *mockStore) InsertAlerts(_ context.Context, _, _ string, alerts []models.AlertUpload) (int, error) {
	return len(alerts), nil
}
func (m *mockStore) InsertDecisionsAndIOCs(_ context.Context, _, _ string, d []models.DecisionUpload) (int, []domain.ThreatIOC, int64, error) {
	iocs := []domain.ThreatIOC{{ID: "ioc-1", IP: d[0].IP, Confidence: 80, Severity: "high"}}
	return len(d), iocs, 42, nil
}
func (m *mockStore) GetIOCVersion(_ context.Context, _ string) (int64, error) { return 41, nil }
func (m *mockStore) GetLatestPolicyVersion(_ context.Context, _ string) (int, error) { return 1, nil }
func (m *mockStore) ListIOCsSince(_ context.Context, _ string, _ int64) (int64, []models.IOC, error) {
	return 42, []models.IOC{{ID: "1", IP: "1.2.3.4", Action: "block"}}, nil
}
func (m *mockStore) ListRevokedSince(_ context.Context, _ string, _ int64) ([]string, error) {
	return []string{}, nil
}
func (m *mockStore) ListAgents(_ context.Context, _ string) ([]domain.Agent, error) {
	return []domain.Agent{{ID: "a1", Hostname: "test", Status: "online"}}, nil
}
func (m *mockStore) CountAlerts(_ context.Context, _ string) (int64, error) { return 5, nil }

func TestAgentRegister(t *testing.T) {
	svc := service.NewAgentService(&mockStore{orgID: "org-1"})
	resp, err := svc.Register(context.Background(), models.AgentRegisterRequest{
		OrganizationAPIKey: "test-key",
		Hostname:           "LAP-001",
		AgentVersion:       "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AgentID == "" || resp.AgentToken == "" {
		t.Fatal("expected agent id and token")
	}
}

func TestAlertUpload(t *testing.T) {
	svc := service.NewAlertService(&mockStore{orgID: "org-1"})
	auth := domain.AgentAuth{AgentID: "a1", OrganizationID: "org-1"}
	resp, err := svc.Upload(context.Background(), auth, models.AlertsBatchRequest{
		Alerts: []models.AlertUpload{{
			Scenario: "net-flood", SourceIP: "1.2.3.4", Severity: "high", DetectedAt: time.Now(),
		}},
	})
	if err != nil || resp.Accepted != 1 {
		t.Fatalf("expected 1 accepted, got %+v err=%v", resp, err)
	}
}

func TestDecisionUpload(t *testing.T) {
	svc := service.NewDecisionService(&mockStore{orgID: "org-1"}, nil)
	auth := domain.AgentAuth{AgentID: "a1", OrganizationID: "org-1"}
	resp, err := svc.Upload(context.Background(), auth, models.DecisionsBatchRequest{
		Decisions: []models.DecisionUpload{{IP: "1.2.3.4", Type: "ban", CreatedAt: time.Now()}},
	})
	if err != nil || resp.Accepted != 1 || resp.IOCVersion != 42 {
		t.Fatalf("unexpected response: %+v err=%v", resp, err)
	}
}

func TestIOCList(t *testing.T) {
	svc := service.NewIOCService(&mockStore{orgID: "org-1"})
	auth := domain.AgentAuth{OrganizationID: "org-1"}
	resp, err := svc.ListSince(context.Background(), auth, 0)
	if err != nil || len(resp.IOCs) != 1 {
		t.Fatalf("expected 1 ioc, got %+v err=%v", resp, err)
	}
}
