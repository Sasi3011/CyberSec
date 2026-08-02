package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/handler"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/crypto"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/service"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

type stubStore struct{}

func (stubStore) FindOrganizationByAPIKeyHash(context.Context, string) (string, error) {
	return "00000000-0000-0000-0000-000000000001", nil
}
func (stubStore) CreateAgent(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "agent-id", nil
}
func (stubStore) UpdateHeartbeat(context.Context, string, string, models.HeartbeatRequest) error { return nil }
func (stubStore) InsertAlerts(context.Context, string, string, []models.AlertUpload) (int, error) {
	return 1, nil
}
func (stubStore) InsertDecisionsAndIOCs(context.Context, string, string, []models.DecisionUpload) (int, []domain.ThreatIOC, int64, error) {
	return 1, nil, 1, nil
}
func (stubStore) GetIOCVersion(context.Context, string) (int64, error)            { return 1, nil }
func (stubStore) GetLatestPolicyVersion(context.Context, string) (int, error)   { return 0, nil }
func (stubStore) ListIOCsSince(context.Context, string, int64) (int64, []models.IOC, error) {
	return 1, []models.IOC{}, nil
}
func (stubStore) ListRevokedSince(context.Context, string, int64) ([]string, error) { return nil, nil }
func (stubStore) ListAgents(context.Context, string) ([]domain.Agent, error) { return nil, nil }
func (stubStore) CountAlerts(context.Context, string) (int64, error)       { return 0, nil }

type tokenAuth struct {
	hash string
}

func (t tokenAuth) FindAgentByTokenHash(_ context.Context, hash string) (domain.AgentAuth, error) {
	if hash != t.hash {
		return domain.AgentAuth{}, context.Canceled
	}
	return domain.AgentAuth{AgentID: "agent-id", OrganizationID: "org-id"}, nil
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.Health(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRegisterRoute(t *testing.T) {
	api := &handler.API{Agents: service.NewAgentService(stubStore{})}
	body, _ := json.Marshal(models.AgentRegisterRequest{
		OrganizationAPIKey: "key", Hostname: "h1", AgentVersion: "1.0.0",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	api.Register(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func mountAgentAPI(api *handler.API, auth tokenAuth) http.Handler {
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		api.MountAgentRoutes(r, auth)
	})
	return r
}

func TestHeartbeatRequiresAuth(t *testing.T) {
	api := &handler.API{Agents: service.NewAgentService(stubStore{})}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader([]byte(`{"agent_id":"agent-id"}`)))
	rec := httptest.NewRecorder()

	mountAgentAPI(api, tokenAuth{hash: crypto.HashToken("secret")}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestHeartbeatWithToken(t *testing.T) {
	token := "secret-token"
	api := &handler.API{Agents: service.NewAgentService(stubStore{})}
	body, _ := json.Marshal(models.HeartbeatRequest{AgentID: "agent-id", Health: "healthy", EngineStatus: "running", FirewallStatus: "active"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", token)
	rec := httptest.NewRecorder()

	mountAgentAPI(api, tokenAuth{hash: crypto.HashToken(token)}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}
