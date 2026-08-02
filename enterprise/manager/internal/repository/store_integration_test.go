//go:build integration

package repository_test

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/migrate"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/pkg/crypto"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/repository"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/service"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

func startPostgres(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	if dsn := os.Getenv("CSM_INTEGRATION_DATABASE_URL"); dsn != "" {
		return connectPool(t, ctx, dsn, func() {})
	}

	if runtime.GOOS == "windows" {
		t.Skip("on Windows set CSM_INTEGRATION_DATABASE_URL (e.g. docker compose postgres) or run integration tests in Linux CI")
	}

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("cybersec_enterprise"),
		tcpostgres.WithUsername("cybersec"),
		tcpostgres.WithPassword("cybersec"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("connection string: %v", err)
	}

	pool, cleanup := connectPool(t, ctx, dsn, func() {
		_ = container.Terminate(ctx)
	})
	return pool, cleanup
}

func connectPool(t *testing.T, ctx context.Context, dsn string, extraCleanup func()) (*pgxpool.Pool, func()) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := migrate.Up(ctx, pool); err != nil {
		pool.Close()
		extraCleanup()
		t.Fatalf("migrate: %v", err)
	}
	return pool, func() {
		pool.Close()
		extraCleanup()
	}
}

func TestPostgresAgentRegisterAndHeartbeat(t *testing.T) {
	pool, cleanup := startPostgres(t)
	defer cleanup()

	ctx := context.Background()
	store := repository.NewPostgresStore(pool)
	agents := service.NewAgentService(store)

	resp, err := agents.Register(ctx, models.AgentRegisterRequest{
		OrganizationAPIKey: "cybersec_dev_org_key",
		Hostname:           "integration-test",
		AgentVersion:       "1.0.0",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.AgentID == "" || resp.AgentToken == "" {
		t.Fatal("expected agent id and token")
	}

	auth, err := store.FindAgentByTokenHash(ctx, crypto.HashToken(resp.AgentToken))
	if err != nil {
		t.Fatalf("find agent: %v", err)
	}

	_, err = agents.Heartbeat(ctx, auth, models.HeartbeatRequest{
		AgentID:        resp.AgentID,
		Health:         "healthy",
		EngineStatus:   "running",
		FirewallStatus: "active",
		LocalIP:        "192.168.1.10",
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	alerts := service.NewAlertService(store)
	n, err := alerts.Upload(ctx, auth, models.AlertsBatchRequest{
		Alerts: []models.AlertUpload{{
			Scenario: "net-flood", SourceIP: "203.0.113.50", Severity: "high", DetectedAt: time.Now().UTC(),
		}},
	})
	if err != nil || n.Accepted != 1 {
		t.Fatalf("alert upload: %+v err=%v", n, err)
	}

	count, err := store.CountAlerts(ctx, auth.OrganizationID)
	if err != nil || count < 1 {
		t.Fatalf("expected at least 1 alert, got %d err=%v", count, err)
	}
}
