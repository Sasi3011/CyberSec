package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/iocbus"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/repository"
)

// IOCRevoker deactivates expired threat intel and bumps org IOC versions.
type IOCRevoker struct {
	pool      *pgxpool.Pool
	store     *repository.PostgresStore
	publisher *iocbus.Publisher
}

func NewIOCRevoker(pool *pgxpool.Pool, store *repository.PostgresStore, pub *iocbus.Publisher) *IOCRevoker {
	return &IOCRevoker{pool: pool, store: store, publisher: pub}
}

func (w *IOCRevoker) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.revokeExpired(ctx)
		}
	}
}

func (w *IOCRevoker) revokeExpired(ctx context.Context) {
	rows, err := w.pool.Query(ctx, `
		UPDATE threat_intel SET is_active = false, revoked_at = now()
		WHERE is_active = true AND expires_at < now()
		RETURNING organization_id::text, id::text
	`)
	if err != nil {
		slog.Warn("ioc revoke query failed", "error", err)
		return
	}
	defer rows.Close()
	orgCounts := map[string]int{}
	for rows.Next() {
		var orgID, id string
		if err := rows.Scan(&orgID, &id); err != nil {
			continue
		}
		orgCounts[orgID]++
	}
	for orgID, n := range orgCounts {
		if n == 0 {
			continue
		}
		version, _ := w.store.BumpIOCVersion(ctx, orgID)
		slog.Info("ioc revoked", "org", orgID, "count", n, "version", version)
	}
}
