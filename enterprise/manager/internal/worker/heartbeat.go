package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const staleInterval = "90 seconds"

// HeartbeatMonitor marks agents offline when heartbeats stop and degraded when engine is down.
type HeartbeatMonitor struct {
	pool *pgxpool.Pool
}

func NewHeartbeatMonitor(pool *pgxpool.Pool) *HeartbeatMonitor {
	return &HeartbeatMonitor{pool: pool}
}

func (w *HeartbeatMonitor) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *HeartbeatMonitor) tick(ctx context.Context) {
	staleInterval := "90 seconds"
	tag, err := w.pool.Exec(ctx, `
		UPDATE agents SET status = 'offline', updated_at = now()
		WHERE status != 'offline'
		  AND (last_seen_at IS NULL OR last_seen_at < now() - $1::interval)
	`, staleInterval)
	if err != nil {
		slog.Warn("heartbeat offline sweep failed", "error", err)
		return
	}
	if tag.RowsAffected() > 0 {
		slog.Info("agents marked offline", "count", tag.RowsAffected())
	}

	tag2, err := w.pool.Exec(ctx, `
		UPDATE agents SET status = 'degraded', updated_at = now()
		WHERE status = 'online'
		  AND engine_status IS NOT NULL
		  AND engine_status <> ''
		  AND engine_status <> 'running'
		  AND last_seen_at >= now() - $1::interval
	`, staleInterval)
	if err != nil {
		slog.Warn("heartbeat degraded sweep failed", "error", err)
		return
	}
	if tag2.RowsAffected() > 0 {
		slog.Info("agents marked degraded", "count", tag2.RowsAffected())
	}
}
