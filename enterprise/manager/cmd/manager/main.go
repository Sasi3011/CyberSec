package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/config"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/handler"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/hub"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/iocbus"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/migrate"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/repository"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/service"
	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/worker"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connect failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		logger.Warn("database ping failed — API may degrade", "error", err)
	} else if err := migrate.Up(ctx, pool); err != nil {
		logger.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	var redisPub *iocbus.Publisher
	if cfg.RedisURL != "" {
		rc, err := iocbus.OpenRedis(cfg.RedisURL)
		if err != nil {
			logger.Warn("redis unavailable — IOC pub/sub disabled", "error", err)
		} else {
			defer rc.Close()
			redisPub = iocbus.NewPublisher(rc)
			logger.Info("redis connected")
		}
	}

	alertHub := hub.NewAlertHub()
	store := repository.NewPostgresStore(pool)

	api := &handler.API{
		Agents:      service.NewAgentService(store),
		Alerts:      service.NewAlertServiceWithHub(store, alertHub),
		Decisions:   service.NewDecisionService(store, redisPub),
		IOCs:        service.NewIOCService(store),
		Endpoints:   service.NewEndpointService(store),
		OverviewSvc: service.NewOverviewService(store),
	}

	authSvc := service.NewAuthService(store, cfg.JWTSecret)
	admin := &handler.AdminHandler{
		Admin:        service.NewAdminService(store),
		OverviewSvc:  service.NewOverviewService(store),
		EndpointsSvc: service.NewEndpointService(store),
		FleetSvc:     service.NewFleetDetailService(store),
	}

	go worker.NewIOCRevoker(pool, store, redisPub).Run(ctx, 5*time.Minute)
	go worker.NewHeartbeatMonitor(pool).Run(ctx, 60*time.Second)

	r := chi.NewRouter()
	r.Use(chimw.RequestID, chimw.RealIP, chimw.Recoverer, chimw.Timeout(60*time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Agent-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/health", handler.Health)
	r.Handle("/metrics", handler.Metrics())
	r.Get("/ws/v1/alerts", handler.AlertsWebSocket(cfg.JWTSecret, alertHub))

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/agents/register", api.Register)
		api.MountAgentRoutes(r, store)
		handler.MountAdminRoutes(r, cfg.JWTSecret, authSvc, admin)
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("CyberSec Central Manager started", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info("manager stopped")
}
