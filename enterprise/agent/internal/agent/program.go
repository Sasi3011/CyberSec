package agent

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/client"
	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/collector"
	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/config"
	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/ioc"
	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/queue"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

const agentVersion = "1.0.0"

// Program implements the agent runtime loop.
type Program struct {
	cfg         config.Config
	client      *client.ManagerClient
	lapi        *client.LAPIClient
	queue       *queue.OfflineQueue
	iocApplier  *ioc.Applier
	lastAlertID int64
	iocVersion  int64
	knownDec    map[int64]struct{}
}

func NewProgram(cfg config.Config) *Program {
	lapiPass := cfg.LAPIPassword
	if lapiPass == "" {
		lapiPass = "devpassword"
	}
	lapiKey := cfg.LAPIKey
	if lapiKey == "" {
		lapiKey = "local-dev"
	}
	return &Program{
		cfg:        cfg,
		client:     client.NewManagerClient(cfg.ManagerURL, cfg.AgentToken),
		lapi:       client.NewLAPIClient(cfg.LocalLAPIURL, lapiKey, lapiPass),
		iocApplier: ioc.NewApplier(client.NewLAPIClient(cfg.LocalLAPIURL, lapiKey, lapiPass)),
		knownDec:   map[int64]struct{}{},
	}
}

func (p *Program) Run(ctx context.Context) error {
	if err := p.ensureRegistered(ctx); err != nil {
		return err
	}
	q, err := queue.Open(p.cfg.QueuePath)
	if err != nil {
		return err
	}
	p.queue = q
	defer q.Close()

	ticker := time.NewTicker(p.cfg.HeartbeatEvery)
	defer ticker.Stop()

	log.Printf("CyberSec Agent started manager=%s agent_id=%s", p.cfg.ManagerURL, p.cfg.AgentID)

	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.tick(ctx)
		}
	}
}

func (p *Program) ensureRegistered(ctx context.Context) error {
	if p.cfg.AgentToken != "" && p.cfg.AgentID != "" {
		p.client.SetToken(p.cfg.AgentToken)
		return nil
	}
	if p.cfg.OrgAPIKey == "" {
		return errMissing("organization api key (CS_AGENT_ORG_API_KEY or config.yaml)")
	}
	sys, _ := collector.Collect()
	resp, err := p.client.Register(ctx, models.AgentRegisterRequest{
		OrganizationAPIKey: p.cfg.OrgAPIKey,
		Hostname:           sys.Hostname,
		AgentVersion:       agentVersion,
		OSVersion:          runtime.GOOS,
		Department:         p.cfg.Department,
		Tags:               p.cfg.Tags,
	})
	if err != nil {
		return err
	}
	p.cfg.AgentID = resp.AgentID
	p.cfg.AgentToken = resp.AgentToken
	p.client.SetToken(resp.AgentToken)
	configPath := os.Getenv("CS_AGENT_CONFIG")
	if configPath == "" {
		configPath = `C:\ProgramData\CyberSec\agent\config.yaml`
	}
	_ = p.cfg.Save(configPath)
	log.Printf("agent registered id=%s", resp.AgentID)
	return nil
}

func (p *Program) tick(ctx context.Context) {
	p.flushQueue(ctx)
	p.syncFromLAPI(ctx)
	p.sendHeartbeat(ctx)
}

func (p *Program) sendHeartbeat(ctx context.Context) {
	sys, err := collector.Collect()
	if err != nil {
		log.Printf("collect: %v", err)
	}
	engineStatus := collector.EngineStatus(p.cfg.LocalLAPIURL)
	pending, _ := p.queue.Count()
	health := collector.ComputeHealth(sys.CPUPercent, sys.RAMPercent, sys.DiskPercent, engineStatus)
	req := models.HeartbeatRequest{
		AgentID:          p.cfg.AgentID,
		Hostname:         sys.Hostname,
		PublicIP:         sys.PublicIP,
		LocalIP:          sys.LocalIP,
		CPUPercent:       sys.CPUPercent,
		RAMPercent:       sys.RAMPercent,
		DiskPercent:      sys.DiskPercent,
		AgentVersion:     agentVersion,
		EngineVersion:    "1.7.8",
		EngineStatus:     engineStatus,
		FirewallStatus:   collector.FirewallStatus(),
		Health:           health,
		PendingSyncCount: pending,
	}
	if sys.Geo != nil {
		req.Geo = &models.GeoLocation{
			Country: sys.Geo.Country,
			City:    sys.Geo.City,
			Lat:     sys.Geo.Lat,
			Lon:     sys.Geo.Lon,
		}
	}
	resp, err := p.client.Heartbeat(ctx, req)
	if err != nil {
		log.Printf("heartbeat failed: %v", err)
		return
	}
	if resp.IOCVersion > p.iocVersion {
		p.syncIOCs(ctx, p.iocVersion)
		p.iocVersion = resp.IOCVersion
	}
}

func (p *Program) syncIOCs(ctx context.Context, since int64) {
	list, err := p.client.ListIOCs(ctx, since)
	if err != nil {
		log.Printf("ioc sync: %v", err)
		return
	}
	if len(list.IOCs) > 0 {
		p.iocApplier.Apply(ctx, list.IOCs)
	}
	if len(list.Revoked) > 0 {
		p.iocApplier.Revoke(ctx, list.Revoked)
	}
	if list.Version > p.iocVersion {
		p.iocVersion = list.Version
	}
}

func (p *Program) syncFromLAPI(ctx context.Context) {
	alerts, maxID, err := p.lapi.FetchAlertsSince(ctx, p.lastAlertID)
	if err != nil {
		log.Printf("lapi alerts: %v", err)
	} else if len(alerts) > 0 {
		p.uploadAlerts(ctx, models.AlertsBatchRequest{AgentID: p.cfg.AgentID, Alerts: alerts})
		if maxID > p.lastAlertID {
			p.lastAlertID = maxID
		}
	}

	decisions, err := p.lapi.FetchDecisionsSince(ctx, p.knownDec)
	if err != nil {
		log.Printf("lapi decisions: %v", err)
	} else if len(decisions) > 0 {
		p.uploadDecisions(ctx, models.DecisionsBatchRequest{AgentID: p.cfg.AgentID, Decisions: decisions})
	}
}

func (p *Program) uploadAlerts(ctx context.Context, req models.AlertsBatchRequest) {
	_, err := p.client.UploadAlerts(ctx, req)
	if err != nil {
		log.Printf("alert upload queued: %v", err)
		raw, _ := json.Marshal(req)
		_ = p.queue.EnqueueAlerts(raw)
	}
}

func (p *Program) uploadDecisions(ctx context.Context, req models.DecisionsBatchRequest) {
	_, err := p.client.UploadDecisions(ctx, req)
	if err != nil {
		log.Printf("decision upload queued: %v", err)
		raw, _ := json.Marshal(req)
		_ = p.queue.EnqueueDecisions(raw)
	}
}

func (p *Program) flushQueue(ctx context.Context) {
	if err := p.client.Ping(ctx); err != nil {
		return
	}
	items, err := p.queue.DrainAlerts()
	if err != nil {
		return
	}
	for _, raw := range items {
		var req models.AlertsBatchRequest
		if json.Unmarshal(raw, &req) == nil {
			_, _ = p.client.UploadAlerts(ctx, req)
		}
	}
	items, err = p.queue.DrainDecisions()
	if err != nil {
		return
	}
	for _, raw := range items {
		var req models.DecisionsBatchRequest
		if json.Unmarshal(raw, &req) == nil {
			_, _ = p.client.UploadDecisions(ctx, req)
		}
	}
}

type missingErr string

func (e missingErr) Error() string { return string(e) }

func errMissing(msg string) error { return missingErr(msg) }
