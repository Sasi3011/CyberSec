package agent

import (
	"context"
	"log"

	"github.com/kardianos/service"

	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/config"
)

type serviceProgram struct {
	cfg config.Config
	prog *Program
	cancel context.CancelFunc
}

func (s *serviceProgram) Start(svc service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.prog = NewProgram(s.cfg)
	go func() {
		if err := s.prog.Run(ctx); err != nil {
			log.Printf("agent error: %v", err)
		}
	}()
	return nil
}

func (s *serviceProgram) Stop(svc service.Service) error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

// RunService starts the agent as a Windows/Linux service or foreground process.
func RunService(cfg config.Config, foreground bool) error {
	svcCfg := &service.Config{
		Name:        "CyberSecAgent",
		DisplayName: "CyberSec Enterprise Agent",
		Description: "Syncs local CyberSec engine telemetry to Central Manager",
	}
	prg := &serviceProgram{cfg: cfg}
	s, err := service.New(prg, svcCfg)
	if err != nil {
		return err
	}
	if foreground {
		return prg.Start(s)
	}
	return s.Run()
}
