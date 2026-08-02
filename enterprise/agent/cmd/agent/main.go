package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kardianos/service"

	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/agent"
	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/config"
)

func main() {
	foreground := flag.Bool("foreground", false, "run in foreground (not as Windows service)")
	flag.Parse()

	cfg := config.Load()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install", "uninstall", "start", "stop", "restart", "status":
			if err := runServiceControl(cfg, os.Args[1]); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	runForeground := *foreground
	if !runForeground {
		runForeground = service.Interactive()
	}
	if err := agent.RunService(cfg, runForeground); err != nil {
		log.Fatal(err)
	}
}

func runServiceControl(cfg config.Config, action string) error {
	svcCfg := &service.Config{
		Name:        "CyberSecAgent",
		DisplayName: "CyberSec Enterprise Agent",
		Description: "Syncs local CyberSec engine telemetry to Central Manager",
	}
	s, err := service.New(&noopProgram{cfg: cfg}, svcCfg)
	if err != nil {
		return err
	}
	switch action {
	case "install":
		return s.Install()
	case "uninstall":
		return s.Uninstall()
	case "start":
		return s.Start()
	case "stop":
		return s.Stop()
	case "restart":
		if err := s.Stop(); err != nil {
			log.Printf("stop: %v", err)
		}
		return s.Start()
	case "status":
		st, err := s.Status()
		if err != nil {
			return err
		}
		fmt.Println(st)
		return nil
	default:
		return fmt.Errorf("unknown action %s", action)
	}
}

type noopProgram struct {
	cfg config.Config
}

func (n *noopProgram) Start(s service.Service) error { return nil }
func (n *noopProgram) Stop(s service.Service) error  { return nil }
