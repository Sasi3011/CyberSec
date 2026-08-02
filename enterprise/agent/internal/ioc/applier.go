package ioc

import (
	"context"
	"log"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Sasi3011/CyberSec/enterprise/agent/internal/client"
	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

// Applier pushes organization IOCs to the local engine / firewall.
type Applier struct {
	lapi *client.LAPIClient
}

func NewApplier(lapi *client.LAPIClient) *Applier {
	return &Applier{lapi: lapi}
}

func (a *Applier) Apply(ctx context.Context, iocs []models.IOC) {
	for _, ioc := range iocs {
		if ioc.IP == "" || ioc.Action != "block" {
			continue
		}
		scenario := ioc.Scenario
		if scenario == "" {
			scenario = "enterprise/ioc-sync"
		}
		if err := a.lapi.AddBan(ctx, ioc.IP, scenario); err != nil {
			log.Printf("ioc lapi ban %s: %v", ioc.IP, err)
		}
		if runtime.GOOS == "windows" {
			a.firewallBlock(ioc.IP)
		}
	}
}

func (a *Applier) Revoke(ctx context.Context, ips []string) {
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if err := a.lapi.RemoveBan(ctx, ip); err != nil {
			log.Printf("ioc lapi unban %s: %v", ip, err)
		}
		if runtime.GOOS == "windows" {
			a.firewallUnblock(ip)
		}
	}
}

func (a *Applier) firewallUnblock(ip string) {
	name := "CyberSec-IOC-" + strings.ReplaceAll(ip, ".", "-")
	ps := exec.Command("powershell", "-NoProfile", "-Command",
		`Remove-NetFirewallRule -DisplayName $args[0] -ErrorAction SilentlyContinue`, name)
	if err := ps.Run(); err != nil {
		log.Printf("ioc firewall remove %s: %v", ip, err)
	}
}

func (a *Applier) firewallBlock(ip string) {
	ps := exec.Command("powershell", "-NoProfile", "-Command",
		`$n="CyberSec-IOC-"+$args[0].Replace(".","-"); if(-not (Get-NetFirewallRule -DisplayName $n -EA SilentlyContinue)){ New-NetFirewallRule -DisplayName $n -Direction Inbound -Action Block -RemoteAddress $args[0] -Enabled True | Out-Null }`,
		ip)
	if err := ps.Run(); err != nil {
		log.Printf("ioc firewall %s: %v", ip, err)
	}
}
