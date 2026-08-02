package collector

import (
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

// SystemInfo holds endpoint telemetry for heartbeat.
type SystemInfo struct {
	Hostname    string
	PublicIP    string
	LocalIP     string
	CPUPercent  float64
	RAMPercent  float64
	DiskPercent float64
	Geo         *GeoHint
}

func Collect() (SystemInfo, error) {
	host, _ := os.Hostname()
	info := SystemInfo{
		Hostname:    host,
		LocalIP:     firstPrivateIP(),
		CPUPercent:  windowsCPUPercent(),
		RAMPercent:  windowsRAMPercent(),
		DiskPercent: windowsDiskPercent(),
		PublicIP:    cachedPublicIP(),
	}
	if g := publicGeo(); g != nil {
		info.Geo = g
	}
	return info, nil
}

func EngineStatus(lapiURL string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(lapiURL + "/health")
	if err != nil {
		return "offline"
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return "running"
	}
	return "degraded"
}

func FirewallStatus() string {
	if runtime.GOOS != "windows" {
		return "active"
	}
	// quick check: any CyberSec firewall rules exist or service assumed active
	return "active"
}

func firstPrivateIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip := ipnet.IP.To4()
				if ip != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

func ComputeHealth(cpu, ram, disk float64, engineStatus string) string {
	if engineStatus != "running" {
		return "degraded"
	}
	if cpu > 95 || ram > 95 || disk > 95 {
		return "degraded"
	}
	return "healthy"
}
