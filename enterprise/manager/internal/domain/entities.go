package domain

import "time"

type AgentAuth struct {
	AgentID        string
	OrganizationID string
	Hostname       string
}

type Agent struct {
	ID             string
	OrganizationID string
	Hostname       string
	Username       string
	OSVersion      string
	AgentVersion   string
	Department     string
	Status         string
	PublicIP       string
	LocalIP        string
	Health         string
	EngineStatus   string
	FirewallStatus string
	LastSeenAt     *time.Time
}

type Alert struct {
	ID         string
	AgentID    string
	Scenario   string
	SourceIP   string
	Severity   string
	DetectedAt time.Time
}

type ThreatIOC struct {
	ID         string
	IP         string
	Confidence int
	Severity   string
	Scenario   string
	Country    string
	ASN        int64
	Version    int64
	ExpiresAt  time.Time
}
