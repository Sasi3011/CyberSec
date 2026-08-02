// Package models contains shared DTOs between Manager, Agent, and Dashboard.
package models

import "time"

const DefaultHeartbeatIntervalSec = 30

type GeoLocation struct {
	Country string  `json:"country"`
	City    string  `json:"city,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

type AgentRegisterRequest struct {
	OrganizationAPIKey string   `json:"organization_api_key"`
	Hostname           string   `json:"hostname"`
	Username           string   `json:"username,omitempty"`
	OSVersion          string   `json:"os_version,omitempty"`
	AgentVersion       string   `json:"agent_version"`
	MACAddress         string   `json:"mac_address,omitempty"`
	Department         string   `json:"department,omitempty"`
	Tags               []string `json:"tags,omitempty"`
}

type AgentRegisterResponse struct {
	AgentID              string `json:"agent_id"`
	AgentToken           string `json:"agent_token"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	ManagerWSURL         string `json:"manager_ws_url,omitempty"`
}

type HeartbeatRequest struct {
	AgentID          string       `json:"agent_id"`
	Hostname         string       `json:"hostname"`
	PublicIP         string       `json:"public_ip,omitempty"`
	LocalIP          string       `json:"local_ip,omitempty"`
	Geo              *GeoLocation `json:"geo,omitempty"`
	CPUPercent       float64      `json:"cpu_percent"`
	RAMPercent       float64      `json:"ram_percent"`
	DiskPercent      float64      `json:"disk_percent"`
	AgentVersion     string       `json:"agent_version"`
	EngineVersion    string       `json:"engine_version,omitempty"`
	EngineStatus     string       `json:"engine_status"`
	FirewallStatus   string       `json:"firewall_status"`
	Health           string       `json:"health"`
	PendingSyncCount int          `json:"pending_sync_count"`
}

type HeartbeatResponse struct {
	OK            bool      `json:"ok"`
	ServerTime    time.Time `json:"server_time"`
	PolicyVersion int       `json:"policy_version"`
	IOCVersion    int64     `json:"ioc_version"`
}

type AlertUpload struct {
	ID         string    `json:"id,omitempty"`
	Scenario   string    `json:"scenario"`
	SourceIP   string    `json:"source_ip"`
	Country    string    `json:"country,omitempty"`
	ASN        int64     `json:"asn,omitempty"`
	ISP        string    `json:"isp,omitempty"`
	Confidence int       `json:"confidence"`
	Severity   string    `json:"severity"`
	Evidence   []string  `json:"evidence,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}

type AlertsBatchRequest struct {
	AgentID string        `json:"agent_id"`
	Alerts  []AlertUpload `json:"alerts"`
}

type DecisionUpload struct {
	IP        string    `json:"ip"`
	Type      string    `json:"type"`
	Duration  string    `json:"duration,omitempty"`
	Scenario  string    `json:"scenario,omitempty"`
	Origin    string    `json:"origin,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type DecisionsBatchRequest struct {
	AgentID   string           `json:"agent_id"`
	Decisions []DecisionUpload `json:"decisions"`
}

type IOC struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Confidence int      `json:"confidence"`
	Severity  string    `json:"severity"`
	Scenario  string    `json:"scenario,omitempty"`
	Country   string    `json:"country,omitempty"`
	ASN       int64     `json:"asn,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Action    string    `json:"action"` // block, monitor
}

type IOCListResponse struct {
	Version int64  `json:"version"`
	IOCs    []IOC  `json:"iocs"`
	Revoked []string `json:"revoked"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error APIError `json:"error"`
}

type BatchUploadResponse struct {
	Accepted   int   `json:"accepted"`
	IOCVersion int64 `json:"ioc_version,omitempty"`
}

type EndpointSummary struct {
	ID             string     `json:"id"`
	Hostname       string     `json:"hostname"`
	Status         string     `json:"status"`
	PublicIP       string     `json:"public_ip,omitempty"`
	LocalIP        string     `json:"local_ip,omitempty"`
	AgentVersion   string     `json:"agent_version,omitempty"`
	Health         string     `json:"health,omitempty"`
	EngineStatus   string     `json:"engine_status,omitempty"`
	FirewallStatus string     `json:"firewall_status,omitempty"`
	Department     string     `json:"department,omitempty"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
}

type OverviewStats struct {
	OnlineAgents    int            `json:"online_agents"`
	OfflineAgents   int            `json:"offline_agents"`
	DegradedAgents  int            `json:"degraded_agents"`
	TotalAgents     int            `json:"total_agents"`
	TotalAlerts     int64          `json:"total_alerts"`
	IOCVersion      int64          `json:"ioc_version"`
	EngineDownCount int            `json:"engine_down_count"`
	ByDepartment    map[string]int `json:"by_department,omitempty"`
	ByStatus        map[string]int `json:"by_status,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Role         string `json:"role"`
	Organization string `json:"organization_id"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type UserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	OrganizationID string `json:"organization_id"`
}

type ThreatFeedEntry struct {
	IP         string `json:"ip"`
	Confidence int    `json:"confidence"`
	Severity   string `json:"severity"`
	Scenario   string `json:"scenario,omitempty"`
	Country    string `json:"country,omitempty"`
}

type ThreatFeedImportRequest struct {
	Source string            `json:"source"`
	IOCs   []ThreatFeedEntry `json:"iocs"`
}

type AlertSummary struct {
	ID         string    `json:"id"`
	AgentID    string    `json:"agent_id"`
	Scenario   string    `json:"scenario"`
	SourceIP   string    `json:"source_ip"`
	Severity   string    `json:"severity"`
	Confidence int       `json:"confidence"`
	DetectedAt time.Time `json:"detected_at"`
}

type IncidentSummary struct {
	SourceIP       string    `json:"source_ip"`
	Scenario       string    `json:"scenario"`
	Count          int       `json:"count"`
	AffectedAgents int       `json:"affected_agents"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	MaxSeverity    string    `json:"max_severity"`
}

type EndpointDetail struct {
	EndpointSummary
	Username     string              `json:"username,omitempty"`
	OSVersion    string              `json:"os_version,omitempty"`
	CPUPercent   float64             `json:"cpu_percent,omitempty"`
	RAMPercent   float64             `json:"ram_percent,omitempty"`
	DiskPercent  float64             `json:"disk_percent,omitempty"`
	RecentAlerts []AlertSummary      `json:"recent_alerts"`
	ActiveIOCs   []IOC               `json:"active_iocs,omitempty"`
}

type AuditLogEntry struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

type ThreatIntelRevokeRequest struct {
	IPs []string `json:"ips"`
}
