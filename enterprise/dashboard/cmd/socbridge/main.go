package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	managerURL   = env("CSM_MANAGER_URL", "http://manager:8443")
	adminEmail   = env("CSM_ADMIN_EMAIL", "admin@demo.local")
	adminPass    = env("CSM_ADMIN_PASSWORD", "demo123")
	listenAddr   = env("SOC_LISTEN", ":80")
)

type managerClient struct {
	mu    sync.Mutex
	token string
	hc    *http.Client
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (c *managerClient) login() error {
	body, _ := json.Marshal(map[string]string{"email": adminEmail, "password": adminPass})
	req, err := http.NewRequest(http.MethodPost, managerURL+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login %d: %s", resp.StatusCode, b)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	c.token = out.AccessToken
	return nil
}

func (c *managerClient) ensureToken() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return nil
	}
	return c.login()
}

func (c *managerClient) get(path string, dest any) error {
	if err := c.ensureToken(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, managerURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		c.token = ""
		if err := c.login(); err != nil {
			return err
		}
		return c.get(path, dest)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}

func (c *managerClient) post(path string, body any, dest any) error {
	if err := c.ensureToken(); err != nil {
		return err
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, managerURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %d %s", path, resp.StatusCode, b)
	}
	if dest != nil {
		return json.NewDecoder(resp.Body).Decode(dest)
	}
	return nil
}

func managerUp(hc *http.Client) bool {
	resp, err := hc.Get(managerURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var h struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&h)
	return h.Status == "ok"
}

type uiAlert struct {
	Scenario    string `json:"scenario"`
	Source      struct {
		IP string `json:"ip"`
	} `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
	EventsCount int       `json:"events_count"`
	Decisions   []uiDecision `json:"decisions"`
}

type uiDecision struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Scenario string `json:"scenario"`
	Duration string `json:"duration"`
	Origin   string `json:"origin"`
}

type uiBan struct {
	IP               string `json:"ip"`
	Scenario         string `json:"scenario"`
	Duration         string `json:"duration"`
	Origin           string `json:"origin"`
	EngineBanned     bool   `json:"engineBanned"`
	FirewallBlocked  bool   `json:"firewallBlocked"`
}

func fetchAlerts(mc *managerClient) ([]uiAlert, error) {
	var raw struct {
		Alerts []struct {
			Scenario   string    `json:"scenario"`
			SourceIP   string    `json:"source_ip"`
			DetectedAt time.Time `json:"detected_at"`
		} `json:"alerts"`
	}
	if err := mc.get("/api/v1/admin/alerts", &raw); err != nil {
		return nil, err
	}
	out := make([]uiAlert, 0, len(raw.Alerts))
	for _, a := range raw.Alerts {
		u := uiAlert{
			Scenario:    a.Scenario,
			CreatedAt:   a.DetectedAt,
			EventsCount: 1,
		}
		u.Source.IP = a.SourceIP
		u.Decisions = []uiDecision{{
			Type: "ban", Value: a.SourceIP, Scenario: a.Scenario, Duration: "4h", Origin: "enterprise",
		}}
		out = append(out, u)
	}
	return out, nil
}

func fetchDecisions(mc *managerClient) ([]uiDecision, error) {
	var raw struct {
		IOCs []struct {
			IP       string `json:"ip"`
			Scenario string `json:"scenario"`
		} `json:"iocs"`
	}
	if err := mc.get("/api/v1/admin/threat-intel", &raw); err != nil {
		return nil, err
	}
	out := make([]uiDecision, 0, len(raw.IOCs))
	for _, i := range raw.IOCs {
		out = append(out, uiDecision{
			Type: "ban", Value: i.IP, Scenario: i.Scenario, Duration: "4h", Origin: "enterprise-ioc",
		})
	}
	return out, nil
}

func fetchBans(mc *managerClient) ([]uiBan, error) {
	decs, err := fetchDecisions(mc)
	if err != nil {
		return nil, err
	}
	seen := map[string]uiBan{}
	for _, d := range decs {
		if d.Value == "" {
			continue
		}
		if _, ok := seen[d.Value]; !ok {
			seen[d.Value] = uiBan{
				IP: d.Value, Scenario: d.Scenario, Duration: d.Duration, Origin: d.Origin,
				EngineBanned: true, FirewallBlocked: true,
			}
		}
	}
	out := make([]uiBan, 0, len(seen))
	for _, b := range seen {
		out = append(out, b)
	}
	return out, nil
}

func fetchMetrics(mc *managerClient) (map[string]any, error) {
	var ov struct {
		OnlineAgents    int            `json:"online_agents"`
		OfflineAgents   int            `json:"offline_agents"`
		DegradedAgents  int            `json:"degraded_agents"`
		TotalAgents     int            `json:"total_agents"`
		TotalAlerts     int64          `json:"total_alerts"`
		IOCVersion      int64          `json:"ioc_version"`
		EngineDownCount int            `json:"engine_down_count"`
		ByDepartment    map[string]int `json:"by_department"`
		ByStatus        map[string]int `json:"by_status"`
	}
	if err := mc.get("/api/v1/admin/overview", &ov); err != nil {
		return nil, err
	}
	return map[string]any{
		"activeBans":      ov.IOCVersion,
		"eventsPoured":    float64(ov.TotalAlerts),
		"bucketsOverflow": float64(ov.TotalAlerts),
		"parserHits":      float64(ov.TotalAgents),
		"bucketsCreated":  float64(ov.OnlineAgents + ov.OfflineAgents + ov.DegradedAgents),
		"goroutines":      ov.OnlineAgents,
		"onlineAgents":    ov.OnlineAgents,
		"offlineAgents":   ov.OfflineAgents,
		"degradedAgents":  ov.DegradedAgents,
		"engineDownCount": ov.EngineDownCount,
		"byDepartment":    ov.ByDepartment,
		"byStatus":        ov.ByStatus,
	}, nil
}

func fetchGeo(ip string) map[string]any {
	if isPrivateIP(ip) {
		return map[string]any{
			"lat": 20.59, "lon": 78.96, "city": "LAN", "country": "Local",
			"isPrivate": true, "label": ip + " (local)", "accuracy": "Private IP",
		}
	}
	hc := &http.Client{Timeout: 6 * time.Second}
	resp, err := hc.Get("http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org")
	if err != nil {
		return map[string]any{"lat": 0, "lon": 0, "city": "Unknown", "country": "?", "label": "Unknown"}
	}
	defer resp.Body.Close()
	var d struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
	}
	if json.NewDecoder(resp.Body).Decode(&d) != nil || d.Status != "success" {
		return map[string]any{"lat": 0, "lon": 0, "city": "Unknown", "country": "?", "label": "Unknown"}
	}
	return map[string]any{
		"lat": d.Lat, "lon": d.Lon, "city": d.City, "region": d.RegionName,
		"country": d.Country, "countryCode": d.CountryCode, "zip": d.Zip,
		"isp": d.ISP, "org": d.Org, "isPrivate": false, "source": "ip-api",
		"label": fmt.Sprintf("%s, %s, %s", d.City, d.RegionName, d.Country),
	}
}

func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") || strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") || strings.HasPrefix(ip, "172.2") ||
		strings.HasPrefix(ip, "172.30.") || strings.HasPrefix(ip, "172.31.")
}

func loadIndexHTML() ([]byte, error) {
	if p := os.Getenv("SOC_INDEX_PATH"); p != "" {
		return os.ReadFile(p)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "index.html"),
		"index.html",
		filepath.Join("..", "..", "index.html"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("index.html not found (set SOC_INDEX_PATH)")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	hc := &http.Client{Timeout: 15 * time.Second}
	mc := &managerClient{hc: hc}

	if managerUp(hc) {
		if err := mc.login(); err != nil {
			log.Printf("manager login failed (will retry on API calls): %v", err)
		} else {
			log.Printf("connected to manager at %s", managerURL)
		}
	} else {
		log.Printf("manager offline at %s", managerURL)
	}

	indexHTML, err := loadIndexHTML()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		a, err := fetchAlerts(mc)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, a)
	})

	mux.HandleFunc("/api/decisions", func(w http.ResponseWriter, r *http.Request) {
		d, err := fetchDecisions(mc)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, d)
	})

	mux.HandleFunc("/api/bans", func(w http.ResponseWriter, r *http.Request) {
		b, err := fetchBans(mc)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, b)
	})

	mux.HandleFunc("/api/endpoints", func(w http.ResponseWriter, r *http.Request) {
		var ep any
		if err := mc.get("/api/v1/admin/endpoints", &ep); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, ep)
	})

	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) {
		var inc any
		if err := mc.get("/api/v1/admin/incidents", &inc); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, inc)
	})

	mux.HandleFunc("/api/audit-logs", func(w http.ResponseWriter, r *http.Request) {
		var logs any
		if err := mc.get("/api/v1/admin/audit-logs", &logs); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, logs)
	})

	mux.HandleFunc("/api/ws-token", func(w http.ResponseWriter, r *http.Request) {
		if err := mc.ensureToken(); err != nil {
			writeJSON(w, 503, map[string]string{"error": err.Error()})
			return
		}
		mc.mu.Lock()
		tok := mc.token
		mc.mu.Unlock()
		writeJSON(w, 200, map[string]string{"token": tok, "ws_url": strings.Replace(managerURL, "http", "ws", 1) + "/ws/v1/alerts"})
	})

	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		m, err := fetchMetrics(mc)
		if err != nil {
			writeJSON(w, 200, map[string]string{"error": "offline"})
			return
		}
		writeJSON(w, 200, m)
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		ok := managerUp(hc) && mc.token != ""
		status := "offline"
		code := http.StatusServiceUnavailable
		if ok {
			status = "ok"
			code = http.StatusOK
		}
		writeJSON(w, code, map[string]string{
			"status": status, "service": "CyberSec Enterprise", "version": "fleet", "backend": managerURL,
		})
	})

	mux.HandleFunc("/api/geo", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			writeJSON(w, 400, map[string]string{"error": "missing ip"})
			return
		}
		writeJSON(w, 200, fetchGeo(ip))
	})

	mux.HandleFunc("/api/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			IP       string `json:"ip"`
			Duration string `json:"duration"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
			writeJSON(w, 400, map[string]string{"error": "missing ip"})
			return
		}
		payload := map[string]any{
			"source": "soc-dashboard",
			"iocs": []map[string]any{{
				"ip": body.IP, "confidence": 85, "severity": "high", "scenario": "soc/manual-block",
			}},
		}
		if err := mc.post("/api/v1/admin/threat-feed/import", payload, nil); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "ip": body.IP, "action": "block"})
	})

	mux.HandleFunc("/api/unban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
			writeJSON(w, 400, map[string]string{"error": "missing ip"})
			return
		}
		var result map[string]any
		if err := mc.post("/api/v1/admin/threat-intel/revoke", map[string]any{"ips": []string{body.IP}}, &result); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "ip": body.IP, "result": result})
	})

	// Path-param endpoint detail (DefaultServeMux prefix match)
	mux.HandleFunc("/api/endpoints/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/endpoints/")
		if id == "" || id == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		var detail any
		if err := mc.get("/api/v1/admin/endpoints/"+id, &detail); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, detail)
	})

	log.Printf("CyberSec SOC bridge listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
