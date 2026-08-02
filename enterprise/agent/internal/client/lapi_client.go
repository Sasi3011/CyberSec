package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

// LAPIClient polls the local CyberSec engine API.
type LAPIClient struct {
	baseURL  string
	apiKey   string
	password string
	http     *http.Client
}

func NewLAPIClient(baseURL, apiKey, password string) *LAPIClient {
	return &LAPIClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   apiKey,
		password: password,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

type lapiAlert struct {
	ID       int64  `json:"id"`
	Scenario string `json:"scenario"`
	Source   struct {
		IP    string `json:"ip"`
		Value string `json:"value"`
	} `json:"source"`
	StartAt string `json:"start_at"`
}

type lapiDecision struct {
	ID        int64  `json:"id"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Scenario  string `json:"scenario"`
	Origin    string `json:"origin"`
	Duration  string `json:"duration"`
	CreatedAt string `json:"created_at"`
}

func (c *LAPIClient) FetchAlertsSince(ctx context.Context, sinceID int64) ([]models.AlertUpload, int64, error) {
	path := c.baseURL + "/v1/alerts?simulated=false"
	if sinceID > 0 {
		path += "&id_gt=" + strconv.FormatInt(sinceID, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, sinceID, err
	}
	c.setAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, sinceID, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, sinceID, fmt.Errorf("lapi alerts %d: %s", resp.StatusCode, string(b))
	}
	var raw []lapiAlert
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, sinceID, err
	}
	out := make([]models.AlertUpload, 0, len(raw))
	maxID := sinceID
	for _, a := range raw {
		ip := a.Source.IP
		if ip == "" {
			ip = a.Source.Value
		}
		if ip == "" || a.Scenario == "" {
			continue
		}
		detected := time.Now().UTC()
		if a.StartAt != "" {
			if t, err := time.Parse(time.RFC3339, a.StartAt); err == nil {
				detected = t
			}
		}
		out = append(out, models.AlertUpload{
			ID:         strconv.FormatInt(a.ID, 10),
			Scenario:   a.Scenario,
			SourceIP:   ip,
			Severity:   "medium",
			Confidence: 70,
			DetectedAt: detected,
		})
		if a.ID > maxID {
			maxID = a.ID
		}
	}
	return out, maxID, nil
}

func (c *LAPIClient) FetchDecisionsSince(ctx context.Context, known map[int64]struct{}) ([]models.DecisionUpload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/decisions?type=ban", nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("lapi decisions %d", resp.StatusCode)
	}
	var raw []lapiDecision
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]models.DecisionUpload, 0)
	for _, d := range raw {
		if d.Type != "ban" || d.Value == "" {
			continue
		}
		if known != nil {
			if _, ok := known[d.ID]; ok {
				continue
			}
		}
		created := time.Now().UTC()
		if d.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, d.CreatedAt); err == nil {
				created = t
			}
		}
		out = append(out, models.DecisionUpload{
			IP:        d.Value,
			Type:      "ban",
			Duration:  d.Duration,
			Scenario:  d.Scenario,
			Origin:    d.Origin,
			CreatedAt: created,
		})
	}
	return out, nil
}

func (c *LAPIClient) AddBan(ctx context.Context, ip, scenario string) error {
	body := fmt.Sprintf(`{"duration":"4h","reason":"enterprise-ioc","scope":"Ip","type":"ban","value":"%s","scenario":"%s"}`, ip, scenario)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/decisions", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != 409 {
		return fmt.Errorf("lapi add ban %d", resp.StatusCode)
	}
	return nil
}

func (c *LAPIClient) RemoveBan(ctx context.Context, ip string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/decisions/"+ip+"?type=ban&scope=Ip", nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != 404 {
		return fmt.Errorf("lapi remove ban %d", resp.StatusCode)
	}
	return nil
}

func (c *LAPIClient) setAuth(req *http.Request) {
	if c.apiKey != "" {
		req.SetBasicAuth(c.apiKey, c.password)
		req.Header.Set("X-Api-Key", c.apiKey)
	} else if c.password != "" {
		req.SetBasicAuth("local-dev", c.password)
	}
}
