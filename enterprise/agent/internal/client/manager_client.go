package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Sasi3011/CyberSec/enterprise/shared/pkg/models"
)

// ManagerClient communicates with Central Manager (outbound HTTPS only).
type ManagerClient struct {
	baseURL    string
	agentToken string
	http       *http.Client
}

func NewManagerClient(baseURL, agentToken string) *ManagerClient {
	return &ManagerClient{
		baseURL:    baseURL,
		agentToken: agentToken,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *ManagerClient) SetToken(token string) {
	c.agentToken = token
}

func (c *ManagerClient) Heartbeat(ctx context.Context, req models.HeartbeatRequest) (*models.HeartbeatResponse, error) {
	return postJSON[models.HeartbeatResponse](ctx, c, "/api/v1/heartbeat", req)
}

func (c *ManagerClient) Register(ctx context.Context, req models.AgentRegisterRequest) (*models.AgentRegisterResponse, error) {
	return postJSON[models.AgentRegisterResponse](ctx, c, "/api/v1/agents/register", req)
}

func (c *ManagerClient) UploadAlerts(ctx context.Context, req models.AlertsBatchRequest) (*models.BatchUploadResponse, error) {
	return postJSON[models.BatchUploadResponse](ctx, c, "/api/v1/alerts", req)
}

func (c *ManagerClient) UploadDecisions(ctx context.Context, req models.DecisionsBatchRequest) (*models.BatchUploadResponse, error) {
	return postJSON[models.BatchUploadResponse](ctx, c, "/api/v1/decisions", req)
}

func (c *ManagerClient) ListIOCs(ctx context.Context, sinceVersion int64) (*models.IOCListResponse, error) {
	path := fmt.Sprintf("/api/v1/iocs?since_version=%d", sinceVersion)
	return getJSON[models.IOCListResponse](ctx, c, path)
}

func postJSON[T any](ctx context.Context, c *ManagerClient, path string, body interface{}) (*T, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.agentToken != "" {
		req.Header.Set("X-Agent-Token", c.agentToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("manager returned %d: %s", resp.StatusCode, string(b))
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func getJSON[T any](ctx context.Context, c *ManagerClient, path string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.agentToken != "" {
		req.Header.Set("X-Agent-Token", c.agentToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("manager returned %d", resp.StatusCode)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *ManagerClient) Ping(ctx context.Context) error {
	u, err := url.Parse(c.baseURL + "/health")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("manager health %d", resp.StatusCode)
	}
	return nil
}
