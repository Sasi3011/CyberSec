package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultConfigPath = `C:\ProgramData\CyberSec\agent\config.yaml`

// Config is loaded from config.yaml or environment variables.
type Config struct {
	ManagerURL           string        `yaml:"manager_url"`
	OrgAPIKey            string        `yaml:"org_api_key"`
	AgentToken           string        `yaml:"agent_token"`
	AgentID              string        `yaml:"agent_id"`
	LocalLAPIURL         string        `yaml:"local_lapi_url"`
	LAPIKey              string        `yaml:"lapi_key"`
	LAPIPassword         string        `yaml:"lapi_password"`
	HeartbeatEvery       time.Duration `yaml:"-"`
	HeartbeatIntervalSec int           `yaml:"heartbeat_interval_sec"`
	QueuePath            string        `yaml:"queue_path"`
	BouncerScript        string        `yaml:"bouncer_script"`
	Department           string        `yaml:"department"`
	Tags                 []string      `yaml:"tags"`
}

func Load() Config {
	cfg := Config{
		ManagerURL:           getEnv("CS_AGENT_MANAGER_URL", "http://localhost:8443"),
		OrgAPIKey:            os.Getenv("CS_AGENT_ORG_API_KEY"),
		AgentToken:           os.Getenv("CS_AGENT_TOKEN"),
		AgentID:              os.Getenv("CS_AGENT_ID"),
		LocalLAPIURL:         getEnv("CS_AGENT_LAPI_URL", "http://127.0.0.1:8080"),
		LAPIKey:              os.Getenv("CS_AGENT_LAPI_KEY"),
		LAPIPassword:         os.Getenv("CS_AGENT_LAPI_PASSWORD"),
		HeartbeatIntervalSec: 30,
		QueuePath:            defaultQueuePath(),
	}
	if path := os.Getenv("CS_AGENT_CONFIG"); path != "" {
		mergeFile(&cfg, path)
	} else if _, err := os.Stat(defaultConfigPath); err == nil {
		mergeFile(&cfg, defaultConfigPath)
	}
	cfg.applyEnvOverrides()
	cfg.HeartbeatEvery = time.Duration(cfg.HeartbeatIntervalSec) * time.Second
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	return cfg
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("CS_AGENT_MANAGER_URL"); v != "" {
		c.ManagerURL = v
	}
	if v := os.Getenv("CS_AGENT_ORG_API_KEY"); v != "" {
		c.OrgAPIKey = v
	}
	if v := os.Getenv("CS_AGENT_TOKEN"); v != "" {
		c.AgentToken = v
	}
	if v := os.Getenv("CS_AGENT_ID"); v != "" {
		c.AgentID = v
	}
	if v := os.Getenv("CS_AGENT_LAPI_URL"); v != "" {
		c.LocalLAPIURL = v
	}
	if v := os.Getenv("CS_AGENT_QUEUE_PATH"); v != "" {
		c.QueuePath = v
	}
}

func mergeFile(cfg *Config, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = yaml.Unmarshal(raw, cfg)
}

func defaultQueuePath() string {
	return filepath.Join(`C:\ProgramData\CyberSec\agent`, "queue.db")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out := c
	out.HeartbeatEvery = 0
	data, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
