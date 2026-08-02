package config

import (
	"os"
	"strconv"
)

// Config holds Central Manager configuration.
type Config struct {
	ListenAddr  string
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
	TLSEnabled  bool
}

func Load() Config {
	return Config{
		ListenAddr:  getEnv("CSM_LISTEN_ADDR", ":8443"),
		DatabaseURL: getEnv("CSM_DATABASE_URL", "postgres://cybersec:cybersec@localhost:5432/cybersec_enterprise?sslmode=disable"),
		RedisURL:    getEnv("CSM_REDIS_URL", "redis://localhost:6379/0"),
		JWTSecret:   getEnv("CSM_JWT_SECRET", "dev-change-me-in-production"),
		TLSEnabled:  getEnvBool("CSM_TLS_ENABLED", false),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
