package config

import (
	"os"
	"strconv"
)

type Config struct {
	Domain       string
	ACMEEmail    string
	SSHPort      int
	HTTPPort     int
	HTTPSPort    int
	ACMEStaging  bool
}

func Load() *Config {
	cfg := &Config{
		Domain:       getEnv("DOMAIN", "localhost"),
		ACMEEmail:    getEnv("ACME_EMAIL", "test@example.com"),
		SSHPort:      getEnvInt("SSH_PORT", 2222),
		HTTPPort:     getEnvInt("HTTP_PORT", 8080),
		HTTPSPort:    getEnvInt("HTTPS_PORT", 8443),
		ACMEStaging:  getEnv("ACME_STAGING", "true") == "true",
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}