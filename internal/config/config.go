package config

import (
	"os"
	"strconv"
)

type Config struct {
	Domain            string
	ACMEEmail         string
	SSHPort           int
	HTTPPort          int
	HTTPSPort         int
	HTTPExternalPort  int
	HTTPSExternalPort int
	SSHExternalPort   int
	ACMEStaging       bool
	ACMECertPath      string
	ACMEKeyPath       string
	ACMEChallengeDir  string
	ACMERenewalDays   int
	ACMEForceLocal    bool  // Force ACME even for local domains (for custom PKI)
	ACMEDirectoryURL  string // Custom ACME directory URL (empty = Let's Encrypt)
	SkipACME          bool  // Skip ACME entirely, use self-signed certificates
	AuthorizedKeys    string
}

func Load() *Config {
	cfg := &Config{
		Domain:            getEnv("DOMAIN", "localhost"),
		ACMEEmail:         getEnv("ACME_EMAIL", "test@example.com"),
		SSHPort:           getEnvInt("SSH_PORT", 22),
		HTTPPort:          getEnvInt("HTTP_PORT", 80),
		HTTPSPort:         getEnvInt("HTTPS_PORT", 443),
		HTTPExternalPort:  getEnvInt("HTTP_EXTERNAL_PORT", 0), // 0 means use HTTPPort
		HTTPSExternalPort: getEnvInt("HTTPS_EXTERNAL_PORT", 0), // 0 means use HTTPSPort
		SSHExternalPort:   getEnvInt("SSH_EXTERNAL_PORT", 0), // 0 means use SSHPort
		ACMEStaging:       getEnv("ACME_STAGING", "true") == "true",
		ACMECertPath:      getEnv("ACME_CERT_PATH", "/data/certs/fullchain.pem"),
		ACMEKeyPath:       getEnv("ACME_KEY_PATH", "/data/certs/key.pem"),
		ACMEChallengeDir:  getEnv("ACME_CHALLENGE_DIR", "/data/acme-challenge"),
		ACMERenewalDays:   getEnvInt("ACME_RENEWAL_DAYS", 30),
		ACMEForceLocal:    getEnv("ACME_FORCE_LOCAL", "false") == "true",
		ACMEDirectoryURL:  getEnv("ACME_DIRECTORY_URL", ""),
		SkipACME:          getEnv("SKIP_ACME", "false") == "true",
		AuthorizedKeys:    getEnv("SSH_AUTHORIZED_KEYS", "/data/authorized_keys"),
	}
	
	// If external ports are not set, use internal ports
	if cfg.HTTPExternalPort == 0 {
		cfg.HTTPExternalPort = cfg.HTTPPort
	}
	if cfg.HTTPSExternalPort == 0 {
		cfg.HTTPSExternalPort = cfg.HTTPSPort
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

