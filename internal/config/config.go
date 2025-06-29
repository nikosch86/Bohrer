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
	ACMEForceLocal    bool   // Force ACME even for local domains (for custom PKI)
	ACMEDirectoryURL  string // Custom ACME directory URL (empty = Let's Encrypt)
	SkipACME          bool   // Skip ACME entirely, use self-signed certificates
	AuthorizedKeys    string
	LogLevel          string // Log level: DEBUG, INFO, WARN, ERROR, FATAL
	UserStorageType   string // User storage type: "memory" or "file"
	UserStoragePath   string // Path to user storage file (used when UserStorageType is "file")
	WebUIUsername     string // WebUI admin username (if empty, will be generated)
	WebUIPassword     string // WebUI admin password (if empty, will be generated)
	SSHHostKeyPath    string // Path to SSH host key file
}

func Load() *Config {
	cfg := &Config{
		Domain:            getEnv("DOMAIN", "localhost"),
		ACMEEmail:         getEnv("ACME_EMAIL", "test@example.com"),
		SSHPort:           getEnvInt("SSH_PORT", 22),
		HTTPPort:          getEnvInt("HTTP_PORT", 80),
		HTTPSPort:         getEnvInt("HTTPS_PORT", 443),
		HTTPExternalPort:  getEnvInt("HTTP_EXTERNAL_PORT", 0),  // 0 means use HTTPPort
		HTTPSExternalPort: getEnvInt("HTTPS_EXTERNAL_PORT", 0), // 0 means use HTTPSPort
		SSHExternalPort:   getEnvInt("SSH_EXTERNAL_PORT", 0),   // 0 means use SSHPort
		ACMEStaging:       getEnvBool("ACME_STAGING", true),
		ACMECertPath:      getEnv("ACME_CERT_PATH", "/data/certs/fullchain.pem"),
		ACMEKeyPath:       getEnv("ACME_KEY_PATH", "/data/certs/key.pem"),
		ACMEChallengeDir:  getEnv("ACME_CHALLENGE_DIR", "/data/acme-challenge"),
		ACMERenewalDays:   getEnvInt("ACME_RENEWAL_DAYS", 30),
		ACMEForceLocal:    getEnvBool("ACME_FORCE_LOCAL", false),
		ACMEDirectoryURL:  getEnv("ACME_DIRECTORY_URL", ""),
		SkipACME:          getEnvBool("SKIP_ACME", false),
		AuthorizedKeys:    getEnv("SSH_AUTHORIZED_KEYS", "/data/authorized_keys"),
		LogLevel:          getEnv("LOG_LEVEL", "INFO"),
		UserStorageType:   getEnv("USER_STORAGE_TYPE", "file"),
		UserStoragePath:   getEnv("USER_STORAGE_PATH", "/data/users.json"),
		WebUIUsername:     getEnv("WEBUI_USERNAME", ""),
		WebUIPassword:     getEnv("WEBUI_PASSWORD", ""),
		SSHHostKeyPath:    getEnv("SSH_HOST_KEY_PATH", "/data/ssh_host_rsa_key"),
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

func getEnvBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		// Accept various boolean representations
		switch value {
		case "true", "True", "TRUE", "1", "yes", "Yes", "YES", "on", "On", "ON":
			return true
		case "false", "False", "FALSE", "0", "no", "No", "NO", "off", "Off", "OFF":
			return false
		}
	}
	return fallback
}
