package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	cfg := Load()
	
	if cfg.Domain != "localhost" {
		t.Errorf("Expected default domain 'localhost', got %s", cfg.Domain)
	}
	
	if cfg.SSHPort != 22 {
		t.Errorf("Expected default SSH port 22, got %d", cfg.SSHPort)
	}
	
	if cfg.HTTPPort != 80 {
		t.Errorf("Expected default HTTP port 80, got %d", cfg.HTTPPort)
	}
	
	if cfg.HTTPSPort != 443 {
		t.Errorf("Expected default HTTPS port 443, got %d", cfg.HTTPSPort)
	}
	
	// External ports should default to internal ports
	if cfg.HTTPExternalPort != cfg.HTTPPort {
		t.Errorf("Expected HTTPExternalPort to default to HTTPPort %d, got %d", cfg.HTTPPort, cfg.HTTPExternalPort)
	}
	
	if cfg.HTTPSExternalPort != cfg.HTTPSPort {
		t.Errorf("Expected HTTPSExternalPort to default to HTTPSPort %d, got %d", cfg.HTTPSPort, cfg.HTTPSExternalPort)
	}
	
	// Test ACME defaults
	if cfg.ACMEStaging != true {
		t.Errorf("Expected ACME staging to default to true, got %v", cfg.ACMEStaging)
	}
	
	if cfg.ACMECertPath != "/data/certs/fullchain.pem" {
		t.Errorf("Expected default ACME cert path '/data/certs/fullchain.pem', got %s", cfg.ACMECertPath)
	}
	
	if cfg.ACMEKeyPath != "/data/certs/key.pem" {
		t.Errorf("Expected default ACME key path '/data/certs/key.pem', got %s", cfg.ACMEKeyPath)
	}
	
	if cfg.ACMEChallengeDir != "/data/acme-challenge" {
		t.Errorf("Expected default ACME challenge dir '/data/acme-challenge', got %s", cfg.ACMEChallengeDir)
	}
	
	if cfg.ACMERenewalDays != 30 {
		t.Errorf("Expected default ACME renewal days 30, got %d", cfg.ACMERenewalDays)
	}
	
	if cfg.ACMEDirectoryURL != "" {
		t.Errorf("Expected default ACME directory URL to be empty, got %s", cfg.ACMEDirectoryURL)
	}
}

func TestLoadWithEnv(t *testing.T) {
	os.Setenv("DOMAIN", "test.com")
	os.Setenv("SSH_PORT", "2223")
	os.Setenv("ACME_DIRECTORY_URL", "https://custom-ca.example.com/directory")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("SSH_PORT")
		os.Unsetenv("ACME_DIRECTORY_URL")
	}()
	
	cfg := Load()
	
	if cfg.Domain != "test.com" {
		t.Errorf("Expected domain 'test.com', got %s", cfg.Domain)
	}
	
	if cfg.SSHPort != 2223 {
		t.Errorf("Expected SSH port 2223, got %d", cfg.SSHPort)
	}
	
	if cfg.ACMEDirectoryURL != "https://custom-ca.example.com/directory" {
		t.Errorf("Expected ACME directory URL 'https://custom-ca.example.com/directory', got %s", cfg.ACMEDirectoryURL)
	}
}

func TestGetEnv(t *testing.T) {
	result := getEnv("NONEXISTENT_VAR", "fallback")
	if result != "fallback" {
		t.Errorf("Expected 'fallback', got %s", result)
	}
	
	os.Setenv("TEST_VAR", "value")
	defer os.Unsetenv("TEST_VAR")
	
	result = getEnv("TEST_VAR", "fallback")
	if result != "value" {
		t.Errorf("Expected 'value', got %s", result)
	}
}

func TestGetEnvInt(t *testing.T) {
	result := getEnvInt("NONEXISTENT_INT", 42)
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}
	
	os.Setenv("TEST_INT", "123")
	defer os.Unsetenv("TEST_INT")
	
	result = getEnvInt("TEST_INT", 42)
	if result != 123 {
		t.Errorf("Expected 123, got %d", result)
	}
	
	os.Setenv("INVALID_INT", "not_a_number")
	defer os.Unsetenv("INVALID_INT")
	
	result = getEnvInt("INVALID_INT", 42)
	if result != 42 {
		t.Errorf("Expected fallback 42 for invalid int, got %d", result)
	}
}