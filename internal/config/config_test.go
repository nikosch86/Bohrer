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
}

func TestLoadWithEnv(t *testing.T) {
	os.Setenv("DOMAIN", "test.com")
	os.Setenv("SSH_PORT", "2223")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("SSH_PORT")
	}()
	
	cfg := Load()
	
	if cfg.Domain != "test.com" {
		t.Errorf("Expected domain 'test.com', got %s", cfg.Domain)
	}
	
	if cfg.SSHPort != 2223 {
		t.Errorf("Expected SSH port 2223, got %d", cfg.SSHPort)
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