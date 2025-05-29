package ssh

import (
	"testing"

	"github.com/hoffmann/bohrer-go/internal/config"
)

func TestNewServer(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		SSHPort:   2222,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	server := NewServer(cfg)
	
	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}
	
	if server.config != cfg {
		t.Error("Expected server config to match input config")
	}
	
	if server.hostKey == nil {
		t.Error("Expected host key to be generated")
	}
	
	if server.tunnels == nil {
		t.Error("Expected tunnels map to be initialized")
	}
}

func TestGenerateSubdomain(t *testing.T) {
	subdomain := generateSubdomain()
	
	if len(subdomain) != 8 {
		t.Errorf("Expected subdomain length 8, got %d", len(subdomain))
	}
	
	// Test that it only contains valid characters
	validChars := "abcdefghijklmnopqrstuvwxyz0123456789"
	for _, char := range subdomain {
		found := false
		for _, valid := range validChars {
			if char == valid {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Invalid character '%c' in subdomain '%s'", char, subdomain)
		}
	}
	
	// Test uniqueness (run multiple times)
	subdomains := make(map[string]bool)
	for i := 0; i < 100; i++ {
		sub := generateSubdomain()
		subdomains[sub] = true
	}
	
	// Should have generated many unique subdomains
	if len(subdomains) < 50 {
		t.Errorf("Expected high uniqueness, got only %d unique subdomains out of 100", len(subdomains))
	}
}

func TestGenerateHostKey(t *testing.T) {
	hostKey, err := generateHostKey()
	
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}
	
	if hostKey == nil {
		t.Fatal("Expected host key to be generated, got nil")
	}
	
	// Test that we can get the public key
	pubKey := hostKey.PublicKey()
	if pubKey == nil {
		t.Error("Expected to get public key from host key")
	}
}