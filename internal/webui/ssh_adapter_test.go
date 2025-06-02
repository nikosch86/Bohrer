package webui

import (
	"testing"

	"bohrer-go/internal/config"
)

func TestSSHServerAdapter(t *testing.T) {
	mockSSHServer := &MockSSHServer{
		subdomains: []string{"api", "web", "test"},
	}

	mockProxy := &MockProxy{
		tunnels: map[string]string{
			"api":  "localhost:3000",
			"web":  "localhost:8080",
			"test": "localhost:9000",
		},
	}

	adapter := NewSSHServerAdapter(mockSSHServer, mockProxy)

	// Test GetActiveTunnelSubdomains
	subdomains := adapter.GetActiveTunnelSubdomains()
	if len(subdomains) != 3 {
		t.Errorf("Expected 3 subdomains, got %d", len(subdomains))
	}

	expectedSubdomains := map[string]bool{
		"api": false, "web": false, "test": false,
	}

	for _, subdomain := range subdomains {
		if _, exists := expectedSubdomains[subdomain]; exists {
			expectedSubdomains[subdomain] = true
		} else {
			t.Errorf("Unexpected subdomain: %s", subdomain)
		}
	}

	for subdomain, found := range expectedSubdomains {
		if !found {
			t.Errorf("Expected subdomain %s not found", subdomain)
		}
	}

	// Test GetTunnelInfo
	target, exists := adapter.GetTunnelInfo("api")
	if !exists {
		t.Error("Expected tunnel 'api' to exist")
	}
	if target != "localhost:3000" {
		t.Errorf("Expected target 'localhost:3000', got '%s'", target)
	}

	// Test non-existent tunnel
	_, exists = adapter.GetTunnelInfo("nonexistent")
	if exists {
		t.Error("Expected tunnel 'nonexistent' to not exist")
	}
}

func TestSSHServerAdapterWithNilComponents(t *testing.T) {
	adapter := NewSSHServerAdapter(nil, nil)

	// Test with nil SSH server
	subdomains := adapter.GetActiveTunnelSubdomains()
	if len(subdomains) != 0 {
		t.Errorf("Expected 0 subdomains with nil SSH server, got %d", len(subdomains))
	}

	// Test with nil proxy
	_, exists := adapter.GetTunnelInfo("api")
	if exists {
		t.Error("Expected no tunnel info with nil proxy")
	}
}

func TestWebUIWithSSHAdapter(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	// Create adapter with mock components
	mockSSHServer := &MockSSHServer{
		subdomains: []string{"api", "dashboard"},
	}

	mockProxy := &MockProxy{
		tunnels: map[string]string{
			"api":       "localhost:3000",
			"dashboard": "localhost:8080",
		},
	}

	adapter := NewSSHServerAdapter(mockSSHServer, mockProxy)
	webui.SetSSHTunnelProvider(adapter)

	// Test getting tunnels
	tunnels := webui.getTunnels()
	if len(tunnels) != 2 {
		t.Errorf("Expected 2 tunnels, got %d", len(tunnels))
	}

	// Check tunnel details
	for _, tunnel := range tunnels {
		if tunnel.Subdomain == "api" {
			if tunnel.Target != "localhost:3000" {
				t.Errorf("Expected target 'localhost:3000', got '%s'", tunnel.Target)
			}
			if tunnel.HTTPURL != "http://api.example.com" {
				t.Errorf("Expected HTTP URL 'http://api.example.com', got '%s'", tunnel.HTTPURL)
			}
			if tunnel.HTTPSURL != "https://api.example.com" {
				t.Errorf("Expected HTTPS URL 'https://api.example.com', got '%s'", tunnel.HTTPSURL)
			}
		}
	}
}

// Mock implementations for testing

type MockSSHServer struct {
	subdomains []string
}

func (m *MockSSHServer) GetActiveTunnelSubdomains() []string {
	return m.subdomains
}

type MockProxy struct {
	tunnels map[string]string
}

func (m *MockProxy) GetTunnel(subdomain string) (string, bool) {
	target, exists := m.tunnels[subdomain]
	return target, exists
}

func TestNewUserStoreAdapter(t *testing.T) {
	userStore := NewInMemoryUserStore()
	adapter := NewUserStoreAdapter(userStore)

	if adapter == nil {
		t.Fatal("NewUserStoreAdapter returned nil")
	}
}

func TestUserStoreAdapter_GetUser(t *testing.T) {
	userStore := NewInMemoryUserStore()
	userStore.CreateUser("testuser", "testpass")

	adapter := NewUserStoreAdapter(userStore)

	// Test existing user
	password, exists := adapter.GetUser("testuser")
	if !exists {
		t.Error("Expected user to exist")
	}
	if password != "testpass" {
		t.Errorf("Expected password 'testpass', got %s", password)
	}

	// Test non-existing user
	_, exists = adapter.GetUser("nonexistent")
	if exists {
		t.Error("Non-existing user should not exist")
	}
}

func TestUserStoreAdapter_VerifyPassword(t *testing.T) {
	userStore := NewInMemoryUserStore()
	userStore.CreateUser("testuser", "testpass")

	adapter := NewUserStoreAdapter(userStore)

	// Test correct password
	if !adapter.VerifyPassword("testuser", "testpass") {
		t.Error("Should verify correct password")
	}

	// Test incorrect password
	if adapter.VerifyPassword("testuser", "wrongpass") {
		t.Error("Should not verify incorrect password")
	}

	// Test non-existing user
	if adapter.VerifyPassword("nonexistent", "anypass") {
		t.Error("Should not verify non-existing user")
	}
}
