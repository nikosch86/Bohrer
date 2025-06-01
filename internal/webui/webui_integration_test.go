package webui

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bohrer-go/internal/config"
	"bohrer-go/internal/proxy"
	"bohrer-go/internal/ssh"
)

func TestFullWebUIIntegration(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		HTTPPort:      8080,
		SSHPort:       2022,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}
	
	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:testpass123"))

	// Create real components
	proxyServer := proxy.NewProxy(cfg)
	sshServer := ssh.NewServer(cfg)
	sshServer.SetTunnelManager(proxyServer)

	// Create WebUI and connect everything
	webUI := NewWebUI(cfg)
	sshAdapter := NewSSHServerAdapter(sshServer, proxyServer)
	webUI.SetSSHTunnelProvider(sshAdapter)
	sshServer.SetUserStore(webUI.GetUserStore())
	proxyServer.SetWebUI(webUI)

	// Create a test user
	err := webUI.GetUserStore().CreateUser("testuser", "testpass")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test that WebUI serves on root domain (use ServeHTTPS handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.local"
	req.Header.Set("Authorization", "Basic "+auth)
	rr := httptest.NewRecorder()

	// Use ServeHTTPS which handles WebUI on root domain
	proxyServer.ServeHTTPS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for root domain, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Tunnel Dashboard") {
		t.Error("Expected WebUI content on root domain")
	}

	// Test users page
	req = httptest.NewRequest("GET", "/users", nil)
	req.Host = "test.local"
	req.Header.Set("Authorization", "Basic "+auth)
	rr = httptest.NewRecorder()

	// Use ServeHTTPS which handles WebUI on root domain
	proxyServer.ServeHTTPS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for users page, got %d", rr.Code)
	}

	body = rr.Body.String()
	if !strings.Contains(body, "User Management") {
		t.Error("Expected users page content")
	}

	// Test that CSS is served
	req = httptest.NewRequest("GET", "/static/style.css", nil)
	req.Host = "test.local"
	req.Header.Set("Authorization", "Basic "+auth)
	rr = httptest.NewRecorder()

	// Use ServeHTTPS which handles WebUI on root domain
	proxyServer.ServeHTTPS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for CSS, got %d", rr.Code)
	}

	if !strings.Contains(rr.Header().Get("Content-Type"), "text/css") {
		t.Error("Expected CSS content type")
	}
}

func TestWebUIWithActiveTunnels(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		HTTPPort:      8080,
		SSHPort:       2022,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}
	
	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:testpass123"))

	// Create components
	proxyServer := proxy.NewProxy(cfg)
	sshServer := ssh.NewServer(cfg)
	sshServer.SetTunnelManager(proxyServer)

	// Add some tunnels to proxy (simulating active SSH tunnels)
	proxyServer.AddTunnel("api", "localhost:3000")
	proxyServer.AddTunnel("web", "localhost:8080")

	// Create WebUI
	webUI := NewWebUI(cfg)
	sshAdapter := NewSSHServerAdapter(sshServer, proxyServer)
	webUI.SetSSHTunnelProvider(sshAdapter)
	proxyServer.SetWebUI(webUI)

	// Mock SSH server to return subdomains (simulating active tunnels)
	mockSSHServer := &MockSSHServer{
		subdomains: []string{"api", "web"},
	}
	mockAdapter := NewSSHServerAdapter(mockSSHServer, proxyServer)
	webUI.SetSSHTunnelProvider(mockAdapter)

	// Test dashboard shows tunnels
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.local"
	req.Header.Set("Authorization", "Basic "+auth)
	rr := httptest.NewRecorder()

	// Use ServeHTTPS which handles WebUI on root domain
	proxyServer.ServeHTTPS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "api") || !strings.Contains(body, "web") {
		t.Error("Expected tunnel information in dashboard")
	}

	if !strings.Contains(body, "localhost:3000") || !strings.Contains(body, "localhost:8080") {
		t.Error("Expected tunnel targets in dashboard")
	}
}

func TestUserAuthenticationFlow(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		HTTPPort:      8080,
		SSHPort:       2022,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	// Create components
	sshServer := ssh.NewServer(cfg)
	webUI := NewWebUI(cfg)
	sshServer.SetUserStore(webUI.GetUserStore())

	// Create a test user
	err := webUI.GetUserStore().CreateUser("alice", "secret123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test that user store integration works
	password, exists := webUI.GetUserStore().GetUser("alice")
	if !exists {
		t.Error("Expected user 'alice' to exist")
	}
	if password != "secret123" {
		t.Errorf("Expected password 'secret123', got '%s'", password)
	}

	// Test non-existent user
	_, exists = webUI.GetUserStore().GetUser("bob")
	if exists {
		t.Error("Expected user 'bob' to not exist")
	}
}

func TestWebUIUserManagement(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}
	
	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:testpass123"))

	webUI := NewWebUI(cfg)

	// Create users via WebUI
	err := webUI.GetUserStore().CreateUser("user1", "pass1")
	if err != nil {
		t.Fatalf("Failed to create user1: %v", err)
	}

	err = webUI.GetUserStore().CreateUser("user2", "pass2")
	if err != nil {
		t.Fatalf("Failed to create user2: %v", err)
	}

	// Test user creation POST request
	req := httptest.NewRequest("POST", "/users", strings.NewReader("username=user3&password=pass3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+auth)
	rr := httptest.NewRecorder()

	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect status 303, got %d", rr.Code)
	}

	// Verify user was created
	password, exists := webUI.GetUserStore().GetUser("user3")
	if !exists {
		t.Error("Expected user3 to be created")
	}
	if password != "pass3" {
		t.Errorf("Expected password 'pass3', got '%s'", password)
	}

	// Test user deletion
	req = httptest.NewRequest("DELETE", "/users/user2", nil)
	req.Header.Set("Authorization", "Basic "+auth)
	rr = httptest.NewRecorder()

	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for deletion, got %d", rr.Code)
	}

	// Verify user was deleted
	_, exists = webUI.GetUserStore().GetUser("user2")
	if exists {
		t.Error("Expected user2 to be deleted")
	}
}