package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bohrer-go/internal/config"
	"bohrer-go/internal/webui"
)

func TestProxyWithWebUI(t *testing.T) {
	cfg := &config.Config{
		Domain:        "example.com",
		HTTPPort:      8080,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:testpass123"))

	proxy := NewProxy(cfg)

	// Create and set WebUI
	ui := webui.NewWebUI(cfg)
	proxy.SetWebUI(ui)

	// Test request to root domain via HTTPS handler (should serve WebUI)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("Authorization", "Basic "+auth)
	rr := httptest.NewRecorder()

	proxy.ServeHTTPS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for root domain via HTTPS, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Tunnel Dashboard") {
		t.Error("Expected WebUI dashboard content for root domain via HTTPS")
	}
}

func TestProxyWithSubdomainStillWorks(t *testing.T) {
	cfg := &config.Config{
		Domain:        "example.com",
		HTTPPort:      8080,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	proxy := NewProxy(cfg)

	// Add a tunnel
	proxy.AddTunnel("api", "localhost:3000")

	// Create and set WebUI
	ui := webui.NewWebUI(cfg)
	proxy.SetWebUI(ui)

	// Test request to subdomain (should still proxy)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "api.example.com"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	// Should get connection refused or similar since localhost:3000 isn't running
	// The important thing is it doesn't serve WebUI content
	body := rr.Body.String()
	if strings.Contains(body, "Tunnel Dashboard") {
		t.Error("Subdomain should not serve WebUI content")
	}
}

func TestProxyWebUIUsersPage(t *testing.T) {
	cfg := &config.Config{
		Domain:        "example.com",
		HTTPPort:      8080,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:testpass123"))

	proxy := NewProxy(cfg)

	// Create and set WebUI
	ui := webui.NewWebUI(cfg)
	proxy.SetWebUI(ui)

	// Test request to users page via HTTPS handler
	req := httptest.NewRequest("GET", "/users", nil)
	req.Host = "example.com"
	req.Header.Set("Authorization", "Basic "+auth)
	rr := httptest.NewRecorder()

	proxy.ServeHTTPS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for users page via HTTPS, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "User Management") {
		t.Error("Expected WebUI users page content")
	}
}

func TestProxyHTTPRootDomainNoWebUI(t *testing.T) {
	cfg := &config.Config{
		Domain:        "example.com",
		HTTPPort:      8080,
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	proxy := NewProxy(cfg)

	// Create and set WebUI
	ui := webui.NewWebUI(cfg)
	proxy.SetWebUI(ui)

	// Test request to root domain via HTTP (should NOT serve WebUI)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for HTTP root domain, got %d", rr.Code)
	}

	body := rr.Body.String()
	if strings.Contains(body, "Tunnel Dashboard") {
		t.Error("HTTP root domain should NOT serve WebUI dashboard")
	}
}
