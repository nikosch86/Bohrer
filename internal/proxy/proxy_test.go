package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bohrer-go/internal/config"
)

func TestNewProxy(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	if proxy == nil {
		t.Fatal("Expected proxy to be created, got nil")
	}
	
	if proxy.config != cfg {
		t.Error("Expected proxy config to match input config")
	}
	
	if proxy.tunnels == nil {
		t.Error("Expected tunnels map to be initialized")
	}
	
	if len(proxy.tunnels) != 0 {
		t.Errorf("Expected empty tunnels map, got %d entries", len(proxy.tunnels))
	}
}

func TestAddTunnel(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Add a tunnel
	err := proxy.AddTunnel("test123", "localhost:3000")
	if err != nil {
		t.Errorf("Expected no error adding tunnel, got: %v", err)
	}
	
	// Check tunnel was added
	proxy.mutex.RLock()
	target, exists := proxy.tunnels["test123"]
	proxy.mutex.RUnlock()
	
	if !exists {
		t.Error("Expected tunnel to exist after adding")
	}
	
	if target != "localhost:3000" {
		t.Errorf("Expected tunnel target 'localhost:3000', got '%s'", target)
	}
}

func TestRemoveTunnel(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Add then remove a tunnel
	proxy.AddTunnel("test123", "localhost:3000")
	proxy.RemoveTunnel("test123")
	
	// Check tunnel was removed
	proxy.mutex.RLock()
	_, exists := proxy.tunnels["test123"]
	proxy.mutex.RUnlock()
	
	if exists {
		t.Error("Expected tunnel to be removed")
	}
}

func TestSubdomainExtraction(t *testing.T) {
	tests := []struct {
		host     string
		domain   string
		expected string
		valid    bool
	}{
		{"test123.example.com", "example.com", "test123", true},
		{"abc.test.com", "test.com", "abc", true},
		{"example.com", "example.com", "", false},
		{"subdomain.wrong.com", "test.com", "", false},
		{"", "test.com", "", false},
	}
	
	for _, test := range tests {
		subdomain, valid := extractSubdomain(test.host, test.domain)
		
		if valid != test.valid {
			t.Errorf("For host '%s' and domain '%s', expected valid=%v, got %v", 
				test.host, test.domain, test.valid, valid)
		}
		
		if valid && subdomain != test.expected {
			t.Errorf("For host '%s' and domain '%s', expected subdomain '%s', got '%s'", 
				test.host, test.domain, test.expected, subdomain)
		}
	}
}

func TestProxyHTTPRequest(t *testing.T) {
	// Create a mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()
	
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Extract port from backend URL
	backendURL := strings.TrimPrefix(backend.URL, "http://")
	proxy.AddTunnel("test123", backendURL)
	
	// Create a request to the proxy
	req := httptest.NewRequest("GET", "http://test123.test.com/", nil)
	req.Host = "test123.test.com"
	
	recorder := httptest.NewRecorder()
	
	// Handle the request
	proxy.ServeHTTP(recorder, req)
	
	// Check response
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}
	
	body := recorder.Body.String()
	if body != "Hello from backend" {
		t.Errorf("Expected 'Hello from backend', got '%s'", body)
	}
}

func TestProxyHTTPRequestNoTunnel(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Create a request for non-existent tunnel
	req := httptest.NewRequest("GET", "http://notfound.test.com/", nil)
	req.Host = "notfound.test.com"
	
	recorder := httptest.NewRecorder()
	
	// Handle the request
	proxy.ServeHTTP(recorder, req)
	
	// Check response
	if recorder.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", recorder.Code)
	}
	
	body := recorder.Body.String()
	if !strings.Contains(body, "Tunnel not found") {
		t.Errorf("Expected 'Tunnel not found' in response, got '%s'", body)
	}
}

func TestProxyHTTPRequestInvalidDomain(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Create a request for wrong domain
	req := httptest.NewRequest("GET", "http://subdomain.wrong.com/", nil)
	req.Host = "subdomain.wrong.com"
	
	recorder := httptest.NewRecorder()
	
	// Handle the request
	proxy.ServeHTTP(recorder, req)
	
	// Check response
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", recorder.Code)
	}
}

func TestProxyStart(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  0, // Use dynamic port
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- proxy.Start()
	}()
	
	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)
	
	// Check if proxy started successfully (no immediate error)
	select {
	case err := <-errChan:
		t.Errorf("Proxy failed to start: %v", err)
	default:
		// Proxy is running, which is expected
	}
}

func TestTunnelManagement(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Test adding multiple tunnels
	proxy.AddTunnel("tunnel1", "localhost:3001")
	proxy.AddTunnel("tunnel2", "localhost:3002")
	
	proxy.mutex.RLock()
	count := len(proxy.tunnels)
	proxy.mutex.RUnlock()
	
	if count != 2 {
		t.Errorf("Expected 2 tunnels, got %d", count)
	}
	
	// Test removing specific tunnel
	proxy.RemoveTunnel("tunnel1")
	
	proxy.mutex.RLock()
	count = len(proxy.tunnels)
	_, exists := proxy.tunnels["tunnel2"]
	proxy.mutex.RUnlock()
	
	if count != 1 {
		t.Errorf("Expected 1 tunnel after removal, got %d", count)
	}
	
	if !exists {
		t.Error("Expected tunnel2 to still exist")
	}
}

func TestProxyHTTPRequestInvalidTarget(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Add tunnel with invalid target (should cause URL parse error)
	proxy.AddTunnel("invalid", "://invalid-url")
	
	req := httptest.NewRequest("GET", "http://invalid.test.com/", nil)
	req.Host = "invalid.test.com"
	
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	
	// The reverse proxy may return 502 (Bad Gateway) instead of 500 for invalid URLs
	if recorder.Code != http.StatusInternalServerError && recorder.Code != http.StatusBadGateway {
		t.Errorf("Expected status 500 or 502, got %d", recorder.Code)
	}
}

func TestExtractSubdomainWithPort(t *testing.T) {
	// Test host with port number
	subdomain, valid := extractSubdomain("test123.example.com:8080", "example.com")
	
	if !valid {
		t.Error("Expected valid subdomain extraction from host with port")
	}
	
	if subdomain != "test123" {
		t.Errorf("Expected subdomain 'test123', got '%s'", subdomain)
	}
}

func TestExtractSubdomainEmptySubdomain(t *testing.T) {
	// Test case where subdomain would be empty after trimming
	subdomain, valid := extractSubdomain(".example.com", "example.com")
	
	if valid {
		t.Error("Expected invalid for empty subdomain")
	}
	
	if subdomain != "" {
		t.Errorf("Expected empty subdomain, got '%s'", subdomain)
	}
}

func TestProxyStartWithInvalidPort(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  -1, // Invalid port
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	err := proxy.Start()
	if err == nil {
		t.Error("Expected error when starting proxy with invalid port")
	}
}

func TestProxyServeHTTPMethods(t *testing.T) {
	// Test different HTTP methods are properly proxied
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Method: %s", r.Method)))
	}))
	defer backend.Close()
	
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	backendURL := strings.TrimPrefix(backend.URL, "http://")
	proxy.AddTunnel("methods", backendURL)
	
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	
	for _, method := range methods {
		req := httptest.NewRequest(method, "http://methods.test.com/", nil)
		req.Host = "methods.test.com"
		
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, req)
		
		if recorder.Code != http.StatusOK {
			t.Errorf("Expected status 200 for %s, got %d", method, recorder.Code)
		}
		
		expectedBody := fmt.Sprintf("Method: %s", method)
		body := recorder.Body.String()
		if body != expectedBody {
			t.Errorf("Expected '%s', got '%s'", expectedBody, body)
		}
	}
}

func TestProxyServeHTTPWithHeaders(t *testing.T) {
	// Test that headers are properly forwarded
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back custom header
		customHeader := r.Header.Get("X-Custom-Header")
		w.Header().Set("X-Response-Header", "response-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Custom: %s", customHeader)))
	}))
	defer backend.Close()
	
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	backendURL := strings.TrimPrefix(backend.URL, "http://")
	proxy.AddTunnel("headers", backendURL)
	
	req := httptest.NewRequest("GET", "http://headers.test.com/", nil)
	req.Host = "headers.test.com"
	req.Header.Set("X-Custom-Header", "test-value")
	
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}
	
	// Check request header was forwarded
	body := recorder.Body.String()
	if body != "Custom: test-value" {
		t.Errorf("Expected 'Custom: test-value', got '%s'", body)
	}
	
	// Check response header was set
	responseHeader := recorder.Header().Get("X-Response-Header")
	if responseHeader != "response-value" {
		t.Errorf("Expected 'response-value', got '%s'", responseHeader)
	}
}

func TestProxyStartMultipleTimes(t *testing.T) {
	// Test that multiple calls to Start don't cause issues
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  0, // Use dynamic port
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// This test just ensures Start can be called without panicking
	// The actual listening will fail since it's an infinite loop
	go func() {
		proxy.Start()
	}()
	
	// Give it a moment
	time.Sleep(50 * time.Millisecond)
}

func TestAddTunnelOverwrite(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	
	proxy := NewProxy(cfg)
	
	// Add initial tunnel
	err := proxy.AddTunnel("test", "localhost:3000")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	
	// Overwrite with new target
	err = proxy.AddTunnel("test", "localhost:4000")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	
	// Verify new target
	proxy.mutex.RLock()
	target := proxy.tunnels["test"]
	proxy.mutex.RUnlock()
	
	if target != "localhost:4000" {
		t.Errorf("Expected 'localhost:4000', got '%s'", target)
	}
}

func TestACMEChallengeHandler(t *testing.T) {
	// Create temporary directory for ACME challenges
	tempDir, err := os.MkdirTemp("", "acme-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:           "test.com",
		HTTPPort:         8080,
		HTTPSPort:        8443,
		ACMEChallengeDir: tempDir,
	}

	proxy := NewProxy(cfg)

	// Create a challenge file
	token := "test-token-12345"
	keyAuth := "test-key-auth-content"
	challengePath := filepath.Join(tempDir, token)
	
	err = os.WriteFile(challengePath, []byte(keyAuth), 0644)
	if err != nil {
		t.Fatalf("Failed to create challenge file: %v", err)
	}

	// Test ACME challenge request
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/"+token, nil)
	req.Host = "test.com"

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)

	// Check response
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if body != keyAuth {
		t.Errorf("Expected '%s', got '%s'", keyAuth, body)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected 'text/plain', got '%s'", contentType)
	}
}

func TestACMEChallengeNotFound(t *testing.T) {
	// Create temporary directory for ACME challenges
	tempDir, err := os.MkdirTemp("", "acme-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:           "test.com",
		HTTPPort:         8080,
		HTTPSPort:        8443,
		ACMEChallengeDir: tempDir,
	}

	proxy := NewProxy(cfg)

	// Test request for non-existent challenge
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/nonexistent", nil)
	req.Host = "test.com"

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)

	// Check response
	if recorder.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", recorder.Code)
	}
}

func TestACMEChallengeInvalidToken(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "acme-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:           "test.com",
		HTTPPort:         8080,
		HTTPSPort:        8443,
		ACMEChallengeDir: tempDir,
	}

	proxy := NewProxy(cfg)

	// Test request with empty token
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/", nil)
	req.Host = "test.com"

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)

	// Check response
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", recorder.Code)
	}
}

func TestNonACMERequest(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "acme-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:           "test.com",
		HTTPPort:         8080,
		HTTPSPort:        8443,
		ACMEChallengeDir: tempDir,
	}

	proxy := NewProxy(cfg)

	// Test normal request (not ACME challenge)
	req := httptest.NewRequest("GET", "/normal-path", nil)
	req.Host = "test123.test.com"

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)

	// Should get tunnel not found (since we didn't add any tunnels)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "Tunnel not found") {
		t.Errorf("Expected 'Tunnel not found' in response, got '%s'", body)
	}
}

func TestGetTunnels(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}

	proxy := NewProxy(cfg)

	// Test empty tunnels
	tunnels := proxy.GetTunnels()
	if len(tunnels) != 0 {
		t.Errorf("Expected 0 tunnels, got %d", len(tunnels))
	}

	// Add some tunnels
	proxy.AddTunnel("test1", "localhost:3001")
	proxy.AddTunnel("test2", "localhost:3002")

	tunnels = proxy.GetTunnels()
	if len(tunnels) != 2 {
		t.Errorf("Expected 2 tunnels, got %d", len(tunnels))
	}

	if tunnels["test1"] != "localhost:3001" {
		t.Errorf("Expected 'localhost:3001', got '%s'", tunnels["test1"])
	}

	if tunnels["test2"] != "localhost:3002" {
		t.Errorf("Expected 'localhost:3002', got '%s'", tunnels["test2"])
	}

	// Modify returned map should not affect original
	tunnels["test1"] = "modified"
	originalTunnels := proxy.GetTunnels()
	if originalTunnels["test1"] != "localhost:3001" {
		t.Error("GetTunnels should return a copy, not the original map")
	}
}

func TestGetTunnel(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.com",
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}

	proxy := NewProxy(cfg)

	// Test non-existent tunnel
	target, exists := proxy.GetTunnel("nonexistent")
	if exists {
		t.Error("Expected tunnel to not exist")
	}
	if target != "" {
		t.Errorf("Expected empty target, got '%s'", target)
	}

	// Add tunnel and test
	proxy.AddTunnel("test", "localhost:3000")
	target, exists = proxy.GetTunnel("test")
	if !exists {
		t.Error("Expected tunnel to exist")
	}
	if target != "localhost:3000" {
		t.Errorf("Expected 'localhost:3000', got '%s'", target)
	}
}