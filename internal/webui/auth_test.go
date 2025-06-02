package webui

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bohrer-go/internal/config"
)

func TestWebUIAuthentication_ValidCredentials(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	webUI := NewWebUI(cfg)

	// Test with valid credentials
	req := httptest.NewRequest("GET", "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:testpass123"))
	req.Header.Set("Authorization", "Basic "+auth)

	rr := httptest.NewRecorder()
	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 with valid credentials, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Tunnel Dashboard") {
		t.Error("Expected dashboard content with valid credentials")
	}
}

func TestWebUIAuthentication_InvalidCredentials(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	webUI := NewWebUI(cfg)

	// Test with invalid password
	req := httptest.NewRequest("GET", "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("testadmin:wrongpassword"))
	req.Header.Set("Authorization", "Basic "+auth)

	rr := httptest.NewRecorder()
	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 with invalid credentials, got %d", rr.Code)
	}

	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("Expected WWW-Authenticate header in 401 response")
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Authentication Required") {
		t.Error("Expected authentication error page")
	}
}

func TestWebUIAuthentication_InvalidUsername(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	webUI := NewWebUI(cfg)

	// Test with invalid username
	req := httptest.NewRequest("GET", "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("wronguser:testpass123"))
	req.Header.Set("Authorization", "Basic "+auth)

	rr := httptest.NewRecorder()
	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 with invalid username, got %d", rr.Code)
	}
}

func TestWebUIAuthentication_NoCredentials(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "testadmin",
		WebUIPassword: "testpass123",
	}

	webUI := NewWebUI(cfg)

	// Test without any authentication
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 without credentials, got %d", rr.Code)
	}

	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("Expected WWW-Authenticate header")
	}

	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), `realm="SSH Tunnel Server WebUI"`) {
		t.Error("Expected correct realm in WWW-Authenticate header")
	}
}

func TestWebUIAuthentication_AllEndpoints(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "admin",
		WebUIPassword: "secret",
	}

	webUI := NewWebUI(cfg)
	auth := base64.StdEncoding.EncodeToString([]byte("admin:secret"))

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/"},
		{"GET", "/users"},
		{"GET", "/static/style.css"},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+"_"+endpoint.path, func(t *testing.T) {
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			req.Header.Set("Authorization", "Basic "+auth)

			rr := httptest.NewRecorder()
			webUI.ServeHTTP(rr, req)

			if rr.Code == http.StatusUnauthorized {
				t.Errorf("Valid credentials should allow access to %s %s", endpoint.method, endpoint.path)
			}
		})
	}
}

func TestWebUIAuthentication_GeneratedCredentials(t *testing.T) {
	cfg := &config.Config{
		Domain: "test.local",
		// Leave username and password empty to test generation
	}

	webUI := NewWebUI(cfg)

	// Generated credentials should be set
	if webUI.adminUsername == "" {
		t.Error("Expected generated username to be set")
	}

	if webUI.adminPassword == "" {
		t.Error("Expected generated password to be set")
	}

	// Test that generated credentials work
	req := httptest.NewRequest("GET", "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte(webUI.adminUsername + ":" + webUI.adminPassword))
	req.Header.Set("Authorization", "Basic "+auth)

	rr := httptest.NewRecorder()
	webUI.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Generated credentials should work, got status %d", rr.Code)
	}
}

func TestWebUIAuthentication_ConstantTimeComparison(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "admin",
		WebUIPassword: "secret123",
	}

	webUI := NewWebUI(cfg)

	// Test with credentials of different lengths (should still be constant time)
	testCases := []struct {
		username string
		password string
		expected int
	}{
		{"admin", "secret123", http.StatusOK},                      // Correct
		{"admin", "wrong", http.StatusUnauthorized},                // Wrong password, different length
		{"a", "secret123", http.StatusUnauthorized},                // Wrong username, different length
		{"administrator", "secret123456", http.StatusUnauthorized}, // Both wrong, longer
		{"", "", http.StatusUnauthorized},                          // Empty credentials
	}

	for _, tc := range testCases {
		t.Run("user_"+tc.username+"_pass_"+tc.password, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(tc.username + ":" + tc.password))
			req.Header.Set("Authorization", "Basic "+auth)

			rr := httptest.NewRecorder()
			webUI.ServeHTTP(rr, req)

			if rr.Code != tc.expected {
				t.Errorf("Expected status %d for %s:%s, got %d", tc.expected, tc.username, tc.password, rr.Code)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	// Test that random string generation works
	str1, err := generateRandomString(16)
	if err != nil {
		t.Fatalf("Failed to generate random string: %v", err)
	}

	if len(str1) != 16 {
		t.Errorf("Expected string length 16, got %d", len(str1))
	}

	// Generate another string and ensure they're different
	str2, err := generateRandomString(16)
	if err != nil {
		t.Fatalf("Failed to generate second random string: %v", err)
	}

	if str1 == str2 {
		t.Error("Generated strings should be different")
	}

	// Test different lengths
	lengths := []int{8, 12, 16, 24, 32}
	for _, length := range lengths {
		str, err := generateRandomString(length)
		if err != nil {
			t.Errorf("Failed to generate string of length %d: %v", length, err)
		}
		if len(str) != length {
			t.Errorf("Expected length %d, got %d", length, len(str))
		}
	}
}

func TestWebUIAuthentication_RegisterRoutes(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "admin",
		WebUIPassword: "password",
	}

	webUI := NewWebUI(cfg)
	mux := http.NewServeMux()
	webUI.RegisterRoutes(mux)

	// Test that routes require authentication
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for unauthenticated request to RegisterRoutes, got %d", rr.Code)
	}

	// Test with valid auth
	auth := base64.StdEncoding.EncodeToString([]byte("admin:password"))
	req.Header.Set("Authorization", "Basic "+auth)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 with valid auth via RegisterRoutes, got %d", rr.Code)
	}
}
