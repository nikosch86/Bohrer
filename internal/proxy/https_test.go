package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"bohrer-go/internal/config"
)

func TestServeHTTPS(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		setupTunnel    bool
		setupWebUI     bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "root domain with webui",
			host:           "test.com",
			setupWebUI:     true,
			expectedStatus: http.StatusOK,
			expectedBody:   "Mock WebUI",
		},
		{
			name:           "root domain without webui",
			host:           "test.com",
			setupWebUI:     false,
			expectedStatus: http.StatusOK,
			expectedBody:   "SSH Tunnel Server",
		},
		{
			name:           "subdomain with tunnel",
			host:           "test.test.com",
			setupTunnel:    true,
			expectedStatus: http.StatusOK,
			expectedBody:   "target response",
		},
		{
			name:           "subdomain without tunnel",
			host:           "notfound.test.com",
			setupTunnel:    false,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "Tunnel not found",
		},
		{
			name:           "invalid domain",
			host:           "invalid.domain.com",
			setupTunnel:    false,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid domain",
		},
		{
			name:           "root domain with port",
			host:           "test.com:443",
			setupWebUI:     false,
			expectedStatus: http.StatusOK,
			expectedBody:   "SSH Tunnel Server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create proxy
			cfg := &config.Config{
				Domain:    "test.com",
				HTTPPort:  8080,
				HTTPSPort: 8443,
			}
			proxy := NewProxy(cfg)

			// Setup webui if needed
			if tt.setupWebUI {
				mockWebUI := &mockWebUI{}
				proxy.SetWebUI(mockWebUI)
			}

			// Setup tunnel if needed
			if tt.setupTunnel {
				// Start a test server to act as the tunnel target
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("target response"))
				}))
				defer target.Close()

				proxy.AddTunnel("test", target.Listener.Addr().String())
			}

			// Create request
			req := httptest.NewRequest("GET", "https://"+tt.host+"/", nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()

			// Call ServeHTTPS
			proxy.ServeHTTPS(rec, req)

			// Check status
			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			// Check body contains expected text
			body := rec.Body.String()
			if !contains(body, tt.expectedBody) {
				t.Errorf("Expected body to contain %q, got %q", tt.expectedBody, body)
			}
		})
	}
}

func TestIsRootDomainRequest(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}
	proxy := NewProxy(cfg)

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "exact domain match",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "domain with port",
			host:     "example.com:443",
			expected: true,
		},
		{
			name:     "subdomain",
			host:     "sub.example.com",
			expected: false,
		},
		{
			name:     "subdomain with port",
			host:     "sub.example.com:443",
			expected: false,
		},
		{
			name:     "different domain",
			host:     "other.com",
			expected: false,
		},
		{
			name:     "empty host",
			host:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := proxy.isRootDomainRequest(tt.host)
			if result != tt.expected {
				t.Errorf("isRootDomainRequest(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestStartHTTPSErrors(t *testing.T) {
	t.Run("missing certificate files", func(t *testing.T) {
		cfg := &config.Config{
			Domain:       "test.com",
			HTTPSPort:    8443,
			ACMECertPath: "/nonexistent/cert.pem",
			ACMEKeyPath:  "/nonexistent/key.pem",
		}
		proxy := NewProxy(cfg)

		err := proxy.StartHTTPS()
		if err == nil {
			t.Error("Expected error when certificate files don't exist")
		}
		if !contains(err.Error(), "certificate file not found") {
			t.Errorf("Expected certificate not found error, got: %v", err)
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		// Create a temp cert file
		certFile := t.TempDir() + "/cert.pem"
		if err := writeFile(certFile, []byte("dummy cert")); err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}

		cfg := &config.Config{
			Domain:       "test.com",
			HTTPSPort:    8443,
			ACMECertPath: certFile,
			ACMEKeyPath:  "/nonexistent/key.pem",
		}
		proxy := NewProxy(cfg)

		err := proxy.StartHTTPS()
		if err == nil {
			t.Error("Expected error when key file doesn't exist")
		}
		if !contains(err.Error(), "key file not found") {
			t.Errorf("Expected key not found error, got: %v", err)
		}
	})
}

// mockWebUI implements a basic http.Handler for testing
type mockWebUI struct{}

func (m *mockWebUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Mock WebUI"))
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}