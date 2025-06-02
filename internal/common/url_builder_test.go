package common

import (
	"strings"
	"testing"
)

func TestNewURLBuilder(t *testing.T) {
	builder := NewURLBuilder("example.com")
	if builder.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", builder.Domain)
	}
}

func TestBuildHTTPURL(t *testing.T) {
	builder := NewURLBuilder("test.com")

	tests := []struct {
		name      string
		subdomain string
		port      int
		expected  string
	}{
		{
			name:      "default HTTP port",
			subdomain: "api",
			port:      80,
			expected:  "http://api.test.com",
		},
		{
			name:      "zero port treated as default",
			subdomain: "api",
			port:      0,
			expected:  "http://api.test.com",
		},
		{
			name:      "custom HTTP port",
			subdomain: "api",
			port:      8080,
			expected:  "http://api.test.com:8080",
		},
		{
			name:      "different custom port",
			subdomain: "web",
			port:      3000,
			expected:  "http://web.test.com:3000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.BuildHTTPURL(tt.subdomain, tt.port)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestBuildHTTPSURL(t *testing.T) {
	builder := NewURLBuilder("test.com")

	tests := []struct {
		name      string
		subdomain string
		port      int
		expected  string
	}{
		{
			name:      "default HTTPS port",
			subdomain: "api",
			port:      443,
			expected:  "https://api.test.com",
		},
		{
			name:      "zero port treated as default",
			subdomain: "api",
			port:      0,
			expected:  "https://api.test.com",
		},
		{
			name:      "custom HTTPS port",
			subdomain: "api",
			port:      8443,
			expected:  "https://api.test.com:8443",
		},
		{
			name:      "different custom port",
			subdomain: "secure",
			port:      9443,
			expected:  "https://secure.test.com:9443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.BuildHTTPSURL(tt.subdomain, tt.port)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestBuildURLs(t *testing.T) {
	builder := NewURLBuilder("tunnel.dev")

	tests := []struct {
		name         string
		subdomain    string
		httpPort     int
		httpsPort    int
		expectedHTTP string
		expectedHTTPS string
	}{
		{
			name:          "default ports",
			subdomain:     "myapp",
			httpPort:      80,
			httpsPort:     443,
			expectedHTTP:  "http://myapp.tunnel.dev",
			expectedHTTPS: "https://myapp.tunnel.dev",
		},
		{
			name:          "custom ports",
			subdomain:     "myapp",
			httpPort:      8080,
			httpsPort:     8443,
			expectedHTTP:  "http://myapp.tunnel.dev:8080",
			expectedHTTPS: "https://myapp.tunnel.dev:8443",
		},
		{
			name:          "mixed ports",
			subdomain:     "test",
			httpPort:      80,
			httpsPort:     8443,
			expectedHTTP:  "http://test.tunnel.dev",
			expectedHTTPS: "https://test.tunnel.dev:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpURL, httpsURL := builder.BuildURLs(tt.subdomain, tt.httpPort, tt.httpsPort)
			if httpURL != tt.expectedHTTP {
				t.Errorf("Expected HTTP URL '%s', got '%s'", tt.expectedHTTP, httpURL)
			}
			if httpsURL != tt.expectedHTTPS {
				t.Errorf("Expected HTTPS URL '%s', got '%s'", tt.expectedHTTPS, httpsURL)
			}
		})
	}
}

func TestFormatTunnelSuccessMessage(t *testing.T) {
	httpURL := "http://test.example.com"
	httpsURL := "https://test.example.com"
	
	message := FormatTunnelSuccessMessage(httpURL, httpsURL)
	
	// Check key components are present
	if !strings.Contains(message, "🎉 Tunnel Created Successfully!") {
		t.Error("Expected success header in message")
	}
	
	if !strings.Contains(message, httpURL) {
		t.Error("Expected HTTP URL in message")
	}
	
	if !strings.Contains(message, httpsURL) {
		t.Error("Expected HTTPS URL in message")
	}
	
	if !strings.Contains(message, "💡 Your local service is now publicly accessible!") {
		t.Error("Expected accessibility notice in message")
	}
	
	// Check formatting
	if !strings.HasPrefix(message, "\r\n") || !strings.HasSuffix(message, "\r\n\r\n") {
		t.Error("Expected proper line endings in message")
	}
}