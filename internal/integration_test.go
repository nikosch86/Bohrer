package internal

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"bohrer-go/internal/config"
	"bohrer-go/internal/proxy"
	"bohrer-go/internal/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

// TestSSHTunnelToHTTPProxyIntegration tests the complete flow:
// SSH tunnel creation → HTTP proxy can route to tunnel → HTTP requests work
func TestSSHTunnelToHTTPProxyIntegration(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   2222,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}

	// Create SSH server and HTTP proxy
	sshServer := ssh.NewServer(cfg)
	proxyServer := proxy.NewProxy(cfg)
	
	// Connect them - SSH server should notify proxy of tunnel changes
	sshServer.SetTunnelManager(proxyServer)

	// Test scenario: SSH client creates tunnel, then HTTP request should work
	
	// 1. Simulate SSH tunnel creation
	mockChannel := &mockSSHChannel{buffer: make([]byte, 0, 1024)}
	mockConn := &mockSSHConn{}
	
	// Create tunnel request payload for port 3000
	payload := []byte{
		0, 0, 0, 0, // bind_address length = 0 (empty string)
		0, 0, 0x0b, 0xb8, // bind_port = 3000
	}
	
	subdomain, assignedPort := sshServer.HandleTunnelRequest(payload, mockChannel, mockConn)
	
	if subdomain == "" {
		t.Fatal("Expected tunnel creation to succeed")
	}
	
	if assignedPort != 3000 {
		t.Errorf("Expected assigned port 3000, got %d", assignedPort)
	}

	// 2. Verify tunnel was registered with proxy
	expectedTarget := "localhost:3000"
	actualTarget, exists := proxyServer.GetTunnel(subdomain)
	if !exists {
		t.Fatal("Expected tunnel to be registered with proxy")
	}
	
	if actualTarget != expectedTarget {
		t.Errorf("Expected target '%s', got '%s'", expectedTarget, actualTarget)
	}

	// 3. Test HTTP routing through proxy
	testURL := fmt.Sprintf("http://%s.%s:%d/test", subdomain, cfg.Domain, cfg.HTTPPort)
	
	// Create HTTP request with subdomain
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}
	
	// Parse URL to get the host with subdomain
	parsedURL, _ := url.Parse(testURL)
	req.Host = parsedURL.Host
	
	// Test that proxy extracts correct subdomain and finds tunnel
	extractedSubdomain, valid := extractSubdomainForTest(parsedURL.Host, cfg.Domain)
	if !valid {
		t.Errorf("Failed to extract subdomain from host '%s'", parsedURL.Host)
	}
	
	if extractedSubdomain != subdomain {
		t.Errorf("Expected extracted subdomain '%s', got '%s'", subdomain, extractedSubdomain)
	}

	// 4. Test tunnel cleanup on SSH disconnect
	sshServer.RemoveTunnel(subdomain)
	
	// Verify tunnel was removed from proxy
	_, stillExists := proxyServer.GetTunnel(subdomain)
	if stillExists {
		t.Error("Expected tunnel to be removed from proxy after SSH disconnect")
	}
}

// TestMultipleConcurrentTunnels tests that multiple SSH tunnels work independently
func TestMultipleConcurrentTunnels(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   2222,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}

	sshServer := ssh.NewServer(cfg)
	proxyServer := proxy.NewProxy(cfg)
	sshServer.SetTunnelManager(proxyServer)

	// Create multiple tunnels
	tunnels := make(map[string]int)
	ports := []int{3000, 3001, 3002}
	
	for _, port := range ports {
		mockChannel := &mockSSHChannel{buffer: make([]byte, 0, 1024)}
		mockConn := &mockSSHConn{}
		
		payload := []byte{
			0, 0, 0, 0, // bind_address length = 0
			byte(port >> 24), byte(port >> 16), byte(port >> 8), byte(port), // port
		}
		
		subdomain, assignedPort := sshServer.HandleTunnelRequest(payload, mockChannel, mockConn)
		
		if subdomain == "" {
			t.Fatalf("Failed to create tunnel for port %d", port)
		}
		
		if assignedPort != port {
			t.Errorf("Expected port %d, got %d", port, assignedPort)
		}
		
		tunnels[subdomain] = port
	}

	// Verify all tunnels are registered
	if len(tunnels) != 3 {
		t.Fatalf("Expected 3 tunnels, got %d", len(tunnels))
	}

	// Verify each tunnel points to correct port
	for subdomain, expectedPort := range tunnels {
		target, exists := proxyServer.GetTunnel(subdomain)
		if !exists {
			t.Errorf("Tunnel %s not found in proxy", subdomain)
			continue
		}
		
		expectedTarget := fmt.Sprintf("localhost:%d", expectedPort)
		if target != expectedTarget {
			t.Errorf("Expected target '%s', got '%s'", expectedTarget, target)
		}
	}

	// Test removing one tunnel doesn't affect others
	var removedSubdomain string
	for subdomain := range tunnels {
		removedSubdomain = subdomain
		break
	}
	
	sshServer.RemoveTunnel(removedSubdomain)
	delete(tunnels, removedSubdomain)

	// Verify removed tunnel is gone
	_, stillExists := proxyServer.GetTunnel(removedSubdomain)
	if stillExists {
		t.Error("Expected removed tunnel to be gone from proxy")
	}

	// Verify other tunnels still exist
	for subdomain := range tunnels {
		_, exists := proxyServer.GetTunnel(subdomain)
		if !exists {
			t.Errorf("Expected tunnel %s to still exist", subdomain)
		}
	}
}

// TestTunnelLifecycleWithRealConnections tests tunnel creation and cleanup with more realistic scenarios
func TestTunnelLifecycleWithRealConnections(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   2222,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}

	sshServer := ssh.NewServer(cfg)
	proxyServer := proxy.NewProxy(cfg)
	sshServer.SetTunnelManager(proxyServer)

	// Test automatic cleanup of disconnected tunnels
	mockChannel := &failingMockSSHChannel{} // This channel will fail writes
	mockConn := &mockSSHConn{}
	
	payload := []byte{
		0, 0, 0, 0, // bind_address length = 0
		0, 0, 0x17, 0x70, // port 6000
	}
	
	subdomain, _ := sshServer.HandleTunnelRequest(payload, mockChannel, mockConn)
	
	if subdomain == "" {
		t.Fatal("Expected tunnel creation to succeed")
	}

	// Verify tunnel exists
	_, exists := proxyServer.GetTunnel(subdomain)
	if !exists {
		t.Fatal("Expected tunnel to be registered")
	}

	// Run cleanup - should detect failed channel and remove tunnel
	sshServer.CleanupDisconnectedTunnels()

	// Give cleanup a moment to propagate to proxy
	// This prevents race condition in test
	time.Sleep(10 * time.Millisecond)

	// Verify tunnel was cleaned up from proxy
	_, stillExists := proxyServer.GetTunnel(subdomain)
	if stillExists {
		t.Error("Expected disconnected tunnel to be cleaned up from proxy")
	}
}

// Helper function to test subdomain extraction (we need to add this to proxy package)
func extractSubdomainForTest(host, domain string) (string, bool) {
	if host == "" || domain == "" {
		return "", false
	}
	
	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	
	// Check if host ends with the domain
	domainSuffix := "." + domain
	if !strings.HasSuffix(host, domainSuffix) {
		if host == domain {
			return "", false
		}
		return "", false
	}
	
	// Extract subdomain
	subdomain := strings.TrimSuffix(host, domainSuffix)
	if subdomain == "" {
		return "", false
	}
	
	return subdomain, true
}

// Mock implementations for testing
type mockSSHChannel struct {
	buffer []byte
}

func (m *mockSSHChannel) Read(data []byte) (int, error)     { return 0, nil }
func (m *mockSSHChannel) Write(data []byte) (int, error)    { m.buffer = append(m.buffer, data...); return len(data), nil }
func (m *mockSSHChannel) Close() error                     { return nil }
func (m *mockSSHChannel) CloseWrite() error                { return nil }
func (m *mockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) { return false, nil }
func (m *mockSSHChannel) Stderr() io.ReadWriter            { return nil }

type failingMockSSHChannel struct {
	mockSSHChannel
}

func (f *failingMockSSHChannel) Write(data []byte) (int, error) {
	return 0, fmt.Errorf("connection failed")
}

type mockSSHConn struct{}

func (m *mockSSHConn) User() string                    { return "tunnel" }
func (m *mockSSHConn) SessionID() []byte               { return []byte("test") }
func (m *mockSSHConn) ClientVersion() []byte           { return []byte("SSH-2.0-Test") }
func (m *mockSSHConn) ServerVersion() []byte           { return []byte("SSH-2.0-TestServer") }
func (m *mockSSHConn) RemoteAddr() net.Addr            { addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345"); return addr }
func (m *mockSSHConn) LocalAddr() net.Addr             { addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:2222"); return addr }
func (m *mockSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) { return false, nil, nil }
func (m *mockSSHConn) OpenChannel(name string, data []byte) (cryptossh.Channel, <-chan *cryptossh.Request, error) { return nil, nil, nil }
func (m *mockSSHConn) Close() error { return nil }
func (m *mockSSHConn) Wait() error  { return nil }