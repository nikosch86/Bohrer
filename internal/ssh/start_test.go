package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"bohrer-go/internal/config"
	"bohrer-go/internal/testutil/mocks"
	"golang.org/x/crypto/ssh"
)

// TestStartPasswordAuthentication tests password authentication through Start function
func TestStartPasswordAuthentication(t *testing.T) {

	tests := []struct {
		name          string
		setupUserStore bool
		username      string
		password      string
		expectSuccess bool
	}{
		{
			name:          "successful auth with user store",
			setupUserStore: true,
			username:      "testuser",
			password:      "testpass",
			expectSuccess: true,
		},
		{
			name:          "failed auth with user store - wrong password",
			setupUserStore: true,
			username:      "testuser",
			password:      "wrongpass",
			expectSuccess: false,
		},
		{
			name:          "successful auth with fallback credentials",
			setupUserStore: false,
			username:      "tunnel",
			password:      "test123",
			expectSuccess: true,
		},
		{
			name:          "failed auth with fallback - wrong username",
			setupUserStore: false,
			username:      "wronguser",
			password:      "test123",
			expectSuccess: false,
		},
		{
			name:          "failed auth with fallback - wrong password",
			setupUserStore: false,
			username:      "tunnel",
			password:      "wrongpass",
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find available port for each test
			listener, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatalf("Failed to find available port: %v", err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			
			cfg := &config.Config{
				Domain:    "test.local",
				SSHPort:   port,
				HTTPPort:  8080,
				HTTPSPort: 8443,
			}

			server := NewServer(cfg)

			// Setup user store if needed
			if tt.setupUserStore {
				mockStore := mocks.NewUserStore()
				mockStore.AddUser("testuser", "testpass")
				server.SetUserStore(mockStore)
			}

			// Start server in goroutine
			serverErr := make(chan error, 1)
			go func() {
				serverErr <- server.Start()
			}()

			// Give server time to start
			time.Sleep(50 * time.Millisecond)

			// Test SSH connection with password
			sshConfig := &ssh.ClientConfig{
				User: tt.username,
				Auth: []ssh.AuthMethod{
					ssh.Password(tt.password),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", port), sshConfig)

			if tt.expectSuccess {
				if err != nil {
					t.Errorf("Expected successful connection, but got error: %v", err)
				} else {
					client.Close()
				}
			} else {
				if err == nil {
					t.Error("Expected connection to fail, but it succeeded")
					client.Close()
				} else if !strings.Contains(err.Error(), "unable to authenticate") {
					t.Errorf("Expected authentication error, but got: %v", err)
				}
			}

			// Cleanup: try to stop server by closing connection
			// Note: In real implementation, we'd need a way to stop the server gracefully
		})
		
		// Add delay between tests to avoid port conflicts
		time.Sleep(100 * time.Millisecond)
	}
}

// TestStartPublicKeyAuthentication tests public key authentication through Start function
func TestStartPublicKeyAuthentication(t *testing.T) {
	// Generate test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	publicKey := signer.PublicKey()
	authorizedKey := string(ssh.MarshalAuthorizedKey(publicKey))

	tests := []struct {
		name            string
		setupKeyStore   bool
		keyStoreContent string
		username        string
		expectSuccess   bool
	}{
		{
			name:            "successful public key auth",
			setupKeyStore:   true,
			keyStoreContent: authorizedKey,
			username:        "tunnel",
			expectSuccess:   true,
		},
		{
			name:            "failed public key auth - wrong username",
			setupKeyStore:   true,
			keyStoreContent: authorizedKey,
			username:        "wronguser",
			expectSuccess:   false,
		},
		{
			name:            "failed public key auth - no key store",
			setupKeyStore:   false,
			username:        "tunnel",
			expectSuccess:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find available port for each test
			listener, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatalf("Failed to find available port: %v", err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			
			cfg := &config.Config{
				Domain:         "test.local",
				SSHPort:        port,
				HTTPPort:       8080,
				HTTPSPort:      8443,
				AuthorizedKeys: "/non/existent/file", // Ensure file-based auth fails
			}

			server := NewServer(cfg)

			// Setup key store if needed
			if tt.setupKeyStore {
				mockStore := mocks.NewSSHKeyStore(tt.keyStoreContent)
				server.SetSSHKeyStore(mockStore)
			} else {
				// Explicitly ensure no key store is set
				server.sshKeyStore = nil
			}

			// Start server in goroutine
			serverErr := make(chan error, 1)
			go func() {
				serverErr <- server.Start()
			}()

			// Give server time to start
			time.Sleep(50 * time.Millisecond)

			// Test SSH connection with public key
			sshConfig := &ssh.ClientConfig{
				User: tt.username,
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signer),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", port), sshConfig)

			if tt.expectSuccess {
				if err != nil {
					t.Errorf("Expected successful connection, but got error: %v", err)
				} else {
					client.Close()
				}
			} else {
				if err == nil {
					t.Error("Expected connection to fail, but it succeeded")
					client.Close()
				}
			}
		})
		
		// Add delay between tests to avoid port conflicts
		time.Sleep(100 * time.Millisecond)
	}
}

// TestStartConnectionHandling tests basic connection handling
func TestStartConnectionHandling(t *testing.T) {
	// Find available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   port,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}

	server := NewServer(cfg)
	
	// Setup user store for easy auth
	mockStore := mocks.NewUserStore()
	mockStore.AddUser("testuser", "testpass")
	server.SetUserStore(mockStore)

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Test multiple concurrent connections
	t.Run("handle multiple connections", func(t *testing.T) {
		numConnections := 3
		done := make(chan bool, numConnections)

		for i := 0; i < numConnections; i++ {
			go func(id int) {
				sshConfig := &ssh.ClientConfig{
					User: "testuser",
					Auth: []ssh.AuthMethod{
						ssh.Password("testpass"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         2 * time.Second,
				}

				client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", port), sshConfig)
				if err != nil {
					t.Errorf("Connection %d failed: %v", id, err)
					done <- false
					return
				}
				
				// Keep connection alive briefly
				time.Sleep(10 * time.Millisecond)
				client.Close()
				done <- true
			}(i)
		}

		// Wait for all connections
		successCount := 0
		for i := 0; i < numConnections; i++ {
			if <-done {
				successCount++
			}
		}

		if successCount != numConnections {
			t.Errorf("Expected %d successful connections, got %d", numConnections, successCount)
		}
	})

	// Test connection with session channel
	t.Run("handle session channel", func(t *testing.T) {
		sshConfig := &ssh.ClientConfig{
			User: "testuser",
			Auth: []ssh.AuthMethod{
				ssh.Password("testpass"),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}

		client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", port), sshConfig)
		if err != nil {
			t.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// Open a session
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
		defer session.Close()

		// Request a shell (server accepts shell requests)
		if err := session.Shell(); err != nil {
			t.Errorf("Failed to start shell: %v", err)
		}
	})
}