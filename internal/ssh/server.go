package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"bohrer-go/internal/common"
	"bohrer-go/internal/config"
	"bohrer-go/internal/fileutil"
	"bohrer-go/internal/logger"
	"golang.org/x/crypto/ssh"
)

// TunnelManager interface for managing tunnel registrations
type TunnelManager interface {
	AddTunnel(subdomain, target string) error
	RemoveTunnel(subdomain string)
}

// CertificateManager interface for managing subdomain certificates
type CertificateManager interface {
	EnsureSubdomainCertificate(ctx context.Context, subdomain string) error
	CleanupSubdomainCertificate(subdomain string) error
}

// UserStore interface for SSH user authentication
type UserStore interface {
	GetUser(username string) (password string, exists bool)
	VerifyPassword(username, password string) bool
}

// SSHKeyStore interface for managing SSH public keys (simple interface for SSH authentication)
type SSHKeyStore interface {
	GetAuthorizedKeysContent() string
}

type Server struct {
	config             *config.Config
	hostKey            ssh.Signer
	tunnels            map[string]*Tunnel
	sessions           map[ssh.Conn][]ssh.Channel // Track active sessions per connection
	pendingURLs        map[ssh.Conn][]string      // Track pending tunnel URLs per connection
	mutex              sync.RWMutex
	tunnelManager      TunnelManager
	certificateManager CertificateManager
	userStore          UserStore
	sshKeyStore        SSHKeyStore
}

type Tunnel struct {
	Subdomain   string
	LocalPort   int
	Channel     ssh.Channel
	Connections map[string]net.Conn // Track active forwarded connections
	ConnMutex   sync.RWMutex        // Protect connections map
	HTTPURL     string              // Full HTTP URL for this tunnel
	HTTPSURL    string              // Full HTTPS URL for this tunnel
	Listener    net.Listener        // Track the listener for cleanup
}

func NewServer(cfg *config.Config) *Server {
	// Use persistent host key path from config
	hostKeyPath := cfg.SSHHostKeyPath
	// For testing, use in-memory key if path is empty
	var hostKey ssh.Signer
	var err error
	
	if hostKeyPath == "" {
		logger.Info("No SSH host key path configured, generating ephemeral key")
		hostKey, err = generateHostKey()
	} else {
		hostKey, err = loadOrGenerateHostKey(hostKeyPath)
	}
	
	if err != nil {
		logger.Fatalf("Failed to load or generate host key: %v", err)
	}

	return &Server{
		config:             cfg,
		hostKey:            hostKey,
		tunnels:            make(map[string]*Tunnel),
		sessions:           make(map[ssh.Conn][]ssh.Channel),
		pendingURLs:        make(map[ssh.Conn][]string),
		tunnelManager:      nil, // Set later via SetTunnelManager
		certificateManager: nil, // Set later via SetCertificateManager
	}
}

func (s *Server) SetTunnelManager(tm TunnelManager) {
	s.tunnelManager = tm
}

func (s *Server) SetCertificateManager(cm CertificateManager) {
	s.certificateManager = cm
}

func (s *Server) SetUserStore(us UserStore) {
	s.userStore = us
}

func (s *Server) SetSSHKeyStore(sks SSHKeyStore) {
	s.sshKeyStore = sks
}

// GetActiveTunnelSubdomains implements the TunnelProvider interface for ACME client
func (s *Server) GetActiveTunnelSubdomains() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var subdomains []string
	for subdomain := range s.tunnels {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}

// HandleTunnelRequest exposes the handleTunnelRequest method for integration testing
func (s *Server) HandleTunnelRequest(payload []byte, channel ssh.Channel, conn ssh.Conn) (string, int) {
	return s.handleTunnelRequest(payload, channel, conn)
}

func (s *Server) RemoveTunnel(subdomain string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Close the listener if it exists
	if tunnel, exists := s.tunnels[subdomain]; exists {
		if tunnel.Listener != nil {
			tunnel.Listener.Close()
		}

		// Close all active connections
		tunnel.ConnMutex.Lock()
		for connID, conn := range tunnel.Connections {
			conn.Close()
			delete(tunnel.Connections, connID)
		}
		tunnel.ConnMutex.Unlock()
	}

	delete(s.tunnels, subdomain)

	// Also remove from proxy if available
	if s.tunnelManager != nil {
		s.tunnelManager.RemoveTunnel(subdomain)
	}

	// Clean up certificate for this subdomain
	if s.certificateManager != nil {
		if err := s.certificateManager.CleanupSubdomainCertificate(subdomain); err != nil {
			logger.Debugf("Failed to cleanup certificate for subdomain %s: %v", subdomain, err)
		}
	}
}

func (s *Server) GetTunnels() map[string]*Tunnel {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Return a copy to avoid race conditions
	tunnels := make(map[string]*Tunnel)
	for k, v := range s.tunnels {
		tunnels[k] = v
	}
	return tunnels
}

func (s *Server) CleanupDisconnectedTunnels() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for subdomain, tunnel := range s.tunnels {
		// Check if channel is still active by trying to write
		if tunnel.Channel != nil {
			_, err := tunnel.Channel.Write([]byte{})
			if err != nil {
				// Channel is closed, clean up all connections and remove tunnel
				tunnel.ConnMutex.Lock()
				for connID, conn := range tunnel.Connections {
					conn.Close()
					delete(tunnel.Connections, connID)
				}
				tunnel.ConnMutex.Unlock()

				// Close the listener to stop accepting new connections
				if tunnel.Listener != nil {
					tunnel.Listener.Close()
				}

				delete(s.tunnels, subdomain)
				if s.tunnelManager != nil {
					s.tunnelManager.RemoveTunnel(subdomain)
				}

				// Clean up certificate for this subdomain
				if s.certificateManager != nil {
					if err := s.certificateManager.CleanupSubdomainCertificate(subdomain); err != nil {
						logger.Debugf("Failed to cleanup certificate for subdomain %s: %v", subdomain, err)
					}
				}

				logger.Infof("Cleaned up disconnected tunnel: %s", subdomain)
			}
		}
	}
}

func (s *Server) Start() error {
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Use user store if available
			if s.userStore != nil {
				if s.userStore.VerifyPassword(c.User(), string(pass)) {
					logger.Infof("User %s authenticated successfully", c.User())
					return nil, nil
				}
				logger.Warnf("Authentication failed for user %s", c.User())
				return nil, fmt.Errorf("password rejected for %q", c.User())
			}

			// Fallback to hardcoded credentials if no user store
			if c.User() == "tunnel" && string(pass) == "test123" {
				logger.Infof("User %s authenticated with fallback credentials", c.User())
				return nil, nil
			}
			logger.Warnf("Authentication failed for user %s (fallback)", c.User())
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return s.authenticatePublicKey(c, pubKey)
		},
	}
	sshConfig.AddHostKey(s.hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.SSHPort))
	if err != nil {
		return fmt.Errorf("failed to listen on SSH port: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Debugf("Failed to accept SSH connection: %v", err)
			continue
		}

		go s.handleConnection(conn, sshConfig)
	}
}

func (s *Server) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		// logger.Debugf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	logger.Infof("SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.User())

	// Handle global requests (including tcpip-forward)
	go func() {
		for req := range reqs {
			if req.Type == "tcpip-forward" {
				// debug output Payload
				subdomain, assignedPort := s.handleTunnelRequest(req.Payload, nil, sshConn)
				if subdomain != "" {
					// handleTunnelRequest already stored the tunnel, just reply with port
					// Reply with assigned port (SSH protocol requirement)
					portReply := make([]byte, 4)
					portReply[0] = byte(assignedPort >> 24)
					portReply[1] = byte(assignedPort >> 16)
					portReply[2] = byte(assignedPort >> 8)
					portReply[3] = byte(assignedPort)
					req.Reply(true, portReply)
				} else {
					req.Reply(false, nil)
				}
			} else {
				req.Reply(false, nil)
			}
		}
	}()

	// Handle new channels (for interactive sessions or direct-tcpip connections)
	go func() {
		for newChannel := range chans {
			switch newChannel.ChannelType() {
			case "session":
				// Handle session channels (for interactive sessions)
				channel, requests, err := newChannel.Accept()
				if err != nil {
					logger.Debugf("Could not accept session channel: %v", err)
					continue
				}

				// Track this session channel for tunnel URL notifications
				s.mutex.Lock()
				if s.sessions[sshConn] == nil {
					s.sessions[sshConn] = []ssh.Channel{}
				}
				s.sessions[sshConn] = append(s.sessions[sshConn], channel)

				// Send any pending tunnel URLs to this new session
				pendingURLs := s.pendingURLs[sshConn]
				if len(pendingURLs) > 0 {
					// Clear pending URLs since we're sending them now
					delete(s.pendingURLs, sshConn)
				}
				s.mutex.Unlock()

				// Send pending URLs to the new session
				for _, urlMessage := range pendingURLs {
					go func(ch ssh.Channel, msg string) {
						defer func() {
							if r := recover(); r != nil {
								// Session might be closed, ignore errors
							}
						}()
						ch.Write([]byte(msg))
					}(channel, urlMessage)
				}

				go func(in <-chan *ssh.Request) {
					for req := range in {
						if req.Type == "shell" || req.Type == "exec" {
							// Accept shell and exec requests but don't actually provide execution
							req.Reply(true, nil)
						} else {
							req.Reply(false, nil)
						}
					}
				}(requests)

				go func() {
					// Keep session alive and echo any input
					// This allows the tunnel URL message to be visible
					defer func() {
						channel.Close()
						// Remove this session from tracking
						s.mutex.Lock()
						if sessions := s.sessions[sshConn]; sessions != nil {
							for i, ch := range sessions {
								if ch == channel {
									s.sessions[sshConn] = append(sessions[:i], sessions[i+1:]...)
									break
								}
							}
							remaining := len(s.sessions[sshConn])
							if remaining == 0 {
								delete(s.sessions, sshConn)
								// Also clean up any pending URLs for this connection
								delete(s.pendingURLs, sshConn)
							}
							s.mutex.Unlock()
						} else {
							s.mutex.Unlock()
						}
					}()

					buf := make([]byte, 1024)
					for {
						n, err := channel.Read(buf)
						if err != nil {
							break
						}
						// Echo back any input to keep session interactive
						channel.Write(buf[:n])
					}
				}()

			case "direct-tcpip":
				// Handle direct TCP connections (actual port forwarding)
				go s.handleDirectTcpip(newChannel)

			default:
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			}
		}
	}()

	// Wait for the SSH connection to close
	// This is essential for ssh -N connections that don't open channels
	err = sshConn.Wait()
	if err != nil {
		logger.Debugf("SSH connection closed with error: %v", err)
	}
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return ssh.ParsePrivateKey(keyPEM)
}

// loadOrGenerateHostKey loads an existing host key from disk or generates a new one
func loadOrGenerateHostKey(keyPath string) (ssh.Signer, error) {
	// Try to load existing key
	if keyData, err := os.ReadFile(keyPath); err == nil {
		// Try to parse the key
		if signer, err := ssh.ParsePrivateKey(keyData); err == nil {
			logger.Infof("Loaded existing SSH host key from %s", keyPath)
			return signer, nil
		}
		// If parsing fails, log warning and generate new key
		logger.Warnf("Failed to parse existing host key, generating new one: %v", err)
	}

	// Generate new key
	logger.Info("Generating new SSH host key")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Convert to PEM format
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Save key to disk
	if err := fileutil.WriteFileWithDir(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save host key: %w", err)
	}

	logger.Infof("Saved new SSH host key to %s", keyPath)

	// Parse and return the key
	return ssh.ParsePrivateKey(keyPEM)
}

// authenticatePublicKey checks if the provided public key is authorized
func (s *Server) authenticatePublicKey(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	// Only allow "tunnel" user for public key authentication
	if c.User() != "tunnel" {
		return nil, fmt.Errorf("user %q not allowed", c.User())
	}

	// Try SSH key store first (preferred method)
	if s.sshKeyStore != nil {
		// Try key store authentication
		perms, err := s.authenticateWithKeyStore(c, pubKey)
		if err == nil {
			return perms, nil
		}
		// If key store has no keys, fall back to file-based auth
		if err.Error() == "no SSH keys configured" {
			logger.Debugf("No keys in SSH key store, falling back to file-based authentication")
		} else {
			// For other errors, still try file-based as fallback
			logger.Debugf("SSH key store authentication failed: %v, trying file-based authentication", err)
		}
	}

	// Fallback to file-based authentication
	authorizedKeys, err := s.loadAuthorizedKeys()
	if err != nil {
		logger.Debugf("Failed to load authorized keys: %v", err)
		return nil, fmt.Errorf("public key authentication not available")
	}

	for _, authorizedKey := range authorizedKeys {
		authorizedKey = strings.TrimSpace(authorizedKey)
		if authorizedKey == "" || strings.HasPrefix(authorizedKey, "#") {
			continue // Skip empty lines and comments
		}

		// Parse the authorized key to compare properly
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
		if err != nil {
			continue // Skip invalid keys
		}

		// Compare the marshalled representations of the keys
		clientKeyBytes := ssh.MarshalAuthorizedKey(pubKey)
		authorizedKeyBytes := ssh.MarshalAuthorizedKey(parsedKey)

		if strings.TrimSpace(string(clientKeyBytes)) == strings.TrimSpace(string(authorizedKeyBytes)) {
			logger.Debugf("Public key authentication successful for user %s", c.User())
			return nil, nil
		}
	}

	return nil, fmt.Errorf("public key not authorized for %q", c.User())
}

// authenticateWithKeyStore authenticates using the SSH key store
func (s *Server) authenticateWithKeyStore(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	authorizedKeysContent := s.sshKeyStore.GetAuthorizedKeysContent()
	if authorizedKeysContent == "" {
		logger.Debugf("No SSH keys configured in key store")
		return nil, fmt.Errorf("no SSH keys configured")
	}

	// Split the content into individual keys
	authorizedKeys := strings.Split(authorizedKeysContent, "\n")
	clientKeyBytes := ssh.MarshalAuthorizedKey(pubKey)

	for _, authorizedKey := range authorizedKeys {
		authorizedKey = strings.TrimSpace(authorizedKey)
		if authorizedKey == "" || strings.HasPrefix(authorizedKey, "#") {
			continue // Skip empty lines and comments
		}

		// Parse the authorized key to compare properly
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
		if err != nil {
			logger.Debugf("Invalid SSH key in store: %v", err)
			continue // Skip invalid keys
		}

		// Compare the marshalled representations of the keys
		authorizedKeyBytes := ssh.MarshalAuthorizedKey(parsedKey)

		if strings.TrimSpace(string(clientKeyBytes)) == strings.TrimSpace(string(authorizedKeyBytes)) {
			logger.Infof("Public key authentication successful for user %s using SSH key store", c.User())
			return nil, nil
		}
	}

	logger.Debugf("Public key not found in SSH key store for user %s", c.User())
	return nil, fmt.Errorf("public key not authorized for %q", c.User())
}

// loadAuthorizedKeys loads the authorized keys from the configured file
func (s *Server) loadAuthorizedKeys() ([]string, error) {
	// Check if authorized keys file exists
	if _, err := os.Stat(s.config.AuthorizedKeys); os.IsNotExist(err) {
		return nil, fmt.Errorf("authorized keys file not found: %s", s.config.AuthorizedKeys)
	}

	content, err := ioutil.ReadFile(s.config.AuthorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized keys file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	var keys []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}

	return keys, nil
}

func (s *Server) handleTunnelRequest(payload []byte, channel ssh.Channel, conn ssh.Conn) (string, int) {
	// Parse tcpip-forward request payload
	// Format: string bind_address, uint32 bind_port
	if len(payload) < 8 {
		logger.Debugf("Invalid tcpip-forward payload length: %d", len(payload))
		return "", 0
	}

	// Skip bind_address (we'll use localhost)
	addressLen := int(payload[3])
	if len(payload) < 4+addressLen+4 {
		logger.Debugf("Invalid tcpip-forward payload format")
		return "", 0
	}

	// Extract requested port
	portBytes := payload[4+addressLen : 4+addressLen+4]
	requestedPort := int(portBytes[0])<<24 | int(portBytes[1])<<16 | int(portBytes[2])<<8 | int(portBytes[3])

	// Validate port is within valid range
	if requestedPort < 0 || requestedPort > 65535 {
		logger.Debugf("Invalid requested port number: %d", requestedPort)
		return "", 0
	}

	// For SSH remote forwarding, we assign a virtual port for the tunnel
	// Since we're doing HTTP proxy routing by subdomain, the actual port doesn't matter
	// but SSH clients expect a non-zero port to indicate success
	assignedPort := requestedPort
	if assignedPort == 0 {
		// Assign a virtual port for dynamic allocation requests
		// Ensure it stays within valid port range (22000-22999)
		assignedPort = 22000 + (int(time.Now().UnixNano()) % 1000)
	} else {
		logger.Debugf("Using requested port: %d", assignedPort)
	}

	subdomain := generateSubdomain()

	// For SSH remote forwarding, we need to actually bind to the allocated port
	// and forward connections through the SSH tunnel to the client
	tunnelTarget := fmt.Sprintf("localhost:%d", assignedPort)

	// Start listening on the allocated port for incoming connections
	listener := s.startRemoteForwardListener(assignedPort, conn)

	// Register tunnel with proxy if available
	if s.tunnelManager != nil {
		err := s.tunnelManager.AddTunnel(subdomain, tunnelTarget)
		if err != nil {
			logger.Debugf("Failed to register tunnel: %v", err)
			if listener != nil {
				listener.Close()
			}
			return "", 0
		}
	}

	// Store tunnel in SSH server's internal map for lifecycle management
	s.mutex.Lock()
	s.tunnels[subdomain] = &Tunnel{
		Subdomain:   subdomain,
		LocalPort:   assignedPort,
		Channel:     channel,
		Connections: make(map[string]net.Conn),
		Listener:    listener,
	}
	s.mutex.Unlock()

	// Ensure certificate exists for this subdomain
	if s.certificateManager != nil {
		go func() {
			ctx := context.Background()
			if err := s.certificateManager.EnsureSubdomainCertificate(ctx, subdomain); err != nil {
				logger.Debugf("Failed to ensure certificate for subdomain %s: %v", subdomain, err)
			}
		}()
	}

	// Build complete URLs for the user
	// Use external ports if set, otherwise fall back to internal ports
	httpExternalPort := s.config.HTTPExternalPort
	if httpExternalPort == 0 {
		httpExternalPort = s.config.HTTPPort
	}
	httpsExternalPort := s.config.HTTPSExternalPort
	if httpsExternalPort == 0 {
		httpsExternalPort = s.config.HTTPSPort
	}

	urlBuilder := common.NewURLBuilder(s.config.Domain)
	httpURL, httpsURL := urlBuilder.BuildURLs(subdomain, httpExternalPort, httpsExternalPort)

	logger.Infof("✅ Tunnel created: %s -> %s (port %d)", subdomain, tunnelTarget, assignedPort)
	logger.Infof("🌐 HTTP:  %s", httpURL)
	logger.Infof("🔒 HTTPS: %s", httpsURL)

	// Store URLs in tunnel struct for reference
	s.mutex.Lock()
	if tunnel := s.tunnels[subdomain]; tunnel != nil {
		tunnel.HTTPURL = httpURL
		tunnel.HTTPSURL = httpsURL
	}
	s.mutex.Unlock()

	// Write tunnel URLs to SSH channel for client to see
	if channel != nil {
		fmt.Fprintf(channel, "\r\n🎉 Tunnel Created Successfully!\r\n")
		fmt.Fprintf(channel, "🌐 HTTP URL:  %s\r\n", httpURL)
		fmt.Fprintf(channel, "🔒 HTTPS URL: %s\r\n", httpsURL)
		fmt.Fprintf(channel, "\r\n💡 Your local service on port %d is now publicly accessible!\r\n", requestedPort)
		fmt.Fprintf(channel, "   Share these URLs with anyone who needs access.\r\n\r\n")
	} else {
		// Send tunnel URLs to all active sessions for this connection
		s.sendTunnelURLsToSessions(conn, httpURL, httpsURL)
	}

	return subdomain, assignedPort
}

// startRemoteForwardListener starts listening on the allocated port and forwards
// incoming connections through the SSH tunnel to the client
func (s *Server) startRemoteForwardListener(port int, sshConn ssh.Conn) net.Listener {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Debugf("Failed to listen on port %d for remote forwarding: %v", port, err)
		return nil
	}

	// Accept connections and forward them through SSH tunnel
	go func() {
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				logger.Debugf("Error accepting connection on port %d: %v", port, err)
				// If we can't accept connections, exit the listener
				return
			}

			// Forward this connection through the SSH tunnel
			go s.forwardConnectionThroughSSH(conn, sshConn, port)
		}
	}()

	return listener
}

// forwardConnectionThroughSSH forwards a TCP connection through an SSH tunnel
func (s *Server) forwardConnectionThroughSSH(localConn net.Conn, sshConn ssh.Conn, listeningPort int) {
	defer localConn.Close()

	// Check if sshConn is nil (can happen if connection closed while listener still running)
	if sshConn == nil {
		logger.Debugf("SSH connection is nil, cannot forward connection")
		return
	}

	// Get originator address and port from the incoming connection
	originAddr, originPortStr, _ := net.SplitHostPort(localConn.RemoteAddr().String())
	originPort, _ := strconv.Atoi(originPortStr)

	// Validate port numbers are within valid range for uint32
	if listeningPort < 0 || listeningPort > 65535 {
		logger.Debugf("Invalid listening port number: %d", listeningPort)
		return
	}
	if originPort < 0 || originPort > 65535 {
		logger.Debugf("Invalid origin port number: %d", originPort)
		return
	}

	// Open a new channel for this forwarded connection
	// According to RFC 4254, forwarded-tcpip payload is:
	// string  address that was connected (server's listening address)
	// uint32  port that was connected (server's listening port)
	// string  originator IP address
	// uint32  originator port
	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&struct {
		ConnectedAddress string
		ConnectedPort    uint32
		OriginAddress    string
		OriginPort       uint32
	}{
		ConnectedAddress: "localhost",
		ConnectedPort:    uint32(listeningPort),
		OriginAddress:    originAddr,
		OriginPort:       uint32(originPort),
	}))

	if err != nil {
		logger.Debugf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	// Handle any channel requests
	go ssh.DiscardRequests(reqs)

	// Bridge the local connection and SSH channel
	go func() {
		defer channel.Close()
		defer localConn.Close()
		io.Copy(channel, localConn)
	}()

	io.Copy(localConn, channel)
}

// sendTunnelURLsToSessions sends tunnel URL information to all active sessions for the given connection
func (s *Server) sendTunnelURLsToSessions(conn ssh.Conn, httpURL, httpsURL string) {
	tunnelMessage := common.FormatTunnelSuccessMessage(httpURL, httpsURL)

	s.mutex.Lock()
	sessions := s.sessions[conn]
	sessionCount := len(sessions)

	if sessionCount == 0 {
		// Store the tunnel URL for when sessions become available
		if s.pendingURLs[conn] == nil {
			s.pendingURLs[conn] = []string{}
		}
		s.pendingURLs[conn] = append(s.pendingURLs[conn], tunnelMessage)
		s.mutex.Unlock()
		return
	}
	s.mutex.Unlock()

	for _, session := range sessions {
		// Send message to each active session
		// Use a goroutine to avoid blocking if session is not reading
		go func(ch ssh.Channel) {
			defer func() {
				if r := recover(); r != nil {
					// Session might be closed, ignore errors
				}
			}()
			ch.Write([]byte(tunnelMessage))
		}(session)
	}
}

func (s *Server) handleDirectTcpip(newChannel ssh.NewChannel) {
	// Parse the direct-tcpip payload to get target host and port
	targetHost, targetPort, err := parseDirectTcpipPayload(newChannel.ExtraData())
	if err != nil {
		logger.Debugf("Failed to parse direct-tcpip payload: %v", err)
		newChannel.Reject(ssh.Prohibited, "invalid payload")
		return
	}

	logger.Debugf("Direct TCP connection request to %s:%d", targetHost, targetPort)

	// Find the tunnel that matches this port
	var tunnel *Tunnel
	s.mutex.RLock()
	for _, t := range s.tunnels {
		if t.LocalPort == targetPort {
			tunnel = t
			break
		}
	}
	s.mutex.RUnlock()

	if tunnel == nil {
		logger.Debugf("No tunnel found for port %d", targetPort)
		newChannel.Reject(ssh.Prohibited, "no tunnel for port")
		return
	}

	// Accept the SSH channel
	sshChannel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Debugf("Could not accept direct-tcpip channel: %v", err)
		return
	}
	defer sshChannel.Close()

	// Discard any requests on this channel
	go ssh.DiscardRequests(requests)

	// Connect to the local service
	localAddr := fmt.Sprintf("localhost:%d", targetPort)
	tcpConn, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
	if err != nil {
		logger.Debugf("Failed to connect to local service %s: %v", localAddr, err)
		return
	}

	// Generate connection ID and track it
	connID := fmt.Sprintf("%s:%d-%d", targetHost, targetPort, time.Now().UnixNano())
	tunnel.ConnMutex.Lock()
	tunnel.Connections[connID] = tcpConn
	tunnel.ConnMutex.Unlock()

	// Clean up connection when done
	defer func() {
		tunnel.ConnMutex.Lock()
		delete(tunnel.Connections, connID)
		tunnel.ConnMutex.Unlock()
		tcpConn.Close()
	}()

	logger.Debugf("Bridging SSH channel to %s (tunnel: %s)", localAddr, tunnel.Subdomain)

	// Bridge the connections
	err = bridgeConnections(sshChannel, tcpConn, 30*time.Minute)
	if err != nil {
		logger.Debugf("Bridge connection ended: %v", err)
	}
}

func generateSubdomain() string {
	// Human-readable adjectives and nouns for memorable subdomains
	adjectives := []string{
		"happy", "bright", "calm", "swift", "clever", "gentle", "bold", "warm",
		"cool", "fresh", "quiet", "smart", "kind", "brave", "quick", "smooth",
		"clear", "sweet", "bright", "clean", "pure", "sharp", "soft", "strong",
		"light", "dark", "deep", "high", "wide", "rich", "full", "empty",
		"young", "old", "new", "fast", "slow", "big", "small", "long", "short",
		"hot", "cold", "dry", "wet", "loud", "soft", "hard", "easy", "tough",
		"wild", "tame", "free", "busy", "lazy", "eager", "proud", "shy",
	}

	nouns := []string{
		"cat", "dog", "bird", "fish", "tree", "star", "moon", "sun", "cloud",
		"wave", "rock", "leaf", "flower", "grass", "wind", "rain", "snow",
		"fire", "water", "earth", "sky", "mountain", "valley", "river", "ocean",
		"forest", "desert", "island", "bridge", "castle", "tower", "garden",
		"house", "door", "window", "road", "path", "field", "meadow", "pond",
		"lake", "stream", "brook", "hill", "cliff", "cave", "beach", "shore",
		"storm", "rainbow", "thunder", "lightning", "sunset", "sunrise", "dawn",
		"dusk", "morning", "evening", "night", "day", "hour", "moment", "time",
	}

	adjective := adjectives[mathrand.Intn(len(adjectives))]
	noun := nouns[mathrand.Intn(len(nouns))]

	// Add a random number to ensure uniqueness in case of collisions
	number := mathrand.Intn(100)

	return fmt.Sprintf("%s-%s-%d", adjective, noun, number)
}

// parseTcpipForwardPayload parses the payload of a tcpip-forward request
// Format: string bind_address, uint32 bind_port
func parseTcpipForwardPayload(payload []byte) (int, error) {
	if len(payload) < 8 {
		return 0, fmt.Errorf("payload too short: %d bytes", len(payload))
	}

	// Read address length
	addressLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])

	// Check if we have enough bytes for address + port
	if len(payload) < 4+addressLen+4 {
		return 0, fmt.Errorf("payload incomplete: expected %d bytes, got %d", 4+addressLen+4, len(payload))
	}

	// Extract port (skip address)
	portBytes := payload[4+addressLen : 4+addressLen+4]
	port := int(portBytes[0])<<24 | int(portBytes[1])<<16 | int(portBytes[2])<<8 | int(portBytes[3])

	return port, nil
}

// parseDirectTcpipPayload parses the payload of a direct-tcpip channel
// Format: string target_host, uint32 target_port, string source_host, uint32 source_port
func parseDirectTcpipPayload(payload []byte) (string, int, error) {
	if len(payload) < 8 {
		return "", 0, fmt.Errorf("payload too short: %d bytes", len(payload))
	}

	// Read target host length
	hostLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])

	// Check if we have enough bytes for host + port
	if len(payload) < 4+hostLen+4 {
		return "", 0, fmt.Errorf("payload incomplete for host and port")
	}

	// Extract target host
	host := string(payload[4 : 4+hostLen])

	// Extract target port
	portBytes := payload[4+hostLen : 4+hostLen+4]
	port := int(portBytes[0])<<24 | int(portBytes[1])<<16 | int(portBytes[2])<<8 | int(portBytes[3])

	logger.Debugf("parseDirectTcpipPayload: host=%s, port=%d", host, port)
	return host, port, nil
}

// bridgeConnections creates a bidirectional bridge between an SSH channel and a TCP connection
func bridgeConnections(sshChannel ssh.Channel, tcpConn net.Conn, timeout time.Duration) error {
	if tcpConn != nil {
		defer tcpConn.Close()
	}
	defer sshChannel.Close()

	// Set up bidirectional copying
	errChan := make(chan error, 2)

	// Copy from SSH channel to TCP connection
	go func() {
		_, err := io.Copy(tcpConn, sshChannel)
		errChan <- err
	}()

	// Copy from TCP connection to SSH channel
	go func() {
		_, err := io.Copy(sshChannel, tcpConn)
		errChan <- err
	}()

	// Wait for either direction to complete or timeout
	select {
	case err := <-errChan:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("bridge timeout after %v", timeout)
	}
}
