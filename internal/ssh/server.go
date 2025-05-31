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
	"log"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"bohrer-go/internal/config"
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

type Server struct {
	config             *config.Config
	hostKey            ssh.Signer
	tunnels            map[string]*Tunnel
	sessions           map[ssh.Conn][]ssh.Channel // Track active sessions per connection
	pendingURLs        map[ssh.Conn][]string      // Track pending tunnel URLs per connection
	mutex              sync.RWMutex
	tunnelManager      TunnelManager
	certificateManager CertificateManager
}

type Tunnel struct {
	Subdomain     string
	LocalPort     int
	Channel       ssh.Channel
	Connections   map[string]net.Conn // Track active forwarded connections
	ConnMutex     sync.RWMutex        // Protect connections map
	HTTPURL       string              // Full HTTP URL for this tunnel
	HTTPSURL      string              // Full HTTPS URL for this tunnel
	ForwardTarget string              // Target host:port for SSH forwarding (e.g., localhost:3000)
}

func NewServer(cfg *config.Config) *Server {
	hostKey, err := generateHostKey()
	if err != nil {
		log.Fatalf("Failed to generate host key: %v", err)
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

	delete(s.tunnels, subdomain)

	// Also remove from proxy if available
	if s.tunnelManager != nil {
		s.tunnelManager.RemoveTunnel(subdomain)
	}

	// Clean up certificate for this subdomain
	if s.certificateManager != nil {
		if err := s.certificateManager.CleanupSubdomainCertificate(subdomain); err != nil {
			log.Printf("Failed to cleanup certificate for subdomain %s: %v", subdomain, err)
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

				delete(s.tunnels, subdomain)
				if s.tunnelManager != nil {
					s.tunnelManager.RemoveTunnel(subdomain)
				}

				// Clean up certificate for this subdomain
				if s.certificateManager != nil {
					if err := s.certificateManager.CleanupSubdomainCertificate(subdomain); err != nil {
						log.Printf("Failed to cleanup certificate for subdomain %s: %v", subdomain, err)
					}
				}

				log.Printf("Cleaned up disconnected tunnel: %s", subdomain)
			}
		}
	}
}

func (s *Server) Start() error {
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "tunnel" && string(pass) == "test123" {
				return nil, nil
			}
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
			log.Printf("Failed to accept SSH connection: %v", err)
			continue
		}

		go s.handleConnection(conn, sshConfig)
	}
}

func (s *Server) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.User())

	// Handle global requests (including tcpip-forward)
	go func() {
		for req := range reqs {
			if req.Type == "tcpip-forward" {
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
					log.Printf("Could not accept session channel: %v", err)
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
		log.Printf("SSH connection closed with error: %v", err)
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

// authenticatePublicKey checks if the provided public key is authorized
func (s *Server) authenticatePublicKey(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	// Only allow "tunnel" user for public key authentication
	if c.User() != "tunnel" {
		return nil, fmt.Errorf("user %q not allowed", c.User())
	}

	authorizedKeys, err := s.loadAuthorizedKeys()
	if err != nil {
		log.Printf("Failed to load authorized keys: %v", err)
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
			log.Printf("Public key authentication successful for user %s", c.User())
			return nil, nil
		}
	}

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
		log.Printf("Invalid tcpip-forward payload length: %d", len(payload))
		return "", 0
	}

	// Skip bind_address (we'll use localhost)
	addressLen := int(payload[3])
	if len(payload) < 4+addressLen+4 {
		log.Printf("Invalid tcpip-forward payload format")
		return "", 0
	}

	// Extract requested port
	portBytes := payload[4+addressLen : 4+addressLen+4]
	requestedPort := int(portBytes[0])<<24 | int(portBytes[1])<<16 | int(portBytes[2])<<8 | int(portBytes[3])

	// For SSH remote forwarding, we assign a virtual port for the tunnel
	// Since we're doing HTTP proxy routing by subdomain, the actual port doesn't matter
	// but SSH clients expect a non-zero port to indicate success
	assignedPort := requestedPort
	if assignedPort == 0 {
		// Assign a virtual port for dynamic allocation requests
		assignedPort = 22000 + (int(time.Now().UnixNano()) % 1000)
	}

	subdomain := generateSubdomain()

	// For SSH remote forwarding, we need to actually bind to the allocated port
	// and forward connections through the SSH tunnel to the client
	tunnelTarget := fmt.Sprintf("localhost:%d", assignedPort)

	// Determine the SSH forwarding target (where to send connections through SSH tunnel)
	forwardTarget := "localhost:3000" // default target
	if requestedPort > 0 {
		forwardTarget = fmt.Sprintf("localhost:%d", requestedPort)
	}

	// Start listening on the allocated port for incoming connections
	go s.startRemoteForwardListener(assignedPort, conn, forwardTarget)

	// Register tunnel with proxy if available
	if s.tunnelManager != nil {
		err := s.tunnelManager.AddTunnel(subdomain, tunnelTarget)
		if err != nil {
			log.Printf("Failed to register tunnel: %v", err)
			return "", 0
		}
	}

	// Store tunnel in SSH server's internal map for lifecycle management
	s.mutex.Lock()
	s.tunnels[subdomain] = &Tunnel{
		Subdomain:     subdomain,
		LocalPort:     assignedPort,
		Channel:       channel,
		Connections:   make(map[string]net.Conn),
		ForwardTarget: forwardTarget,
	}
	s.mutex.Unlock()

	// Ensure certificate exists for this subdomain
	if s.certificateManager != nil {
		go func() {
			ctx := context.Background()
			if err := s.certificateManager.EnsureSubdomainCertificate(ctx, subdomain); err != nil {
				log.Printf("Failed to ensure certificate for subdomain %s: %v", subdomain, err)
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

	httpURL := fmt.Sprintf("http://%s.%s", subdomain, s.config.Domain)
	if httpExternalPort != 80 {
		httpURL = fmt.Sprintf("http://%s.%s:%d", subdomain, s.config.Domain, httpExternalPort)
	}

	httpsURL := fmt.Sprintf("https://%s.%s", subdomain, s.config.Domain)
	if httpsExternalPort != 443 {
		httpsURL = fmt.Sprintf("https://%s.%s:%d", subdomain, s.config.Domain, httpsExternalPort)
	}

	log.Printf("✅ Tunnel created: %s -> %s (port %d, forward to %s)", subdomain, tunnelTarget, assignedPort, forwardTarget)
	log.Printf("🌐 HTTP:  %s", httpURL)
	log.Printf("🔒 HTTPS: %s (when available)", httpsURL)

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
func (s *Server) startRemoteForwardListener(port int, sshConn ssh.Conn, forwardTarget string) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("Failed to listen on port %d for remote forwarding: %v", port, err)
		return
	}

	log.Printf("Started SSH remote forward listener on port %d -> %s", port, forwardTarget)

	// Accept connections and forward them through SSH tunnel
	go func() {
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting connection on port %d: %v", port, err)
				// If we can't accept connections, exit the listener
				return
			}

			// Forward this connection through the SSH tunnel
			go s.forwardConnectionThroughSSH(conn, sshConn, forwardTarget, port)
		}
	}()
}

// forwardConnectionThroughSSH forwards a TCP connection through an SSH tunnel
func (s *Server) forwardConnectionThroughSSH(localConn net.Conn, sshConn ssh.Conn, forwardTarget string, listeningPort int) {
	defer localConn.Close()

	// Parse the forward target (host:port)
	parts := strings.Split(forwardTarget, ":")
	if len(parts) != 2 {
		log.Printf("Invalid forward target format: %s", forwardTarget)
		return
	}

	targetHost := parts[0]
	targetPort := parts[1]

	// Convert port to uint32
	portNum, err := strconv.Atoi(targetPort)
	if err != nil {
		log.Printf("Invalid target port: %s", targetPort)
		return
	}
	targetPortNum := uint32(portNum)

	log.Printf("Forwarding connection to %s:%d through SSH tunnel", targetHost, targetPortNum)

	// Get originator address and port from the incoming connection
	originAddr, originPortStr, _ := net.SplitHostPort(localConn.RemoteAddr().String())
	originPort, _ := strconv.Atoi(originPortStr)

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
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
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
	tunnelMessage := fmt.Sprintf("\r\n🎉 Tunnel Created Successfully!\r\n🌐 HTTP URL:  %s\r\n🔒 HTTPS URL: %s\r\n\r\n💡 Your local service is now publicly accessible!\r\n   Share these URLs with anyone who needs access.\r\n\r\n", httpURL, httpsURL)

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
		log.Printf("Failed to parse direct-tcpip payload: %v", err)
		newChannel.Reject(ssh.Prohibited, "invalid payload")
		return
	}

	log.Printf("Direct TCP connection request to %s:%d", targetHost, targetPort)

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
		log.Printf("No tunnel found for port %d", targetPort)
		newChannel.Reject(ssh.Prohibited, "no tunnel for port")
		return
	}

	// Accept the SSH channel
	sshChannel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept direct-tcpip channel: %v", err)
		return
	}
	defer sshChannel.Close()

	// Discard any requests on this channel
	go ssh.DiscardRequests(requests)

	// Connect to the local service
	localAddr := fmt.Sprintf("localhost:%d", targetPort)
	tcpConn, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to local service %s: %v", localAddr, err)
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

	log.Printf("Bridging SSH channel to %s (tunnel: %s)", localAddr, tunnel.Subdomain)

	// Bridge the connections
	err = bridgeConnections(sshChannel, tcpConn, 30*time.Minute)
	if err != nil {
		log.Printf("Bridge connection ended: %v", err)
	}
}

func generateSubdomain() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[mathrand.Intn(len(chars))]
	}
	return string(b)
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