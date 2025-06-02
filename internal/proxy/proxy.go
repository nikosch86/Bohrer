package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"bohrer-go/internal/config"
	"bohrer-go/internal/logger"
)

// WebUIHandler interface for serving the web interface
type WebUIHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type Proxy struct {
	config  *config.Config
	tunnels map[string]string // subdomain -> target (host:port)
	mutex   sync.RWMutex
	webui   WebUIHandler
}

func NewProxy(cfg *config.Config) *Proxy {
	return &Proxy{
		config:  cfg,
		tunnels: make(map[string]string),
	}
}

func (p *Proxy) AddTunnel(subdomain, target string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.tunnels[subdomain] = target
	return nil
}

func (p *Proxy) RemoveTunnel(subdomain string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	delete(p.tunnels, subdomain)
}

// GetTunnel returns the target for a given subdomain (for testing and integration)
func (p *Proxy) GetTunnel(subdomain string) (string, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	target, exists := p.tunnels[subdomain]
	return target, exists
}

// SetWebUI sets the WebUI handler for serving the web interface on root domain
func (p *Proxy) SetWebUI(webui WebUIHandler) {
	p.webui = webui
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check for ACME challenge requests first
	if p.handleACMEChallenge(w, r) {
		return
	}

	// Check if this is a request to the root domain (no subdomain)
	if p.isRootDomainRequest(r.Host) {
		// Root domain on HTTP - return 404, WebUI only available via HTTPS
		http.NotFound(w, r)
		return
	}

	// Extract subdomain from host
	subdomain, valid := extractSubdomain(r.Host, p.config.Domain)
	if !valid {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	// Look up tunnel target
	p.mutex.RLock()
	target, exists := p.tunnels[subdomain]
	p.mutex.RUnlock()

	if !exists {
		http.Error(w, "Tunnel not found for subdomain: "+subdomain, http.StatusNotFound)
		return
	}

	// Create reverse proxy to target
	targetURL, err := url.Parse("http://" + target)
	if err != nil {
		http.Error(w, "Invalid tunnel target", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ServeHTTP(w, r)
}

// ServeHTTPS handles HTTPS requests, including WebUI on root domain
func (p *Proxy) ServeHTTPS(w http.ResponseWriter, r *http.Request) {
	// Check for ACME challenge requests first (though unlikely on HTTPS)
	if p.handleACMEChallenge(w, r) {
		return
	}

	// Check if this is a request to the root domain (no subdomain)
	if p.isRootDomainRequest(r.Host) {
		// Serve WebUI if available
		if p.webui != nil {
			p.webui.ServeHTTP(w, r)
			return
		}

		// Fallback to simple message if no WebUI
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<html><body>
				<h1>SSH Tunnel Server</h1>
				<p>Connect via SSH to create tunnels: <code>ssh -R 0:localhost:YOUR_PORT user@%s</code></p>
			</body></html>
		`, p.config.Domain)
		return
	}

	// Extract subdomain from host
	subdomain, valid := extractSubdomain(r.Host, p.config.Domain)
	if !valid {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	// Look up tunnel target
	p.mutex.RLock()
	target, exists := p.tunnels[subdomain]
	p.mutex.RUnlock()

	if !exists {
		http.Error(w, "Tunnel not found for subdomain: "+subdomain, http.StatusNotFound)
		return
	}

	// Create reverse proxy to target
	targetURL, err := url.Parse("http://" + target)
	if err != nil {
		http.Error(w, "Invalid tunnel target", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ServeHTTP(w, r)
}

func (p *Proxy) Start() error {
	return http.ListenAndServe(fmt.Sprintf(":%d", p.config.HTTPPort), p)
}

// StartHTTPS starts the HTTPS server with TLS certificates
func (p *Proxy) StartHTTPS() error {
	// Check if certificate files exist
	if _, err := os.Stat(p.config.ACMECertPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", p.config.ACMECertPath)
	}
	if _, err := os.Stat(p.config.ACMEKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", p.config.ACMEKeyPath)
	}

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(p.config.ACMECertPath, p.config.ACMEKeyPath)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create HTTPS server with separate handler
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", p.config.HTTPSPort),
		Handler:   http.HandlerFunc(p.ServeHTTPS),
		TLSConfig: tlsConfig,
	}

	logger.Debugf("Starting HTTPS server on port %d", p.config.HTTPSPort)
	return server.ListenAndServeTLS("", "")
}

// StartBoth starts both HTTP and HTTPS servers concurrently
func (p *Proxy) StartBoth() error {
	// Start HTTP server in goroutine
	go func() {
		logger.Debugf("Starting HTTP server on port %d", p.config.HTTPPort)
		if err := p.Start(); err != nil {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server in main goroutine
	return p.StartHTTPS()
}

// isRootDomainRequest checks if the request is to the root domain (no subdomain)
func (p *Proxy) isRootDomainRequest(host string) bool {
	if host == "" {
		return false
	}

	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Check if host exactly matches domain (no subdomain)
	return host == p.config.Domain
}

// extractSubdomain extracts the subdomain from a host given a base domain
// Returns (subdomain, valid) where valid indicates if the host matches the domain pattern
func extractSubdomain(host, domain string) (string, bool) {
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
		// Check if host exactly matches domain (no subdomain)
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

// handleACMEChallenge handles ACME HTTP-01 challenge requests
// Returns true if the request was handled, false otherwise
func (p *Proxy) handleACMEChallenge(w http.ResponseWriter, r *http.Request) bool {
	// Check if this is an ACME challenge request
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		return false
	}

	// Extract the token from the path
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" {
		http.Error(w, "Invalid challenge token", http.StatusBadRequest)
		return true
	}

	// Read the challenge file
	challengePath := filepath.Join(p.config.ACMEChallengeDir, token)
	content, err := os.ReadFile(challengePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Challenge not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error reading challenge", http.StatusInternalServerError)
		}
		return true
	}

	// Serve the challenge content
	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
	return true
}

// GetTunnels returns a copy of all current tunnels (for monitoring/debugging)
func (p *Proxy) GetTunnels() map[string]string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	tunnels := make(map[string]string)
	for k, v := range p.tunnels {
		tunnels[k] = v
	}
	return tunnels
}
