package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/hoffmann/bohrer-go/internal/config"
)

type Proxy struct {
	config  *config.Config
	tunnels map[string]string // subdomain -> target (host:port)
	mutex   sync.RWMutex
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

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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