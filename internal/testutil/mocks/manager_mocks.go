package mocks

import (
	"context"
	"sync"
)

// TunnelManager is a mock implementation of TunnelManager for testing
type TunnelManager struct {
	tunnels      map[string]string
	addError     error
	removeError  error
	addCallCount int
	mu           sync.RWMutex
}

// NewTunnelManager creates a new mock tunnel manager
func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		tunnels: make(map[string]string),
	}
}

// SetAddError sets an error to be returned by AddTunnel
func (m *TunnelManager) SetAddError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addError = err
}

// SetRemoveError sets an error to be returned by RemoveTunnel
func (m *TunnelManager) SetRemoveError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeError = err
}

// AddTunnel implements TunnelManager interface
func (m *TunnelManager) AddTunnel(subdomain, target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.addCallCount++
	if m.addError != nil {
		return m.addError
	}
	
	m.tunnels[subdomain] = target
	return nil
}

// RemoveTunnel implements TunnelManager interface
func (m *TunnelManager) RemoveTunnel(subdomain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tunnels, subdomain)
}

// GetTunnel returns the target for a subdomain
func (m *TunnelManager) GetTunnel(subdomain string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	target, exists := m.tunnels[subdomain]
	return target, exists
}

// GetAddCallCount returns how many times AddTunnel was called
func (m *TunnelManager) GetAddCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.addCallCount
}

// CertificateManager is a mock implementation of CertificateManager for testing
type CertificateManager struct {
	ensureError  error
	cleanupError error
	certificates map[string]bool
	mu           sync.RWMutex
}

// NewCertificateManager creates a new mock certificate manager
func NewCertificateManager() *CertificateManager {
	return &CertificateManager{
		certificates: make(map[string]bool),
	}
}

// SetEnsureError sets an error to be returned by EnsureSubdomainCertificate
func (m *CertificateManager) SetEnsureError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureError = err
}

// SetCleanupError sets an error to be returned by CleanupSubdomainCertificate
func (m *CertificateManager) SetCleanupError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupError = err
}

// EnsureSubdomainCertificate implements CertificateManager interface
func (m *CertificateManager) EnsureSubdomainCertificate(ctx context.Context, subdomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.ensureError != nil {
		return m.ensureError
	}
	
	m.certificates[subdomain] = true
	return nil
}

// CleanupSubdomainCertificate implements CertificateManager interface
func (m *CertificateManager) CleanupSubdomainCertificate(subdomain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.cleanupError != nil {
		return m.cleanupError
	}
	
	delete(m.certificates, subdomain)
	return nil
}

// HasCertificate checks if a certificate exists for a subdomain
func (m *CertificateManager) HasCertificate(subdomain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certificates[subdomain]
}