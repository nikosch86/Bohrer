package webui

import (
	"sync"
)

// SSHServerAdapter adapts SSH server and proxy for WebUI tunnel display
type SSHServerAdapter struct {
	sshServer SSHServerInterface
	proxy     ProxyInterface
	mutex     sync.RWMutex
}

// SSHServerInterface defines the methods we need from the SSH server
type SSHServerInterface interface {
	GetActiveTunnelSubdomains() []string
}

// ProxyInterface defines the methods we need from the proxy
type ProxyInterface interface {
	GetTunnel(subdomain string) (string, bool)
}

// NewSSHServerAdapter creates a new adapter
func NewSSHServerAdapter(sshServer SSHServerInterface, proxy ProxyInterface) *SSHServerAdapter {
	return &SSHServerAdapter{
		sshServer: sshServer,
		proxy:     proxy,
	}
}

// GetActiveTunnelSubdomains implements SSHTunnelProvider interface
func (a *SSHServerAdapter) GetActiveTunnelSubdomains() []string {
	if a.sshServer == nil {
		return []string{}
	}
	return a.sshServer.GetActiveTunnelSubdomains()
}

// GetTunnelInfo implements SSHTunnelProvider interface
func (a *SSHServerAdapter) GetTunnelInfo(subdomain string) (string, bool) {
	if a.proxy == nil {
		return "", false
	}
	return a.proxy.GetTunnel(subdomain)
}

// UserStoreAdapter adapts WebUI UserStore to SSH UserStore interface
type UserStoreAdapter struct {
	userStore UserStore
}

// NewUserStoreAdapter creates a new user store adapter
func NewUserStoreAdapter(userStore UserStore) *UserStoreAdapter {
	return &UserStoreAdapter{
		userStore: userStore,
	}
}

// GetUser implements SSH UserStore interface (for backward compatibility)
func (a *UserStoreAdapter) GetUser(username string) (string, bool) {
	return a.userStore.GetUser(username)
}

// VerifyPassword implements SSH UserStore interface (uses bcrypt for FileUserStore)
func (a *UserStoreAdapter) VerifyPassword(username, password string) bool {
	return a.userStore.VerifyPassword(username, password)
}
