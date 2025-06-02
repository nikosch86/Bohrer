package mocks

import (
	"sync"
)

// UserStore is a mock implementation of UserStore for testing
type UserStore struct {
	users map[string]string
	mu    sync.RWMutex
}

// NewUserStore creates a new mock user store
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]string),
	}
}

// AddUser adds a user to the mock store
func (m *UserStore) AddUser(username, password string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[username] = password
}

// GetUser implements UserStore interface
func (m *UserStore) GetUser(username string) (password string, exists bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	password, exists = m.users[username]
	return
}

// VerifyPassword implements UserStore interface
func (m *UserStore) VerifyPassword(username, password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	storedPassword, exists := m.users[username]
	return exists && storedPassword == password
}

// SSHKeyStore is a mock implementation of SSHKeyStore for testing
type SSHKeyStore struct {
	content string
	mu      sync.RWMutex
}

// NewSSHKeyStore creates a new mock SSH key store
func NewSSHKeyStore(content string) *SSHKeyStore {
	return &SSHKeyStore{
		content: content,
	}
}

// GetAuthorizedKeysContent implements SSHKeyStore interface
func (m *SSHKeyStore) GetAuthorizedKeysContent() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.content
}

// SetContent updates the authorized keys content
func (m *SSHKeyStore) SetContent(content string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.content = content
}