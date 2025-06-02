package webui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"bohrer-go/internal/fileutil"
	"bohrer-go/internal/logger"
	"golang.org/x/crypto/ssh"
)

// ValidateSSHPublicKey validates an SSH public key format
// This is a standalone function to avoid code duplication
func ValidateSSHPublicKey(publicKey string) error {
	// Trim whitespace
	publicKey = strings.TrimSpace(publicKey)

	if publicKey == "" {
		return fmt.Errorf("public key cannot be empty")
	}

	// Try to parse the public key
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return fmt.Errorf("invalid SSH public key format: %v", err)
	}

	return nil
}

// FormatAuthorizedKeysContent formats SSH keys for authorized_keys file
// This is a standalone function to avoid code duplication
func FormatAuthorizedKeysContent(keys []SSHKeyData) string {
	var lines []string
	for _, key := range keys {
		// Format: public_key comment
		line := strings.TrimSpace(key.PublicKey)
		if key.Comment != "" {
			line = fmt.Sprintf("%s %s", line, key.Comment)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// SSHKeyStore interface for managing SSH public keys
type SSHKeyStore interface {
	AddKey(name, publicKey, comment string) error
	GetKey(name string) (SSHKeyData, bool)
	DeleteKey(name string) error
	GetAllKeys() []SSHKeyData
	ValidateKey(publicKey string) error
	GetAuthorizedKeysContent() string
}

// SSHKeyData represents stored SSH key information
type SSHKeyData struct {
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	Comment   string    `json:"comment"`
	KeyType   string    `json:"key_type"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FileSSHKeyStore implements SSHKeyStore with file-based persistence
type FileSSHKeyStore struct {
	filePath string
	keys     map[string]SSHKeyData
	mutex    sync.RWMutex
}

// NewFileSSHKeyStore creates a new file-based SSH key store
func NewFileSSHKeyStore(filePath string) (*FileSSHKeyStore, error) {
	store := &FileSSHKeyStore{
		filePath: filePath,
		keys:     make(map[string]SSHKeyData),
	}

	// Load existing keys from file
	if err := store.loadFromFile(); err != nil {
		logger.Warnf("Failed to load SSH keys from file %s: %v", filePath, err)
		// Continue with empty store - file might not exist yet
	}

	return store, nil
}

// loadFromFile loads SSH keys from the JSON file
func (s *FileSSHKeyStore) loadFromFile() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if file exists
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		logger.Debugf("SSH key store file %s does not exist, starting with empty store", s.filePath)
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	if len(data) == 0 {
		logger.Debugf("SSH key store file %s is empty, starting with empty store", s.filePath)
		return nil
	}

	var keys []SSHKeyData
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	// Convert slice to map
	s.keys = make(map[string]SSHKeyData)
	for _, key := range keys {
		s.keys[key.Name] = key
	}

	logger.Debugf("Loaded %d SSH keys from file %s", len(s.keys), s.filePath)
	return nil
}

// saveToFile saves SSH keys to the JSON file
func (s *FileSSHKeyStore) saveToFile() error {
	// Convert map to slice
	keys := make([]SSHKeyData, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Use atomic write to prevent corruption
	if err := fileutil.WriteAtomicFile(s.filePath, data, 0644); err != nil {
		return err
	}

	logger.Debugf("Saved %d SSH keys to file %s", len(keys), s.filePath)
	return nil
}

// ValidateKey validates an SSH public key format
func (s *FileSSHKeyStore) ValidateKey(publicKey string) error {
	return ValidateSSHPublicKey(publicKey)
}

// AddKey adds a new SSH public key
func (s *FileSSHKeyStore) AddKey(name, publicKey, comment string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if name == "" {
		return fmt.Errorf("key name cannot be empty")
	}

	// Validate the public key
	if err := s.ValidateKey(publicKey); err != nil {
		return err
	}

	// Check if key name already exists
	if _, exists := s.keys[name]; exists {
		return fmt.Errorf("SSH key with name %s already exists", name)
	}

	// Parse the key to get type information
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %v", err)
	}

	// Extract key type
	keyType := parsedKey.Type()

	// Create key data
	now := time.Now()
	keyData := SSHKeyData{
		Name:      name,
		PublicKey: strings.TrimSpace(publicKey),
		Comment:   comment,
		KeyType:   keyType,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Add to memory store
	s.keys[name] = keyData

	// Save to file
	if err := s.saveToFile(); err != nil {
		// Remove from memory if save failed
		delete(s.keys, name)
		return fmt.Errorf("failed to save SSH key to file: %v", err)
	}

	logger.Infof("SSH key %s (%s) added and saved to file", name, keyType)
	return nil
}

// GetKey retrieves an SSH key by name
func (s *FileSSHKeyStore) GetKey(name string) (SSHKeyData, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keyData, exists := s.keys[name]
	return keyData, exists
}

// DeleteKey removes an SSH key
func (s *FileSSHKeyStore) DeleteKey(name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if key exists
	if _, exists := s.keys[name]; !exists {
		return fmt.Errorf("SSH key %s does not exist", name)
	}

	// Remove from memory
	delete(s.keys, name)

	// Save to file
	if err := s.saveToFile(); err != nil {
		return fmt.Errorf("failed to save after SSH key deletion: %v", err)
	}

	logger.Infof("SSH key %s deleted and file updated", name)
	return nil
}

// GetAllKeys returns all SSH keys
func (s *FileSSHKeyStore) GetAllKeys() []SSHKeyData {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]SSHKeyData, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	return keys
}

// GetAuthorizedKeysContent returns the content for authorized_keys file
func (s *FileSSHKeyStore) GetAuthorizedKeysContent() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]SSHKeyData, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	return FormatAuthorizedKeysContent(keys)
}

// InMemorySSHKeyStore implements SSHKeyStore interface for testing
type InMemorySSHKeyStore struct {
	keys  map[string]SSHKeyData
	mutex sync.RWMutex
}

// NewInMemorySSHKeyStore creates a new in-memory SSH key store
func NewInMemorySSHKeyStore() *InMemorySSHKeyStore {
	return &InMemorySSHKeyStore{
		keys: make(map[string]SSHKeyData),
	}
}

// ValidateKey validates an SSH public key format
func (s *InMemorySSHKeyStore) ValidateKey(publicKey string) error {
	return ValidateSSHPublicKey(publicKey)
}

// AddKey adds a new SSH public key
func (s *InMemorySSHKeyStore) AddKey(name, publicKey, comment string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if name == "" {
		return fmt.Errorf("key name cannot be empty")
	}

	// Validate the public key
	if err := s.ValidateKey(publicKey); err != nil {
		return err
	}

	// Check if key name already exists
	if _, exists := s.keys[name]; exists {
		return fmt.Errorf("SSH key with name %s already exists", name)
	}

	// Parse the key to get type information
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %v", err)
	}

	// Extract key type
	keyType := parsedKey.Type()

	// Create key data
	now := time.Now()
	keyData := SSHKeyData{
		Name:      name,
		PublicKey: strings.TrimSpace(publicKey),
		Comment:   comment,
		KeyType:   keyType,
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.keys[name] = keyData
	return nil
}

// GetKey retrieves an SSH key by name
func (s *InMemorySSHKeyStore) GetKey(name string) (SSHKeyData, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keyData, exists := s.keys[name]
	return keyData, exists
}

// DeleteKey removes an SSH key
func (s *InMemorySSHKeyStore) DeleteKey(name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.keys[name]; !exists {
		return fmt.Errorf("SSH key %s does not exist", name)
	}

	delete(s.keys, name)
	return nil
}

// GetAllKeys returns all SSH keys
func (s *InMemorySSHKeyStore) GetAllKeys() []SSHKeyData {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]SSHKeyData, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	return keys
}

// GetAuthorizedKeysContent returns the content for authorized_keys file
func (s *InMemorySSHKeyStore) GetAuthorizedKeysContent() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]SSHKeyData, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	return FormatAuthorizedKeysContent(keys)
}

// NewSSHKeyStore creates an SSH key store based on configuration
func NewSSHKeyStore(storageType, filePath string) (SSHKeyStore, error) {
	switch storageType {
	case "file":
		return NewFileSSHKeyStore(filePath)
	case "memory":
		fallthrough
	default:
		logger.Infof("Using in-memory SSH key store (storage_type=%s)", storageType)
		return NewInMemorySSHKeyStore(), nil
	}
}
