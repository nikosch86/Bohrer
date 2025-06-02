package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Valid test SSH keys
const (
	validRSAKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQJlMbPPckn2OGPx+z7rkrQF1nHB1BfmmHecBCYr7sL6ozZPZZnRrCNvyu5CL1JmE6Hm4t9K3hGauvgDw0hOzwz5/5OCD6R8ttKoAhekSs2kaLN3Q8pAIWknKKE6dlCJcqJo8mdOcgYUf4SQ3tafGmHXzvWMfWsMKdhH8A6R+RaYOn6KaxU7F9bPKg8QpNhKDQcw5ZgcKkjL9dYoTosXMxJ9ks9zPD3P2LLvV8rV3CdRnO0w3sboaVGmMEYPCU0Rzl1CVFLb/cOJmPNxK1xXfrDKTGDpIMAcr+xNnJwe7ClbADJxVtcBYrKKg3i1s5LZ7RE3pfmLfAOIhXMXJyVXsn test@example.com"
	validED25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"
)

func TestInMemorySSHKeyStore(t *testing.T) {
	store := NewInMemorySSHKeyStore()

	// Test adding a valid SSH key
	err := store.AddKey("test-key", validRSAKey, "Test comment")
	if err != nil {
		t.Fatalf("Failed to add valid key: %v", err)
	}

	// Test getting the key
	keyData, exists := store.GetKey("test-key")
	if !exists {
		t.Fatal("Key should exist")
	}
	if keyData.Name != "test-key" {
		t.Errorf("Expected key name 'test-key', got %s", keyData.Name)
	}
	if keyData.Comment != "Test comment" {
		t.Errorf("Expected comment 'Test comment', got %s", keyData.Comment)
	}
	if keyData.KeyType != "ssh-rsa" {
		t.Errorf("Expected key type 'ssh-rsa', got %s", keyData.KeyType)
	}

	// Test getting all keys
	keys := store.GetAllKeys()
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}

	// Test authorized keys content
	content := store.GetAuthorizedKeysContent()
	if !strings.Contains(content, validRSAKey) {
		t.Error("Authorized keys content should contain the key")
	}
	if !strings.Contains(content, "Test comment") {
		t.Error("Authorized keys content should contain the comment")
	}

	// Test deleting a key
	err = store.DeleteKey("test-key")
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is deleted
	_, exists = store.GetKey("test-key")
	if exists {
		t.Error("Key should not exist after deletion")
	}

	// Test getting all keys after deletion
	keys = store.GetAllKeys()
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys after deletion, got %d", len(keys))
	}
}

func TestInMemorySSHKeyStore_Validation(t *testing.T) {
	store := NewInMemorySSHKeyStore()

	// Test empty key name
	err := store.AddKey("", validRSAKey, "comment")
	if err == nil {
		t.Error("Should fail with empty key name")
	}

	// Test empty public key
	err = store.AddKey("test", "", "comment")
	if err == nil {
		t.Error("Should fail with empty public key")
	}

	// Test invalid public key
	err = store.AddKey("test", "not-a-valid-key", "comment")
	if err == nil {
		t.Error("Should fail with invalid public key")
	}

	// Test duplicate key name
	err = store.AddKey("duplicate", validRSAKey, "comment1")
	if err != nil {
		t.Fatalf("Failed to add first key: %v", err)
	}
	err = store.AddKey("duplicate", validRSAKey, "comment2")
	if err == nil {
		t.Error("Should fail with duplicate key name")
	}
}

func TestInMemorySSHKeyStore_ValidateKey(t *testing.T) {
	store := NewInMemorySSHKeyStore()

	tests := []struct {
		name      string
		key       string
		wantError bool
	}{
		{
			name:      "valid ssh-rsa key",
			key:       validRSAKey,
			wantError: false,
		},
		{
			name:      "valid ssh-ed25519 key",
			key:       validED25519Key,
			wantError: false,
		},
		{
			name:      "empty key",
			key:       "",
			wantError: true,
		},
		{
			name:      "invalid key format",
			key:       "invalid-key-format",
			wantError: true,
		},
		{
			name:      "key with extra whitespace",
			key:       "  " + validRSAKey + "  ",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.ValidateKey(tt.key)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateKey() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestFileSSHKeyStore(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ssh_keys.json")

	// Test creating new file store
	store, err := NewFileSSHKeyStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create file store: %v", err)
	}

	// Test adding a valid SSH key
	err = store.AddKey("test-key", validRSAKey, "Test comment")
	if err != nil {
		t.Fatalf("Failed to add valid key: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("SSH keys file should exist after adding key")
	}

	// Test persistence - create new store instance
	store2, err := NewFileSSHKeyStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create second file store: %v", err)
	}

	// Verify key persisted
	keyData, exists := store2.GetKey("test-key")
	if !exists {
		t.Fatal("Key should exist in new store instance")
	}
	if keyData.Name != "test-key" {
		t.Errorf("Expected key name 'test-key', got %s", keyData.Name)
	}

	// Test getting all keys
	keys := store2.GetAllKeys()
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}

	// Test authorized keys content
	content := store2.GetAuthorizedKeysContent()
	if !strings.Contains(content, validRSAKey) {
		t.Error("Authorized keys content should contain the key")
	}

	// Test deleting a key
	err = store2.DeleteKey("test-key")
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Test deleting non-existent key
	err = store2.DeleteKey("non-existent")
	if err == nil {
		t.Error("Should fail when deleting non-existent key")
	}
}

func TestFileSSHKeyStore_InvalidPath(t *testing.T) {
	t.Skip("Skipping path creation test as it's environment-dependent")
	// Test with invalid path (path that cannot be created)
	_, err := NewFileSSHKeyStore("/root/invalid/path/that/cannot/be/created/ssh_keys.json")
	if err == nil {
		t.Error("Should fail with invalid path")
	}
}

func TestFileSSHKeyStore_CorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ssh_keys.json")

	// Write corrupt JSON
	err := os.WriteFile(filePath, []byte("not valid json"), 0644)
	if err != nil {
		t.Fatalf("Failed to write corrupt file: %v", err)
	}

	// Should handle corrupt file gracefully
	store, err := NewFileSSHKeyStore(filePath)
	if err != nil {
		t.Fatalf("Should handle corrupt file gracefully: %v", err)
	}

	// Should start with empty store
	keys := store.GetAllKeys()
	if len(keys) != 0 {
		t.Errorf("Expected empty store after corrupt file, got %d keys", len(keys))
	}
}

func TestFileSSHKeyStore_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ssh_keys.json")

	// Create empty file
	err := os.WriteFile(filePath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	// Should handle empty file gracefully
	store, err := NewFileSSHKeyStore(filePath)
	if err != nil {
		t.Fatalf("Should handle empty file gracefully: %v", err)
	}

	// Should start with empty store
	keys := store.GetAllKeys()
	if len(keys) != 0 {
		t.Errorf("Expected empty store after empty file, got %d keys", len(keys))
	}
}

func TestNewSSHKeyStore(t *testing.T) {
	// Test memory store
	store, err := NewSSHKeyStore("memory", "/tmp/test.json")
	if err != nil {
		t.Fatalf("Failed to create memory store: %v", err)
	}
	if _, ok := store.(*InMemorySSHKeyStore); !ok {
		t.Error("Expected InMemorySSHKeyStore for 'memory' type")
	}

	// Test file store
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ssh_keys.json")
	store, err = NewSSHKeyStore("file", filePath)
	if err != nil {
		t.Fatalf("Failed to create file store: %v", err)
	}
	if _, ok := store.(*FileSSHKeyStore); !ok {
		t.Error("Expected FileSSHKeyStore for 'file' type")
	}

	// Test default (unknown type)
	store, err = NewSSHKeyStore("unknown", "/tmp/test.json")
	if err != nil {
		t.Fatalf("Failed to create store with unknown type: %v", err)
	}
	if _, ok := store.(*InMemorySSHKeyStore); !ok {
		t.Error("Expected InMemorySSHKeyStore for unknown type")
	}
}

func TestSSHKeyStore_AuthorizedKeysFormat(t *testing.T) {
	store := NewInMemorySSHKeyStore()

	// Add keys with different scenarios
	store.AddKey("key1", validRSAKey, "Comment 1")
	store.AddKey("key2", validED25519Key, "")  // No comment
	
	content := store.GetAuthorizedKeysContent()
	lines := strings.Split(strings.TrimSpace(content), "\n")
	
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}
	
	// First key should have comment appended
	if !strings.Contains(lines[0], "Comment 1") {
		t.Error("First key should have comment")
	}
	
	// Second key already has a comment in the key itself
	if !strings.Contains(lines[1], validED25519Key) {
		t.Error("Second key should be present")
	}
}