package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	
	"bohrer-go/internal/testutil"
)

func TestInMemorySSHKeyStore(t *testing.T) {
	store := NewInMemorySSHKeyStore()

	// Test adding a valid SSH key
	err := store.AddKey("test-key", testutil.ValidRSAKey, "Test comment")
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
	if !strings.Contains(content, testutil.ValidRSAKey) {
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
	err := store.AddKey("", testutil.ValidRSAKey, "comment")
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
	err = store.AddKey("duplicate", testutil.ValidRSAKey, "comment1")
	if err != nil {
		t.Fatalf("Failed to add first key: %v", err)
	}
	err = store.AddKey("duplicate", testutil.ValidRSAKey, "comment2")
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
			key:       testutil.ValidRSAKey,
			wantError: false,
		},
		{
			name:      "valid ssh-ed25519 key",
			key:       testutil.ValidED25519Key,
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
			key:       "  " + testutil.ValidRSAKey + "  ",
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
	err = store.AddKey("test-key", testutil.ValidRSAKey, "Test comment")
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
	if !strings.Contains(content, testutil.ValidRSAKey) {
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
	store.AddKey("key1", testutil.ValidRSAKey, "Comment 1")
	store.AddKey("key2", testutil.ValidED25519Key, "")  // No comment
	
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
	if !strings.Contains(lines[1], testutil.ValidED25519Key) {
		t.Error("Second key should be present")
	}
}

func TestFormatAuthorizedKeysContent(t *testing.T) {
	tests := []struct {
		name     string
		keys     []SSHKeyData
		expected []string
	}{
		{
			name: "key with comment",
			keys: []SSHKeyData{
				{PublicKey: testutil.ValidRSAKey, Comment: "my comment"},
			},
			expected: []string{
				testutil.ValidRSAKey + " my comment",
			},
		},
		{
			name: "key without comment",
			keys: []SSHKeyData{
				{PublicKey: testutil.ValidRSAKey, Comment: ""},
			},
			expected: []string{
				testutil.ValidRSAKey,
			},
		},
		{
			name: "key with whitespace",
			keys: []SSHKeyData{
				{PublicKey: "  " + testutil.ValidRSAKey + "  ", Comment: "trimmed"},
			},
			expected: []string{
				testutil.ValidRSAKey + " trimmed",
			},
		},
		{
			name: "multiple keys",
			keys: []SSHKeyData{
				{PublicKey: testutil.ValidRSAKey, Comment: "key1"},
				{PublicKey: testutil.ValidED25519Key, Comment: "key2"},
			},
			expected: []string{
				testutil.ValidRSAKey + " key1",
				testutil.ValidED25519Key + " key2",
			},
		},
		{
			name: "empty keys",
			keys: []SSHKeyData{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatAuthorizedKeysContent(tt.keys)
			lines := strings.Split(strings.TrimSpace(result), "\n")
			
			// Handle empty case
			if len(tt.expected) == 0 && result == "" {
				return
			}
			
			if len(lines) != len(tt.expected) {
				t.Errorf("Expected %d lines, got %d", len(tt.expected), len(lines))
				return
			}
			
			for i, expected := range tt.expected {
				if lines[i] != expected {
					t.Errorf("Line %d: expected %q, got %q", i, expected, lines[i])
				}
			}
		})
	}
}

func TestValidateSSHPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid ssh-rsa key",
			key:       testutil.ValidRSAKey,
			wantError: false,
		},
		{
			name:      "valid ssh-ed25519 key",
			key:       testutil.ValidED25519Key,
			wantError: false,
		},
		{
			name:      "empty key",
			key:       "",
			wantError: true,
			errorMsg:  "public key cannot be empty",
		},
		{
			name:      "invalid key format",
			key:       "invalid-key-format",
			wantError: true,
			errorMsg:  "invalid SSH public key format",
		},
		{
			name:      "key with extra whitespace",
			key:       "  " + testutil.ValidRSAKey + "  ",
			wantError: false,
		},
		{
			name:      "whitespace only",
			key:       "   \t\n  ",
			wantError: true,
			errorMsg:  "public key cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHPublicKey(tt.key)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateSSHPublicKey() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("ValidateSSHPublicKey() error = %v, want error containing %v", err, tt.errorMsg)
			}
		})
	}
}