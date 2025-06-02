package webui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestFileUserStore_CreateAndRetrieveUser(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Test creating a user
	username := "testuser"
	password := "testpassword123"

	err = store.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test retrieving user
	hashedPassword, exists := store.GetUser(username)
	if !exists {
		t.Error("Expected user to exist")
	}

	// Verify password hash
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		t.Error("Password hash verification failed")
	}

	// Test VerifyPassword method
	if !store.VerifyPassword(username, password) {
		t.Error("VerifyPassword should return true for correct password")
	}

	if store.VerifyPassword(username, "wrongpassword") {
		t.Error("VerifyPassword should return false for incorrect password")
	}
}

func TestFileUserStore_FilePersistence(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")

	// Create first store and add users
	store1, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	err = store1.CreateUser("alice", "password123")
	if err != nil {
		t.Fatalf("Failed to create user alice: %v", err)
	}

	err = store1.CreateUser("bob", "secret456")
	if err != nil {
		t.Fatalf("Failed to create user bob: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("User store file should have been created")
	}

	// Create second store from same file (simulating restart)
	store2, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create second FileUserStore: %v", err)
	}

	// Verify users were loaded
	if !store2.VerifyPassword("alice", "password123") {
		t.Error("Alice's password should be correct after reload")
	}

	if !store2.VerifyPassword("bob", "secret456") {
		t.Error("Bob's password should be correct after reload")
	}

	// Verify user list
	users := store2.GetAllUsers()
	if len(users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users))
	}

	expectedUsers := map[string]bool{"alice": false, "bob": false}
	for _, user := range users {
		if _, exists := expectedUsers[user]; exists {
			expectedUsers[user] = true
		}
	}

	for user, found := range expectedUsers {
		if !found {
			t.Errorf("Expected user %s not found in list", user)
		}
	}
}

func TestFileUserStore_JSONFormat(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Create a user
	username := "testuser"
	password := "testpass"
	err = store.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Read and validate JSON file directly
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read user file: %v", err)
	}

	var users []UserData
	err = json.Unmarshal(data, &users)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected 1 user in JSON, got %d", len(users))
	}

	user := users[0]
	if user.Username != username {
		t.Errorf("Expected username %s, got %s", username, user.Username)
	}

	// Verify password is hashed (not plaintext)
	if user.PasswordHash == password {
		t.Error("Password should be hashed, not stored in plaintext")
	}

	// Verify bcrypt hash format (starts with $2a$, $2b$, etc.)
	if len(user.PasswordHash) < 60 || user.PasswordHash[:4] != "$2a$" && user.PasswordHash[:4] != "$2b$" {
		t.Error("Password hash does not appear to be bcrypt format")
	}

	// Verify timestamps are set
	if user.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	if user.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}

	// Verify password can be verified with bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		t.Error("Stored password hash should verify against original password")
	}
}

func TestFileUserStore_UserDeletion(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Create users
	store.CreateUser("alice", "password1")
	store.CreateUser("bob", "password2")
	store.CreateUser("charlie", "password3")

	// Verify all users exist
	users := store.GetAllUsers()
	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}

	// Delete one user
	err = store.DeleteUser("bob")
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	// Verify user is deleted from memory
	_, exists := store.GetUser("bob")
	if exists {
		t.Error("User bob should not exist after deletion")
	}

	// Verify other users still exist
	if !store.VerifyPassword("alice", "password1") {
		t.Error("Alice should still exist")
	}
	if !store.VerifyPassword("charlie", "password3") {
		t.Error("Charlie should still exist")
	}

	// Verify deletion persisted to file
	store2, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create second store: %v", err)
	}

	_, exists = store2.GetUser("bob")
	if exists {
		t.Error("User bob should not exist in reloaded store")
	}

	users = store2.GetAllUsers()
	if len(users) != 2 {
		t.Errorf("Expected 2 users after deletion, got %d", len(users))
	}
}

func TestFileUserStore_DuplicateUser(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Create user
	err = store.CreateUser("testuser", "password")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Try to create same user again
	err = store.CreateUser("testuser", "differentpassword")
	if err == nil {
		t.Error("Expected error when creating duplicate user")
	}

	// Verify original password still works
	if !store.VerifyPassword("testuser", "password") {
		t.Error("Original password should still work")
	}

	if store.VerifyPassword("testuser", "differentpassword") {
		t.Error("Different password should not work")
	}
}

func TestFileUserStore_EmptyCredentials(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Test empty username
	err = store.CreateUser("", "password")
	if err == nil {
		t.Error("Expected error for empty username")
	}

	// Test empty password
	err = store.CreateUser("user", "")
	if err == nil {
		t.Error("Expected error for empty password")
	}

	// Test both empty
	err = store.CreateUser("", "")
	if err == nil {
		t.Error("Expected error for both empty")
	}
}

func TestFileUserStore_NonExistentUser(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Test getting non-existent user
	_, exists := store.GetUser("nonexistent")
	if exists {
		t.Error("Non-existent user should not exist")
	}

	// Test verifying non-existent user
	if store.VerifyPassword("nonexistent", "password") {
		t.Error("Non-existent user should not verify")
	}

	// Test deleting non-existent user
	err = store.DeleteUser("nonexistent")
	if err == nil {
		t.Error("Expected error when deleting non-existent user")
	}
}

func TestFileUserStore_AtomicWrites(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")
	store, err := NewFileUserStore(filePath)
	if err != nil {
		t.Fatalf("Failed to create FileUserStore: %v", err)
	}

	// Create initial user
	err = store.CreateUser("user1", "password1")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Check that no temporary files are left behind
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".tmp" {
			t.Errorf("Temporary file %s should not exist", file.Name())
		}
	}

	// Verify the main file exists and is valid
	if _, err := os.Stat(filePath); err != nil {
		t.Errorf("Main user file should exist: %v", err)
	}
}

func TestNewUserStore_Factory(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "userstore_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "users.json")

	// Test file store creation
	store, err := NewUserStore("file", filePath)
	if err != nil {
		t.Fatalf("Failed to create file store: %v", err)
	}

	// Verify it's a FileUserStore
	_, ok := store.(*FileUserStore)
	if !ok {
		t.Error("Expected FileUserStore")
	}

	// Test memory store creation
	store, err = NewUserStore("memory", "")
	if err != nil {
		t.Fatalf("Failed to create memory store: %v", err)
	}

	// Verify it's an InMemoryUserStore
	_, ok = store.(*InMemoryUserStore)
	if !ok {
		t.Error("Expected InMemoryUserStore")
	}

	// Test default (unknown type)
	store, err = NewUserStore("unknown", "")
	if err != nil {
		t.Fatalf("Failed to create default store: %v", err)
	}

	// Verify it's an InMemoryUserStore (default)
	_, ok = store.(*InMemoryUserStore)
	if !ok {
		t.Error("Expected InMemoryUserStore as default")
	}
}
