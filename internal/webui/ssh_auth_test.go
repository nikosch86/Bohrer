package webui

import (
	"testing"

	"bohrer-go/internal/config"
)

func TestUserStoreForSSHAuth(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	// Create some users
	err := webui.userStore.CreateUser("alice", "password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	err = webui.userStore.CreateUser("bob", "secret456")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test authentication
	password, exists := webui.userStore.GetUser("alice")
	if !exists {
		t.Error("Expected user 'alice' to exist")
	}
	if password != "password123" {
		t.Errorf("Expected password 'password123', got '%s'", password)
	}

	// Test invalid user
	_, exists = webui.userStore.GetUser("charlie")
	if exists {
		t.Error("Expected user 'charlie' to not exist")
	}

	// Test user listing
	users := webui.userStore.GetAllUsers()
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

func TestUserStorePasswordAuthentication(t *testing.T) {
	store := NewInMemoryUserStore()

	// Create user
	err := store.CreateUser("testuser", "mypassword")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test correct password
	password, exists := store.GetUser("testuser")
	if !exists {
		t.Error("Expected user to exist")
	}
	if password != "mypassword" {
		t.Error("Password mismatch")
	}

	// Test user deletion
	err = store.DeleteUser("testuser")
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	// Verify user is deleted
	_, exists = store.GetUser("testuser")
	if exists {
		t.Error("Expected user to be deleted")
	}
}

