package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bohrer-go/internal/config"
)

func TestNewWebUI(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)
	if webui == nil {
		t.Fatal("Expected WebUI to be created")
	}

	if webui.config != cfg {
		t.Error("Expected config to be set")
	}

	if webui.userStore == nil {
		t.Error("Expected user store to be initialized")
	}
}

func TestDashboardHandler(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)
	
	// Create mock tunnel provider
	mockProvider := &MockTunnelProvider{
		tunnels: []Tunnel{
			{Subdomain: "api", Target: "localhost:3000", Active: true},
			{Subdomain: "web", Target: "localhost:8080", Active: true},
		},
	}
	webui.SetTunnelProvider(mockProvider)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	webui.handleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Tunnel Dashboard") {
		t.Error("Expected dashboard title in response")
	}

	if !strings.Contains(body, "api") || !strings.Contains(body, "web") {
		t.Error("Expected tunnel information in response")
	}
}

func TestUsersHandler(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	req := httptest.NewRequest("GET", "/users", nil)
	rr := httptest.NewRecorder()

	webui.handleUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "User Management") {
		t.Error("Expected user management title in response")
	}
}

func TestCreateUserHandler(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	// Test POST request to create user
	formData := "username=testuser&password=testpass"
	req := httptest.NewRequest("POST", "/users", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	webui.handleUsers(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 (redirect), got %d", rr.Code)
	}

	// Check if user was created
	if _, exists := webui.userStore.GetUser("testuser"); !exists {
		t.Error("Expected user to be created in store")
	}
}

func TestDeleteUserHandler(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	// First create a user
	webui.userStore.CreateUser("testuser", "testpass")

	// Test DELETE request
	req := httptest.NewRequest("DELETE", "/users/testuser", nil)
	rr := httptest.NewRecorder()

	webui.handleDeleteUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check if user was deleted
	if _, exists := webui.userStore.GetUser("testuser"); exists {
		t.Error("Expected user to be deleted from store")
	}
}

func TestTunnelProviderIntegration(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)
	
	// Initially no tunnel provider
	tunnels := webui.getTunnels()
	if len(tunnels) != 0 {
		t.Error("Expected no tunnels without tunnel provider")
	}

	// Set tunnel provider
	mockProvider := &MockTunnelProvider{
		tunnels: []Tunnel{
			{Subdomain: "test", Target: "localhost:8000", Active: true},
		},
	}
	webui.SetTunnelProvider(mockProvider)

	tunnels = webui.getTunnels()
	if len(tunnels) != 1 {
		t.Errorf("Expected 1 tunnel, got %d", len(tunnels))
	}

	if tunnels[0].Subdomain != "test" {
		t.Errorf("Expected subdomain 'test', got %s", tunnels[0].Subdomain)
	}
}

// Mock implementations for testing

type MockTunnelProvider struct {
	tunnels []Tunnel
}

func (m *MockTunnelProvider) GetActiveTunnels() []Tunnel {
	return m.tunnels
}

type MockUserStore struct {
	users map[string]string
}

func (m *MockUserStore) CreateUser(username, password string) error {
	if m.users == nil {
		m.users = make(map[string]string)
	}
	m.users[username] = password
	return nil
}

func (m *MockUserStore) GetUser(username string) (string, bool) {
	if m.users == nil {
		return "", false
	}
	password, exists := m.users[username]
	return password, exists
}

func (m *MockUserStore) DeleteUser(username string) error {
	if m.users == nil {
		return nil
	}
	delete(m.users, username)
	return nil
}

func (m *MockUserStore) GetAllUsers() []string {
	if m.users == nil {
		return []string{}
	}
	var users []string
	for username := range m.users {
		users = append(users, username)
	}
	return users
}

func (m *MockUserStore) VerifyPassword(username, password string) bool {
	if m.users == nil {
		return false
	}
	storedPassword, exists := m.users[username]
	return exists && storedPassword == password
}

func TestInMemoryUserStore_DuplicateUser(t *testing.T) {
	store := NewInMemoryUserStore()
	
	// Create first user
	err := store.CreateUser("alice", "password123")
	if err != nil {
		t.Fatalf("Failed to create first user: %v", err)
	}
	
	// Try to create duplicate user
	err = store.CreateUser("alice", "differentpassword")
	if err == nil {
		t.Error("Expected error when creating duplicate user, got nil")
	}
	
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Expected 'already exists' error, got: %v", err)
	}
}


func TestWebUI_CreateUser_Duplicate(t *testing.T) {
	cfg := &config.Config{
		Domain:        "test.local",
		WebUIUsername: "admin",
		WebUIPassword: "admin123",
	}
	
	webui := NewWebUI(cfg)
	
	// Create first user
	err := webui.GetUserStore().CreateUser("charlie", "pass789")
	if err != nil {
		t.Fatalf("Failed to create first user: %v", err)
	}
	
	// Test duplicate user creation via HTTP endpoint
	req := httptest.NewRequest("POST", "/users", strings.NewReader("username=charlie&password=newpass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", "admin123")
	rr := httptest.NewRecorder()
	
	webui.handleUsers(rr, req)
	
	// Check for conflict status
	if rr.Code != http.StatusConflict {
		t.Errorf("Expected status 409 (Conflict), got %d", rr.Code)
	}
	
	// Check error message
	body := rr.Body.String()
	if !strings.Contains(body, "already exists") {
		t.Errorf("Expected 'already exists' in error message, got: %s", body)
	}
}

func TestHandleAPITunnels(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)
	
	// Create mock tunnel provider
	mockProvider := &MockTunnelProvider{
		tunnels: []Tunnel{
			{Subdomain: "api", Target: "localhost:3000", Active: true, HTTPURL: "http://api.example.com", HTTPSURL: "https://api.example.com"},
			{Subdomain: "web", Target: "localhost:8080", Active: true, HTTPURL: "http://web.example.com", HTTPSURL: "https://web.example.com"},
		},
	}
	webui.SetTunnelProvider(mockProvider)

	// Test GET request
	req := httptest.NewRequest("GET", "/api/tunnels", nil)
	rr := httptest.NewRecorder()

	webui.handleAPITunnels(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check content type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", contentType)
	}

	// Check response body contains tunnel data
	body := rr.Body.String()
	if !strings.Contains(body, "api") || !strings.Contains(body, "web") {
		t.Error("Response should contain tunnel subdomains")
	}
	if !strings.Contains(body, "localhost:3000") || !strings.Contains(body, "localhost:8080") {
		t.Error("Response should contain tunnel targets")
	}

	// Test non-GET request
	req = httptest.NewRequest("POST", "/api/tunnels", nil)
	rr = httptest.NewRecorder()

	webui.handleAPITunnels(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

func TestGetSSHKeyStore(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)
	
	keyStore := webui.GetSSHKeyStore()
	if keyStore == nil {
		t.Fatal("Expected SSH key store to be initialized")
	}
}

func TestHandleSSHKeys(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	// Test GET request
	req := httptest.NewRequest("GET", "/ssh-keys", nil)
	rr := httptest.NewRecorder()

	webui.handleSSHKeys(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Check response contains SSH keys page elements
	body := rr.Body.String()
	if !strings.Contains(body, "SSH Key Management") {
		t.Error("Response should contain SSH Key Management title")
	}

	// Test POST request (create SSH key)
	formData := strings.NewReader("name=test-key&public_key=ssh-rsa+AAAAB3NzaC1yc2EAAAADAQABAAABAQDQJlMbPPckn2OGPx%2Bz7rkrQF1nHB1BfmmHecBCYr7sL6ozZPZZnRrCNvyu5CL1JmE6Hm4t9K3hGauvgDw0hOzwz5%2F5OCD6R8ttKoAhekSs2kaLN3Q8pAIWknKKE6dlCJcqJo8mdOcgYUf4SQ3tafGmHXzvWMfWsMKdhH8A6R%2BRaYOn6KaxU7F9bPKg8QpNhKDQcw5ZgcKkjL9dYoTosXMxJ9ks9zPD3P2LLvV8rV3CdRnO0w3sboaVGmMEYPCU0Rzl1CVFLb%2FcOJmPNxK1xXfrDKTGDpIMAcr%2BxNnJwe7ClbADJxVtcBYrKKg3i1s5LZ7RE3pfmLfAOIhXMXJyVXsn+test%40example.com&comment=Test+comment")
	req = httptest.NewRequest("POST", "/ssh-keys", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()

	webui.handleSSHKeys(rr, req)

	// Should redirect after creation
	if rr.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 (See Other), got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/ssh-keys" {
		t.Errorf("Expected redirect to '/ssh-keys', got %s", location)
	}
}

func TestHandleDeleteSSHKey(t *testing.T) {
	cfg := &config.Config{
		Domain: "example.com",
	}

	webui := NewWebUI(cfg)

	// First add a key
	webui.sshKeyStore.AddKey("test-key", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQJlMbPPckn2OGPx+z7rkrQF1nHB1BfmmHecBCYr7sL6ozZPZZnRrCNvyu5CL1JmE6Hm4t9K3hGauvgDw0hOzwz5/5OCD6R8ttKoAhekSs2kaLN3Q8pAIWknKKE6dlCJcqJo8mdOcgYUf4SQ3tafGmHXzvWMfWsMKdhH8A6R+RaYOn6KaxU7F9bPKg8QpNhKDQcw5ZgcKkjL9dYoTosXMxJ9ks9zPD3P2LLvV8rV3CdRnO0w3sboaVGmMEYPCU0Rzl1CVFLb/cOJmPNxK1xXfrDKTGDpIMAcr+xNnJwe7ClbADJxVtcBYrKKg3i1s5LZ7RE3pfmLfAOIhXMXJyVXsn test@example.com", "Test comment")

	// Test DELETE request
	req := httptest.NewRequest("DELETE", "/ssh-keys/test-key", nil)
	rr := httptest.NewRecorder()

	webui.handleDeleteSSHKey(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Verify key was deleted
	_, exists := webui.sshKeyStore.GetKey("test-key")
	if exists {
		t.Error("Key should have been deleted")
	}

	// Test deleting non-existent key
	req = httptest.NewRequest("DELETE", "/ssh-keys/non-existent", nil)
	rr = httptest.NewRecorder()

	webui.handleDeleteSSHKey(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for non-existent key, got %d", rr.Code)
	}

	// Test non-DELETE request
	req = httptest.NewRequest("GET", "/ssh-keys/test-key", nil)
	rr = httptest.NewRecorder()

	webui.handleDeleteSSHKey(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

func TestInMemoryUserStore_VerifyPassword(t *testing.T) {
	store := NewInMemoryUserStore()
	
	// Create a user
	err := store.CreateUser("testuser", "testpass")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test correct password
	if !store.VerifyPassword("testuser", "testpass") {
		t.Error("Should verify correct password")
	}

	// Test incorrect password
	if store.VerifyPassword("testuser", "wrongpass") {
		t.Error("Should not verify incorrect password")
	}

	// Test non-existent user
	if store.VerifyPassword("nonexistent", "anypass") {
		t.Error("Should not verify non-existent user")
	}
}