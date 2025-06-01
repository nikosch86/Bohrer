package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"bohrer-go/internal/config"
	"bohrer-go/internal/logger"
)

// TunnelProvider interface to get tunnel information
type TunnelProvider interface {
	GetActiveTunnels() []Tunnel
}

// SSHTunnelProvider adapts SSH server tunnel information for WebUI
type SSHTunnelProvider interface {
	GetActiveTunnelSubdomains() []string
	GetTunnelInfo(subdomain string) (target string, exists bool)
}

// UserStore interface for managing SSH users
type UserStore interface {
	CreateUser(username, password string) error
	GetUser(username string) (string, bool)
	DeleteUser(username string) error
	GetAllUsers() []string
	VerifyPassword(username, password string) bool
}

// Tunnel represents a tunnel for display
type Tunnel struct {
	Subdomain string
	Target    string
	Active    bool
	HTTPURL   string
	HTTPSURL  string
}

// WebUI handles the web interface
type WebUI struct {
	config             *config.Config
	tunnelProvider     TunnelProvider
	sshTunnelProvider  SSHTunnelProvider
	userStore          UserStore
	templates          *template.Template
	adminUsername      string
	adminPassword      string
}

// generateRandomString generates a secure random string for passwords
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// NewWebUI creates a new WebUI instance
func NewWebUI(cfg *config.Config) *WebUI {
	logger.Debugf("Initializing WebUI with user storage: type=%s, path=%s", cfg.UserStorageType, cfg.UserStoragePath)
	userStore, err := NewUserStore(cfg.UserStorageType, cfg.UserStoragePath)
	if err != nil {
		logger.Errorf("Failed to create user store (type=%s, path=%s): %v", cfg.UserStorageType, cfg.UserStoragePath, err)
		logger.Infof("Falling back to in-memory user store")
		userStore = NewInMemoryUserStore()
	} else {
		logger.Debugf("Successfully created user store: type=%s, path=%s", cfg.UserStorageType, cfg.UserStoragePath)
	}

	// Setup WebUI admin credentials
	adminUsername := cfg.WebUIUsername
	adminPassword := cfg.WebUIPassword

	// Generate credentials if not provided
	if adminUsername == "" {
		adminUsername = "admin"
	}

	if adminPassword == "" {
		generatedPassword, err := generateRandomString(16)
		if err != nil {
			logger.Errorf("Failed to generate WebUI password: %v", err)
			adminPassword = "admin123" // Fallback password
			logger.Warnf("Using fallback WebUI password")
		} else {
			adminPassword = generatedPassword
		}
		logger.Infof("🔐 WebUI Admin Credentials (auto-generated):")
		logger.Infof("   Username: %s", adminUsername)
		logger.Infof("   Password: %s", adminPassword)
	} else {
		logger.Infof("Using configured WebUI admin credentials for user: %s", adminUsername)
	}

	webui := &WebUI{
		config:        cfg,
		userStore:     userStore,
		adminUsername: adminUsername,
		adminPassword: adminPassword,
	}

	webui.loadTemplates()
	return webui
}

// SetTunnelProvider sets the tunnel provider
func (w *WebUI) SetTunnelProvider(tp TunnelProvider) {
	w.tunnelProvider = tp
}

// SetSSHTunnelProvider sets the SSH tunnel provider
func (w *WebUI) SetSSHTunnelProvider(stp SSHTunnelProvider) {
	w.sshTunnelProvider = stp
}

// GetUserStore returns the user store for SSH authentication integration
func (w *WebUI) GetUserStore() UserStore {
	return w.userStore
}

// basicAuth implements HTTP Basic Authentication
func (w *WebUI) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.requireAuth(rw)
			return
		}

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(w.adminUsername)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(w.adminPassword)) == 1

		if !usernameMatch || !passwordMatch {
			logger.Warnf("WebUI authentication failed for user: %s from %s", username, r.RemoteAddr)
			w.requireAuth(rw)
			return
		}

		logger.Debugf("WebUI authentication successful for user: %s from %s", username, r.RemoteAddr)
		next(rw, r)
	}
}

// requireAuth sends a 401 Unauthorized response with Basic Auth challenge
func (w *WebUI) requireAuth(rw http.ResponseWriter) {
	rw.Header().Set("WWW-Authenticate", `Basic realm="SSH Tunnel Server WebUI"`)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusUnauthorized)
	rw.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <title>Authentication Required</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .error { color: #e74c3c; }
    </style>
</head>
<body>
    <h1 class="error">Authentication Required</h1>
    <p>You need to provide valid credentials to access the SSH Tunnel Server WebUI.</p>
    <p>Please check the server logs for generated credentials.</p>
</body>
</html>`))
}

// ServeHTTP implements http.Handler interface for the WebUI
func (w *WebUI) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		w.basicAuth(w.handleDashboard)(rw, r)
	case r.URL.Path == "/users":
		w.basicAuth(w.handleUsers)(rw, r)
	case strings.HasPrefix(r.URL.Path, "/users/") && r.Method == "DELETE":
		w.basicAuth(w.handleDeleteUser)(rw, r)
	case strings.HasPrefix(r.URL.Path, "/static/"):
		w.basicAuth(w.handleStatic)(rw, r)
	default:
		http.NotFound(rw, r)
	}
}

// RegisterRoutes registers the WebUI routes with an HTTP mux (alternative method)
func (w *WebUI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", w.basicAuth(w.handleDashboard))
	mux.HandleFunc("/users", w.basicAuth(w.handleUsers))
	mux.HandleFunc("/users/", w.basicAuth(w.handleDeleteUser))
	mux.HandleFunc("/static/", w.basicAuth(w.handleStatic))
}

// handleDashboard shows the main dashboard with tunnel information
func (w *WebUI) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	tunnels := w.getTunnels()

	data := struct {
		Domain  string
		Tunnels []Tunnel
	}{
		Domain:  w.config.Domain,
		Tunnels: tunnels,
	}

	if err := w.templates.ExecuteTemplate(rw, "dashboard.html", data); err != nil {
		logger.Errorf("Failed to render dashboard template: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleUsers handles user management page and user creation
func (w *WebUI) handleUsers(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.showUsersPage(rw, r)
	case "POST":
		w.createUser(rw, r)
	default:
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeleteUser handles user deletion
func (w *WebUI) handleDeleteUser(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := path.Base(r.URL.Path)
	if username == "" || username == "users" {
		http.Error(rw, "Username required", http.StatusBadRequest)
		return
	}

	if err := w.userStore.DeleteUser(username); err != nil {
		logger.Errorf("Failed to delete user %s: %v", username, err)
		http.Error(rw, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	logger.Infof("User %s deleted", username)
	rw.WriteHeader(http.StatusOK)
}

// handleStatic serves static files (CSS, JS)
func (w *WebUI) handleStatic(rw http.ResponseWriter, r *http.Request) {
	// Simple static file serving for basic CSS
	if strings.HasSuffix(r.URL.Path, ".css") {
		rw.Header().Set("Content-Type", "text/css")
		rw.Write([]byte(getBasicCSS()))
		return
	}

	http.NotFound(rw, r)
}

// showUsersPage displays the user management page
func (w *WebUI) showUsersPage(rw http.ResponseWriter, r *http.Request) {
	users := w.userStore.GetAllUsers()

	data := struct {
		Domain string
		Users  []string
	}{
		Domain: w.config.Domain,
		Users:  users,
	}

	if err := w.templates.ExecuteTemplate(rw, "users.html", data); err != nil {
		logger.Errorf("Failed to render users template: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
	}
}

// createUser creates a new SSH user
func (w *WebUI) createUser(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "Failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(rw, "Username and password required", http.StatusBadRequest)
		return
	}

	if err := w.userStore.CreateUser(username, password); err != nil {
		logger.Errorf("Failed to create user %s: %v", username, err)
		// Return specific error message to the user
		if strings.Contains(err.Error(), "already exists") {
			http.Error(rw, fmt.Sprintf("User %s already exists", username), http.StatusConflict)
		} else {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	logger.Infof("User %s created", username)

	// Redirect back to users page
	http.Redirect(rw, r, "/users", http.StatusSeeOther)
}

// getTunnels gets tunnel information from the tunnel provider
func (w *WebUI) getTunnels() []Tunnel {
	// Try SSH tunnel provider first (preferred)
	if w.sshTunnelProvider != nil {
		return w.getTunnelsFromSSH()
	}

	// Fallback to generic tunnel provider
	if w.tunnelProvider == nil {
		return []Tunnel{}
	}

	return w.tunnelProvider.GetActiveTunnels()
}

// getTunnelsFromSSH converts SSH tunnel data to WebUI tunnel format
func (w *WebUI) getTunnelsFromSSH() []Tunnel {
	subdomains := w.sshTunnelProvider.GetActiveTunnelSubdomains()
	tunnels := make([]Tunnel, 0, len(subdomains))

	for _, subdomain := range subdomains {
		target, exists := w.sshTunnelProvider.GetTunnelInfo(subdomain)
		if !exists {
			continue
		}

		tunnel := Tunnel{
			Subdomain: subdomain,
			Target:    target,
			Active:    true,
			HTTPURL:   fmt.Sprintf("http://%s.%s", subdomain, w.config.Domain),
			HTTPSURL:  fmt.Sprintf("https://%s.%s", subdomain, w.config.Domain),
		}

		tunnels = append(tunnels, tunnel)
	}

	return tunnels
}

// loadTemplates loads HTML templates
func (w *WebUI) loadTemplates() {
	dashboardTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>Tunnel Dashboard - {{.Domain}}</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Tunnel Dashboard</h1>
            <p>SSH Tunnel Server for {{.Domain}}</p>
        </header>

        <nav>
            <a href="/">Dashboard</a>
            <a href="/users">Manage Users</a>
        </nav>

        <main>
            <section class="tunnels">
                <h2>Active Tunnels</h2>
                {{if .Tunnels}}
                    <table>
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>URLs</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Tunnels}}
                            <tr>
                                <td>{{.Subdomain}}</td>
                                <td>{{.Target}}</td>
                                <td class="status {{if .Active}}active{{else}}inactive{{end}}">
                                    {{if .Active}}Active{{else}}Inactive{{end}}
                                </td>
                                <td>
                                    {{if .HTTPURL}}<a href="{{.HTTPURL}}" target="_blank">HTTP</a>{{end}}
                                    {{if .HTTPSURL}}<a href="{{.HTTPSURL}}" target="_blank">HTTPS</a>{{end}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                {{else}}
                    <p class="no-tunnels">No active tunnels</p>
                {{end}}
            </section>

            <section class="info">
                <h2>Connect via SSH</h2>
                <div class="ssh-info">
                    <p>To create a tunnel, connect via SSH with remote forwarding:</p>
                    <code>ssh -R 0:localhost:YOUR_PORT user@{{.Domain}}</code>
                    <p>Replace YOUR_PORT with your local service port (e.g., 3000, 8080)</p>
                </div>
            </section>
        </main>
    </div>
</body>
</html>
`

	usersTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>User Management - {{.Domain}}</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>User Management</h1>
            <p>SSH Tunnel Server for {{.Domain}}</p>
        </header>

        <nav>
            <a href="/">Dashboard</a>
            <a href="/users">Manage Users</a>
        </nav>

        <main>
            <section class="user-form">
                <h2>Add New User</h2>
                <form method="POST" action="/users">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Create User</button>
                </form>
            </section>

            <section class="users-list">
                <h2>Existing Users</h2>
                {{if .Users}}
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Users}}
                            <tr>
                                <td>{{.}}</td>
                                <td>
                                    <button onclick="deleteUser('{{.}}')" class="delete-btn">Delete</button>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                {{else}}
                    <p class="no-users">No users configured</p>
                {{end}}
            </section>
        </main>
    </div>

    <script>
        function deleteUser(username) {
            if (confirm('Are you sure you want to delete user: ' + username + '?')) {
                fetch('/users/' + username, {
                    method: 'DELETE'
                }).then(response => {
                    if (response.ok) {
                        location.reload();
                    } else {
                        alert('Failed to delete user');
                    }
                });
            }
        }
    </script>
</body>
</html>
`

	tmpl := template.New("webui")
	template.Must(tmpl.New("dashboard.html").Parse(dashboardTemplate))
	template.Must(tmpl.New("users.html").Parse(usersTemplate))

	w.templates = tmpl
}

// getBasicCSS returns basic CSS styling
func getBasicCSS() string {
	return `
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 0;
    background-color: #f5f5f5;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    background: white;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

header h1 {
    margin: 0 0 10px 0;
    color: #2c3e50;
}

nav {
    background: white;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

nav a {
    text-decoration: none;
    color: #3498db;
    margin-right: 20px;
    font-weight: 500;
}

nav a:hover {
    color: #2980b9;
}

main {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

th, td {
    text-align: left;
    padding: 12px;
    border-bottom: 1px solid #eee;
}

th {
    background-color: #f8f9fa;
    font-weight: 600;
}

.status.active {
    color: #27ae60;
    font-weight: 500;
}

.status.inactive {
    color: #e74c3c;
    font-weight: 500;
}

.no-tunnels, .no-users {
    text-align: center;
    color: #666;
    font-style: italic;
    padding: 40px;
}

.ssh-info {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 4px;
    margin-top: 15px;
}

.ssh-info code {
    background: #2c3e50;
    color: white;
    padding: 10px;
    border-radius: 4px;
    display: block;
    margin: 10px 0;
    font-family: 'Courier New', monospace;
}

.form-group {
    margin-bottom: 15px;
}

.form-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: 500;
}

.form-group input {
    width: 100%;
    max-width: 300px;
    padding: 8px 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

button {
    background: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}

button:hover {
    background: #2980b9;
}

.delete-btn {
    background: #e74c3c;
    padding: 5px 10px;
    font-size: 12px;
}

.delete-btn:hover {
    background: #c0392b;
}

section {
    margin-bottom: 30px;
}

section h2 {
    color: #2c3e50;
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
}
`
}

// InMemoryUserStore implements UserStore interface
type InMemoryUserStore struct {
	users map[string]string
	mutex sync.RWMutex
}

// NewInMemoryUserStore creates a new in-memory user store
func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users: make(map[string]string),
	}
}

// CreateUser creates a new user
func (s *InMemoryUserStore) CreateUser(username, password string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}

	// Check if user already exists
	if _, exists := s.users[username]; exists {
		return fmt.Errorf("user %s already exists", username)
	}

	s.users[username] = password
	return nil
}

// GetUser retrieves a user's password
func (s *InMemoryUserStore) GetUser(username string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	password, exists := s.users[username]
	return password, exists
}

// DeleteUser removes a user
func (s *InMemoryUserStore) DeleteUser(username string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.users, username)
	return nil
}

// GetAllUsers returns all usernames
func (s *InMemoryUserStore) GetAllUsers() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var users []string
	for username := range s.users {
		users = append(users, username)
	}
	return users
}

// VerifyPassword verifies a password (plaintext comparison for InMemoryUserStore)
func (s *InMemoryUserStore) VerifyPassword(username, password string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	storedPassword, exists := s.users[username]
	return exists && storedPassword == password
}

// UserData represents the stored user information
type UserData struct {
	Username    string    `json:"username"`
	PasswordHash string   `json:"password_hash"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FileUserStore implements UserStore interface with file-based persistence
type FileUserStore struct {
	filePath string
	users    map[string]UserData
	mutex    sync.RWMutex
}

// NewFileUserStore creates a new file-based user store
func NewFileUserStore(filePath string) (*FileUserStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	store := &FileUserStore{
		filePath: filePath,
		users:    make(map[string]UserData),
	}

	// Load existing users from file
	if err := store.loadFromFile(); err != nil {
		logger.Warnf("Failed to load users from file %s: %v", filePath, err)
		// Continue with empty store - file might not exist yet
	}

	return store, nil
}

// loadFromFile loads users from the JSON file
func (s *FileUserStore) loadFromFile() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if file exists
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		logger.Debugf("User store file %s does not exist, starting with empty store", s.filePath)
		return nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	if len(data) == 0 {
		logger.Debugf("User store file %s is empty, starting with empty store", s.filePath)
		return nil
	}

	var users []UserData
	if err := json.Unmarshal(data, &users); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	// Convert slice to map
	s.users = make(map[string]UserData)
	for _, user := range users {
		s.users[user.Username] = user
	}

	logger.Debugf("Loaded %d users from file %s", len(s.users), s.filePath)
	return nil
}

// saveToFile saves users to the JSON file
func (s *FileUserStore) saveToFile() error {
	// Convert map to slice
	users := make([]UserData, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Write to temporary file first, then rename for atomic operation
	tempFile := s.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary file: %v", err)
	}

	if err := os.Rename(tempFile, s.filePath); err != nil {
		os.Remove(tempFile) // Clean up temp file on error
		return fmt.Errorf("failed to rename temporary file: %v", err)
	}

	logger.Debugf("Saved %d users to file %s", len(users), s.filePath)
	return nil
}

// CreateUser creates a new user with bcrypt-hashed password
func (s *FileUserStore) CreateUser(username, password string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}

	// Check if user already exists
	if _, exists := s.users[username]; exists {
		return fmt.Errorf("user %s already exists", username)
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Create user data
	now := time.Now()
	userData := UserData{
		Username:     username,
		PasswordHash: string(hashedPassword),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Add to memory store
	s.users[username] = userData

	// Save to file
	if err := s.saveToFile(); err != nil {
		// Remove from memory if save failed
		delete(s.users, username)
		return fmt.Errorf("failed to save user to file: %v", err)
	}

	logger.Infof("User %s created and saved to file", username)
	return nil
}

// GetUser retrieves a user's password hash for authentication
func (s *FileUserStore) GetUser(username string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	userData, exists := s.users[username]
	if !exists {
		return "", false
	}

	return userData.PasswordHash, true
}

// VerifyPassword verifies a password against the stored hash
func (s *FileUserStore) VerifyPassword(username, password string) bool {
	passwordHash, exists := s.GetUser(username)
	if !exists {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	return err == nil
}

// DeleteUser removes a user
func (s *FileUserStore) DeleteUser(username string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if user exists
	if _, exists := s.users[username]; !exists {
		return fmt.Errorf("user %s does not exist", username)
	}

	// Remove from memory
	delete(s.users, username)

	// Save to file
	if err := s.saveToFile(); err != nil {
		return fmt.Errorf("failed to save after user deletion: %v", err)
	}

	logger.Infof("User %s deleted and file updated", username)
	return nil
}

// GetAllUsers returns all usernames
func (s *FileUserStore) GetAllUsers() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	users := make([]string, 0, len(s.users))
	for username := range s.users {
		users = append(users, username)
	}
	return users
}

// NewUserStore creates a user store based on configuration
func NewUserStore(storageType, filePath string) (UserStore, error) {
	switch storageType {
	case "file":
		return NewFileUserStore(filePath)
	case "memory":
		fallthrough
	default:
		logger.Infof("Using in-memory user store (storage_type=%s)", storageType)
		return NewInMemoryUserStore(), nil
	}
}