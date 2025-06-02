package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCertificateValidator(t *testing.T) {
	validator := NewCertificateValidator("/path/to/cert.pem", "/path/to/key.pem")
	
	if validator.CertPath != "/path/to/cert.pem" {
		t.Errorf("Expected cert path '/path/to/cert.pem', got '%s'", validator.CertPath)
	}
	
	if validator.KeyPath != "/path/to/key.pem" {
		t.Errorf("Expected key path '/path/to/key.pem', got '%s'", validator.KeyPath)
	}
}

func TestValidateCertPath(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certFile, []byte("dummy cert"), 0644); err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	
	tests := []struct {
		name      string
		certPath  string
		wantError bool
	}{
		{
			name:      "existing certificate",
			certPath:  certFile,
			wantError: false,
		},
		{
			name:      "non-existent certificate",
			certPath:  filepath.Join(tmpDir, "nonexistent.pem"),
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewCertificateValidator(tt.certPath, "")
			err := validator.ValidateCertPath()
			
			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidateKeyPath(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy key"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	
	tests := []struct {
		name      string
		keyPath   string
		wantError bool
	}{
		{
			name:      "existing key",
			keyPath:   keyFile,
			wantError: false,
		},
		{
			name:      "non-existent key",
			keyPath:   filepath.Join(tmpDir, "nonexistent.pem"),
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewCertificateValidator("", tt.keyPath)
			err := validator.ValidateKeyPath()
			
			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePaths(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	
	// Create both files
	if err := os.WriteFile(certFile, []byte("dummy cert"), 0644); err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("dummy key"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	
	tests := []struct {
		name      string
		certPath  string
		keyPath   string
		wantError bool
	}{
		{
			name:      "both files exist",
			certPath:  certFile,
			keyPath:   keyFile,
			wantError: false,
		},
		{
			name:      "missing cert",
			certPath:  filepath.Join(tmpDir, "missing.pem"),
			keyPath:   keyFile,
			wantError: true,
		},
		{
			name:      "missing key",
			certPath:  certFile,
			keyPath:   filepath.Join(tmpDir, "missing.pem"),
			wantError: true,
		},
		{
			name:      "both missing",
			certPath:  filepath.Join(tmpDir, "missing1.pem"),
			keyPath:   filepath.Join(tmpDir, "missing2.pem"),
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewCertificateValidator(tt.certPath, tt.keyPath)
			err := validator.ValidatePaths()
			
			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestLoadCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	
	// Generate a valid certificate and key for testing
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}
	
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	
	// Write certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()
	
	// Write private key
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyDER})
	keyOut.Close()
	
	tests := []struct {
		name      string
		certPath  string
		keyPath   string
		wantError bool
	}{
		{
			name:      "valid certificate",
			certPath:  certFile,
			keyPath:   keyFile,
			wantError: false,
		},
		{
			name:      "missing files",
			certPath:  filepath.Join(tmpDir, "missing.pem"),
			keyPath:   filepath.Join(tmpDir, "missing.pem"),
			wantError: true,
		},
		{
			name:      "invalid certificate content",
			certPath:  filepath.Join(tmpDir, "invalid.pem"),
			keyPath:   keyFile,
			wantError: true,
		},
	}
	
	// Create invalid cert for testing
	invalidCert := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(invalidCert, []byte("invalid cert content"), 0644); err != nil {
		t.Fatalf("Failed to create invalid cert: %v", err)
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewCertificateValidator(tt.certPath, tt.keyPath)
			cert, err := validator.LoadCertificate()
			
			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(cert.Certificate) == 0 {
					t.Error("Expected valid certificate")
				}
			}
		})
	}
}

func TestValidateCertificatePaths(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	
	// Create files
	if err := os.WriteFile(certFile, []byte("cert"), 0644); err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("key"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	
	// Test valid paths
	if err := ValidateCertificatePaths(certFile, keyFile); err != nil {
		t.Errorf("Expected no error for valid paths, got: %v", err)
	}
	
	// Test invalid paths
	if err := ValidateCertificatePaths("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Error("Expected error for invalid paths")
	}
}