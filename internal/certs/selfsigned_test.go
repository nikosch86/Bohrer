package certs

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"bohrer-go/internal/config"
)

func TestGenerateWildcardCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:       "test.local",
		ACMECertPath: filepath.Join(tempDir, "cert.pem"),
		ACMEKeyPath:  filepath.Join(tempDir, "key.pem"),
	}

	err = GenerateWildcardCertificate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate wildcard certificate: %v", err)
	}

	// Verify certificate file exists
	certBytes, err := os.ReadFile(cfg.ACMECertPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	// Verify key file exists
	keyBytes, err := os.ReadFile(cfg.ACMEKeyPath)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}

	// Parse and verify certificate
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify certificate contains both domain and wildcard
	expectedDNS := map[string]bool{"test.local": false, "*.test.local": false}
	for _, name := range cert.DNSNames {
		if _, exists := expectedDNS[name]; exists {
			expectedDNS[name] = true
		}
	}

	for name, found := range expectedDNS {
		if !found {
			t.Errorf("Expected DNS name %s not found in certificate", name)
		}
	}

	// Parse and verify private key
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		t.Fatal("Failed to decode key PEM")
	}

	_, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}
}

func TestGenerateSelfSignedCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:       "example.com",
		ACMECertPath: filepath.Join(tempDir, "cert.pem"),
		ACMEKeyPath:  filepath.Join(tempDir, "key.pem"),
	}

	domains := []string{"localhost", "test.local", "192.168.1.1"}
	err = GenerateSelfSignedCertificate(cfg, domains)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Verify certificate file exists
	certBytes, err := os.ReadFile(cfg.ACMECertPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	// Parse and verify certificate
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		t.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify certificate contains expected domains
	expectedDNS := map[string]bool{"localhost": false, "test.local": false, "192.168.1.1": false}
	for _, name := range cert.DNSNames {
		if _, exists := expectedDNS[name]; exists {
			expectedDNS[name] = true
		}
	}

	for name, found := range expectedDNS {
		if !found {
			t.Errorf("Expected DNS name %s not found in certificate", name)
		}
	}

	// Verify IP addresses are included
	if len(cert.IPAddresses) < 2 { // At least localhost IPs should be present
		t.Errorf("Expected at least 2 IP addresses, got %d", len(cert.IPAddresses))
	}
}

func TestGenerateWildcardCertificateErrorPaths(t *testing.T) {
	// Test with invalid directory path (use /dev/null which can't be a directory)
	cfg := &config.Config{
		Domain:       "test.local",
		ACMECertPath: "/dev/null/cert.pem",
		ACMEKeyPath:  "/dev/null/key.pem",
	}

	err := GenerateWildcardCertificate(cfg)
	if err == nil {
		t.Error("Expected error when trying to write to invalid directory path")
	}
}

func TestGenerateSelfSignedCertificateErrorPaths(t *testing.T) {
	// Test with invalid directory path
	cfg := &config.Config{
		Domain:       "example.com",
		ACMECertPath: "/dev/null/cert.pem",
		ACMEKeyPath:  "/dev/null/key.pem",
	}

	domains := []string{"localhost"}
	err := GenerateSelfSignedCertificate(cfg, domains)
	if err == nil {
		t.Error("Expected error when trying to write to invalid directory path")
	}
}

func TestPermissionErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a file where we want a directory
	invalidDir := filepath.Join(tempDir, "not-a-dir")
	err = os.WriteFile(invalidDir, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &config.Config{
		Domain:       "test.local",
		ACMECertPath: filepath.Join(invalidDir, "cert.pem"), // This should fail
		ACMEKeyPath:  filepath.Join(tempDir, "key.pem"),
	}

	err = GenerateWildcardCertificate(cfg)
	if err == nil {
		t.Error("Expected error when certificate directory creation fails")
	}
}

func TestGenerateWildcardCertificateFilePermissionErrors(t *testing.T) {
	// Test with invalid path that will definitely fail
	cfg := &config.Config{
		Domain:       "test.local",
		ACMECertPath: "/proc/invalid/cert.pem", // This path should fail
		ACMEKeyPath:  "/proc/invalid/key.pem",
	}

	err := GenerateWildcardCertificate(cfg)
	if err == nil {
		t.Error("Expected error when writing to invalid path")
	}
}

func TestGenerateSelfSignedCertificateFilePermissionErrors(t *testing.T) {
	// Test with invalid path that will definitely fail
	cfg := &config.Config{
		Domain:       "example.com",
		ACMECertPath: "/proc/invalid/cert.pem", // This path should fail
		ACMEKeyPath:  "/proc/invalid/key.pem",
	}

	domains := []string{"localhost"}
	err := GenerateSelfSignedCertificate(cfg, domains)
	if err == nil {
		t.Error("Expected error when writing to invalid path")
	}
}

func TestGenerateWildcardCertificateKeyFileErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a scenario where cert directory exists but key directory is invalid
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := "/proc/invalid/key.pem" // This will cause key file creation to fail

	cfg := &config.Config{
		Domain:       "test.local",
		ACMECertPath: certPath,
		ACMEKeyPath:  keyPath,
	}

	err = GenerateWildcardCertificate(cfg)
	if err == nil {
		t.Error("Expected error when key file creation fails")
	}
}

func TestGenerateSelfSignedCertificateWithIPAddresses(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Domain:       "example.com",
		ACMECertPath: filepath.Join(tempDir, "cert.pem"),
		ACMEKeyPath:  filepath.Join(tempDir, "key.pem"),
	}

	// Test with IP addresses to ensure IP parsing code is covered
	domains := []string{"localhost", "127.0.0.1", "::1", "192.168.1.1"}
	err = GenerateSelfSignedCertificate(cfg, domains)
	if err != nil {
		t.Fatalf("Failed to generate certificate with IP addresses: %v", err)
	}

	// Verify certificate was created
	_, err = os.Stat(cfg.ACMECertPath)
	if err != nil {
		t.Errorf("Certificate file was not created: %v", err)
	}

	// Verify key was created
	_, err = os.Stat(cfg.ACMEKeyPath)
	if err != nil {
		t.Errorf("Key file was not created: %v", err)
	}
}
