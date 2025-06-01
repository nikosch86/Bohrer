package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"bohrer-go/internal/config"
	"bohrer-go/internal/logger"
)

const (
	filePerm = 0644
	keyPerm  = 0600
	dirPerm  = 0755
)

// GenerateWildcardCertificate creates a self-signed wildcard certificate for local development
func GenerateWildcardCertificate(cfg *config.Config) error {
	domains := []string{cfg.Domain, "*." + cfg.Domain}
	logger.Debugf("Generating self-signed wildcard certificate for: %v", domains)

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Bohrer SSH Tunnel"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{},
		DNSNames:     domains,
	}

	// Add localhost and common local IPs
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1))
	template.IPAddresses = append(template.IPAddresses, net.IPv6loopback)

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	// Create directory if it doesn't exist
	certDir := filepath.Dir(cfg.ACMECertPath)
	if err := os.MkdirAll(certDir, dirPerm); err != nil {
		return fmt.Errorf("creating certificate directory: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(cfg.ACMECertPath)
	if err != nil {
		return fmt.Errorf("creating certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encoding certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(cfg.ACMEKeyPath)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer keyOut.Close()

	// Encode private key
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod(cfg.ACMEKeyPath, keyPerm); err != nil {
		return fmt.Errorf("setting key file permissions: %w", err)
	}

	logger.Debugf("Wildcard self-signed certificate generated for *.%s", cfg.Domain)
	return nil
}

// GenerateSelfSignedCertificate creates a self-signed certificate for specific domains
func GenerateSelfSignedCertificate(cfg *config.Config, domains []string) error {
	logger.Debugf("Generating self-signed certificate for domains: %v", domains)

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Bohrer SSH Tunnel"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{},
		DNSNames:     domains,
	}

	// Add localhost and common local IPs
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1))
	template.IPAddresses = append(template.IPAddresses, net.IPv6loopback)

	// Parse any IP addresses in domains
	for _, domain := range domains {
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	// Create directory if it doesn't exist
	certDir := filepath.Dir(cfg.ACMECertPath)
	if err := os.MkdirAll(certDir, dirPerm); err != nil {
		return fmt.Errorf("creating certificate directory: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(cfg.ACMECertPath)
	if err != nil {
		return fmt.Errorf("creating certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encoding certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(cfg.ACMEKeyPath)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer keyOut.Close()

	// Encode private key
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod(cfg.ACMEKeyPath, keyPerm); err != nil {
		return fmt.Errorf("setting key file permissions: %w", err)
	}

	logger.Debugf("Self-signed certificate generated for domains: %v", domains)
	return nil
}