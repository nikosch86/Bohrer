package common

import (
	"crypto/tls"
	"fmt"
	"os"
)

// CertificateValidator provides utilities for certificate validation
type CertificateValidator struct {
	CertPath string
	KeyPath  string
}

// NewCertificateValidator creates a new certificate validator
func NewCertificateValidator(certPath, keyPath string) *CertificateValidator {
	return &CertificateValidator{
		CertPath: certPath,
		KeyPath:  keyPath,
	}
}

// ValidatePaths checks if certificate and key files exist
func (v *CertificateValidator) ValidatePaths() error {
	if err := v.ValidateCertPath(); err != nil {
		return err
	}
	if err := v.ValidateKeyPath(); err != nil {
		return err
	}
	return nil
}

// ValidateCertPath checks if the certificate file exists
func (v *CertificateValidator) ValidateCertPath() error {
	if _, err := os.Stat(v.CertPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate file not found: %s", v.CertPath)
	}
	return nil
}

// ValidateKeyPath checks if the key file exists
func (v *CertificateValidator) ValidateKeyPath() error {
	if _, err := os.Stat(v.KeyPath); os.IsNotExist(err) {
		return fmt.Errorf("key file not found: %s", v.KeyPath)
	}
	return nil
}

// LoadCertificate validates paths and loads the X509 key pair
func (v *CertificateValidator) LoadCertificate() (tls.Certificate, error) {
	if err := v.ValidatePaths(); err != nil {
		return tls.Certificate{}, err
	}
	
	cert, err := tls.LoadX509KeyPair(v.CertPath, v.KeyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading TLS certificate: %w", err)
	}
	
	return cert, nil
}

// ValidateCertificatePaths is a convenience function for quick path validation
func ValidateCertificatePaths(certPath, keyPath string) error {
	validator := NewCertificateValidator(certPath, keyPath)
	return validator.ValidatePaths()
}