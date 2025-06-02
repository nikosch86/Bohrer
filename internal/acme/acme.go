package acme

import (
	"context"
	"crypto"
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
	"strings"
	"time"

	"bohrer-go/internal/config"
	"bohrer-go/internal/fileutil"
	"bohrer-go/internal/logger"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	filePerm = 0644
	keyPerm  = 0600
	dirPerm  = 0755
)

// TunnelProvider interface for getting active tunnel subdomains
type TunnelProvider interface {
	GetActiveTunnelSubdomains() []string
}

// Client represents an ACME client for managing SSL certificates
type Client struct {
	config         *config.Config
	client         *lego.Client
	user           *User
	tunnelProvider TunnelProvider
	rateLimiter    *ACMERateLimiter
}

// User implements the acme.User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// HTTP01Provider implements the challenge.Provider interface for HTTP-01 challenges
type HTTP01Provider struct {
	challengeDir string
}

func (p *HTTP01Provider) Present(domain, token, keyAuth string) error {
	challengePath := filepath.Join(p.challengeDir, token)
	return fileutil.WriteFileWithDir(challengePath, []byte(keyAuth), filePerm)
}

func (p *HTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	challengePath := filepath.Join(p.challengeDir, token)
	return os.Remove(challengePath)
}

// NewClient creates a new ACME client
func NewClient(cfg *config.Config) (*Client, error) {
	// Generate private key for ACME account
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	user := &User{
		Email: cfg.ACMEEmail,
		key:   privateKey,
	}

	// Create lego config
	legoConfig := lego.NewConfig(user)
	if cfg.ACMEDirectoryURL != "" {
		legoConfig.CADirURL = cfg.ACMEDirectoryURL
	} else if cfg.ACMEStaging {
		legoConfig.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	} else {
		legoConfig.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("creating ACME client: %w", err)
	}

	// Set up HTTP-01 challenge provider
	provider := &HTTP01Provider{challengeDir: cfg.ACMEChallengeDir}
	err = client.Challenge.SetHTTP01Provider(provider)
	if err != nil {
		return nil, fmt.Errorf("setting HTTP-01 provider: %w", err)
	}

	// Register user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering user: %w", err)
	}
	user.Registration = reg

	// Determine if this is production (not staging and not custom ACME)
	isProduction := !cfg.ACMEStaging && cfg.ACMEDirectoryURL == ""

	return &Client{
		config:         cfg,
		client:         client,
		user:           user,
		tunnelProvider: nil, // Set later via SetTunnelProvider
		rateLimiter:    NewACMERateLimiter(isProduction),
	}, nil
}

// getSubdomainCertPath returns the certificate file path for a specific subdomain
func (c *Client) getSubdomainCertPath(subdomain string) string {
	certDir := filepath.Dir(c.config.ACMECertPath)
	return filepath.Join(certDir, fmt.Sprintf("%s.crt", subdomain))
}

// getSubdomainKeyPath returns the private key file path for a specific subdomain
func (c *Client) getSubdomainKeyPath(subdomain string) string {
	keyDir := filepath.Dir(c.config.ACMEKeyPath)
	return filepath.Join(keyDir, fmt.Sprintf("%s.key", subdomain))
}

// CheckSubdomainCertificate checks if a certificate exists and is valid for a specific subdomain
func (c *Client) CheckSubdomainCertificate(subdomain string) (bool, error) {
	fullDomain := fmt.Sprintf("%s.%s", subdomain, c.config.Domain)
	certPath := c.getSubdomainCertPath(subdomain)

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debugf("Certificate file for subdomain %s does not exist, needs to be obtained", subdomain)
			return false, nil
		}
		return false, fmt.Errorf("reading certificate for subdomain %s: %w", subdomain, err)
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		logger.Debugf("Certificate PEM data for subdomain %s is invalid, needs renewal", subdomain)
		return false, nil
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		logger.Debugf("Failed to parse certificate for subdomain %s: %v", subdomain, err)
		return false, nil
	}

	// Check if certificate is valid for the domain
	if err := cert.VerifyHostname(fullDomain); err != nil {
		logger.Debugf("Certificate is not valid for domain %s: %v", fullDomain, err)
		return false, nil
	}

	// Check expiration
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	logger.Debugf("Certificate for subdomain %s expires in %d days", subdomain, daysUntilExpiry)

	if daysUntilExpiry <= c.config.ACMERenewalDays {
		logger.Debugf("Certificate for subdomain %s expires within %d days, renewal needed", subdomain, c.config.ACMERenewalDays)
		return false, nil
	}

	logger.Debugf("Certificate for subdomain %s is valid and not due for renewal", subdomain)
	return true, nil
}

// CheckCertificate checks if a certificate exists and is valid for the given domains (legacy - kept for backward compatibility)
func (c *Client) CheckCertificate(domains []string) (bool, error) {
	certBytes, err := os.ReadFile(c.config.ACMECertPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debugf("Certificate file does not exist, needs to be obtained")
			return false, nil // Certificate doesn't exist, needs to be obtained
		}
		return false, fmt.Errorf("reading certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		logger.Debugf("Certificate PEM data is invalid, needs renewal")
		return false, nil
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		logger.Debugf("Failed to parse certificate: %v", err)
		return false, nil
	}

	// Check if certificate is valid for all required domains
	for _, domain := range domains {
		if err := cert.VerifyHostname(domain); err != nil {
			logger.Debugf("Certificate is not valid for domain %s: %v", domain, err)
			return false, nil // Certificate needs to be renewed
		}
	}

	// Check expiration
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	logger.Debugf("Certificate expires in %d days", daysUntilExpiry)

	if daysUntilExpiry <= c.config.ACMERenewalDays {
		logger.Debugf("Certificate expires within %d days, renewal needed", c.config.ACMERenewalDays)
		return false, nil
	}

	logger.Debugf("Certificate is valid and not due for renewal")
	return true, nil
}

// ObtainSubdomainCertificate obtains a new certificate for a specific subdomain
func (c *Client) ObtainSubdomainCertificate(ctx context.Context, subdomain string) error {
	fullDomain := fmt.Sprintf("%s.%s", subdomain, c.config.Domain)
	logger.Debugf("Obtaining certificate for subdomain domain: %s", fullDomain)

	// Check rate limits before attempting
	if err := c.rateLimiter.CanMakeNewOrder(); err != nil {
		return fmt.Errorf("rate limit check failed for new order: %w", err)
	}

	if err := c.rateLimiter.CanIssueCertificateForDomain(c.config.Domain); err != nil {
		return fmt.Errorf("rate limit check failed for domain %s: %w", c.config.Domain, err)
	}

	if err := c.rateLimiter.CanRetryAuthFailure(fullDomain); err != nil {
		return fmt.Errorf("rate limit check failed for auth retry on %s: %w", fullDomain, err)
	}

	// Record that we're making a new order
	c.rateLimiter.RecordNewOrder()

	request := certificate.ObtainRequest{
		Domains: []string{fullDomain},
		Bundle:  true,
	}

	certificates, err := c.client.Certificate.Obtain(request)
	if err != nil {
		// Record auth failure for rate limiting
		c.rateLimiter.RecordAuthFailure(fullDomain)
		return fmt.Errorf("obtaining certificate for subdomain %s: %w", subdomain, err)
	}

	// Record successful certificate issuance
	c.rateLimiter.RecordCertificateIssued(c.config.Domain)

	// Create directory if it doesn't exist
	certDir := filepath.Dir(c.config.ACMECertPath)
	if err := os.MkdirAll(certDir, dirPerm); err != nil {
		return fmt.Errorf("creating certificate directory: %w", err)
	}

	certPath := c.getSubdomainCertPath(subdomain)
	keyPath := c.getSubdomainKeyPath(subdomain)

	// Save certificate
	if err := fileutil.WriteFileWithDir(certPath, certificates.Certificate, filePerm); err != nil {
		return fmt.Errorf("saving certificate for subdomain %s: %w", subdomain, err)
	}

	// Save private key
	if err := fileutil.WriteFileWithDir(keyPath, certificates.PrivateKey, keyPerm); err != nil {
		return fmt.Errorf("saving private key for subdomain %s: %w", subdomain, err)
	}

	logger.Debugf("Certificate for subdomain %s saved to %s", subdomain, certPath)
	logger.Debugf("Private key for subdomain %s saved to %s", subdomain, keyPath)

	return nil
}

// ObtainCertificate obtains a new certificate for the given domains (legacy - kept for backward compatibility)
func (c *Client) ObtainCertificate(ctx context.Context, domains []string) error {
	logger.Debugf("Obtaining certificate for domains: %v", domains)

	// Check rate limits before attempting
	if err := c.rateLimiter.CanMakeNewOrder(); err != nil {
		return fmt.Errorf("rate limit check failed for new order: %w", err)
	}

	if err := c.rateLimiter.CanIssueCertificateForDomain(c.config.Domain); err != nil {
		return fmt.Errorf("rate limit check failed for domain %s: %w", c.config.Domain, err)
	}

	// Check auth failure rate limits for all domains
	for _, domain := range domains {
		if err := c.rateLimiter.CanRetryAuthFailure(domain); err != nil {
			return fmt.Errorf("rate limit check failed for auth retry on %s: %w", domain, err)
		}
	}

	// Record that we're making a new order
	c.rateLimiter.RecordNewOrder()

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := c.client.Certificate.Obtain(request)
	if err != nil {
		// Record auth failures for all domains
		for _, domain := range domains {
			c.rateLimiter.RecordAuthFailure(domain)
		}
		return fmt.Errorf("obtaining certificate: %w", err)
	}

	// Record successful certificate issuance
	c.rateLimiter.RecordCertificateIssued(c.config.Domain)

	// Save certificate
	if err := fileutil.WriteFileWithDir(c.config.ACMECertPath, certificates.Certificate, filePerm); err != nil {
		return fmt.Errorf("saving certificate: %w", err)
	}

	// Save private key
	if err := fileutil.WriteFileWithDir(c.config.ACMEKeyPath, certificates.PrivateKey, keyPerm); err != nil {
		return fmt.Errorf("saving private key: %w", err)
	}

	logger.Debugf("Certificate saved to %s", c.config.ACMECertPath)
	logger.Debugf("Private key saved to %s", c.config.ACMEKeyPath)

	return nil
}

// SetTunnelProvider sets the tunnel provider for getting active subdomains
func (c *Client) SetTunnelProvider(tp TunnelProvider) {
	c.tunnelProvider = tp
}

// GetDomains returns the list of domains that need certificates
func (c *Client) GetDomains() []string {
	if c.tunnelProvider == nil {
		return []string{} // No tunnels, no certificates needed
	}

	// Get active tunnel subdomains
	subdomains := c.tunnelProvider.GetActiveTunnelSubdomains()
	var domains []string

	// Convert subdomains to full domain names
	for _, subdomain := range subdomains {
		fullDomain := fmt.Sprintf("%s.%s", subdomain, c.config.Domain)
		domains = append(domains, fullDomain)
	}

	return domains
}

// GetSubdomainCertificatePaths returns the certificate and key file paths for a subdomain
func (c *Client) GetSubdomainCertificatePaths(subdomain string) (certPath, keyPath string) {
	return c.getSubdomainCertPath(subdomain), c.getSubdomainKeyPath(subdomain)
}

// IsValidDomain checks if a domain is valid for certificate generation
func (c *Client) IsValidDomain(domain string) bool {
	// Must contain at least one dot for a valid domain (except localhost)
	if domain != "localhost" && !strings.Contains(domain, ".") {
		return false
	}
	return true
}

// GetRateLimitStatus returns current rate limit status for monitoring
func (c *Client) GetRateLimitStatus() map[string]interface{} {
	return c.rateLimiter.GetRateLimitStatus()
}

// IsLocalDomain checks if a domain should use self-signed certificates
func (c *Client) IsLocalDomain(domain string) bool {
	// Unless forced to use ACME for local domains, treat these as local
	if c.config.ACMEForceLocal {
		return false
	}

	// Common local domain patterns
	localPatterns := []string{
		"localhost",
		".local",
		".lan",
		".home",
		".internal",
		".dev",
		".test",
	}

	for _, pattern := range localPatterns {
		if domain == pattern[1:] || domain == pattern || strings.HasSuffix(domain, pattern) {
			return true
		}
	}

	// Check for private IP addresses or local hostnames
	if ip := net.ParseIP(domain); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback()
	}

	return false
}

// EnsureCertificatesForActiveTunnels ensures valid certificates exist for all active tunnel subdomains
func (c *Client) EnsureCertificatesForActiveTunnels(ctx context.Context) error {
	if c.tunnelProvider == nil {
		logger.Debugf("No tunnel provider set, skipping certificate management")
		return nil
	}

	// Get active tunnel subdomains
	subdomains := c.tunnelProvider.GetActiveTunnelSubdomains()
	if len(subdomains) == 0 {
		logger.Debugf("No active tunnels, no certificates needed")
		return nil
	}

	logger.Debugf("Ensuring certificates for active tunnel subdomains: %v", subdomains)

	// Ensure certificate for each subdomain
	for _, subdomain := range subdomains {
		if err := c.EnsureSubdomainCertificate(ctx, subdomain); err != nil {
			logger.Debugf("Failed to ensure certificate for subdomain %s: %v", subdomain, err)
			// Continue with other subdomains instead of failing completely
			continue
		}
	}

	return nil
}

// EnsureCertificate ensures a valid certificate exists for the configured domain (legacy - now handles per-subdomain)
func (c *Client) EnsureCertificate(ctx context.Context) error {
	// New behavior: ensure certificates for active tunnels
	return c.EnsureCertificatesForActiveTunnels(ctx)
}

// GenerateSelfSignedCertificate creates a self-signed certificate for local domains
func (c *Client) GenerateSelfSignedCertificate(domains []string) error {
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
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
		DNSNames:    domains,
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
	certDir := filepath.Dir(c.config.ACMECertPath)
	if err := os.MkdirAll(certDir, dirPerm); err != nil {
		return fmt.Errorf("creating certificate directory: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(c.config.ACMECertPath)
	if err != nil {
		return fmt.Errorf("creating certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encoding certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(c.config.ACMEKeyPath)
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
	if err := os.Chmod(c.config.ACMEKeyPath, keyPerm); err != nil {
		return fmt.Errorf("setting key file permissions: %w", err)
	}

	logger.Debugf("Self-signed certificate saved to %s", c.config.ACMECertPath)
	logger.Debugf("Private key saved to %s", c.config.ACMEKeyPath)

	return nil
}

// CleanupSubdomainCertificate removes certificate files for a specific subdomain
func (c *Client) CleanupSubdomainCertificate(subdomain string) error {
	certPath := c.getSubdomainCertPath(subdomain)
	keyPath := c.getSubdomainKeyPath(subdomain)

	// Remove certificate file
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		logger.Debugf("Warning: failed to remove certificate file for subdomain %s: %v", subdomain, err)
	}

	// Remove key file
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		logger.Debugf("Warning: failed to remove key file for subdomain %s: %v", subdomain, err)
	}

	logger.Debugf("Cleaned up certificate files for subdomain %s", subdomain)
	return nil
}

// StartPeriodicRenewal starts a background goroutine that periodically checks and renews certificates
func (c *Client) StartPeriodicRenewal(ctx context.Context) {
	// Check certificates every 24 hours
	ticker := time.NewTicker(24 * time.Hour)

	go func() {
		defer ticker.Stop()

		logger.Infof("Starting periodic certificate renewal checker (every 24 hours)")

		// Do an initial check after 1 minute to allow system to fully start
		time.Sleep(1 * time.Minute)
		c.checkAndRenewCertificates(ctx)

		for {
			select {
			case <-ctx.Done():
				logger.Debugf("Certificate renewal checker stopping due to context cancellation")
				return
			case <-ticker.C:
				c.checkAndRenewCertificates(ctx)
			}
		}
	}()
}

// checkAndRenewCertificates checks all active tunnel certificates and renews them if needed
func (c *Client) checkAndRenewCertificates(ctx context.Context) {
	logger.Debugf("Running periodic certificate renewal check")

	if c.tunnelProvider == nil {
		logger.Debugf("No tunnel provider set, skipping certificate renewal check")
		return
	}

	// Get active tunnel subdomains
	subdomains := c.tunnelProvider.GetActiveTunnelSubdomains()
	if len(subdomains) == 0 {
		logger.Debugf("No active tunnels, no certificates to check for renewal")
		return
	}

	logger.Debugf("Checking certificates for renewal: %v", subdomains)
	renewalCount := 0

	// Check each subdomain certificate
	for _, subdomain := range subdomains {
		fullDomain := fmt.Sprintf("%s.%s", subdomain, c.config.Domain)

		// Skip invalid domains
		if !c.IsValidDomain(fullDomain) {
			continue
		}

		// Check if certificate is valid
		valid, err := c.CheckSubdomainCertificate(subdomain)
		if err != nil {
			logger.Warnf("Error checking certificate for subdomain %s: %v", subdomain, err)
			continue
		}

		if !valid {
			logger.Infof("Certificate for subdomain %s needs renewal", subdomain)

			if c.IsLocalDomain(fullDomain) {
				// Renew self-signed certificate for local domains
				if err := c.GenerateSubdomainSelfSignedCertificate(subdomain); err != nil {
					logger.Errorf("Failed to renew self-signed certificate for subdomain %s: %v", subdomain, err)
					continue
				}
				logger.Infof("✅ Renewed self-signed certificate for subdomain %s", subdomain)
			} else {
				// Renew ACME certificate for public domains
				if err := c.ObtainSubdomainCertificate(ctx, subdomain); err != nil {
					logger.Errorf("Failed to renew ACME certificate for subdomain %s: %v", subdomain, err)
					continue
				}
				logger.Infof("✅ Renewed ACME certificate for subdomain %s", subdomain)
			}
			renewalCount++
		}
	}

	if renewalCount > 0 {
		logger.Infof("✅ Certificate renewal check completed: %d certificates renewed", renewalCount)
	} else {
		logger.Debugf("Certificate renewal check completed: no certificates needed renewal")
	}
}

// EnsureSubdomainCertificate ensures a valid certificate exists for a specific subdomain
func (c *Client) EnsureSubdomainCertificate(ctx context.Context, subdomain string) error {
	fullDomain := fmt.Sprintf("%s.%s", subdomain, c.config.Domain)

	// Check if domain is valid
	if !c.IsValidDomain(fullDomain) {
		logger.Debugf("Domain %s is not valid for certificate generation", fullDomain)
		return nil
	}

	// Check if certificate is valid
	valid, err := c.CheckSubdomainCertificate(subdomain)
	if err != nil {
		return fmt.Errorf("checking certificate for subdomain %s: %w", subdomain, err)
	}

	if !valid {
		if c.IsLocalDomain(fullDomain) {
			// Generate self-signed certificate for local domains
			if err := c.GenerateSubdomainSelfSignedCertificate(subdomain); err != nil {
				return fmt.Errorf("generating self-signed certificate for subdomain %s: %w", subdomain, err)
			}
		} else {
			// Obtain ACME certificate for public domains
			if err := c.ObtainSubdomainCertificate(ctx, subdomain); err != nil {
				return fmt.Errorf("obtaining ACME certificate for subdomain %s: %w", subdomain, err)
			}
		}
	}

	return nil
}

// GenerateSubdomainSelfSignedCertificate creates a self-signed certificate for a specific subdomain
func (c *Client) GenerateSubdomainSelfSignedCertificate(subdomain string) error {
	fullDomain := fmt.Sprintf("%s.%s", subdomain, c.config.Domain)
	logger.Debugf("Generating self-signed certificate for subdomain domain: %s", fullDomain)

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating private key for subdomain %s: %w", subdomain, err)
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
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
		DNSNames:    []string{fullDomain},
	}

	// Add localhost and common local IPs
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1))
	template.IPAddresses = append(template.IPAddresses, net.IPv6loopback)

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("creating certificate for subdomain %s: %w", subdomain, err)
	}

	// Create directory if it doesn't exist
	certDir := filepath.Dir(c.config.ACMECertPath)
	if err := os.MkdirAll(certDir, dirPerm); err != nil {
		return fmt.Errorf("creating certificate directory: %w", err)
	}

	certPath := c.getSubdomainCertPath(subdomain)
	keyPath := c.getSubdomainKeyPath(subdomain)

	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("creating certificate file for subdomain %s: %w", subdomain, err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("encoding certificate for subdomain %s: %w", subdomain, err)
	}

	// Save private key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("creating key file for subdomain %s: %w", subdomain, err)
	}
	defer keyOut.Close()

	// Encode private key
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshaling private key for subdomain %s: %w", subdomain, err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("encoding private key for subdomain %s: %w", subdomain, err)
	}

	// Set proper permissions
	if err := os.Chmod(keyPath, keyPerm); err != nil {
		return fmt.Errorf("setting key file permissions for subdomain %s: %w", subdomain, err)
	}

	logger.Debugf("Self-signed certificate for subdomain %s saved to %s", subdomain, certPath)
	logger.Debugf("Private key for subdomain %s saved to %s", subdomain, keyPath)

	return nil
}
