package main

import (
	"fmt"
	"log"
	"os"

	"bohrer-go/internal/acme"
	"bohrer-go/internal/certs"
	"bohrer-go/internal/config"
	"bohrer-go/internal/proxy"
	"bohrer-go/internal/ssh"
)

func main() {
	cfg := config.Load()
	
	// Display startup configuration
	displayConfig(cfg)
	
	// Create proxy for HTTP tunnel routing
	proxyServer := proxy.NewProxy(cfg)
	
	// Create SSH server and connect it to the proxy
	sshServer := ssh.NewServer(cfg)
	sshServer.SetTunnelManager(proxyServer)
	
	// Create and configure ACME certificate manager
	var certificateManager *acme.Client
	if !cfg.SkipACME && cfg.ACMEEmail != "" {
		// Try to create ACME client, but don't fail if it can't connect to ACME server
		client, err := acme.NewClient(cfg)
		if err != nil {
			log.Printf("Warning: Failed to initialize ACME client: %v", err)
			// Generate self-signed certificate as fallback
			if err := certs.GenerateWildcardCertificate(cfg); err != nil {
				log.Printf("Failed to generate self-signed certificate: %v", err)
			}
		} else {
			certificateManager = client
			// Set tunnel provider for per-subdomain certificates
			certificateManager.SetTunnelProvider(sshServer)
			// Set certificate manager in SSH server for automatic cert generation
			sshServer.SetCertificateManager(certificateManager)
			
			// Check certificate strategy based on domain type and configuration
			if client.IsLocalDomain(cfg.Domain) {
				// Local domain: check if custom ACME directory URL is specified
				if cfg.ACMEDirectoryURL != "" {
					log.Printf("Local domain with custom ACME directory URL: %s", cfg.ACMEDirectoryURL)
					log.Printf("Will use ACME for certificate generation")
				} else {
					log.Printf("Local domain detected, generating wildcard self-signed certificate")
					if err := certs.GenerateWildcardCertificate(cfg); err != nil {
						log.Printf("Failed to generate wildcard certificate: %v", err)
					}
				}
			} else {
				log.Printf("Public domain detected, will use ACME for certificate generation")
			}
			
			log.Printf("✅ ACME certificate manager initialized")
		}
	} else {
		if cfg.SkipACME {
			log.Printf("ACME disabled (SKIP_ACME=true), generating self-signed certificate")
		} else {
			log.Printf("No ACME email configured, generating self-signed certificate")
		}
		// Generate self-signed wildcard certificate
		if err := certs.GenerateWildcardCertificate(cfg); err != nil {
			log.Printf("Failed to generate self-signed certificate: %v", err)
		}
	}
	
	// Start SSH server
	go func() {
		log.Printf("Starting SSH server on port %d", cfg.SSHPort)
		if err := sshServer.Start(); err != nil {
			log.Fatalf("SSH server failed: %v", err)
		}
	}()

	// Start HTTP and HTTPS proxy servers for tunnel routing
	log.Printf("Starting HTTP proxy server on port %d", cfg.HTTPPort)
	
	// Check if we should start HTTPS
	startHTTPS := false
	if certificateManager != nil {
		// For now, just start HTTP - HTTPS will be enabled when certificates are available
		log.Printf("Certificate manager available - HTTPS will be enabled when tunnels are created")
	} else if _, err := os.Stat(cfg.ACMECertPath); err == nil {
		// Certificate file exists, try to start HTTPS
		startHTTPS = true
		log.Printf("Certificate file found, enabling HTTPS on port %d", cfg.HTTPSPort)
	}
	
	if startHTTPS {
		if err := proxyServer.StartBoth(); err != nil {
			log.Printf("HTTPS server failed (falling back to HTTP only): %v", err)
			// Fall back to HTTP only if HTTPS fails
			if err := proxyServer.Start(); err != nil {
				log.Fatalf("HTTP proxy server failed: %v", err)
			}
		}
	} else {
		// Start HTTP only
		if err := proxyServer.Start(); err != nil {
			log.Fatalf("HTTP proxy server failed: %v", err)
		}
	}
}

func displayConfig(cfg *config.Config) {
	fmt.Println("🚀 Bohrer SSH Tunnel Server Starting")
	fmt.Println("=====================================")
	fmt.Printf("📍 Domain:              %s\n", cfg.Domain)
	fmt.Printf("🔧 SSH Port:            %d\n", cfg.SSHPort)
	fmt.Printf("🌐 HTTP Port:           %d\n", cfg.HTTPPort)
	fmt.Printf("🔒 HTTPS Port:          %d\n", cfg.HTTPSPort)
	
	// Show external ports if they differ from internal ports
	if cfg.HTTPExternalPort != 0 && cfg.HTTPExternalPort != cfg.HTTPPort {
		fmt.Printf("🌐 HTTP External Port:  %d\n", cfg.HTTPExternalPort)
	}
	if cfg.HTTPSExternalPort != 0 && cfg.HTTPSExternalPort != cfg.HTTPSPort {
		fmt.Printf("🔒 HTTPS External Port: %d\n", cfg.HTTPSExternalPort)
	}
	if cfg.SSHExternalPort != 0 && cfg.SSHExternalPort != cfg.SSHPort {
		fmt.Printf("🔧 SSH External Port:   %d\n", cfg.SSHExternalPort)
	}
	
	// Show example tunnel URL
	httpPort := cfg.HTTPExternalPort
	if httpPort == 0 {
		httpPort = cfg.HTTPPort
	}
	exampleURL := fmt.Sprintf("http://[subdomain].%s", cfg.Domain)
	if httpPort != 80 {
		exampleURL = fmt.Sprintf("http://[subdomain].%s:%d", cfg.Domain, httpPort)
	}
	fmt.Printf("🔗 Tunnel URL Format:   %s\n", exampleURL)
	
	// Show SSH connection command
	sshPort := cfg.SSHExternalPort
	if sshPort == 0 {
		sshPort = cfg.SSHPort
	}
	sshCommand := fmt.Sprintf("ssh -R 0:localhost:3000 tunnel@%s", cfg.Domain)
	if sshPort != 22 {
		sshCommand = fmt.Sprintf("ssh -R 0:localhost:3000 tunnel@%s -p %d", cfg.Domain, sshPort)
	}
	fmt.Printf("🔑 SSH Command Example: %s\n", sshCommand)
	
	if cfg.AuthorizedKeys != "" {
		fmt.Printf("🔐 SSH Auth Keys:       %s\n", cfg.AuthorizedKeys)
	}
	
	fmt.Println("=====================================")
	fmt.Println()
}

