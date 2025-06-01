package main

import (
	"fmt"
	"os"

	"bohrer-go/internal/acme"
	"bohrer-go/internal/certs"
	"bohrer-go/internal/config"
	"bohrer-go/internal/logger"
	"bohrer-go/internal/proxy"
	"bohrer-go/internal/ssh"
	"bohrer-go/internal/webui"
)

func main() {
	cfg := config.Load()

	// Initialize logger with config
	logger.SetLevel(cfg.LogLevel)

	// Display startup configuration
	displayConfig(cfg)

	// Create proxy for HTTP tunnel routing
	proxyServer := proxy.NewProxy(cfg)

	// Create SSH server and connect it to the proxy
	sshServer := ssh.NewServer(cfg)
	sshServer.SetTunnelManager(proxyServer)

	// Create and configure WebUI for management interface
	webUI := webui.NewWebUI(cfg)
	
	// Create adapter to connect SSH server and proxy with WebUI
	sshAdapter := webui.NewSSHServerAdapter(sshServer, proxyServer)
	webUI.SetSSHTunnelProvider(sshAdapter)
	
	// Connect WebUI user store to SSH server for authentication (via adapter)
	userStoreAdapter := webui.NewUserStoreAdapter(webUI.GetUserStore())
	sshServer.SetUserStore(userStoreAdapter)
	
	// Set WebUI in proxy to serve on root domain
	proxyServer.SetWebUI(webUI)

	// Create and configure ACME certificate manager
	var certificateManager *acme.Client
	if !cfg.SkipACME && cfg.ACMEEmail != "" {
		// Try to create ACME client, but don't fail if it can't connect to ACME server
		client, err := acme.NewClient(cfg)
		if err != nil {
			logger.Warnf("Failed to initialize ACME client: %v", err)
			// Generate self-signed certificate as fallback
			if err := certs.GenerateWildcardCertificate(cfg); err != nil {
				logger.Errorf("Failed to generate self-signed certificate: %v", err)
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
					logger.Debugf("Local domain with custom ACME directory URL: %s", cfg.ACMEDirectoryURL)
					logger.Debugf("Will use ACME for certificate generation")
				} else {
					logger.Infof("Local domain detected, generating wildcard self-signed certificate")
					if err := certs.GenerateWildcardCertificate(cfg); err != nil {
						logger.Errorf("Failed to generate wildcard certificate: %v", err)
					}
				}
			} else {
				logger.Infof("Public domain detected, will use ACME for certificate generation")
			}

			logger.Infof("✅ ACME certificate manager initialized")
		}
	} else {
		if cfg.SkipACME {
			logger.Infof("ACME disabled (SKIP_ACME=true), generating self-signed certificate")
		} else {
			logger.Infof("No ACME email configured, generating self-signed certificate")
		}
		// Generate self-signed wildcard certificate
		if err := certs.GenerateWildcardCertificate(cfg); err != nil {
			logger.Errorf("Failed to generate self-signed certificate: %v", err)
		}
	}

	// Start SSH server
	go func() {
		logger.Debugf("Starting SSH server on port %d", cfg.SSHPort)
		if err := sshServer.Start(); err != nil {
			logger.Fatalf("SSH server failed: %v", err)
		}
	}()

	// Start HTTP and HTTPS proxy servers for tunnel routing
	logger.Debugf("Starting HTTP proxy server on port %d", cfg.HTTPPort)

	// Check if we should start HTTPS
	startHTTPS := false
	if certificateManager != nil {
		// For now, just start HTTP - HTTPS will be enabled when certificates are available
		logger.Debugf("Certificate manager available - HTTPS will be enabled when tunnels are created")
	} else if _, err := os.Stat(cfg.ACMECertPath); err == nil {
		// Certificate file exists, try to start HTTPS
		startHTTPS = true
		logger.Debugf("Certificate file found, enabling HTTPS on port %d", cfg.HTTPSPort)
	}

	if startHTTPS {
		if err := proxyServer.StartBoth(); err != nil {
			logger.Warnf("HTTPS server failed (falling back to HTTP only): %v", err)
			// Fall back to HTTP only if HTTPS fails
			if err := proxyServer.Start(); err != nil {
				logger.Fatalf("HTTP proxy server failed: %v", err)
			}
		}
	} else {
		// Start HTTP only
		if err := proxyServer.Start(); err != nil {
			logger.Fatalf("HTTP proxy server failed: %v", err)
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

	// Show WebUI admin URL (HTTPS only)
	webuiHTTPSPort := cfg.HTTPSExternalPort
	if webuiHTTPSPort == 0 {
		webuiHTTPSPort = cfg.HTTPSPort
	}

	// Show HTTPS WebUI URL only
	webuiHTTPSURL := fmt.Sprintf("https://%s", cfg.Domain)
	if webuiHTTPSPort != 443 {
		webuiHTTPSURL = fmt.Sprintf("https://%s:%d", cfg.Domain, webuiHTTPSPort)
	}
	fmt.Printf("🔒 WebUI Admin (HTTPS): %s\n", webuiHTTPSURL)

	fmt.Println("=====================================")
	fmt.Println()
}

