package main

import (
	"fmt"
	"log"

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
	
	// Start SSH server
	go func() {
		log.Printf("Starting SSH server on port %d", cfg.SSHPort)
		if err := sshServer.Start(); err != nil {
			log.Fatalf("SSH server failed: %v", err)
		}
	}()

	// Start HTTP proxy server for tunnel routing
	log.Printf("Starting HTTP proxy server on port %d", cfg.HTTPPort)
	if err := proxyServer.Start(); err != nil {
		log.Fatalf("HTTP proxy server failed: %v", err)
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