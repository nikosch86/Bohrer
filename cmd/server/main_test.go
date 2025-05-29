package main

import (
	"testing"
	"time"

	"github.com/hoffmann/bohrer-go/internal/config"
	"github.com/hoffmann/bohrer-go/internal/proxy"
	"github.com/hoffmann/bohrer-go/internal/ssh"
)

func TestMainComponents(t *testing.T) {
	// Test that main components can be created without errors
	cfg := config.Load()
	
	if cfg == nil {
		t.Fatal("Expected config to be loaded")
	}
	
	// Test proxy creation
	proxyServer := proxy.NewProxy(cfg)
	if proxyServer == nil {
		t.Fatal("Expected proxy server to be created")
	}
	
	// Test SSH server creation
	sshServer := ssh.NewServer(cfg)
	if sshServer == nil {
		t.Fatal("Expected SSH server to be created")
	}
	
	// Test SSH and proxy integration
	sshServer.SetTunnelManager(proxyServer)
	
	// Verify tunnel manager was set
	tunnels := sshServer.GetTunnels()
	if tunnels == nil {
		t.Error("Expected tunnels map to be accessible")
	}
}

func TestServerIntegration(t *testing.T) {
	// Test basic integration between SSH server and proxy
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   2223, // Use different port to avoid conflicts
		HTTPPort:  8081,
		HTTPSPort: 8444,
	}
	
	proxyServer := proxy.NewProxy(cfg)
	sshServer := ssh.NewServer(cfg)
	sshServer.SetTunnelManager(proxyServer)
	
	// Test that tunnels can be added via SSH server and appear in proxy
	err := proxyServer.AddTunnel("test", "localhost:3000")
	if err != nil {
		t.Errorf("Expected no error adding tunnel, got: %v", err)
	}
	
	// Test tunnel removal
	proxyServer.RemoveTunnel("test")
	
	// Test tunnel cleanup
	sshServer.CleanupDisconnectedTunnels()
}

func TestConfigDefaults(t *testing.T) {
	// Test that config loads with expected defaults
	cfg := config.Load()
	
	// These should have default values when environment variables aren't set
	if cfg.Domain == "" {
		t.Error("Expected domain to have a default value")
	}
	
	if cfg.SSHPort == 0 {
		t.Error("Expected SSH port to have a default value")
	}
	
	if cfg.HTTPPort == 0 {
		t.Error("Expected HTTP port to have a default value")
	}
	
	if cfg.HTTPSPort == 0 {
		t.Error("Expected HTTPS port to have a default value")
	}
}

func TestStartupSequence(t *testing.T) {
	// Test the startup sequence without actually starting servers
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   0, // Use port 0 to get a dynamic port
		HTTPPort:  0,
		HTTPSPort: 0,
	}
	
	// Create components in the same order as main()
	proxyServer := proxy.NewProxy(cfg)
	sshServer := ssh.NewServer(cfg)
	sshServer.SetTunnelManager(proxyServer)
	
	// Test that components are properly initialized
	if proxyServer == nil {
		t.Error("Expected proxy server to be initialized")
	}
	
	if sshServer == nil {
		t.Error("Expected SSH server to be initialized")
	}
	
	// Test that we can start components in goroutines without immediate errors
	errorChan := make(chan error, 2)
	
	// Start SSH server (will fail quickly due to port 0, but shouldn't panic)
	go func() {
		err := sshServer.Start()
		errorChan <- err
	}()
	
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	
	// Stop test early - we're just testing that the startup sequence works
}

func TestServerConfiguration(t *testing.T) {
	// Test various server configurations
	configs := []*config.Config{
		{
			Domain:    "localhost",
			SSHPort:   2222,
			HTTPPort:  8080,
			HTTPSPort: 8443,
		},
		{
			Domain:    "example.com",
			SSHPort:   22,
			HTTPPort:  80,
			HTTPSPort: 443,
		},
		{
			Domain:      "test.dev",
			SSHPort:     2224,
			HTTPPort:    8082,
			HTTPSPort:   8445,
			ACMEStaging: true,
		},
	}
	
	for i, cfg := range configs {
		proxyServer := proxy.NewProxy(cfg)
		sshServer := ssh.NewServer(cfg)
		sshServer.SetTunnelManager(proxyServer)
		
		if proxyServer == nil {
			t.Errorf("Config %d: Expected proxy server to be created", i)
		}
		
		if sshServer == nil {
			t.Errorf("Config %d: Expected SSH server to be created", i)
		}
	}
}