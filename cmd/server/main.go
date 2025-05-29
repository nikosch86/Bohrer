package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/hoffmann/bohrer-go/internal/config"
	"github.com/hoffmann/bohrer-go/internal/ssh"
)

func main() {
	cfg := config.Load()
	
	sshServer := ssh.NewServer(cfg)
	go func() {
		log.Printf("Starting SSH server on port %d", cfg.SSHPort)
		if err := sshServer.Start(); err != nil {
			log.Fatalf("SSH server failed: %v", err)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "SSH Tunnel Server Running\nHost: %s\n", r.Host)
	})
	
	log.Printf("Starting HTTP server on port %d", cfg.HTTPPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.HTTPPort), nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}